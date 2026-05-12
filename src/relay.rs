use crate::audit::AuditGuard;
use crate::config::RelayConfig;
use crate::guards::PipeGuard;

use log::Level;
// Fix: Import ReadableTable for .iter() and ReadableDatabase for .begin_read()
use redb::{Database, TableDefinition, ReadableDatabase, ReadableTable};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;

const HEADER_LEN: usize = 8 + 4;
const KEY_LEN: usize = 16;
const MESSAGES_TABLE: TableDefinition<[u8; KEY_LEN], &[u8]> = TableDefinition::new("messages");

#[derive(Debug)]
pub struct IngestGate {
    paused: AtomicBool,
}

impl IngestGate {
    pub fn new() -> Self {
        Self { paused: AtomicBool::new(false) }
    }
    pub fn set_paused(&self, v: bool) {
        self.paused.store(v, Ordering::Relaxed);
    }
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }
}

fn make_key(ts_ns: u64, ctr: u64) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    key[..8].copy_from_slice(&ts_ns.to_be_bytes());
    key[8..].copy_from_slice(&ctr.to_be_bytes());
    key
}

pub async fn run_ingestion(
    pipe_path: String,
    db: Arc<Database>,
    audit: Arc<AuditGuard>,
    gate: Arc<IngestGate>,
) {
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_path)
        .expect("NIST AC-4: Failed to create secure named pipe");

    let mut last_ts_ns: u64 = 0;
    let mut counter: u64 = 0;

    loop {
        if server.connect().await.is_ok() {
            let _g = PipeGuard(&mut server);
            let mut buf = vec![0u8; 65_536];

            loop {
                if gate.is_paused() {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }

                let n = match _g.0.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => break,
                };

                let mut now_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
                if now_ns < last_ts_ns { now_ns = last_ts_ns; }
                if now_ns != last_ts_ns {
                    counter = 0;
                    last_ts_ns = now_ns;
                } else {
                    counter = counter.wrapping_add(1);
                }

                let key = make_key(now_ns, counter);
                let mut value = Vec::with_capacity(HEADER_LEN + n);
                value.extend_from_slice(&now_ns.to_be_bytes());
                value.extend_from_slice(&(n as u32).to_be_bytes());
                value.extend_from_slice(&buf[..n]);

                let res = (|| -> Result<(), redb::Error> {
                    let txn = db.begin_write()?;
                    {
                        let mut table = txn.open_table(MESSAGES_TABLE)?;
                        table.insert(key, value.as_slice())?;
                    }
                    txn.commit()?;
                    Ok(())
                })();

                if let Err(e) = res {
                    audit.log(Level::Error, 1022, &format!("redb insert failed: {e}"));
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub async fn run_disk_guard(
    _db: Arc<Database>,
    cfg: RelayConfig,
    audit: Arc<AuditGuard>,
    gate: Arc<IngestGate>,
) {
    let interval_secs = cfg.buffer.retention_check_interval_seconds.unwrap_or(5).max(1);
    let max_disk_bytes = cfg.buffer.max_disk_bytes.unwrap_or(4_294_967_296);
    let resume_bytes = (max_disk_bytes as f64 * 0.95) as u64;

    loop {
        // Fix: Use metrics_queue field as 'path' is missing from config
        let disk = std::fs::metadata(&cfg.buffer.metrics_queue)
            .map(|m| m.len())
            .unwrap_or(0);

        if disk >= max_disk_bytes {
            if !gate.is_paused() {
                gate.set_paused(true);
                audit.log(Level::Error, 1023, &format!("Disk limit hit: {disk} bytes. Pausing."));
            }
        } else if disk <= resume_bytes && gate.is_paused() {
            gate.set_paused(false);
            audit.log(Level::Info, 1034, &format!("Disk recovered: {disk} bytes. Resuming."));
        }
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}

pub async fn run_egress(
    url: String,
    http: reqwest::Client,
    db: Arc<Database>,
    cfg: RelayConfig,
    audit: Arc<AuditGuard>,
) {
    let batch_size = cfg.forwarder.batch_size.unwrap_or(1_000);
    let base_backoff = Duration::from_millis(cfg.forwarder.base_backoff_ms.unwrap_or(500));
    let mut backoff = base_backoff;

    loop {
        let mut batch = Vec::with_capacity(batch_size);

        // Fix: ReadableDatabase and ReadableTable traits required here
        let read_res = (|| -> Result<(), redb::Error> {
            let txn = db.begin_read()?;
            let table = txn.open_table(MESSAGES_TABLE)?;
            for item in table.iter()?.take(batch_size) {
                let (k, v) = item?;
                batch.push((k.value(), v.value().to_vec()));
            }
            Ok(())
        })();

        if batch.is_empty() {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }

        let mut payload = Vec::new();
        for (_, v) in &batch {
            if v.len() >= HEADER_LEN {
                let len = u32::from_be_bytes([v[8], v[9], v[10], v[11]]) as usize;
                payload.extend_from_slice(&v[HEADER_LEN..(HEADER_LEN + len).min(v.len())]);
            }
        }

        match http.post(&url).body(payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                let _ = (|| -> Result<(), redb::Error> {
                    let txn = db.begin_write()?;
                    {
                        let mut table = txn.open_table(MESSAGES_TABLE)?;
                        for (k, _) in &batch { table.remove(k)?; }
                    }
                    txn.commit()?;
                    Ok(())
                })();
                backoff = base_backoff;
            }
            _ => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}
