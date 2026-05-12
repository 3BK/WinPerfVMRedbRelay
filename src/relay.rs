use crate::audit::AuditGuard;
use crate::config::RelayConfig;
use crate::guards::PipeGuard;

use log::Level;
use rand::RngExt;
use redb::{Database, TableDefinition, WriteStrategy};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;

/// Stored value encoding:
/// [0..8)   = ingest_ts_ns (u64 BE)
/// [8..12)  = payload_len (u32 BE)
/// [12..]   = payload bytes
const HEADER_LEN: usize = 8 + 4;

/// Key encoding: [0..8) = timestamp_ns (u64 BE), [8..16) = counter (u64 BE)
const KEY_LEN: usize = 16;

/// redb Table definition for the persistent queue
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
    db: Arc<Database>, // Changed from Keyspace
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
                    audit.log(Level::Warn, 1023, "Ingest paused due to disk high-water mark.");
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }

                let n = match _g.0.read(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        audit.log(Level::Warn, 1012, &format!("Named pipe read error: {e}"));
                        break;
                    }
                };

                if n == 0 { break; }

                let mut now_ns = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;

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

                // redb write transaction
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
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub async fn run_disk_guard(
    db: Arc<Database>, // Changed from Keyspace
    cfg: RelayConfig,
    audit: Arc<AuditGuard>,
    gate: Arc<IngestGate>,
) {
    let interval_secs = cfg.buffer.retention_check_interval_seconds.unwrap_or(5).max(1);
    let max_disk_bytes = cfg.buffer.max_disk_bytes.unwrap_or(4_294_967_296);
    let resume_bytes = (max_disk_bytes as f64 * 0.95) as u64;

    loop {
        // In redb, we check the underlying file size or metadata
        // For simple usage, we can look at the database file size
        let disk = std::fs::metadata(cfg.buffer.path.as_deref().unwrap_or("relay.redb"))
            .map(|m| m.len())
            .unwrap_or(0);

        if disk >= max_disk_bytes {
            if !gate.is_paused() {
                gate.set_paused(true);
                audit.log(Level::Error, 1023, &format!("Disk high-water exceeded: disk_bytes={disk}. Pausing."));
            }
        } else if disk <= resume_bytes {
            if gate.is_paused() {
                gate.set_paused(false);
                audit.log(Level::Info, 1034, &format!("Disk back under threshold: disk_bytes={disk}. Resuming."));
            }
        }

        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}

pub async fn run_egress(
    url: String,
    http: reqwest::Client,
    db: Arc<Database>, // Changed from Keyspace
    cfg: RelayConfig,
    audit: Arc<AuditGuard>,
) {
    let base_backoff = cfg.forwarder.base_backoff_ms.unwrap_or(500);
    let max_backoff = cfg.forwarder.max_backoff_ms.unwrap_or(30_000);
    let max_jitter = cfg.forwarder.max_jitter_ms.unwrap_or(2_000);
    let batch_size = cfg.forwarder.batch_size.unwrap_or(1_000);

    let mut backoff = base_backoff;
    let mut rng = rand::rng();

    loop {
        let mut batch: Vec<([u8; KEY_LEN], Vec<u8>)> = Vec::with_capacity(batch_size);

        // redb read transaction for batching
        let read_res = (|| -> Result<(), redb::Error> {
            let txn = db.begin_read()?;
            let table = txn.open_table(MESSAGES_TABLE)?;
            // table.iter() returns elements in sorted order (FIFO)
            for item in table.iter()?.take(batch_size) {
                let (k, v) = item?;
                batch.push((k.value(), v.value().to_vec()));
            }
            Ok(())
        })();

        if let Err(e) = read_res {
            audit.log(Level::Warn, 1031, &format!("redb iter read error: {e}"));
        }

        if batch.is_empty() {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }

        let mut payload: Vec<u8> = Vec::new();
        let mut malformed = 0usize;

        for (_k, v) in &batch {
            if v.len() < HEADER_LEN {
                malformed += 1;
                continue;
            }
            let declared_len = u32::from_be_bytes([v[8], v[9], v[10], v[11]]) as usize;
            let available = v.len().saturating_sub(HEADER_LEN);
            let take_len = declared_len.min(available);
            payload.extend_from_slice(&v[HEADER_LEN..HEADER_LEN + take_len]);
        }

        if malformed > 0 {
            audit.log(Level::Error, 1033, &format!("Malformed records in FIFO head: count={malformed}"));
        }

        if payload.is_empty() {
            let sleep_ms = backoff + rng.random_range(0..max_jitter);
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
            backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
            continue;
        }

        let started = Instant::now();
        match http.post(&url).body(payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                // SUCCESS: Delete keys in a single write transaction
                let delete_res = (|| -> Result<(), redb::Error> {
                    let txn = db.begin_write()?;
                    {
                        let mut table = txn.open_table(MESSAGES_TABLE)?;
                        for (k, _) in &batch {
                            table.remove(k)?;
                        }
                    }
                    txn.commit()?;
                    Ok(())
                })();

                if let Err(e) = delete_res {
                    audit.log(Level::Error, 1031, &format!("redb batch delete failed: {e}"));
                } else {
                    let latency_ms = started.elapsed().as_millis();
                    audit.log(Level::Info, 1030, &format!("Batch delivered; count={}; latency={}ms", batch.len(), latency_ms));
                    backoff = base_backoff;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Ok(resp) => {
                let status = resp.status().as_u16();
                let sleep_ms = backoff + rng.random_range(0..max_jitter);
                audit.log(Level::Warn, 1031, &format!("Egress HTTP {status}; retrying in {sleep_ms}ms"));
                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
            }
            Err(e) => {
                let sleep_ms = backoff + rng.random_range(0..max_jitter);
                audit.log(Level::Warn, 1031, &format!("Egress transport failure: {e}; retrying in {sleep_ms}ms"));
                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
            }
        }
    }
}
