mod config;
mod guards;
mod tls;
mod relay;
mod audit;

use std::{env, sync::Arc, path::Path};
use windows_service::{define_windows_service, service_dispatcher};
// Replace Fjall with redb imports [cite: 8, 23]
use redb::{Database, WriteStrategy};

define_windows_service!(ffi_service_main, my_service_main);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args().any(|x| x == "--console") {
        run_app()?; [cite: 3]
    } else {
        service_dispatcher::start("WinPerfVMFjallRelay", ffi_service_main)?; [cite: 4]
    }
    Ok(())
}

fn my_service_main(_args: Vec<std::ffi::OsString>) {
    let _ = run_app(); [cite: 6]
}

#[tokio::main]
async fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    // Load and validate configuration
    let cfg = config::load_config(); [cite: 7]

    // Initialize Audit Logging
    let audit = Arc::new(audit::AuditGuard::new(&cfg.audit.audit_source_name));
    audit.log(log::Level::Info, 1000, "Relay Application Initializing with redb storage."); [cite: 7]

    // 1) Initialize redb Database [cite: 23, 31]
    // redb creates a single file for the entire database.
    let db_path = &cfg.buffer.metrics_queue; 
    let redb_db = Database::builder()
        .set_write_strategy(WriteStrategy::TwoPhase) // ACID compliant [cite: 42, 43]
        .create(db_path)?;
    let db = Arc::new(redb_db);

    // 2) Setup Hardened TLS Client [cite: 10]
    let rustls_cfg = tls::build_rustls_config(
        &cfg.tls.client_cert_sha1,
        &cfg.tls.server_sha256_pin,
        &audit,
    );
    audit.log(log::Level::Info, 1050, "TLS configured: CNG mTLS enabled; server pinning enabled."); [cite: 11]

    let http_client = reqwest::Client::builder()
        .use_preconfigured_tls(rustls_cfg)
        .build()?; [cite: 12]

    let pingora_url = cfg.forwarder.pingora_url.clone(); [cite: 13]
    let pipe_path = cfg.ingest.named_pipe_path.clone(); [cite: 14]

    // Shared handles for tasks (Arc<Database> instead of Keyspace) 
    let audit_ingest = Arc::clone(&audit);
    let audit_guard = Arc::clone(&audit);
    let db_ingest = Arc::clone(&db);
    let db_guard = Arc::clone(&db);
    let db_egress = Arc::clone(&db);

    // 3) Backpressure gate [cite: 16, 28]
    let gate = Arc::new(relay::IngestGate::new());

    // 4) Spawn Ingestion Task (pipe -> redb) [cite: 18, 31]
    {
        let gate_ingest = Arc::clone(&gate);
        tokio::spawn(async move {
            relay::run_ingestion(pipe_path, db_ingest, audit_ingest, gate_ingest).await;
        });
    }

    // 5) Spawn Disk Guard Task [cite: 20, 46]
    {
        let cfg_guard = cfg.clone();
        let gate_guard = Arc::clone(&gate);
        tokio::spawn(async move {
            relay::run_disk_guard(db_guard, cfg_guard, audit_guard, gate_guard).await;
        });
    }

    // 6) Run Egress Loop (redb -> pingora/victoria) strict FIFO [cite: 21, 52]
    relay::run_egress(
        pingora_url,
        http_client,
        db_egress,
        cfg,
        Arc::clone(&audit),
    )
    .await;

    audit.log(log::Level::Info, 1001, "Relay Application Shutdown Complete."); [cite: 22]
    Ok(())
}
