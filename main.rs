mod config;
mod guards;
mod tls;
mod relay;
mod audit;

use std::{env, sync::Arc, path::Path};
use windows_service::{define_windows_service, service_dispatcher};

// NOTE: add KeyspaceCreateOptions import
use fjall::{Config as FjallConfig, Database, Keyspace, KeyspaceCreateOptions};

define_windows_service!(ffi_service_main, my_service_main);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args().any(|x| x == "--console") {
        run_app()?;
    } else {
        service_dispatcher::start("WinPerfVMFjallRelay", ffi_service_main)?;
    }
    Ok(())
}

fn my_service_main(_args: Vec<std::ffi::OsString>) {
    let _ = run_app();
}

#[tokio::main]
async fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    // Load and validate configuration
    let cfg = config::load_config();

    // Initialize Audit Logging
    let audit = Arc::new(audit::AuditGuard::new(&cfg.audit.audit_source_name));
    audit.log(log::Level::Info, 1000, "Relay Application Initializing with Fjall v3 storage.");

    // 1) Initialize Fjall v3 Database + single keyspace
    let db_path = Path::new(&cfg.buffer.metrics_queue);
    let fjall_db = Database::open(FjallConfig::new(db_path))?;

    // FIX: Fjall expects a closure: FnOnce() -> KeyspaceCreateOptions 【1-92c161】【2-229519】
    let items: Keyspace = fjall_db.keyspace("metrics", KeyspaceCreateOptions::default)?;

    // 2) Setup Hardened TLS Client (CNG mTLS + server pinning in tls.rs)
    let rustls_cfg = tls::build_rustls_config(
        &cfg.tls.client_cert_sha1,
        &cfg.tls.server_sha256_pin,
        &audit,
    );
    audit.log(log::Level::Info, 1050, "TLS configured: CNG mTLS enabled; server pinning enabled.");

    let http_client = reqwest::Client::builder()
        .use_preconfigured_tls(rustls_cfg)
        .build()?;

    // Avoid partial move: clone pingora_url before moving cfg into run_egress
    let pingora_url = cfg.forwarder.pingora_url.clone();

    // Shared handles for tasks
    let audit_ingest = Arc::clone(&audit);
    let audit_guard = Arc::clone(&audit);

    let pipe_path = cfg.ingest.named_pipe_path.clone();

    let db_ingest = items.clone();
    let db_guard = items.clone();
    let db_egress = items.clone();

    // 3) Backpressure gate (single keyspace, no DLQ, never delete unsent)
    let gate = Arc::new(relay::IngestGate::new());

    // 4) Spawn Ingestion Task (pipe -> fjall) with backpressure gate
    {
        let gate_ingest = Arc::clone(&gate);
        tokio::spawn(async move {
            relay::run_ingestion(pipe_path, db_ingest, audit_ingest, gate_ingest).await;
        });
    }

    // 5) Spawn Disk Guard Task (monitors disk usage, pauses ingest when near full)
    {
        let cfg_guard = cfg.clone();
        let gate_guard = Arc::clone(&gate);
        tokio::spawn(async move {
            relay::run_disk_guard(db_guard, cfg_guard, audit_guard, gate_guard).await;
        });
    }

    // 6) Run Egress Loop (fjall -> pingora/victoria) strict FIFO
    relay::run_egress(
        pingora_url,
        http_client,
        db_egress,
        cfg,
        Arc::clone(&audit),
    )
    .await;

    audit.log(log::Level::Info, 1001, "Relay Application Shutdown Complete.");
    Ok(())
}
