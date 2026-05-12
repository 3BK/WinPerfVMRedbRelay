mod config;
mod guards;
mod tls;
mod relay;
mod audit;

use std::{env, sync::Arc};
use windows_service::{define_windows_service, service_dispatcher};
// Use redb 4.1.0 Database [cite: 83]
use redb::Database;

define_windows_service!(ffi_service_main, my_service_main);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args().any(|x| x == "--console") {
        run_app()?;
    } else {
        // Updated service name to reflect redb transition [cite: 4]
        service_dispatcher::start("WinPerfVMRedbRelay", ffi_service_main)?;
    }
    Ok(())
}

fn my_service_main(_args: Vec<std::ffi::OsString>) {
    let _ = run_app();
}

#[tokio::main]
async fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::load_config();
    let audit = Arc::new(audit::AuditGuard::new(&cfg.audit.audit_source_name));
    audit.log(log::Level::Info, 1000, "Relay Application Initializing with redb v4.1 storage.");

    // 1) Initialize redb v4.1 Database [cite: 83]
    let db_path = &cfg.buffer.metrics_queue; 
    let redb_db = Database::builder().create(db_path)?;
    let db = Arc::new(redb_db);

    // 2) Setup Hardened TLS Client [cite: 10]
    let rustls_cfg = tls::build_rustls_config(
        &cfg.tls.client_cert_sha1,
        &cfg.tls.server_sha256_pin,
        &audit,
    );

    let http_client = reqwest::Client::builder()
        .use_preconfigured_tls(rustls_cfg)
        .build()?;

    let pingora_url = cfg.forwarder.pingora_url.clone();
    let pipe_path = cfg.ingest.named_pipe_path.clone();

    // Shared handles for tasks [cite: 14, 15]
    let db_ingest = Arc::clone(&db);
    let db_guard = Arc::clone(&db);
    let db_egress = Arc::clone(&db);
    let gate = Arc::new(relay::IngestGate::new());

    // 4) Spawn Ingestion Task [cite: 18]
    {
        let audit_ingest = Arc::clone(&audit);
        let gate_ingest = Arc::clone(&gate);
        tokio::spawn(async move {
            relay::run_ingestion(pipe_path, db_ingest, audit_ingest, gate_ingest).await;
        });
    }

    // 5) Spawn Disk Guard Task [cite: 20]
    {
        let cfg_guard = cfg.clone();
        let audit_guard = Arc::clone(&audit);
        let gate_guard = Arc::clone(&gate);
        tokio::spawn(async move {
            relay::run_disk_guard(db_guard, cfg_guard, audit_guard, gate_guard).await;
        });
    }

    // 6) Run Egress Loop [cite: 21]
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
