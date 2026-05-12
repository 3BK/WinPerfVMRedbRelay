use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Clone, Debug)]
pub struct IngestConfig {
    pub named_pipe_path: String,
    pub pipe_buffer_size: Option<u32>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct BufferConfig {
    pub metrics_queue: String,
    pub max_disk_bytes: Option<u64>,
    pub max_age_seconds: Option<u64>,
    pub retention_check_interval_seconds: Option<u64>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ForwarderConfig {
    pub pingora_url: String,
    pub batch_size: Option<usize>,
    pub request_timeout_seconds: Option<u64>,
    pub drain_timeout_seconds: Option<u64>,
    pub base_backoff_ms: Option<u64>,
    pub max_backoff_ms: Option<u64>,
    pub max_jitter_ms: Option<u64>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct TlsConfig {
    pub client_cert_sha1: String,
    pub server_sha256_pin: String,
    pub min_version: Option<String>,
    pub cipher_suites: Option<Vec<String>>,
    pub curves: Option<Vec<String>>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct AuditConfig {
    pub audit_source_name: String,
    pub event_log: Option<String>,
    pub cert_expiry_warning_days: Option<u32>,
    pub log_level: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct RelayConfig {
    pub ingest: IngestConfig,
    pub buffer: BufferConfig,
    pub forwarder: ForwarderConfig,
    pub tls: TlsConfig,
    pub audit: AuditConfig,
    pub version: Option<String>,
}

pub fn load_config() -> RelayConfig {
    let content = fs::read_to_string("config.toml")
        .expect("NIST SC-28: Configuration file missing");
    let cfg: RelayConfig = toml::from_str(&content)
        .expect("ISO 27001: Config format invalid");
    // Add validation here if needed (e.g., check required fields, value ranges)
    cfg
}
