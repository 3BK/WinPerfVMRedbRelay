use log::{Level, info, warn, error};
use eventlog;

/// AuditGuard wraps Windows Event Log registration and provides structured logging.
pub struct AuditGuard {
    source: String,
}

impl AuditGuard {
    /// Registers the event source and initializes logging.
    pub fn new(source: &str) -> Self {
        // Register the event source with Windows Event Log
        let _ = eventlog::register(source);
        // Initialize logging to Windows Event Log at Info level (can be changed)
        let _ = eventlog::init(source, Level::Info);
        Self {
            source: source.to_string(),
        }
    }

    /// Logs a message with a specific level and event ID.
    pub fn log(&self, level: Level, event_id: u32, message: &str) {
        // Use standard Rust logging macros; eventlog crate will write to Event Log
        match level {
            Level::Info => info!("[{}][{}] {}", event_id, self.source, message),
            Level::Warn => warn!("[{}][{}] {}", event_id, self.source, message),
            Level::Error => error!("[{}][{}] {}", event_id, self.source, message),
            _ => info!("[{}][{}] {}", event_id, self.source, message),
        }
    }

    /// Optionally, log structured fields (category, severity, etc.)
    pub fn log_structured(&self, level: Level, event_id: u32, category: &str, severity: &str, message: &str) {
        let structured_msg = format!("[{}][{}][{}] {}", category, severity, event_id, message);
        self.log(level, event_id, &structured_msg);
    }
}

impl Drop for AuditGuard {
    fn drop(&mut self) {
        // No explicit deregistration needed for eventlog crate
    }
}
