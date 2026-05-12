use windows_sys::Win32::{
    Security::Cryptography::{CertCloseStore, CertFreeCertificateContext, CERT_CONTEXT, HCERTSTORE},
};
use tokio::net::windows::named_pipe::NamedPipeServer;

/// RAII guard for Named Pipe connections (prevents ERROR_PIPE_BUSY)
pub struct PipeGuard<'a>(pub &'a mut NamedPipeServer);

impl Drop for PipeGuard<'_> {
    fn drop(&mut self) {
        let _ = self.0.disconnect();
    }
}

/// RAII guard for Windows Certificate Contexts
pub struct CertContextGuard(pub *const CERT_CONTEXT);

impl Drop for CertContextGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                // Optionally zeroize key material here if extracted
                CertFreeCertificateContext(self.0);
            }
        }
    }
}

/// RAII guard for Windows System Certificate Store
pub struct CertStoreGuard(pub HCERTSTORE);

impl Drop for CertStoreGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CertCloseStore(self.0, 0);
            }
        }
    }
}

// Guards should not implement Clone or Copy for safety
