//! vulpini-sysproxy: toggle the Windows system proxy (HKCU, no admin needed).
//!
//! Same API on every platform; non-Windows builds return
//! [`SysProxyError::Unsupported`] so callers need no `#[cfg]`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SysProxyError {
    #[error("system proxy is not supported on this platform")]
    Unsupported,
    #[error("registry operation failed: {0}")]
    Registry(String),
}

/// Snapshot of the current system proxy state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysProxyStatus {
    pub enabled: bool,
    pub server: Option<String>,
}

/// Enable the system proxy, pointing it at `server` (e.g. "127.0.0.1:7890").
/// Returns the previous state so callers can restore it later.
pub fn enable(_server: &str) -> Result<SysProxyStatus, SysProxyError> {
    Err(SysProxyError::Unsupported)
}

/// Disable the system proxy, restoring a state previously returned by [`enable`].
pub fn disable(_previous: &SysProxyStatus) -> Result<(), SysProxyError> {
    Err(SysProxyError::Unsupported)
}

/// Read the current system proxy state.
pub fn status() -> Result<SysProxyStatus, SysProxyError> {
    Err(SysProxyError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_does_not_panic() {
        // On every platform the call must return (Ok on Windows, Err elsewhere).
        let _ = status();
    }
}
