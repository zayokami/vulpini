//! vulpini-sysproxy: toggle the Windows system proxy (HKCU, no admin needed).
//!
//! Same API on every platform; non-Windows builds return
//! [`SysProxyError::Unsupported`] so callers need no `#[cfg]`.
//!
//! Safety model: `enable` snapshots the previous state; `disable` writes
//! the snapshot back. Persist the snapshot across runs so a crash never
//! strands the user's proxy settings.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SysProxyError {
    #[error("system proxy is not supported on this platform")]
    Unsupported,
    #[error("registry operation failed: {0}")]
    Registry(String),
}

impl From<SysProxyError> for std::io::Error {
    fn from(e: SysProxyError) -> Self {
        std::io::Error::other(e.to_string())
    }
}

/// Snapshot of the system proxy state (also the persisted backup type).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SysProxyStatus {
    pub enabled: bool,
    pub server: Option<String>,
}

#[cfg(windows)]
mod imp;
#[cfg(not(windows))]
mod imp {
    use super::{SysProxyError, SysProxyStatus};

    pub fn status() -> Result<SysProxyStatus, SysProxyError> {
        Err(SysProxyError::Unsupported)
    }

    pub fn enable(_server: &str) -> Result<SysProxyStatus, SysProxyError> {
        Err(SysProxyError::Unsupported)
    }

    pub fn disable(_previous: &SysProxyStatus) -> Result<(), SysProxyError> {
        Err(SysProxyError::Unsupported)
    }
}

/// Enable the system proxy pointing at `server` (e.g. "127.0.0.1:7890").
/// Returns the previous state — persist it for [`disable`].
pub fn enable(server: &str) -> Result<SysProxyStatus, SysProxyError> {
    imp::enable(server)
}

/// Restore the state previously returned by [`enable`].
pub fn disable(previous: &SysProxyStatus) -> Result<(), SysProxyError> {
    imp::disable(previous)
}

/// Read the current system proxy state.
pub fn status() -> Result<SysProxyStatus, SysProxyError> {
    imp::status()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_does_not_panic() {
        // On every platform the call must return (Ok on Windows, Err elsewhere).
        let _ = status();
    }

    #[cfg(windows)]
    #[test]
    fn enable_disable_roundtrip() {
        let probe = "127.0.0.1:17890";
        let previous = enable(probe).expect("enable");
        let current = status().expect("status");
        assert!(current.enabled);
        assert_eq!(current.server.as_deref(), Some(probe));

        disable(&previous).expect("disable");
        let restored = status().expect("status after disable");
        assert_eq!(restored.enabled, previous.enabled);
        assert_eq!(restored.server, previous.server);
    }
}
