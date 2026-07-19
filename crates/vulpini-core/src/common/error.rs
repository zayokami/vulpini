use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("udp is not supported by this outbound")]
    UdpUnsupported,

    #[error("no outbound named '{0}'")]
    NoOutbound(String),

    #[error("connection blocked by rule")]
    Blocked,

    #[error("connection timed out")]
    Timeout,
}

impl From<tokio::time::error::Elapsed> for CoreError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        CoreError::Timeout
    }
}
