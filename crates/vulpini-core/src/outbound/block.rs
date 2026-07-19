use async_trait::async_trait;

use crate::common::{BoxedStream, CoreError, Session};
use crate::outbound::{Outbound, TAG_BLOCK};

/// Refuses the connection. Used by rules that should reject traffic.
pub struct BlockOutbound;

impl BlockOutbound {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BlockOutbound {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Outbound for BlockOutbound {
    fn tag(&self) -> &str {
        TAG_BLOCK
    }

    async fn dial_tcp(&self, _sess: &Session) -> Result<BoxedStream, CoreError> {
        Err(CoreError::Blocked)
    }
}
