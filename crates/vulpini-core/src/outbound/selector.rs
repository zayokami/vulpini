use std::sync::Arc;

use arc_swap::ArcSwapOption;
use async_trait::async_trait;

use crate::common::{BoxedStream, CoreError, Session};
use crate::outbound::{Outbound, TAG_PROXY};

/// The currently selected node, dialable as the "proxy" outbound.
/// Switching nodes atomically replaces the inner outbound — listeners and
/// in-flight connections are untouched.
///
/// The newtype slot exists because `ArcSwapOption` needs a `Sized` payload.
struct Slot(Arc<dyn Outbound>);

pub struct Selector {
    inner: ArcSwapOption<Slot>,
}

impl Selector {
    pub fn new() -> Arc<Self> {
        Arc::new(Selector {
            inner: ArcSwapOption::empty(),
        })
    }

    pub fn with_outbound(outbound: Arc<dyn Outbound>) -> Arc<Self> {
        let selector = Self::new();
        selector.set(outbound);
        selector
    }

    /// Atomically switch the active node.
    pub fn set(&self, outbound: Arc<dyn Outbound>) {
        self.inner.store(Some(Arc::new(Slot(outbound))));
    }

    /// Back to "no node selected" — dials will fail closed.
    pub fn clear(&self) {
        self.inner.store(None);
    }

    pub fn current_tag(&self) -> Option<String> {
        self.inner.load_full().map(|o| o.0.tag().to_string())
    }
}

#[async_trait]
impl Outbound for Selector {
    fn tag(&self) -> &str {
        TAG_PROXY
    }

    async fn dial_tcp(&self, sess: &Session) -> Result<BoxedStream, CoreError> {
        let current = self
            .inner
            .load_full()
            .ok_or_else(|| CoreError::NoOutbound("proxy (no node selected)".into()))?;
        current.0.dial_tcp(sess).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Address;

    struct CountingOutbound {
        tag: &'static str,
        dials: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl Outbound for CountingOutbound {
        fn tag(&self) -> &str {
            self.tag
        }

        async fn dial_tcp(&self, _sess: &Session) -> Result<BoxedStream, CoreError> {
            self.dials.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (a, _b) = tokio::io::duplex(64);
            Ok(Box::pin(a))
        }
    }

    #[tokio::test]
    async fn swap_takes_effect_immediately() {
        let a = Arc::new(CountingOutbound {
            tag: "a",
            dials: 0.into(),
        });
        let b = Arc::new(CountingOutbound {
            tag: "b",
            dials: 0.into(),
        });
        let selector = Selector::with_outbound(a.clone());
        let sess = Session::tcp(Address::Domain("example.com".into(), 443), "test");

        let _ = selector.dial_tcp(&sess).await.unwrap();
        assert_eq!(a.dials.load(std::sync::atomic::Ordering::SeqCst), 1);

        selector.set(b.clone());
        let _ = selector.dial_tcp(&sess).await.unwrap();
        assert_eq!(b.dials.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(a.dials.load(std::sync::atomic::Ordering::SeqCst), 1);

        selector.clear();
        assert!(selector.dial_tcp(&sess).await.is_err());
    }
}
