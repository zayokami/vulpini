//! Log bus: a tracing Layer forwarding records into a broadcast channel.
//! The core never prints — shells subscribe and render (CLI prints,
//! Tauri re-emits to the frontend).

use std::fmt::Write as _;

use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

#[derive(Debug, Clone, serde::Serialize)]
pub struct LogEvent {
    pub level: String,
    pub target: String,
    pub message: String,
    /// Unix seconds.
    pub ts: u64,
}

pub fn channel(capacity: usize) -> (broadcast::Sender<LogEvent>, broadcast::Receiver<LogEvent>) {
    broadcast::channel(capacity)
}

/// A tracing layer that mirrors every event into the broadcast channel.
/// Lagging receivers drop silently (broadcast semantics).
pub struct BroadcastLayer {
    tx: broadcast::Sender<LogEvent>,
}

impl BroadcastLayer {
    pub fn new(tx: broadcast::Sender<LogEvent>) -> Self {
        BroadcastLayer { tx }
    }
}

struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            if !self.message.is_empty() {
                self.message.push_str("  ");
            }
            let _ = write!(self.message, "{}={:?}", field.name(), value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            if !self.message.is_empty() {
                self.message.push_str("  ");
            }
            let _ = write!(self.message, "{}={value}", field.name());
        }
    }
}

impl<S> Layer<S> for BroadcastLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor {
            message: String::new(),
        };
        event.record(&mut visitor);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // If nobody listens, the send fails — that is fine and cheap.
        let _ = self.tx.send(LogEvent {
            level: event.metadata().level().to_string(),
            target: event.metadata().target().to_string(),
            message: visitor.message,
            ts,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    #[tokio::test]
    async fn events_flow_through() {
        let (tx, mut rx) = channel(16);
        let subscriber = tracing_subscriber::registry().with(BroadcastLayer::new(tx));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "vulpini_test", answer = 42, "hello logbus");
        });
        let event = rx.recv().await.unwrap();
        assert_eq!(event.level, "INFO");
        assert_eq!(event.target, "vulpini_test");
        assert!(event.message.contains("hello logbus"));
        assert!(event.message.contains("answer=42"));
    }
}
