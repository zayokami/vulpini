use super::Address;

/// One proxied connection as seen by the engine: a target plus metadata
/// about where it came from.
#[derive(Debug, Clone)]
pub struct Session {
    pub target: Address,
    pub network: Network,
    /// Which inbound accepted this connection ("socks5" / "http").
    pub inbound_tag: &'static str,
}

impl Session {
    pub fn tcp(target: Address, inbound_tag: &'static str) -> Self {
        Session {
            target,
            network: Network::Tcp,
            inbound_tag,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}
