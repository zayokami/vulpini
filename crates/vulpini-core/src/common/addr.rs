use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A connection target: either a literal IP or a domain name.
///
/// Domains are intentionally kept unresolved end-to-end where possible:
/// the router never resolves them locally (remote DNS semantics) and
/// proxy outbounds forward them as domains. Only `direct` resolves.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::Ip(addr) => addr.port(),
            Address::Domain(_, port) => *port,
        }
    }

    /// Host part as a string (IP rendered, domain as-is). For display/routing only.
    pub fn host(&self) -> String {
        match self {
            Address::Ip(addr) => addr.ip().to_string(),
            Address::Domain(host, _) => host.clone(),
        }
    }

    pub fn is_domain(&self) -> bool {
        matches!(self, Address::Domain(..))
    }

    /// Append the SOCKS5-style wire encoding (ATYP + addr + port) to `buf`.
    /// Shared by Shadowsocks, Trojan and VLESS request headers.
    pub fn write_socks5(&self, buf: &mut Vec<u8>) {
        match self {
            Address::Ip(addr) => match addr.ip() {
                IpAddr::V4(v4) => {
                    buf.push(0x01);
                    buf.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    buf.push(0x04);
                    buf.extend_from_slice(&v6.octets());
                }
            },
            Address::Domain(host, _) => {
                debug_assert!(host.len() <= 255, "domain too long for socks5 encoding");
                buf.push(0x03);
                buf.push(host.len().min(255) as u8);
                buf.extend_from_slice(host.as_bytes());
            }
        }
        buf.extend_from_slice(&self.port().to_be_bytes());
    }

    /// Append the VLESS address encoding to `buf`: ATYP + address only
    /// (VLESS carries the port separately, before ATYP). ATYP values are
    /// NOT the socks5 ones: 1 = IPv4, 2 = domain, 3 = IPv6.
    pub fn write_vless_addr(&self, buf: &mut Vec<u8>) {
        match self {
            Address::Ip(addr) => match addr.ip() {
                IpAddr::V4(v4) => {
                    buf.push(0x01);
                    buf.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    buf.push(0x03);
                    buf.extend_from_slice(&v6.octets());
                }
            },
            Address::Domain(host, _) => {
                debug_assert!(host.len() <= 255, "domain too long for vless encoding");
                buf.push(0x02);
                buf.push(host.len().min(255) as u8);
                buf.extend_from_slice(host.as_bytes());
            }
        }
    }

    /// True when the target is loopback, private, link-local, or otherwise
    /// non-public address space. Always routed direct by the router.
    pub fn is_private_or_loopback(&self) -> bool {
        match self {
            Address::Domain(host, _) => host.eq_ignore_ascii_case("localhost"),
            Address::Ip(addr) => {
                let ip = addr.ip();
                ip.is_loopback()
                    || ip.is_unspecified()
                    || match ip {
                        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
                        IpAddr::V6(v6) => is_v6_unique_local(&v6),
                    }
            }
        }
    }
}

fn is_v6_unique_local(v6: &Ipv6Addr) -> bool {
    // fc00::/7 (unique local) and fe80::/10 (link local) — is_unique_local /
    // is_unicast_link_local are unstable, so check the prefixes by hand.
    let seg = v6.segments();
    (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ip(addr) => write!(f, "{addr}"),
            Address::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::Ip(addr)
    }
}

impl From<(Ipv4Addr, u16)> for Address {
    fn from((ip, port): (Ipv4Addr, u16)) -> Self {
        Address::Ip(SocketAddr::new(ip.into(), port))
    }
}

impl From<(Ipv6Addr, u16)> for Address {
    fn from((ip, port): (Ipv6Addr, u16)) -> Self {
        Address::Ip(SocketAddr::new(ip.into(), port))
    }
}

/// Parse "host:port" where host may be a domain or a literal IP (v4/v6).
pub fn parse_host_port(host: &str, port: u16) -> Address {
    match host.parse::<IpAddr>() {
        Ok(ip) => Address::Ip(SocketAddr::new(ip, port)),
        Err(_) => Address::Domain(host.to_ascii_lowercase(), port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_vs_domain() {
        assert_eq!(
            parse_host_port("1.2.3.4", 80),
            Address::Ip("1.2.3.4:80".parse().unwrap())
        );
        assert_eq!(
            parse_host_port("::1", 443),
            Address::Ip("[::1]:443".parse().unwrap())
        );
        assert_eq!(
            parse_host_port("Example.COM", 443),
            Address::Domain("example.com".into(), 443)
        );
    }

    #[test]
    fn private_detection() {
        assert!(parse_host_port("127.0.0.1", 80).is_private_or_loopback());
        assert!(parse_host_port("192.168.1.1", 80).is_private_or_loopback());
        assert!(parse_host_port("10.0.0.1", 80).is_private_or_loopback());
        assert!(parse_host_port("localhost", 80).is_private_or_loopback());
        assert!(!parse_host_port("8.8.8.8", 53).is_private_or_loopback());
        assert!(!parse_host_port("example.com", 443).is_private_or_loopback());
    }

    #[test]
    fn display_roundtrip() {
        assert_eq!(
            parse_host_port("example.com", 443).to_string(),
            "example.com:443"
        );
        assert_eq!(parse_host_port("1.2.3.4", 80).to_string(), "1.2.3.4:80");
    }
}
