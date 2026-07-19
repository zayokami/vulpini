//! geoip.dat parsing and IP matching.

use std::collections::HashMap;
use std::net::IpAddr;

use ip_network_table::IpNetworkTable;
use prost::Message;

use crate::RulesError;
use crate::proto::GeoIpList;

/// Parsed geoip database: country code -> longest-prefix-match table.
#[derive(Default)]
pub struct GeoIpDb {
    tables: HashMap<String, IpNetworkTable<()>>,
}

impl GeoIpDb {
    pub fn empty() -> Self {
        GeoIpDb {
            tables: HashMap::new(),
        }
    }

    /// Parse a geoip.dat file. Country codes are lowercased; entries with
    /// malformed addresses are skipped with a warning.
    pub fn parse(data: &[u8]) -> Result<Self, RulesError> {
        let list = GeoIpList::decode(data)?;
        let mut tables: HashMap<String, IpNetworkTable<()>> = HashMap::new();
        for entry in list.entry {
            let code = entry.country_code.to_ascii_lowercase();
            let table = tables.entry(code.clone()).or_default();
            for cidr in entry.cidr {
                let ip = match cidr.ip.len() {
                    4 => {
                        let mut o = [0u8; 4];
                        o.copy_from_slice(&cidr.ip);
                        IpAddr::from(o)
                    }
                    16 => {
                        let mut o = [0u8; 16];
                        o.copy_from_slice(&cidr.ip);
                        IpAddr::from(o)
                    }
                    n => {
                        tracing::warn!(code = %code, len = n, "skipping geoip entry with bad ip length");
                        continue;
                    }
                };
                let net = ip_network::IpNetwork::new(ip, cidr.prefix as u8)
                    .map_err(|_| RulesError::BadIp(format!("{ip}/{}", cidr.prefix)))?;
                table.insert(net, ());
            }
        }
        Ok(GeoIpDb { tables })
    }

    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }

    pub fn codes(&self) -> Vec<String> {
        let mut v: Vec<String> = self.tables.keys().cloned().collect();
        v.sort();
        v
    }

    /// True when `ip` is covered by the given country code's ranges.
    pub fn contains(&self, code: &str, ip: IpAddr) -> bool {
        self.tables
            .get(&code.to_ascii_lowercase())
            .is_some_and(|table| table.longest_match(ip).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Cidr, GeoIp, GeoIpList};

    fn cidr(ip: &[u8], prefix: u32) -> Cidr {
        Cidr {
            ip: ip.to_vec(),
            prefix,
        }
    }

    fn sample_db() -> GeoIpDb {
        let list = GeoIpList {
            entry: vec![GeoIp {
                country_code: "cn".into(),
                cidr: vec![
                    cidr(&[1, 0, 0, 0], 8),
                    cidr(&[203, 0, 113, 0], 24),
                    cidr(
                        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        32,
                    ),
                ],
                inverse_match: false,
                resource_hash: vec![],
                code: "cn".into(),
            }],
        };
        let mut buf = Vec::new();
        list.encode(&mut buf).unwrap();
        GeoIpDb::parse(&buf).unwrap()
    }

    #[test]
    fn contains_by_prefix() {
        let db = sample_db();
        assert!(db.contains("cn", "1.2.3.4".parse().unwrap()));
        assert!(db.contains("CN", "203.0.113.7".parse().unwrap()));
        assert!(!db.contains("cn", "8.8.8.8".parse().unwrap()));
        assert!(db.contains("cn", "2001:db8::1".parse().unwrap()));
        assert!(!db.contains("cn", "2001:db9::1".parse().unwrap()));
        assert!(!db.contains("us", "1.2.3.4".parse().unwrap()));
    }
}
