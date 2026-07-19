//! vulpini-rules: parsing and matching for v2ray-format geosite.dat / geoip.dat.
//!
//! Leaf crate: sync parsing and matching only — downloading and async
//! loading live in vulpini-core.

pub mod geoip;
pub mod geosite;
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/vulpini.rules.rs"));
}

use thiserror::Error;

pub use geoip::GeoIpDb;
pub use geosite::GeoSiteDb;

#[derive(Debug, Error)]
pub enum RulesError {
    #[error("failed to decode data file: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("invalid regex in geosite data: {0}")]
    Regex(String),
    #[error("invalid ip data in geoip entry: {0}")]
    BadIp(String),
}

/// Both databases behind one handle, shared via Arc into the router.
#[derive(Default)]
pub struct GeoDb {
    pub sites: GeoSiteDb,
    pub ips: GeoIpDb,
}

impl GeoDb {
    /// True when neither database has any data (geo rules will never match).
    pub fn is_empty(&self) -> bool {
        self.sites.is_empty() && self.ips.is_empty()
    }
}
