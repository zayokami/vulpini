//! Geo data management: downloading and loading geosite.dat / geoip.dat.
//!
//! Downloading is async and lives here (vulpini-rules stays sync-only);
//! parsing and matching are vulpini-rules' job.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use vulpini_rules::{GeoDb, GeoIpDb, GeoSiteDb};

use crate::common::CoreError;

pub const DEFAULT_GEOSITE_URL: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat";
pub const DEFAULT_GEOIP_URL: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoConfig {
    /// Directory holding geosite.dat / geoip.dat.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_geosite_url")]
    pub geosite_url: String,
    #[serde(default = "default_geoip_url")]
    pub geoip_url: String,
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("vulpini-data")
}

fn default_geosite_url() -> String {
    DEFAULT_GEOSITE_URL.to_string()
}

fn default_geoip_url() -> String {
    DEFAULT_GEOIP_URL.to_string()
}

impl Default for GeoConfig {
    fn default() -> Self {
        GeoConfig {
            data_dir: default_data_dir(),
            geosite_url: default_geosite_url(),
            geoip_url: default_geoip_url(),
        }
    }
}

pub struct GeoManager {
    config: GeoConfig,
    client: reqwest::Client,
}

impl GeoManager {
    pub fn new(config: GeoConfig) -> Self {
        crate::ensure_crypto_provider();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .user_agent(concat!("vulpini/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client builds");
        GeoManager { config, client }
    }

    pub fn geosite_path(&self) -> PathBuf {
        self.config.data_dir.join("geosite.dat")
    }

    pub fn geoip_path(&self) -> PathBuf {
        self.config.data_dir.join("geoip.dat")
    }

    /// Download both data files. Writes go through temp files so a failed
    /// download never clobbers a working copy.
    pub async fn update(&self) -> Result<(u64, u64), CoreError> {
        std::fs::create_dir_all(&self.config.data_dir)?;
        let site_bytes = self.download(&self.config.geosite_url).await?;
        let ip_bytes = self.download(&self.config.geoip_url).await?;

        // Validate before persisting: a corrupt download must not replace
        // a working file.
        GeoSiteDb::parse(&site_bytes).map_err(|e| CoreError::Protocol(e.to_string()))?;
        GeoIpDb::parse(&ip_bytes).map_err(|e| CoreError::Protocol(e.to_string()))?;

        let site_len = site_bytes.len() as u64;
        let ip_len = ip_bytes.len() as u64;
        Self::atomic_write(&self.geosite_path(), &site_bytes)?;
        Self::atomic_write(&self.geoip_path(), &ip_bytes)?;
        info!(geosite = site_len, geoip = ip_len, "geo data updated");
        Ok((site_len, ip_len))
    }

    /// Load whatever is on disk. Returns None (with a warning) when files
    /// are missing or corrupt — geo rules simply never match then.
    pub fn load(&self) -> Option<Arc<GeoDb>> {
        let site_bytes = std::fs::read(self.geosite_path()).ok()?;
        let ip_bytes = std::fs::read(self.geoip_path()).ok()?;
        let db = (|| {
            Ok::<GeoDb, CoreError>(GeoDb {
                sites: GeoSiteDb::parse(&site_bytes)
                    .map_err(|e| CoreError::Protocol(e.to_string()))?,
                ips: GeoIpDb::parse(&ip_bytes).map_err(|e| CoreError::Protocol(e.to_string()))?,
            })
        })();
        match db {
            Ok(db) => Some(Arc::new(db)),
            Err(e) => {
                warn!(error = %e, "failed to load geo data; geo rules disabled");
                None
            }
        }
    }

    async fn download(&self, url: &str) -> Result<Vec<u8>, CoreError> {
        let response = self.client.get(url).send().await?;
        let response = response.error_for_status()?;
        Ok(response.bytes().await?.to_vec())
    }

    fn atomic_write(path: &PathBuf, data: &[u8]) -> Result<(), CoreError> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_returns_none_without_files() {
        let dir = tempfile::tempdir().unwrap();
        let manager = GeoManager::new(GeoConfig {
            data_dir: dir.path().to_path_buf(),
            ..GeoConfig::default()
        });
        assert!(manager.load().is_none());
    }

    /// Real download + real Loyalsoldier files. Gated: needs network.
    /// Run with: VULPINI_TEST_NET=1 cargo test -p vulpini-core geo
    #[tokio::test]
    async fn download_and_match_real_data() {
        if std::env::var("VULPINI_TEST_NET").is_err() {
            eprintln!("skipped (set VULPINI_TEST_NET=1 to run)");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let manager = GeoManager::new(GeoConfig {
            data_dir: dir.path().to_path_buf(),
            ..GeoConfig::default()
        });
        let (site_len, ip_len) = manager.update().await.expect("download failed");
        assert!(site_len > 100_000 && ip_len > 100_000);

        let db = manager.load().expect("load failed");
        let cn = db.sites.matcher("cn").expect("geosite:cn exists");
        assert!(cn.matches("www.baidu.com"));
        assert!(cn.matches("baidu.com"));
        assert!(!cn.matches("www.google.com"));

        assert!(db.ips.contains("cn", "114.114.114.114".parse().unwrap()));
        assert!(!db.ips.contains("cn", "8.8.8.8".parse().unwrap()));
    }
}
