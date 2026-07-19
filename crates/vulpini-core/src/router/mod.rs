pub mod rule;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vulpini_rules::GeoDb;

use crate::common::Session;
use crate::outbound::{TAG_DIRECT, TAG_PROXY};
pub use rule::{RouteRule, Rule, RuleParseError};

/// Routing mode: Global (everything via the selected node), Direct
/// (everything direct), Rule (evaluate rules in order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Global,
    Rule,
    Direct,
}

/// Evaluates sessions to outbound tags. Cheap to construct and immutable —
/// hot switching means swapping a whole Router in an `ArcSwap`.
pub struct Router {
    mode: Mode,
    rules: Vec<RouteRule>,
    geo: Option<Arc<GeoDb>>,
}

impl Router {
    pub fn new(mode: Mode, rules: Vec<RouteRule>) -> Self {
        Router {
            mode,
            rules,
            geo: None,
        }
    }

    pub fn from_config(mode: Mode, rule_strs: &[String]) -> Result<Self, RuleParseError> {
        let rules = rule_strs
            .iter()
            .map(|s| RouteRule::parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Router::new(mode, rules))
    }

    /// Attach the geo database enabling GEOIP/GEOSITE rules.
    pub fn with_geo(mut self, geo: Option<Arc<GeoDb>>) -> Self {
        self.geo = geo;
        self
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn route(&self, session: &Session) -> String {
        // Private/loopback targets never leave the machine, in every mode.
        if session.target.is_private_or_loopback() {
            return TAG_DIRECT.to_string();
        }
        match self.mode {
            Mode::Global => TAG_PROXY.to_string(),
            Mode::Direct => TAG_DIRECT.to_string(),
            Mode::Rule => {
                for rule in &self.rules {
                    if rule.rule.matches_with(&session.target, self.geo.as_deref()) {
                        return rule.target.clone();
                    }
                }
                // No MATCH rule and nothing hit: stay safe, stay direct.
                TAG_DIRECT.to_string()
            }
        }
    }
}

/// Placeholder tag set used until the geo/rule data milestones.
pub fn default_rules() -> Vec<String> {
    vec![
        "DOMAIN-KEYWORD,ads,block".to_string(),
        "MATCH,proxy".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{Address, Session};
    use crate::outbound::TAG_BLOCK;

    fn session(host: &str, port: u16) -> Session {
        Session::tcp(crate::common::parse_host_port(host, port), "test")
    }

    #[test]
    fn global_and_direct_modes() {
        let global = Router::new(Mode::Global, vec![]);
        assert_eq!(global.route(&session("example.com", 443)), TAG_PROXY);
        // Loopback stays direct even in global mode.
        assert_eq!(global.route(&session("127.0.0.1", 8080)), TAG_DIRECT);

        let direct = Router::new(Mode::Direct, vec![]);
        assert_eq!(direct.route(&session("example.com", 443)), TAG_DIRECT);
    }

    #[test]
    fn rule_mode_order_and_fallback() {
        let router = Router::from_config(
            Mode::Rule,
            &[
                "DOMAIN-SUFFIX,cn-site.example,direct".to_string(),
                "DOMAIN-KEYWORD,ads,block".to_string(),
                "MATCH,proxy".to_string(),
            ],
        )
        .unwrap();

        assert_eq!(
            router.route(&session("www.cn-site.example", 443)),
            TAG_DIRECT
        );
        assert_eq!(router.route(&session("ads.tracker.io", 443)), TAG_BLOCK);
        assert_eq!(router.route(&session("example.com", 443)), TAG_PROXY);
        // Private addresses are direct before any rule runs.
        assert_eq!(router.route(&session("192.168.1.1", 443)), TAG_DIRECT);
    }

    #[test]
    fn rule_mode_without_match_defaults_direct() {
        let router =
            Router::from_config(Mode::Rule, &["DOMAIN-SUFFIX,example.com,proxy".to_string()])
                .unwrap();
        assert_eq!(router.route(&session("other.org", 443)), TAG_DIRECT);
        assert_eq!(router.route(&session("a.example.com", 443)), TAG_PROXY);
    }

    #[test]
    fn bad_rule_string_fails_whole_router() {
        assert!(Router::from_config(Mode::Rule, &["BOGUS".to_string()]).is_err());
    }

    #[test]
    fn ip_literal_sessions() {
        let router = Router::from_config(
            Mode::Rule,
            &[
                "IP-CIDR,1.1.1.0/24,direct".to_string(),
                "MATCH,proxy".to_string(),
            ],
        )
        .unwrap();
        let ip_session = Session::tcp(Address::Ip("1.1.1.1:53".parse().unwrap()), "test");
        assert_eq!(router.route(&ip_session), TAG_DIRECT);
    }
}
