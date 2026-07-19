//! Rule matching for the router.
//!
//! Rules are stored and edited as clash-style strings:
//!   DOMAIN,example.com,proxy
//!   DOMAIN-SUFFIX,google.com,proxy
//!   DOMAIN-KEYWORD,ads,block
//!   IP-CIDR,10.0.0.0/8,direct
//!   GEOIP,cn,direct            (M4b: matches only literal-IP targets)
//!   GEOSITE,cn,direct          (M4b)
//!   PORT,53,block
//!   MATCH,proxy

use std::fmt;

use ipnet::IpNet;
use vulpini_rules::GeoDb;

use crate::common::Address;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpCidr(IpNet),
    GeoIp(String),
    GeoSite(String),
    Port(u16),
    Match,
}

impl Rule {
    /// Match without a geo database: GEOIP/GEOSITE never match.
    pub fn matches(&self, target: &Address) -> bool {
        self.matches_with(target, None)
    }

    /// GEOIP matches literal-IP targets only (no local resolution);
    /// GEOSITE matches domain targets only. Without a loaded database
    /// both degrade to "never match" — never to a hard error.
    pub fn matches_with(&self, target: &Address, geo: Option<&GeoDb>) -> bool {
        match self {
            Rule::Domain(d) => target.host().eq_ignore_ascii_case(d),
            Rule::DomainSuffix(suffix) => {
                let host = target.host();
                host.eq_ignore_ascii_case(suffix)
                    || host
                        .to_ascii_lowercase()
                        .ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
            }
            Rule::DomainKeyword(kw) => target
                .host()
                .to_ascii_lowercase()
                .contains(&kw.to_ascii_lowercase()),
            Rule::IpCidr(net) => match target {
                Address::Ip(addr) => net.contains(&addr.ip()),
                // No local resolution: IP rules never match domain targets.
                Address::Domain(..) => false,
            },
            Rule::GeoIp(code) => match (target, geo) {
                (Address::Ip(addr), Some(db)) => db.ips.contains(code, addr.ip()),
                _ => false,
            },
            Rule::GeoSite(code) => match (target, geo) {
                (Address::Domain(host, _), Some(db)) => {
                    db.sites.matcher(code).is_some_and(|m| m.matches(host))
                }
                _ => false,
            },
            Rule::Port(p) => target.port() == *p,
            Rule::Match => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRule {
    pub rule: Rule,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleParseError(pub String);

impl fmt::Display for RuleParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad rule: {}", self.0)
    }
}

impl std::error::Error for RuleParseError {}

impl RouteRule {
    /// Parse "TYPE[,value],TAG" — clash rule syntax.
    pub fn parse(s: &str) -> Result<Self, RuleParseError> {
        let parts: Vec<&str> = s.split(',').map(str::trim).collect();
        let bad = || RuleParseError(format!("'{s}'"));
        match parts.as_slice() {
            [kind, tag] if kind.eq_ignore_ascii_case("MATCH") => Ok(RouteRule {
                rule: Rule::Match,
                target: tag.to_string(),
            }),
            [kind, value, tag] => {
                let rule = match kind.to_ascii_uppercase().as_str() {
                    "DOMAIN" => Rule::Domain(value.to_ascii_lowercase()),
                    "DOMAIN-SUFFIX" => Rule::DomainSuffix(value.to_ascii_lowercase()),
                    "DOMAIN-KEYWORD" => Rule::DomainKeyword(value.to_ascii_lowercase()),
                    "IP-CIDR" => Rule::IpCidr(value.parse().map_err(|_| bad())?),
                    "GEOIP" => Rule::GeoIp(value.to_ascii_lowercase()),
                    "GEOSITE" => Rule::GeoSite(value.to_ascii_lowercase()),
                    "PORT" => Rule::Port(value.parse().map_err(|_| bad())?),
                    _ => return Err(bad()),
                };
                Ok(RouteRule {
                    rule,
                    target: tag.to_string(),
                })
            }
            _ => Err(bad()),
        }
    }
}

impl fmt::Display for RouteRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, value) = match &self.rule {
            Rule::Domain(v) => ("DOMAIN", v.clone()),
            Rule::DomainSuffix(v) => ("DOMAIN-SUFFIX", v.clone()),
            Rule::DomainKeyword(v) => ("DOMAIN-KEYWORD", v.clone()),
            Rule::IpCidr(v) => ("IP-CIDR", v.to_string()),
            Rule::GeoIp(v) => ("GEOIP", v.clone()),
            Rule::GeoSite(v) => ("GEOSITE", v.clone()),
            Rule::Port(v) => ("PORT", v.to_string()),
            Rule::Match => return write!(f, "MATCH,{}", self.target),
        };
        write!(f, "{kind},{value},{}", self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::parse_host_port;

    #[test]
    fn domain_rules() {
        let target = parse_host_port("www.google.com", 443);
        assert!(!Rule::Domain("google.com".into()).matches(&target));
        assert!(Rule::Domain("www.google.com".into()).matches(&target));
        assert!(Rule::DomainSuffix("google.com".into()).matches(&target));
        // Suffix matching is label-boundary aware: "ogle.com" is not a
        // suffix of "www.google.com".
        assert!(!Rule::DomainSuffix("ogle.com".into()).matches(&target));
        // ...and "google.com" is not a suffix of "google.com.evil.com".
        assert!(
            !Rule::DomainSuffix("google.com".into())
                .matches(&parse_host_port("google.com.evil.com", 443))
        );
        assert!(
            Rule::DomainSuffix("evil.com".into())
                .matches(&parse_host_port("google.com.evil.com", 443))
        );
        assert!(Rule::DomainKeyword("goog".into()).matches(&target));
    }

    #[test]
    fn ip_rules_only_match_literal_ips() {
        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        let rule = Rule::IpCidr(net);
        assert!(rule.matches(&parse_host_port("10.1.2.3", 80)));
        assert!(!rule.matches(&parse_host_port("11.0.0.1", 80)));
        // Domain targets are never resolved locally.
        assert!(!rule.matches(&parse_host_port("internal.example", 80)));
    }

    #[test]
    fn port_and_match() {
        let target = parse_host_port("1.1.1.1", 53);
        assert!(Rule::Port(53).matches(&target));
        assert!(!Rule::Port(853).matches(&target));
        assert!(Rule::Match.matches(&target));
    }

    #[test]
    fn parse_clash_syntax() {
        assert_eq!(
            RouteRule::parse("DOMAIN-SUFFIX,google.com,proxy").unwrap(),
            RouteRule {
                rule: Rule::DomainSuffix("google.com".into()),
                target: "proxy".into(),
            }
        );
        assert_eq!(
            RouteRule::parse("match,direct").unwrap(),
            RouteRule {
                rule: Rule::Match,
                target: "direct".into(),
            }
        );
        assert!(RouteRule::parse("IP-CIDR,not-a-net,proxy").is_err());
        assert!(RouteRule::parse("WHAT,ever,proxy").is_err());
        assert!(RouteRule::parse("DOMAIN,nocomma").is_err());
    }

    #[test]
    fn display_roundtrip() {
        for s in [
            "DOMAIN,example.com,proxy",
            "DOMAIN-SUFFIX,google.com,proxy",
            "DOMAIN-KEYWORD,ads,block",
            "IP-CIDR,10.0.0.0/8,direct",
            "GEOIP,cn,direct",
            "GEOSITE,gfw,proxy",
            "PORT,53,block",
            "MATCH,proxy",
        ] {
            let rule = RouteRule::parse(s).unwrap();
            assert_eq!(rule.to_string(), s);
        }
    }
}
