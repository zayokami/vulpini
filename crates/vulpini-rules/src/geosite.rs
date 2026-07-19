//! geosite.dat parsing and domain matching.

use std::collections::HashMap;

use prost::Message;

use crate::RulesError;
use crate::proto::{GeoSiteList, domain};

/// Parsed geosite database: category code -> compiled matcher.
/// Only categories requested by the router get compiled.
#[derive(Default)]
pub struct GeoSiteDb {
    raw: HashMap<String, Vec<crate::proto::Domain>>,
    compiled: std::sync::Mutex<HashMap<String, std::sync::Arc<DomainMatcher>>>,
}

impl GeoSiteDb {
    pub fn empty() -> Self {
        GeoSiteDb {
            raw: HashMap::new(),
            compiled: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Parse a geosite.dat file. Category codes are lowercased.
    pub fn parse(data: &[u8]) -> Result<Self, RulesError> {
        let list = GeoSiteList::decode(data)?;
        let raw = list
            .entry
            .into_iter()
            .map(|site| (site.country_code.to_ascii_lowercase(), site.domain))
            .collect();
        Ok(GeoSiteDb {
            raw,
            compiled: std::sync::Mutex::new(HashMap::new()),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn categories(&self) -> Vec<String> {
        let mut v: Vec<String> = self.raw.keys().cloned().collect();
        v.sort();
        v
    }

    /// The matcher for a category, compiled on first use.
    /// None when the category does not exist.
    pub fn matcher(&self, code: &str) -> Option<std::sync::Arc<DomainMatcher>> {
        let code = code.to_ascii_lowercase();
        let mut compiled = self.compiled.lock().expect("compiled poisoned");
        if let Some(m) = compiled.get(&code) {
            return Some(m.clone());
        }
        let domains = self.raw.get(&code)?;
        let matcher = std::sync::Arc::new(DomainMatcher::compile(domains));
        compiled.insert(code, matcher.clone());
        Some(matcher)
    }
}

/// Compiled matcher for one geosite category.
pub struct DomainMatcher {
    exact: std::collections::HashSet<String>,
    suffixes: Vec<String>,
    keywords: aho_corasick::AhoCorasick,
    regexes: Vec<regex::Regex>,
}

impl DomainMatcher {
    pub fn compile(domains: &[crate::proto::Domain]) -> Self {
        let mut exact = std::collections::HashSet::new();
        let mut suffixes = Vec::new();
        let mut keywords = Vec::new();
        let mut regexes = Vec::new();

        for d in domains {
            let value = d.value.to_ascii_lowercase();
            match domain::Type::try_from(d.r#type).unwrap_or(domain::Type::Plain) {
                domain::Type::Full => {
                    exact.insert(value);
                }
                domain::Type::RootDomain => suffixes.push(value),
                domain::Type::Plain => keywords.push(value),
                domain::Type::Regex => match regex::Regex::new(&format!("^(?:{})$", d.value)) {
                    Ok(re) => regexes.push(re),
                    Err(e) => {
                        tracing::warn!(error = %e, value = %d.value, "skipping bad geosite regex")
                    }
                },
            }
        }

        DomainMatcher {
            exact,
            suffixes,
            keywords: aho_corasick::AhoCorasick::new(&keywords)
                .expect("keywords are valid patterns"),
            regexes,
        }
    }

    /// Match a domain (lowercased inside). IP literals never match.
    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        if self.exact.contains(&domain) {
            return true;
        }
        // Label-walk suffix matching: a.b.c tries a.b.c, b.c, c.
        let mut rest = domain.as_str();
        loop {
            if self.suffixes.iter().any(|s| s == rest) {
                return true;
            }
            match rest.split_once('.') {
                Some((_, parent)) => rest = parent,
                None => break,
            }
        }
        if self.keywords.is_match(&domain) {
            return true;
        }
        self.regexes.iter().any(|re| re.is_match(&domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Domain, GeoSite, GeoSiteList};

    fn site(code: &str, entries: &[(domain::Type, &str)]) -> GeoSite {
        GeoSite {
            country_code: code.into(),
            domain: entries
                .iter()
                .map(|(t, v)| Domain {
                    r#type: (*t) as i32,
                    value: v.to_string(),
                    attribute: vec![],
                })
                .collect(),
            resource_hash: vec![],
            code: code.into(),
        }
    }

    fn sample_db() -> GeoSiteDb {
        let list = GeoSiteList {
            entry: vec![site(
                "test",
                &[
                    (domain::Type::Full, "exact.example.com"),
                    (domain::Type::RootDomain, "suffix.example.org"),
                    (domain::Type::Plain, "keyword"),
                    (domain::Type::Regex, r"ads[0-9]+\.example\.net"),
                ],
            )],
        };
        let mut buf = Vec::new();
        list.encode(&mut buf).unwrap();
        GeoSiteDb::parse(&buf).unwrap()
    }

    #[test]
    fn protobuf_roundtrip_and_categories() {
        let db = sample_db();
        assert!(db.categories().contains(&"test".to_string()));
        assert!(db.matcher("missing").is_none());
    }

    #[test]
    fn matcher_semantics() {
        let db = sample_db();
        let m = db.matcher("test").unwrap();

        assert!(m.matches("exact.example.com"));
        assert!(!m.matches("sub.exact.example.com"));

        assert!(m.matches("suffix.example.org"));
        assert!(m.matches("a.b.suffix.example.org"));
        assert!(!m.matches("uffix.example.org"));

        assert!(m.matches("www.keyword-site.com"));

        assert!(m.matches("ads42.example.net"));
        assert!(!m.matches("ads.example.net"));
    }
}
