
pub mod types {
    use crate::LocalProtocol;
    use ipnet::{IpNet, Ipv4Net, Ipv6Net};
    use regex::Regex;
    use serde::{Deserialize, Deserializer};
    use std::collections::HashMap;
    use std::ops::RangeInclusive;

    #[derive(Debug, Clone, Deserialize)]
    pub struct RestrictionsRules { pub restrictions: Vec<RestrictionConfig> }

    #[derive(Debug, Clone, Deserialize)]
    pub struct RestrictionConfig {
        pub name: String,
        #[serde(deserialize_with = "deserialize_non_empty_vec")]
        pub r#match: Vec<MatchConfig>,
        pub allow: Vec<AllowConfig>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub enum MatchConfig {
        Any,
        #[serde(with = "serde_regex")]
        PathPrefix(Regex),
        #[serde(with = "serde_regex")]
        Authorization(Regex),
    }

    #[derive(Debug, Clone, Deserialize)]
    pub enum AllowConfig {
        ReverseTunnel(AllowReverseTunnelConfig),
        Tunnel(AllowTunnelConfig),
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct AllowTunnelConfig {
        #[serde(default)] pub protocol: Vec<TunnelProtocol>,
        #[serde(deserialize_with = "deserialize_port_range")] #[serde(default)] pub port: Vec<RangeInclusive<u16>>,
        #[serde(with = "serde_regex")] #[serde(default = "default_host")] pub host: Regex,
        #[serde(default = "default_cidr")] pub cidr: Vec<IpNet>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct AllowReverseTunnelConfig {
        #[serde(default)] pub protocol: Vec<ReverseTunnelProtocol>,
        #[serde(deserialize_with = "deserialize_port_range")] #[serde(default)] pub port: Vec<RangeInclusive<u16>>,
        #[serde(deserialize_with = "deserialize_port_mapping")] #[serde(default)] pub port_mapping: HashMap<u16, u16>,
        #[serde(default = "default_cidr")] pub cidr: Vec<IpNet>,
        #[serde(with = "serde_regex")] #[serde(default = "default_host")] pub unix_path: Regex,
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
    pub enum TunnelProtocol { Tcp, Udp, Unknown }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
    pub enum ReverseTunnelProtocol { Tcp, Udp, Socks5, Unix, HttpProxy, Unknown }

    pub fn default_host() -> Regex { Regex::new("^.*$").unwrap() }
    pub fn default_cidr() -> Vec<IpNet> { vec![IpNet::V4(Ipv4Net::default()), IpNet::V6(Ipv6Net::default())] }

    fn deserialize_port_range<'de, D>(d: D) -> Result<Vec<RangeInclusive<u16>>, D::Error> where D: Deserializer<'de> {
        let s = Vec::<String>::deserialize(d)?;
        s.into_iter().map(|s| {
            let range: Result<RangeInclusive<u16>, D::Error> = if let Some((l, r)) = s.split_once("..") {
                Ok(RangeInclusive::new(l.parse().map_err(serde::de::Error::custom)?, r.parse().map_err(serde::de::Error::custom)?))
            } else {
                let port: u16 = s.parse().map_err(serde::de::Error::custom)?;
                Ok(RangeInclusive::new(port, port))
            };
            range
        }).collect()
    }

    fn deserialize_port_mapping<'de, D>(d: D) -> Result<HashMap<u16, u16>, D::Error> where D: Deserializer<'de> {
        let mappings: Vec<String> = Deserialize::deserialize(d)?;
        mappings.into_iter().map(|m| {
            let (a, b) = m.split_once(':').ok_or_else(|| serde::de::Error::custom(format!("bad mapping {m}")))?;
            let a: u16 = a.parse().map_err(serde::de::Error::custom)?;
            let b: u16 = b.parse().map_err(serde::de::Error::custom)?;
            Ok((a, b))
        }).collect()
    }

    fn deserialize_non_empty_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error> where D: Deserializer<'de>, T: Deserialize<'de> {
        let v = Vec::<T>::deserialize(d)?;
        if v.is_empty() { Err(serde::de::Error::custom("empty list")) } else { Ok(v) }
    }

    impl From<&LocalProtocol> for ReverseTunnelProtocol {
        fn from(v: &LocalProtocol) -> Self {
            match v {
                LocalProtocol::ReverseTcp => Self::Tcp,
                LocalProtocol::ReverseUdp { .. } => Self::Udp,
                LocalProtocol::ReverseSocks5 { .. } => Self::Socks5,
                LocalProtocol::ReverseUnix { .. } => Self::Unix,
                LocalProtocol::ReverseHttpProxy { .. } => Self::HttpProxy,
                _ => Self::Unknown,
            }
        }
    }
    impl From<&LocalProtocol> for TunnelProtocol {
        fn from(v: &LocalProtocol) -> Self {
            match v {
                LocalProtocol::Tcp { .. } => Self::Tcp,
                LocalProtocol::Udp { .. } => Self::Udp,
                _ => Self::Unknown,
            }
        }
    }
}

pub use types::{AllowConfig, AllowReverseTunnelConfig, AllowTunnelConfig, MatchConfig, RestrictionConfig, RestrictionsRules, ReverseTunnelProtocol, TunnelProtocol};

pub mod config_reloader {
    use super::types::RestrictionsRules;
    use std::path::PathBuf;
    use std::sync::Arc;
    use arc_swap::ArcSwap;

    pub struct RestrictionsRulesReloader { restrictions: Arc<ArcSwap<RestrictionsRules>> }

    impl RestrictionsRulesReloader {
        pub fn new(rules: RestrictionsRules, _config_path: Option<PathBuf>) -> anyhow::Result<Self> {
            Ok(Self { restrictions: Arc::new(ArcSwap::from_pointee(rules)) })
        }
        pub fn restrictions_rules(&self) -> Arc<RestrictionsRules> {
            self.restrictions.load().clone()
        }
    }
}

impl RestrictionsRules {
    pub fn from_path_prefix(path_prefixes: &[String], restrict_to: &[(String, u16)]) -> anyhow::Result<Self> {
        use crate::restrictions::types::{default_cidr, default_host};
        use ipnet::IpNet;
        use regex::Regex;
        use std::ops::RangeInclusive;

        let tunnels_restrictions: Vec<AllowConfig> = if restrict_to.is_empty() {
            vec![
                AllowConfig::Tunnel(AllowTunnelConfig { protocol: vec![], port: vec![], host: default_host(), cidr: default_cidr() }),
                AllowConfig::ReverseTunnel(AllowReverseTunnelConfig { protocol: vec![], port: vec![], port_mapping: Default::default(), cidr: default_cidr(), unix_path: default_host() }),
            ]
        } else {
            restrict_to.iter().map(|(host, port)| {
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    AllowConfig::Tunnel(AllowTunnelConfig {
                        protocol: vec![], port: vec![RangeInclusive::new(*port, *port)], host: Regex::new("^$").unwrap(),
                        cidr: vec![IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).unwrap()],
                    })
                } else {
                    AllowConfig::Tunnel(AllowTunnelConfig {
                        protocol: vec![], port: vec![RangeInclusive::new(*port, *port)],
                        host: Regex::new(&format!("^{}$", regex::escape(host))).unwrap(), cidr: vec![],
                    })
                }
            }).collect()
        };

        let rules: Vec<RestrictionConfig> = if path_prefixes.is_empty() {
            vec![RestrictionConfig { name: "Allow All".into(), r#match: vec![MatchConfig::Any], allow: tunnels_restrictions }]
        } else {
            path_prefixes.iter().map(|prefix| RestrictionConfig {
                name: format!("Allow prefix {prefix}"),
                r#match: vec![MatchConfig::PathPrefix(Regex::new(&format!("^{}$", regex::escape(prefix))).unwrap())],
                allow: tunnels_restrictions.clone(),
            }).collect()
        };
        Ok(Self { restrictions: rules })
    }
}
