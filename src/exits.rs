//! Exit selection: which IP Packet Router (IPR) exit gateways exist, and in which order to try them.
//!
//! The list comes from the public nym-api, the same directory every Nym client reads its topology from. It is
//! fetched over the clearnet, like the topology itself: it tells the API that you use Nym, nothing about where
//! you connect.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Default nym-api (mainnet).
pub const DEFAULT_NYM_API: &str = "https://validator.nymtech.net/api";

/// IPR protocol v9 (LP Stream framing) is what nym-sdk 1.21.6 speaks; older nodes can't be used.
/// Same value as `nym_ip_packet_requests::v9::MIN_RELEASE_VERSION`.
pub const MIN_NODE_VERSION: (u64, u64, u64) = (1, 30, 0);

/// One exit gateway that runs an IP Packet Router.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Exit {
    /// nym-api node id (as shown in the Nym explorer).
    pub node_id: u32,
    /// The node's ed25519 identity key.
    pub identity: String,
    /// Nym address of its IP Packet Router (`<client id>.<enc key>@<gateway id>`).
    pub ipr_address: String,
    /// Directory performance score, 0.0 to 1.0.
    pub performance: f64,
    /// nym-node release version.
    pub version: String,
    /// Self-declared country (ISO 3166 alpha-2), if any.
    pub country: Option<String>,
    /// The node's public IPs: what a server you connect to sees.
    pub ips: Vec<IpAddr>,
}

impl Exit {
    /// Short human label: `node 2716 (IT)`.
    pub fn label(&self) -> String {
        if self.node_id == 0 {
            // given by address, not in the directory
            return format!("unlisted exit @{}", &self.identity[..self.identity.len().min(8)]);
        }
        match &self.country {
            Some(c) => format!("node {} ({c})", self.node_id),
            None => format!("node {}", self.node_id),
        }
    }
}

// --- nym-api JSON (only the fields used) ---

#[derive(Deserialize)]
struct Skimmed {
    nodes: SkimmedPage,
}
#[derive(Deserialize)]
struct SkimmedPage {
    data: Vec<SkimmedNode>,
}
#[derive(Deserialize)]
struct SkimmedNode {
    node_id: u32,
    ed25519_identity_pubkey: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    supported_roles: Roles,
    #[serde(deserialize_with = "num_or_string")]
    performance: f64,
}
#[derive(Deserialize, Default)]
struct Roles {
    #[serde(default)]
    exit_ipr: bool,
}

#[derive(Deserialize)]
struct Described {
    data: Vec<DescribedNode>,
}
#[derive(Deserialize)]
struct DescribedNode {
    node_id: u32,
    description: Description,
}
#[derive(Deserialize)]
struct Description {
    host_information: HostInfo,
    #[serde(default)]
    ip_packet_router: Option<AddressInfo>,
    #[serde(default)]
    auxiliary_details: Aux,
    build_information: Build,
}
#[derive(Deserialize)]
struct HostInfo {
    #[serde(default)]
    ip_address: Vec<IpAddr>,
}
#[derive(Deserialize)]
struct AddressInfo {
    address: String,
}
#[derive(Deserialize, Default)]
struct Aux {
    #[serde(default)]
    location: Option<String>,
}
#[derive(Deserialize)]
struct Build {
    build_version: String,
}

fn num_or_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum N {
        F(f64),
        S(String),
    }
    match N::deserialize(d)? {
        N::F(f) => Ok(f),
        N::S(s) => s.trim().parse().map_err(serde::de::Error::custom),
    }
}

fn version_ok(v: &str) -> bool {
    let core = v.split(['-', '+']).next().unwrap_or("");
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    match (it.next().flatten(), it.next().flatten(), it.next().flatten()) {
        (Some(a), Some(b), Some(c)) => (a, b, c) >= MIN_NODE_VERSION,
        _ => false,
    }
}

/// Every node the nym-api describes, keyed by node id (also used to map an IP back to a node).
pub fn parse_described(described_json: &str) -> Result<HashMap<u32, (Vec<IpAddr>, Option<String>)>, Error> {
    let d: Described = serde_json::from_str(described_json).map_err(|e| Error::Directory(e.to_string()))?;
    Ok(d.data
        .into_iter()
        .map(|n| {
            (
                n.node_id,
                (n.description.host_information.ip_address, n.description.auxiliary_details.location),
            )
        })
        .collect())
}

/// Build the exit list from the two nym-api documents: the nodes that hold the exit role this epoch and
/// support the IPR (`/v1/unstable/nym-nodes/skimmed/exit-gateways/all`), joined with what each node says about
/// itself (`/v1/nym-nodes/described`): its IPR address, version, country and IPs.
///
/// Same filter as nym-sdk's own IPR discovery: active exit role, `exit_ipr` support, a parseable IPR address and
/// a release that speaks IPR v9.
pub fn parse_exits(skimmed_json: &str, described_json: &str) -> Result<Vec<Exit>, Error> {
    let skimmed: Skimmed = serde_json::from_str(skimmed_json).map_err(|e| Error::Directory(e.to_string()))?;
    let described: Described = serde_json::from_str(described_json).map_err(|e| Error::Directory(e.to_string()))?;
    let by_id: HashMap<u32, &DescribedNode> = described.data.iter().map(|n| (n.node_id, n)).collect();

    let mut out = Vec::new();
    for n in skimmed.nodes.data {
        if n.role != "ExitGateway" || !n.supported_roles.exit_ipr {
            continue;
        }
        let Some(d) = by_id.get(&n.node_id) else { continue };
        let Some(ipr) = &d.description.ip_packet_router else { continue };
        // `<client id>.<enc key>@<gateway id>`, and the gateway must be this node.
        let Some((_, gw)) = ipr.address.split_once('@') else { continue };
        if gw != n.ed25519_identity_pubkey || !ipr.address[..ipr.address.len() - gw.len() - 1].contains('.') {
            continue;
        }
        if !version_ok(&d.description.build_information.build_version) {
            continue;
        }
        out.push(Exit {
            node_id: n.node_id,
            identity: n.ed25519_identity_pubkey,
            ipr_address: ipr.address.clone(),
            performance: n.performance.clamp(0.0, 1.0),
            version: d.description.build_information.build_version.clone(),
            country: d.description.auxiliary_details.location.clone().map(|c| c.to_uppercase()),
            ips: d.description.host_information.ip_address.clone(),
        });
    }
    Ok(out)
}

/// Which exits are allowed, and how to order them.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    /// Only exits in these countries (alpha-2, any case). Empty = any country. Exits that declare no country
    /// are left out when this is set.
    pub countries: Vec<String>,
    /// Skip exits below this directory performance (0.0 to 1.0).
    pub min_performance: f64,
    /// Node ids, identity keys or IPR addresses never to use (for example ones that just failed).
    pub exclude: HashSet<String>,
}

impl Selection {
    fn allows(&self, e: &Exit) -> bool {
        if e.performance < self.min_performance {
            return false;
        }
        if self.exclude.contains(&e.identity)
            || self.exclude.contains(&e.ipr_address)
            || self.exclude.contains(&e.node_id.to_string())
        {
            return false;
        }
        if !self.countries.is_empty() {
            match &e.country {
                Some(c) => self.countries.iter().any(|w| w.eq_ignore_ascii_case(c)),
                None => false,
            }
        } else {
            true
        }
    }
}

/// Order the allowed exits for trying: a performance-weighted random order without replacement
/// (Efraimidis-Spirakis), so better exits tend to come first, every allowed exit appears once, and two clients
/// don't walk the list in the same order. Exits with performance 0 come last, in random order.
pub fn order<R: Rng + ?Sized>(exits: &[Exit], sel: &Selection, rng: &mut R) -> Vec<Exit> {
    let mut keyed: Vec<(f64, &Exit)> = exits
        .iter()
        .filter(|e| sel.allows(e))
        .map(|e| {
            let u: f64 = rng.gen_range(f64::MIN_POSITIVE..1.0);
            // key = u^(1/w); log form keeps it stable for small w. w = 0 -> -inf (last), ties broken by u.
            let key = if e.performance > 0.0 { u.ln() / e.performance } else { f64::NEG_INFINITY };
            (key, e)
        })
        .collect();
    keyed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let (mut live, mut dead): (Vec<_>, Vec<_>) = keyed.into_iter().partition(|(k, _)| k.is_finite());
    // shuffle the zero-performance tail
    for i in (1..dead.len()).rev() {
        let j = rng.gen_range(0..=i);
        dead.swap(i, j);
    }
    live.append(&mut dead);
    live.into_iter().map(|(_, e)| e.clone()).collect()
}

/// Fetch the two directory documents from a nym-api.
pub async fn fetch_raw(api: &str, timeout: Duration) -> Result<(String, String), Error> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("nymdial/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| Error::Directory(e.to_string()))?;
    let get = |path: String| {
        let client = client.clone();
        async move {
            let resp = client.get(&path).send().await.map_err(|e| Error::Directory(format!("{path}: {e}")))?;
            if !resp.status().is_success() {
                return Err(Error::Directory(format!("{path}: HTTP {}", resp.status())));
            }
            resp.text().await.map_err(|e| Error::Directory(format!("{path}: {e}")))
        }
    };
    let api = api.trim_end_matches('/');
    let (s, d) = tokio::join!(
        get(format!("{api}/v1/unstable/nym-nodes/skimmed/exit-gateways/all")),
        get(format!("{api}/v1/nym-nodes/described?per_page=5000")),
    );
    Ok((s?, d?))
}

/// Fetch and parse the exit list.
pub async fn fetch(api: &str, timeout: Duration) -> Result<Vec<Exit>, Error> {
    let (s, d) = fetch_raw(api, timeout).await?;
    parse_exits(&s, &d)
}

/// Which Nym node announces `ip`, if any (node id, country). Used to show that a server saw an exit gateway.
pub fn node_for_ip(described: &HashMap<u32, (Vec<IpAddr>, Option<String>)>, ip: IpAddr) -> Option<(u32, Option<String>)> {
    described
        .iter()
        .find(|(_, (ips, _))| ips.contains(&ip))
        .map(|(id, (_, c))| (*id, c.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const SKIMMED: &str = include_str!("../tests/fixtures/skimmed-exits.json");
    const DESCRIBED: &str = include_str!("../tests/fixtures/described.json");

    fn exit(id: u32, perf: f64, country: Option<&str>) -> Exit {
        Exit {
            node_id: id,
            identity: format!("id{id}"),
            ipr_address: format!("c{id}.e{id}@id{id}"),
            performance: perf,
            version: "1.43.0".into(),
            country: country.map(String::from),
            ips: vec![],
        }
    }

    #[test]
    fn parses_fixture_and_applies_the_sdk_filter() {
        let exits = parse_exits(SKIMMED, DESCRIBED).unwrap();
        let ids: Vec<u32> = exits.iter().map(|e| e.node_id).collect();
        // Real nym-api records from 2026-11-08: 2871 (GR) and 3287 (BG) hold the exit role this epoch and run
        // an IPR (3287's performance edited to a JSON number; the API sends strings).
        assert_eq!(ids, vec![2871, 3287]);
        // Filtered: 2716 is IPR-capable but not in the exit role this epoch; 9001 has the exit role but no
        // exit_ipr support; 9003 runs a release too old for IPR v9; 9004 announces an IPR on another gateway;
        // 9005 has no described record.
        let e = &exits[0];
        assert_eq!(e.country.as_deref(), Some("GR"));
        assert!(e.ipr_address.ends_with(&format!("@{}", e.identity)));
        assert!(e.ips.contains(&"85.113.71.124".parse().unwrap()));
        assert!((exits[0].performance - 0.99).abs() < 1e-9);
        assert!((0.0..=1.0).contains(&exits[1].performance));
    }

    #[test]
    fn versions() {
        assert!(version_ok("1.30.0"));
        assert!(version_ok("1.43.0"));
        assert!(version_ok("1.43.0-rc.1"));
        assert!(version_ok("2.0.0"));
        assert!(!version_ok("1.29.9"));
        assert!(!version_ok("1.1.86"));
        assert!(!version_ok("garbage"));
    }

    #[test]
    fn order_is_a_permutation_of_the_allowed_set() {
        let exits: Vec<Exit> = (1..=50).map(|i| exit(i, (i % 10) as f64 / 10.0, Some("DE"))).collect();
        let mut rng = StdRng::seed_from_u64(7);
        let o = order(&exits, &Selection::default(), &mut rng);
        assert_eq!(o.len(), 50);
        let set: HashSet<u32> = o.iter().map(|e| e.node_id).collect();
        assert_eq!(set.len(), 50);
        // zero-performance exits (10, 20, ...) are all at the end
        let tail: HashSet<u32> = o[45..].iter().map(|e| e.node_id).collect();
        assert_eq!(tail, [10, 20, 30, 40, 50].into_iter().collect());
    }

    #[test]
    fn order_prefers_performance() {
        let exits = vec![exit(1, 0.95, None), exit(2, 0.30, None)];
        let mut rng = StdRng::seed_from_u64(42);
        let firsts = (0..4000).filter(|_| order(&exits, &Selection::default(), &mut rng)[0].node_id == 1).count();
        // P(first = 1) = 0.95 / (0.95 + 0.30) = 0.76
        assert!((2900..3180).contains(&firsts), "{firsts}");
    }

    #[test]
    fn order_is_random_between_clients() {
        let exits: Vec<Exit> = (1..=20).map(|i| exit(i, 0.9, None)).collect();
        let a = order(&exits, &Selection::default(), &mut StdRng::seed_from_u64(1));
        let b = order(&exits, &Selection::default(), &mut StdRng::seed_from_u64(2));
        assert_ne!(a, b);
    }

    #[test]
    fn filters() {
        let exits = vec![exit(1, 0.9, Some("DE")), exit(2, 0.9, Some("ch")), exit(3, 0.9, None), exit(4, 0.2, Some("DE"))];
        let mut rng = StdRng::seed_from_u64(3);
        let sel = Selection { countries: vec!["de".into(), "CH".into()], ..Default::default() };
        let mut ids: Vec<u32> = order(&exits, &sel, &mut rng).iter().map(|e| e.node_id).collect();
        ids.sort();
        assert_eq!(ids, vec![1, 2, 4]); // no-country exit 3 is out when a filter is set

        let sel = Selection { min_performance: 0.5, ..Default::default() };
        let mut ids: Vec<u32> = order(&exits, &sel, &mut rng).iter().map(|e| e.node_id).collect();
        ids.sort();
        assert_eq!(ids, vec![1, 2, 3]);

        let sel = Selection { exclude: ["2".to_string(), "id3".to_string()].into_iter().collect(), ..Default::default() };
        let mut ids: Vec<u32> = order(&exits, &sel, &mut rng).iter().map(|e| e.node_id).collect();
        ids.sort();
        assert_eq!(ids, vec![1, 4]);

        let sel = Selection { countries: vec!["JP".into()], ..Default::default() };
        assert!(order(&exits, &sel, &mut rng).is_empty());
    }

    #[test]
    fn maps_an_ip_back_to_its_node() {
        let d = parse_described(DESCRIBED).unwrap();
        assert_eq!(node_for_ip(&d, "57.131.24.48".parse().unwrap()).map(|x| x.0), Some(2716));
        assert_eq!(node_for_ip(&d, "198.51.100.7".parse().unwrap()), None);
    }
}
