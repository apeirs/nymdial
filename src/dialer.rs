//! The dialer: one tunnel at a time through one exit, replaced when it stops working.

use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use nym_smolmix::{Recipient, Tunnel};
use serde::Serialize;

use crate::dns::{self, DohClient, DohServer, LookupError};
use crate::exits::{self, Exit, Selection};
use crate::rotate::{self, Attempt};
use crate::{tls, Error, TcpStream, TlsStream};

/// Settings. `Config::default()` is what the CLI uses; every timeout is a budget for one step.
#[derive(Debug, Clone)]
pub struct Config {
    /// nym-api to read the exit list from.
    pub nym_api: String,
    /// Which directory exits may be used.
    pub selection: Selection,
    /// Exits to try first, in order: node ids (`2716`) or IPR addresses (`client.key@gateway`).
    pub exits: Vec<String>,
    /// Use only `exits`, never other exits from the directory.
    pub pinned_only: bool,
    /// How many exits to try before giving up on getting a tunnel.
    pub max_attempts: usize,
    /// Budget for one exit: mixnet client start, IPR handshake and the health check.
    pub attempt_timeout: Duration,
    /// TCP handshake through the tunnel.
    pub connect_timeout: Duration,
    /// TLS handshake through the tunnel.
    pub tls_timeout: Duration,
    /// One DoH lookup at one resolver.
    pub dns_timeout: Duration,
    /// Health check: budget per resolver (at most two are asked). A cold probe (TCP + TLS + HTTP/2 + one
    /// query through the mixnet) took 4-6 s in live runs.
    pub health_timeout: Duration,
    /// A tunnel that hasn't shown it is alive for this long gets a quick probe before the next connect, and is
    /// replaced if the probe fails. nym-sdk 1.21.6 tunnels can stop receiving for good after one lost reply
    /// frame (see the README), so an idle tunnel can't be trusted. `None` turns this off.
    pub liveness_after: Option<Duration>,
    /// Budget for that probe (one DoH query on the warm resolver connection).
    pub liveness_timeout: Duration,
    /// DoH resolvers, tried in order.
    pub doh: Vec<DohServer>,
    /// Reading the nym-api.
    pub directory_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            nym_api: exits::DEFAULT_NYM_API.into(),
            selection: Selection::default(),
            exits: vec![],
            pinned_only: false,
            max_attempts: 6,
            attempt_timeout: Duration::from_secs(45),
            connect_timeout: Duration::from_secs(30),
            tls_timeout: Duration::from_secs(30),
            dns_timeout: Duration::from_secs(15),
            health_timeout: Duration::from_secs(12),
            liveness_after: Some(Duration::from_secs(10)),
            liveness_timeout: Duration::from_secs(8),
            doh: dns::default_servers(),
            directory_timeout: Duration::from_secs(30),
        }
    }
}

/// The exit in use.
#[derive(Debug, Clone, Serialize)]
pub struct ExitInfo {
    pub exit: Exit,
    /// Address the IPR gave this tunnel inside its private range.
    pub tunnel_ipv4: Ipv4Addr,
    /// How long it took from the first exit tried to a healthy tunnel.
    pub setup: Duration,
    /// Counts tunnels: 1 for the first, +1 per failover.
    pub generation: u64,
}

struct Active {
    tunnel: Tunnel,
    doh: DohClient,
    info: ExitInfo,
    /// Last time traffic came back through this tunnel (health check, DNS answer, completed connect).
    alive_at: std::sync::Mutex<Instant>,
}

impl Active {
    fn saw_traffic(&self) {
        *self.alive_at.lock().unwrap() = Instant::now();
    }
    fn quiet_for(&self) -> Duration {
        self.alive_at.lock().unwrap().elapsed()
    }
}

struct State {
    queue: VecDeque<Exit>,
    directory: Vec<Exit>,
    bad: HashSet<String>,
    generation: u64,
    log: Vec<Attempt>,
}

/// Dials TCP and TLS through the Nym mixnet. Cheap to share behind an `Arc`; all methods take `&self`.
pub struct Dialer {
    cfg: Config,
    active: RwLock<Option<Arc<Active>>>,
    state: tokio::sync::Mutex<State>,
    cache: dns::Cache,
}

fn parse_recipient(s: &str) -> Result<Recipient, Error> {
    s.parse::<Recipient>().map_err(|e| Error::Invalid(format!("exit address {s:?}: {e}")))
}

/// Fill the queue: pinned exits first, then (unless pinned-only) the directory in weighted random order.
fn plan(cfg: &Config, directory: &[Exit], bad: &HashSet<String>) -> Result<VecDeque<Exit>, Error> {
    let mut q = VecDeque::new();
    for p in &cfg.exits {
        let found = directory
            .iter()
            .find(|e| e.node_id.to_string() == *p || e.ipr_address == *p || e.identity == *p)
            .cloned();
        let exit = match found {
            Some(e) => e,
            None if p.contains('@') => {
                let r = parse_recipient(p)?;
                Exit {
                    node_id: 0,
                    identity: r.gateway().to_base58_string(),
                    ipr_address: p.clone(),
                    performance: 0.0,
                    version: String::new(),
                    country: None,
                    ips: vec![],
                }
            }
            None => return Err(Error::NoExit(format!("{p} is not an active IPR exit in the directory"))),
        };
        q.push_back(exit);
    }
    if !cfg.pinned_only {
        let mut sel = cfg.selection.clone();
        sel.exclude.extend(bad.iter().cloned());
        sel.exclude.extend(q.iter().map(|e| e.ipr_address.clone()));
        let pinned: HashSet<String> = q.iter().map(|e| e.ipr_address.clone()).collect();
        q.extend(exits::order(directory, &sel, &mut rand::thread_rng()).into_iter().filter(|e| !pinned.contains(&e.ipr_address)));
    }
    if q.is_empty() {
        return Err(Error::NoExit(format!(
            "{} exits listed, none left after the filter ({:?}) and {} marked bad",
            directory.len(),
            cfg.selection,
            bad.len()
        )));
    }
    Ok(q)
}

impl Dialer {
    /// Read the exit list, then bring up a tunnel on the first exit that works.
    pub async fn start(cfg: Config) -> Result<Self, Error> {
        let directory = match exits::fetch(&cfg.nym_api, cfg.directory_timeout).await {
            Ok(d) => d,
            // With pinned exits given as full addresses the directory is only used for labels.
            Err(e) if cfg.pinned_only && cfg.exits.iter().all(|p| p.contains('@')) => {
                tracing::warn!("{e}; going on with the pinned exits only");
                vec![]
            }
            Err(e) => return Err(e),
        };
        tracing::info!("nym-api lists {} IPR exits", directory.len());
        let queue = plan(&cfg, &directory, &HashSet::new())?;
        let d = Self {
            cfg,
            active: RwLock::new(None),
            state: tokio::sync::Mutex::new(State { queue, directory, bad: HashSet::new(), generation: 0, log: vec![] }),
            cache: dns::Cache::default(),
        };
        let mut st = d.state.lock().await;
        d.establish(&mut st).await?;
        drop(st);
        Ok(d)
    }

    async fn establish(&self, st: &mut State) -> Result<Arc<Active>, Error> {
        if st.queue.is_empty() {
            if st.bad.len() >= st.directory.len() {
                st.bad.clear(); // everything failed once: give them all a second chance
            }
            st.queue = plan(&self.cfg, &st.directory, &st.bad)?;
        }
        let candidates: Vec<Exit> = st.queue.iter().cloned().collect();
        let servers = self.cfg.doh.clone();
        let dns_timeout = self.cfg.dns_timeout;
        let health_timeout = self.cfg.health_timeout;
        let started = Instant::now();
        let mut log = vec![];
        let result = rotate::first_working(
            &candidates,
            self.cfg.max_attempts,
            self.cfg.attempt_timeout,
            move |exit: Exit| {
                let servers = servers.clone();
                async move {
                    let r = parse_recipient(&exit.ipr_address).map_err(|e| e.to_string())?;
                    let tunnel = Tunnel::new_with_ipr(r).await.map_err(|e| format!("IPR handshake: {e}"))?;
                    let doh = DohClient::new(servers, dns_timeout);
                    // Health check: a real DoH lookup through the exit (TCP + TLS + HTTP/2 + one query),
                    // which also leaves the resolver connection warm for the first real lookup.
                    let t = Instant::now();
                    match doh.probe(&tunnel, "nym.com", 2, health_timeout).await {
                        Ok(by) => tracing::info!("health check: DoH via {by} in {:.1?}", t.elapsed()),
                        Err(e) => {
                            tunnel.shutdown().await;
                            return Err(format!("IPR handshake ok, but the health check failed ({e})"));
                        }
                    }
                    Ok((tunnel, doh))
                }
            },
            |(tunnel, _doh): (Tunnel, DohClient)| async move { tunnel.shutdown().await },
            &mut log,
        )
        .await;
        // Attempts run in candidate order, so attempt i was candidates[i].
        for (i, a) in log.iter().enumerate() {
            st.queue.pop_front();
            if a.error.is_some() {
                st.bad.insert(candidates[i].ipr_address.clone());
            }
        }
        st.log.extend(log);
        let ((tunnel, doh), exit) = result?;
        st.generation += 1;
        let info = ExitInfo {
            tunnel_ipv4: tunnel.allocated_ips().ipv4,
            exit,
            setup: started.elapsed(),
            generation: st.generation,
        };
        let a = Arc::new(Active { tunnel, doh, info, alive_at: std::sync::Mutex::new(Instant::now()) });
        *self.active.write().unwrap() = Some(a.clone());
        Ok(a)
    }

    async fn current(&self) -> Result<Arc<Active>, Error> {
        if let Some(a) = self.active.read().unwrap().clone() {
            return Ok(a);
        }
        let mut st = self.state.lock().await;
        if let Some(a) = self.active.read().unwrap().clone() {
            return Ok(a);
        }
        self.establish(&mut st).await
    }

    /// Replace the tunnel `dead` with one on the next exit (unless another task already did).
    async fn failover(&self, dead: &Arc<Active>, why: &str) -> Result<Arc<Active>, Error> {
        let mut st = self.state.lock().await;
        if let Some(a) = self.active.read().unwrap().clone() {
            if a.info.generation != dead.info.generation {
                return Ok(a);
            }
        }
        tracing::warn!("failover from {}: {why}", dead.info.exit.label());
        st.bad.insert(dead.info.exit.ipr_address.clone());
        *self.active.write().unwrap() = None;
        let old = dead.clone();
        tokio::spawn(async move { old.tunnel.shutdown().await });
        self.establish(&mut st).await
    }

    /// Is this tunnel still carrying traffic? One uncached DoH lookup through it.
    async fn healthy(&self, a: &Active) -> bool {
        let ok = a.doh.probe(&a.tunnel, "nym.com", 2, self.cfg.health_timeout).await.is_ok();
        if ok {
            a.saw_traffic();
        }
        ok
    }

    /// Run the health check on the current tunnel now; on failure, fail over. Returns the exit in use after.
    pub async fn check(&self) -> Result<ExitInfo, Error> {
        let a = self.current().await?;
        if self.healthy(&a).await {
            return Ok(a.info.clone());
        }
        Ok(self.failover(&a, "health check failed").await?.info.clone())
    }

    /// Move to a different exit now (for example a fresh exit per wallet session or per broadcast).
    pub async fn rotate(&self) -> Result<ExitInfo, Error> {
        let a = self.current().await?;
        let mut st = self.state.lock().await;
        if let Some(cur) = self.active.read().unwrap().clone() {
            if cur.info.generation != a.info.generation {
                return Ok(cur.info.clone());
            }
        }
        *self.active.write().unwrap() = None;
        let old = a.clone();
        tokio::spawn(async move { old.tunnel.shutdown().await });
        Ok(self.establish(&mut st).await?.info.clone())
    }

    /// The exit in use, if a tunnel is up.
    pub fn exit(&self) -> Option<ExitInfo> {
        self.active.read().unwrap().as_ref().map(|a| a.info.clone())
    }

    /// Every exit tried so far, with what happened.
    pub async fn attempts(&self) -> Vec<Attempt> {
        self.state.lock().await.log.clone()
    }

    async fn resolve_on(&self, a: &Arc<Active>, host: &str) -> Result<(Vec<Ipv4Addr>, Arc<Active>), Error> {
        if let Some(ips) = self.cache.get(host, Instant::now()) {
            return Ok((ips, a.clone()));
        }
        let mut a = a.clone();
        for round in 0..2 {
            match a.doh.resolve(&a.tunnel, host, 0).await {
                Ok((ips, ttl, by)) => {
                    tracing::debug!("{host} -> {ips:?} via {by}");
                    a.saw_traffic();
                    self.cache.put(host, ips.clone(), ttl, Instant::now());
                    return Ok((ips, a));
                }
                Err(LookupError::NxDomain) => {
                    return Err(Error::Dns { host: host.into(), reason: "no such name (NXDOMAIN)".into() })
                }
                Err(LookupError::NoIpv4) => return Err(Error::NoIpv4(host.into())),
                Err(LookupError::Bad(e)) => return Err(Error::Invalid(e)),
                Err(LookupError::Retry(e)) if round == 0 => {
                    // Every resolver failed: that's the tunnel, not the name.
                    a = self.failover(&a, &format!("DNS failed at every resolver: {e}")).await?;
                }
                Err(LookupError::Retry(e)) => return Err(Error::Dns { host: host.into(), reason: e }),
            }
        }
        unreachable!()
    }

    /// Resolve `host` through the mixnet (DoH via the exit). IP literals are returned as they are.
    pub async fn resolve(&self, host: &str) -> Result<Vec<Ipv4Addr>, Error> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return match ip {
                IpAddr::V4(v4) => Ok(vec![v4]),
                IpAddr::V6(_) => Err(Error::NoIpv4(host.into())),
            };
        }
        let a = self.current().await?;
        Ok(self.resolve_on(&a, host).await?.0)
    }

    /// Open a TCP stream to `host:port` through the mixnet. `host` is a name (resolved through the mixnet) or
    /// an IPv4 literal. If the connect times out and the tunnel fails its health check, nymdial moves to the
    /// next exit and tries once more.
    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, Error> {
        let mut a = self.current().await?;
        if let Some(after) = self.cfg.liveness_after {
            if a.quiet_for() >= after {
                let t = Instant::now();
                match a.doh.probe(&a.tunnel, "nym.com", 1, self.cfg.liveness_timeout).await {
                    Ok(_) => {
                        tracing::debug!("liveness probe ok in {:.1?}", t.elapsed());
                        a.saw_traffic();
                    }
                    Err(e) => {
                        let why = format!("tunnel quiet for {:.0?} and the liveness probe failed ({e})", a.quiet_for());
                        a = self.failover(&a, &why).await?;
                    }
                }
            }
        }
        for round in 0..2 {
            let ips = match host.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => vec![v4],
                Ok(IpAddr::V6(_)) => return Err(Error::NoIpv4(host.into())),
                Err(_) => {
                    let (ips, used) = self.resolve_on(&a, host).await?;
                    a = used;
                    ips
                }
            };
            let addr = SocketAddr::new(IpAddr::V4(ips[0]), port);
            match tokio::time::timeout(self.cfg.connect_timeout, a.tunnel.tcp_connect(addr)).await {
                Ok(Ok(s)) => {
                    a.saw_traffic(); // the SYN-ACK came back through the tunnel
                    return Ok(s);
                }
                Ok(Err(e)) => {
                    let msg = e.to_string();
                    let tunnel_gone = matches!(e, nym_smolmix::SmolmixError::ChannelClosed | nym_smolmix::SmolmixError::NotConnected)
                        || msg.contains("Channel closed");
                    if round == 0 && tunnel_gone {
                        a = self.failover(&a, &format!("tunnel closed: {msg}")).await?;
                        continue;
                    }
                    return Err(Error::Connect { addr, reason: msg });
                }
                Err(_) => {
                    if round == 0 && !self.healthy(&a).await {
                        a = self.failover(&a, &format!("TCP connect to {addr} timed out and the health check failed")).await?;
                        continue;
                    }
                    return Err(Error::ConnectTimeout { addr, after: self.cfg.connect_timeout });
                }
            }
        }
        unreachable!()
    }

    /// Open a TLS stream to `host:port` (certificate checked against `host` with the webpki roots).
    pub async fn connect_tls(&self, host: &str, port: u16) -> Result<TlsStream, Error> {
        self.connect_tls_alpn(host, port, &[]).await
    }

    /// Like [`connect_tls`](Self::connect_tls), offering ALPN protocols (e.g. `b"h2"` for gRPC).
    pub async fn connect_tls_alpn(&self, host: &str, port: u16, alpn: &[&[u8]]) -> Result<TlsStream, Error> {
        let tcp = self.connect(host, port).await?;
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| Error::Invalid(format!("TLS name {host:?}: {e}")))?;
        match tokio::time::timeout(self.cfg.tls_timeout, tls::connector(alpn).connect(name, tcp)).await {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(Error::Tls { host: host.into(), reason: e.to_string() }),
            Err(_) => Err(Error::Tls { host: host.into(), reason: format!("no handshake within {:?}", self.cfg.tls_timeout) }),
        }
    }

    /// Test hook: shut the current tunnel down underneath the dialer, as if the exit had vanished, so the
    /// next call has to notice and fail over. Not for production use.
    #[doc(hidden)]
    pub async fn drop_tunnel_for_test(&self) {
        let a = self.active.read().unwrap().clone();
        if let Some(a) = a {
            a.tunnel.shutdown().await;
        }
    }

    /// Disconnect from the mixnet.
    pub async fn shutdown(&self) {
        let a = self.active.write().unwrap().take();
        if let Some(a) = a {
            a.tunnel.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(id: u32, country: &str) -> Exit {
        Exit {
            node_id: id,
            identity: format!("id{id}"),
            ipr_address: format!("c{id}.e{id}@id{id}"),
            performance: 0.9,
            version: "1.43.0".into(),
            country: Some(country.into()),
            ips: vec![],
        }
    }

    #[test]
    fn plan_puts_pinned_first_and_skips_bad() {
        let dir: Vec<Exit> = (1..=6).map(|i| exit(i, "DE")).collect();
        let cfg = Config { exits: vec!["4".into(), "c2.e2@id2".into()], ..Default::default() };
        let bad: HashSet<String> = ["c5.e5@id5".to_string()].into_iter().collect();
        let q: Vec<u32> = plan(&cfg, &dir, &bad).unwrap().iter().map(|e| e.node_id).collect();
        assert_eq!(&q[..2], &[4, 2]);
        assert_eq!(q.len(), 5, "6 exits, 1 bad: {q:?}");
        assert!(!q.contains(&5));
        assert_eq!(q.iter().filter(|&&i| i == 4).count(), 1, "pinned exit not repeated");
    }

    #[test]
    fn plan_pinned_only_and_unknown_pins() {
        let dir: Vec<Exit> = (1..=3).map(|i| exit(i, "DE")).collect();
        let cfg = Config { exits: vec!["3".into()], pinned_only: true, ..Default::default() };
        let q: Vec<u32> = plan(&cfg, &dir, &HashSet::new()).unwrap().iter().map(|e| e.node_id).collect();
        assert_eq!(q, vec![3]);
        let cfg = Config { exits: vec!["77".into()], ..Default::default() };
        assert!(matches!(plan(&cfg, &dir, &HashSet::new()), Err(Error::NoExit(_))));
    }

    #[test]
    fn plan_reports_an_empty_filter() {
        let dir: Vec<Exit> = (1..=3).map(|i| exit(i, "DE")).collect();
        let mut cfg = Config::default();
        cfg.selection.countries = vec!["JP".into()];
        assert!(matches!(plan(&cfg, &dir, &HashSet::new()), Err(Error::NoExit(_))));
    }
}
