//! DNS over the mixnet: DNS-over-HTTPS (RFC 8484) through the tunnel.
//!
//! The resolver is dialed at a pinned IP through the tunnel, so finding it needs no lookup, and the TLS
//! certificate is checked for its hostname. The resolver sees a Nym exit gateway's IP; the exit sees a TLS
//! connection to a public resolver. Nothing goes to the system resolver.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{Name, RData, RecordType};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use nym_smolmix::Tunnel;
use tokio::sync::Mutex;

use crate::tls;

/// A DoH resolver reached at a fixed IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohServer {
    /// Short name for logs.
    pub name: String,
    /// IP the tunnel dials (no lookup needed to find the resolver).
    pub ip: IpAddr,
    /// Hostname the TLS certificate must match, and the `:authority` of the request.
    pub host: String,
}

impl DohServer {
    pub fn new(name: &str, ip: &str, host: &str) -> Self {
        Self { name: name.into(), ip: ip.parse().expect("valid IP"), host: host.into() }
    }

    /// Parse `name=IP@host` or `IP@host`, for configuration and the CLI.
    pub fn parse(s: &str) -> Result<Self, crate::Error> {
        let (name, rest) = match s.split_once('=') {
            Some((n, r)) => (n.to_string(), r),
            None => (String::new(), s),
        };
        let (ip, host) = rest
            .split_once('@')
            .ok_or_else(|| crate::Error::Invalid(format!("DoH server {s:?}: expected [name=]IP@hostname")))?;
        let ip: IpAddr = ip.parse().map_err(|_| crate::Error::Invalid(format!("DoH server {s:?}: bad IP")))?;
        if host.is_empty() || host.contains('/') {
            return Err(crate::Error::Invalid(format!("DoH server {s:?}: bad hostname")));
        }
        Ok(Self { name: if name.is_empty() { host.to_string() } else { name }, ip, host: host.into() })
    }
}

/// Quad9, Mullvad and Cloudflare: no client-subnet forwarding from the first two, all three speak HTTP/2 DoH.
pub fn default_servers() -> Vec<DohServer> {
    vec![
        DohServer::new("quad9", "9.9.9.9", "dns.quad9.net"),
        DohServer::new("mullvad", "194.242.2.2", "dns.mullvad.net"),
        DohServer::new("cloudflare", "1.1.1.1", "cloudflare-dns.com"),
    ]
}

/// Why a lookup failed at one resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    /// The name doesn't exist. Final: asking another resolver won't change it.
    NxDomain,
    /// The name exists but has no A record. Final.
    NoIpv4,
    /// SERVFAIL, REFUSED, a bad answer, HTTP error, timeout: worth trying the next resolver.
    Retry(String),
    /// The name can't be put in a query.
    Bad(String),
}

/// Build the query: ID 0 (RFC 8484 §4.1), recursion desired, one A question, EDNS(0) with padding to a multiple
/// of 128 bytes (RFC 8467) so the query length doesn't give the name away. No client subnet, no cookies.
pub fn build_query(host: &str) -> Result<Vec<u8>, String> {
    let mut name = Name::from_utf8(host).map_err(|e| format!("bad name {host:?}: {e}"))?;
    name.set_fqdn(true);
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, RecordType::A));
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    msg.set_edns(edns.clone());
    // 4 bytes of option header + padding.
    let unpadded = msg.to_vec().map_err(|e| e.to_string())?.len() + 4;
    let pad = (128 - unpadded % 128) % 128;
    edns.options_mut().insert(EdnsOption::Unknown(u16::from(EdnsCode::Padding), vec![0u8; pad]));
    msg.set_edns(edns);
    msg.to_vec().map_err(|e| e.to_string())
}

/// Read the IPv4 addresses and the smallest TTL out of a DoH answer.
pub fn parse_answer(bytes: &[u8]) -> Result<(Vec<Ipv4Addr>, u32), LookupError> {
    let msg = Message::from_vec(bytes).map_err(|e| LookupError::Retry(format!("malformed answer: {e}")))?;
    if msg.metadata.message_type != MessageType::Response {
        return Err(LookupError::Retry("not a response".into()));
    }
    if msg.metadata.truncation {
        return Err(LookupError::Retry("truncated answer".into()));
    }
    match msg.metadata.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => return Err(LookupError::NxDomain),
        other => return Err(LookupError::Retry(format!("resolver answered {other}"))),
    }
    let mut ips = Vec::new();
    let mut ttl = u32::MAX;
    for r in &msg.answers {
        if let RData::A(a) = &r.data {
            ips.push(a.0);
            ttl = ttl.min(r.ttl);
        }
    }
    if ips.is_empty() {
        return Err(LookupError::NoIpv4);
    }
    Ok((ips, ttl))
}

/// A small TTL cache, so a wallet that reconnects every few seconds doesn't send a lookup each time.
#[derive(Default)]
pub struct Cache {
    map: std::sync::Mutex<HashMap<String, (Vec<Ipv4Addr>, Instant)>>,
}

/// Cached answers live for their TTL, clamped to 30 s .. 1 h.
pub const MIN_TTL: Duration = Duration::from_secs(30);
pub const MAX_TTL: Duration = Duration::from_secs(3600);

impl Cache {
    pub fn get(&self, host: &str, now: Instant) -> Option<Vec<Ipv4Addr>> {
        let mut m = self.map.lock().unwrap();
        match m.get(&host.to_ascii_lowercase()) {
            Some((ips, exp)) if *exp > now => Some(ips.clone()),
            Some(_) => {
                m.remove(&host.to_ascii_lowercase());
                None
            }
            None => None,
        }
    }
    pub fn put(&self, host: &str, ips: Vec<Ipv4Addr>, ttl: u32, now: Instant) {
        let ttl = Duration::from_secs(ttl as u64).clamp(MIN_TTL, MAX_TTL);
        self.map.lock().unwrap().insert(host.to_ascii_lowercase(), (ips, now + ttl));
    }
}

type Sender = hyper::client::conn::http2::SendRequest<Empty<Bytes>>;

/// DoH over one tunnel. Keeps one HTTP/2 connection per resolver open, so after the first lookup a new name
/// costs one round trip through the mixnet instead of TCP + TLS + HTTP/2 setup.
pub struct DohClient {
    servers: Vec<DohServer>,
    timeout: Duration,
    conns: Mutex<HashMap<usize, Sender>>,
    tls: tokio_rustls::TlsConnector,
}

impl DohClient {
    pub fn new(servers: Vec<DohServer>, timeout: Duration) -> Self {
        Self { servers, timeout, conns: Mutex::new(HashMap::new()), tls: tls::connector(&[b"h2"]) }
    }

    pub fn servers(&self) -> &[DohServer] {
        &self.servers
    }

    async fn sender(&self, tunnel: &Tunnel, idx: usize) -> Result<Sender, String> {
        if let Some(s) = self.conns.lock().await.get(&idx) {
            if !s.is_closed() {
                return Ok(s.clone());
            }
        }
        let srv = &self.servers[idx];
        let addr = SocketAddr::new(srv.ip, 443);
        let tcp = tunnel.tcp_connect(addr).await.map_err(|e| format!("TCP to {addr}: {e}"))?;
        let name = rustls::pki_types::ServerName::try_from(srv.host.clone()).map_err(|e| e.to_string())?;
        let tls = self.tls.connect(name, tcp).await.map_err(|e| format!("TLS with {}: {e}", srv.host))?;
        let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .map_err(|e| format!("HTTP/2 with {}: {e}", srv.host))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        self.conns.lock().await.insert(idx, sender.clone());
        Ok(sender)
    }

    /// Health probe: one uncached lookup of `name`, at most `max_servers` resolvers, each bounded by `each`.
    /// A tunnel that completed the IPR handshake can still drop every packet after it (seen live); this is how
    /// that gets noticed in seconds instead of on the user's first real connection.
    pub async fn probe(&self, tunnel: &Tunnel, name: &str, max_servers: usize, each: Duration) -> Result<String, String> {
        let query = build_query(name)?;
        let mut errors = vec![];
        for idx in 0..self.servers.len().min(max_servers.max(1)) {
            let srv = &self.servers[idx];
            match tokio::time::timeout(each, self.ask(tunnel, idx, &query)).await {
                Ok(Ok(_)) => return Ok(srv.name.clone()),
                Ok(Err(e)) => errors.push(format!("{}: {e:?}", srv.name)),
                Err(_) => errors.push(format!("{}: no answer within {each:?}", srv.name)),
            }
            self.conns.lock().await.remove(&idx);
        }
        Err(errors.join("; "))
    }

    /// Open (or reuse) the connection to resolver `idx`. Used as the tunnel's health check: a TCP handshake,
    /// a TLS handshake and an HTTP/2 handshake through the exit, and it leaves DNS warm.
    pub async fn warm(&self, tunnel: &Tunnel, idx: usize) -> Result<(), String> {
        tokio::time::timeout(self.timeout, self.sender(tunnel, idx))
            .await
            .map_err(|_| format!("no answer within {:?}", self.timeout))?
            .map(|_| ())
    }

    async fn ask(&self, tunnel: &Tunnel, idx: usize, query: &[u8]) -> Result<(Vec<Ipv4Addr>, u32), LookupError> {
        let srv = &self.servers[idx];
        let mut sender = self.sender(tunnel, idx).await.map_err(LookupError::Retry)?;
        let q = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(query);
        let req = hyper::Request::get(format!("https://{}/dns-query?dns={q}", srv.host))
            .header(hyper::header::ACCEPT, "application/dns-message")
            .body(Empty::<Bytes>::new())
            .map_err(|e| LookupError::Retry(e.to_string()))?;
        sender.ready().await.map_err(|e| LookupError::Retry(e.to_string()))?;
        let resp = sender.send_request(req).await.map_err(|e| LookupError::Retry(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(LookupError::Retry(format!("HTTP {}", resp.status())));
        }
        let body = resp.into_body().collect().await.map_err(|e| LookupError::Retry(e.to_string()))?.to_bytes();
        parse_answer(&body)
    }

    /// Resolve `host` to IPv4 addresses, trying the resolvers in order (starting at `first`).
    /// Returns the addresses, their TTL and the name of the resolver that answered. `Retry` means every
    /// resolver failed, which points at the tunnel rather than the name.
    pub async fn resolve(
        &self,
        tunnel: &Tunnel,
        host: &str,
        first: usize,
    ) -> Result<(Vec<Ipv4Addr>, u32, String), LookupError> {
        let query = build_query(host).map_err(LookupError::Bad)?;
        let n = self.servers.len();
        let mut errors = Vec::new();
        for k in 0..n {
            let idx = (first + k) % n;
            let srv = &self.servers[idx];
            match tokio::time::timeout(self.timeout, self.ask(tunnel, idx, &query)).await {
                Ok(Ok((ips, ttl))) => return Ok((ips, ttl, srv.name.clone())),
                Ok(Err(LookupError::Retry(e))) => {
                    tracing::warn!("DoH {}: {e}; trying the next resolver", srv.name);
                    self.conns.lock().await.remove(&idx);
                    errors.push(format!("{}: {e}", srv.name));
                }
                Ok(Err(final_answer)) => return Err(final_answer),
                Err(_) => {
                    tracing::warn!("DoH {}: no answer within {:?}; trying the next resolver", srv.name, self.timeout);
                    self.conns.lock().await.remove(&idx);
                    errors.push(format!("{}: no answer within {:?}", srv.name, self.timeout));
                }
            }
        }
        Err(LookupError::Retry(errors.join("; ")))
    }
}

/// Shared handle type.
pub type SharedDoh = Arc<DohClient>;

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::Record;

    #[test]
    fn query_is_padded_id0_and_asks_for_a() {
        for host in ["a.io", "electrum.blockstream.info", "x.y.z.very-long-label-for-padding-test.example.org"] {
            let q = build_query(host).unwrap();
            assert_eq!(q.len() % 128, 0, "{host}: {} bytes", q.len());
            let m = Message::from_vec(&q).unwrap();
            assert_eq!(m.metadata.id, 0);
            assert!(m.metadata.recursion_desired);
            assert_eq!(m.queries.len(), 1);
            assert_eq!(m.queries[0].query_type(), RecordType::A);
            assert_eq!(m.queries[0].name().to_utf8(), format!("{host}."));
            let opts = m.edns.as_ref().unwrap().options();
            assert!(opts.as_ref().iter().all(|(c, _)| *c == EdnsCode::Padding), "only padding, no ECS/cookie");
        }
        assert!(build_query("bad..name").is_err());
    }

    fn response(rcode: ResponseCode, answers: Vec<Record>) -> Vec<u8> {
        let mut m = Message::new(0, MessageType::Response, OpCode::Query);
        m.metadata.response_code = rcode;
        m.add_query(Query::query(Name::from_utf8("example.org.").unwrap(), RecordType::A));
        for a in answers {
            m.add_answer(a);
        }
        m.to_vec().unwrap()
    }

    #[test]
    fn parses_answers_and_follows_cname_records() {
        let n = Name::from_utf8("example.org.").unwrap();
        let c = Name::from_utf8("cdn.example.net.").unwrap();
        let bytes = response(
            ResponseCode::NoError,
            vec![
                Record::from_rdata(n, 300, RData::CNAME(CNAME(c.clone()))),
                Record::from_rdata(c.clone(), 60, RData::A(A::new(192, 0, 2, 1))),
                Record::from_rdata(c, 120, RData::A(A::new(192, 0, 2, 2))),
            ],
        );
        let (ips, ttl) = parse_answer(&bytes).unwrap();
        assert_eq!(ips, vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]);
        assert_eq!(ttl, 60);
    }

    #[test]
    fn classifies_failures() {
        assert_eq!(parse_answer(&response(ResponseCode::NXDomain, vec![])), Err(LookupError::NxDomain));
        assert_eq!(parse_answer(&response(ResponseCode::NoError, vec![])), Err(LookupError::NoIpv4));
        assert!(matches!(parse_answer(&response(ResponseCode::ServFail, vec![])), Err(LookupError::Retry(_))));
        assert!(matches!(parse_answer(b"\x00\x01garbage"), Err(LookupError::Retry(_))));
        // a query echoed back is not an answer
        assert!(matches!(parse_answer(&build_query("example.org").unwrap()), Err(LookupError::Retry(_))));
    }

    #[test]
    fn cache_respects_ttl_with_clamps() {
        let c = Cache::default();
        let t0 = Instant::now();
        c.put("Example.ORG", vec![Ipv4Addr::LOCALHOST], 5, t0); // clamped up to 30 s
        assert!(c.get("example.org", t0 + Duration::from_secs(29)).is_some());
        assert!(c.get("example.org", t0 + Duration::from_secs(31)).is_none());
        c.put("big.example", vec![Ipv4Addr::LOCALHOST], 86_400, t0); // clamped down to 1 h
        assert!(c.get("big.example", t0 + Duration::from_secs(3599)).is_some());
        assert!(c.get("big.example", t0 + Duration::from_secs(3601)).is_none());
    }

    #[test]
    fn server_spec_parsing() {
        assert_eq!(DohServer::parse("q=9.9.9.9@dns.quad9.net").unwrap(), DohServer::new("q", "9.9.9.9", "dns.quad9.net"));
        assert_eq!(DohServer::parse("1.1.1.1@cloudflare-dns.com").unwrap().name, "cloudflare-dns.com");
        assert!(DohServer::parse("dns.quad9.net").is_err());
        assert!(DohServer::parse("x=notanip@h").is_err());
        assert!(DohServer::parse("1.1.1.1@https://x/").is_err());
    }
}
