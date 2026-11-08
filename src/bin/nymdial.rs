//! nymdial: try the library from a shell.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use nymdial::{exits, Config, Dialer, Error};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "nymdial", version, about = "TCP and TLS through the Nym mixnet, in-process (no nym-socks5-client)")]
struct Cli {
    #[command(flatten)]
    opts: Opts,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Opts {
    /// Try this exit first (node id or IPR address); repeat for more.
    #[arg(long = "exit", global = true)]
    exits: Vec<String>,
    /// Use only the --exit exits.
    #[arg(long, global = true)]
    pinned_only: bool,
    /// Only exits in this country (ISO alpha-2); repeat for more.
    #[arg(long = "country", global = true)]
    countries: Vec<String>,
    /// Skip exits below this directory performance (0-1).
    #[arg(long, global = true, default_value_t = 0.0)]
    min_performance: f64,
    /// Put a dead exit first (a real IPR client address on a gateway it isn't registered at), to watch failover.
    #[arg(long, global = true)]
    dead_first: bool,
    /// Seconds one exit gets to come up (mixnet client, IPR handshake, health check).
    #[arg(long, global = true, default_value_t = 45)]
    attempt_timeout: u64,
    /// Seconds per resolver for the health check on a new tunnel (two resolvers at most).
    #[arg(long, global = true, default_value_t = 12)]
    health_timeout: u64,
    /// Probe a tunnel that has been quiet this many seconds before the next connect (0 = off).
    #[arg(long, global = true, default_value_t = 10)]
    liveness_after: u64,
    /// DoH resolver as [name=]IP@hostname; repeat to replace the defaults (quad9, mullvad, cloudflare).
    #[arg(long = "doh", global = true)]
    doh: Vec<String>,
    /// nym-api URL.
    #[arg(long, global = true, default_value = exits::DEFAULT_NYM_API)]
    nym_api: String,
    /// Log level for nymdial (nym-sdk logs at warn unless RUST_LOG says otherwise).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the IPR exits the nym-api offers, best first.
    Exits {
        #[arg(long)]
        json: bool,
    },
    /// Fetch an IP-echo page through the mixnet and show which Nym node the server saw.
    Whoami {
        /// Page that answers with the caller's IP (Cloudflare's trace format or plain text/JSON with the IP).
        #[arg(long, default_value = "https://cloudflare.com/cdn-cgi/trace")]
        url: String,
        /// Then move to another exit and ask again.
        #[arg(long)]
        rotate: bool,
    },
    /// HTTP GET a URL through the mixnet; body to stdout, timings to stderr.
    Get { url: String },
    /// Resolve names through the mixnet (DoH via the exit).
    Resolve { names: Vec<String> },
    /// Pipe stdin/stdout to HOST:PORT through the mixnet. Exits when the server closes the stream.
    Connect {
        host: String,
        port: u16,
        #[arg(long)]
        tls: bool,
        /// Also write one JSON object per line to stderr: each exit attempt, then `connected` (with the exit's
        /// node id, country and IPs) once the stream is open, or `error`. For programs that drive nymdial as a
        /// child process (mixpool, zecmix): wait for `connected`, then talk over stdin/stdout.
        #[arg(long)]
        events: bool,
    },
    /// Repeat an HTTPS GET N times on one tunnel and print the timings.
    Bench {
        url: String,
        #[arg(short, default_value_t = 5)]
        n: usize,
        /// Seconds to wait between requests (to see how long one tunnel lasts).
        #[arg(long, default_value_t = 0)]
        interval: u64,
    },
    /// Failover drill: whoami, then kill the tunnel underneath the dialer, then whoami again.
    #[command(hide = true)]
    Drill {
        #[arg(long, default_value = "https://cloudflare.com/cdn-cgi/trace")]
        url: String,
    },
    /// The same IP check through nym-sdk's in-process SOCKS5 client (network requester path), for comparison.
    WhoamiNr {
        /// IPv4-only echo by default: an NR exit may connect over IPv6 from an address the nym-api doesn't list.
        #[arg(long, default_value = "https://api.ipify.org/?format=json")]
        url: String,
        /// Requests on the same client.
        #[arg(short, default_value_t = 1)]
        n: usize,
        /// Seconds between requests.
        #[arg(long, default_value_t = 0)]
        interval: u64,
    },
}

fn secs(d: Duration) -> String {
    format!("{:.2}s", d.as_secs_f64())
}

struct Url {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(u: &str) -> Result<Url, Error> {
    let (https, rest) = if let Some(r) = u.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = u.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(Error::Invalid(format!("{u}: want http:// or https://")));
    };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => {
            (h.to_string(), p.parse().map_err(|_| Error::Invalid(format!("{u}: bad port")))?)
        }
        _ => (hostport.to_string(), if https { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(Error::Invalid(format!("{u}: no host")));
    }
    Ok(Url { https, host, port, path: path.to_string() })
}

async fn http_get<S>(stream: S, url: &Url) -> Result<(u16, Bytes), Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let e = |x: hyper::Error| Error::Connect { addr: SocketAddr::from(([0, 0, 0, 0], url.port)), reason: format!("HTTP: {x}") };
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(e)?;
    tokio::spawn(conn);
    let host = if (url.https && url.port == 443) || (!url.https && url.port == 80) {
        url.host.clone()
    } else {
        format!("{}:{}", url.host, url.port)
    };
    let req = hyper::Request::get(&url.path)
        .header("Host", host)
        .header("User-Agent", "nymdial")
        .header("Accept", "*/*")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .map_err(|x| Error::Invalid(x.to_string()))?;
    let resp = sender.send_request(req).await.map_err(e)?;
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.map_err(e)?.to_bytes();
    Ok((status, body))
}

/// Budget for the HTTP exchange once the connection is up. Streams have no read timeout of their own: on a
/// tunnel that stalls mid-request, a read would otherwise wait forever.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

async fn http_get_bounded<S>(stream: S, url: &Url) -> Result<(u16, Bytes), Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::time::timeout(HTTP_TIMEOUT, http_get(stream, url)).await.unwrap_or_else(|_| {
        Err(Error::Connect {
            addr: SocketAddr::from(([0, 0, 0, 0], url.port)),
            reason: format!("HTTP: no complete response within {HTTP_TIMEOUT:?} (tunnel stalled mid-request?)"),
        })
    })
}

async fn fetch(d: &Dialer, url: &Url) -> Result<(u16, Bytes, Duration, Duration), Error> {
    let t = Instant::now();
    let (status, body, connected) = if url.https {
        let s = d.connect_tls(&url.host, url.port).await?;
        let c = t.elapsed();
        let (st, b) = http_get_bounded(s, url).await?;
        (st, b, c)
    } else {
        let s = d.connect(&url.host, url.port).await?;
        let c = t.elapsed();
        let (st, b) = http_get_bounded(s, url).await?;
        (st, b, c)
    };
    Ok((status, body, connected, t.elapsed() - connected))
}

/// Pull the caller IP out of a trace/echo page.
fn find_ip(body: &str) -> Option<IpAddr> {
    if let Some(l) = body.lines().find(|l| l.starts_with("ip=")) {
        return l[3..].trim().parse().ok();
    }
    body.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
        .filter(|t| t.len() >= 7)
        .find_map(|t| t.parse::<IpAddr>().ok())
}

async fn show_ip(api: &str, ip: Option<IpAddr>) {
    let Some(ip) = ip else {
        println!("  (no IP found in the answer)");
        return;
    };
    let described = match exits::fetch_raw(api, Duration::from_secs(30)).await {
        Ok((_, d)) => exits::parse_described(&d).ok(),
        Err(_) => None,
    };
    match described.as_ref().and_then(|d| exits::node_for_ip(d, ip)) {
        Some((id, c)) => println!("  the server saw {ip} = Nym node {id} ({}) in the nym-api node list", c.unwrap_or("?".into())),
        None => println!("  the server saw {ip}: NOT a Nym node in the nym-api list"),
    }
}

fn config(o: &Opts) -> Result<Config, Error> {
    let mut c = Config {
        nym_api: o.nym_api.clone(),
        exits: o.exits.clone(),
        pinned_only: o.pinned_only,
        attempt_timeout: Duration::from_secs(o.attempt_timeout),
        health_timeout: Duration::from_secs(o.health_timeout),
        liveness_after: (o.liveness_after > 0).then(|| Duration::from_secs(o.liveness_after)),
        ..Default::default()
    };
    c.selection.countries = o.countries.clone();
    c.selection.min_performance = o.min_performance;
    if !o.doh.is_empty() {
        c.doh = o.doh.iter().map(|s| nymdial::dns::DohServer::parse(s)).collect::<Result<_, _>>()?;
    }
    Ok(c)
}

/// A live client address on a gateway that doesn't host it: packets to it are dropped, so the IPR handshake
/// never gets an answer. Made from two real directory entries.
async fn dead_exit(api: &str) -> Result<String, Error> {
    let list = exits::fetch(api, Duration::from_secs(30)).await?;
    if list.len() < 2 {
        return Err(Error::NoExit("need two exits to build a dead one".into()));
    }
    let client = list[0].ipr_address.split('@').next().unwrap();
    Ok(format!("{client}@{}", list[1].identity))
}

async fn dial(o: &Opts) -> Result<Dialer, Error> {
    let mut cfg = config(o)?;
    if o.dead_first {
        let dead = dead_exit(&cfg.nym_api).await?;
        eprintln!("forcing a dead exit first: {}...@{}", &dead[..12], dead.split('@').nth(1).unwrap());
        cfg.exits.insert(0, dead);
    }
    let t = Instant::now();
    let d = Dialer::start(cfg).await?;
    for a in d.attempts().await {
        match &a.error {
            Some(e) => eprintln!("  exit {:<24} failed after {}: {e}", a.label, secs(a.elapsed)),
            None => eprintln!("  exit {:<24} up after {} (incl. health check)", a.label, secs(a.elapsed)),
        }
    }
    let info = d.exit().expect("connected");
    eprintln!(
        "tunnel up via {} [{}] in {} (tunnel IP {})",
        info.exit.label(),
        info.exit.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "),
        secs(t.elapsed()),
        info.tunnel_ipv4
    );
    Ok(d)
}

async fn run(cli: Cli) -> Result<(), Error> {
    let o = &cli.opts;
    match &cli.cmd {
        Cmd::Exits { json } => {
            let list = exits::fetch(&o.nym_api, Duration::from_secs(30)).await?;
            let sel = config(o)?.selection;
            let ordered = exits::order(&list, &sel, &mut rand::thread_rng());
            if *json {
                println!("{}", serde_json::to_string_pretty(&ordered).unwrap());
            } else {
                println!("{} IPR exits in the directory, {} after filters (random order, weighted by performance):", list.len(), ordered.len());
                use std::io::Write;
                let mut out = std::io::stdout().lock();
                for e in &ordered {
                    let ip = e.ips.iter().find(|i| i.is_ipv4()).map(|i| i.to_string()).unwrap_or_default();
                    let line = format!("  {:>5}  {:<3} perf {:.2}  v{:<8} {:<16} {}", e.node_id, e.country.as_deref().unwrap_or("-"), e.performance, e.version, ip, e.identity);
                    if writeln!(out, "{line}").is_err() {
                        break; // reader went away (| head)
                    }
                }
            }
        }
        Cmd::Whoami { url, rotate } => {
            let url = parse_url(url)?;
            let d = dial(o).await?;
            for round in 0..(if *rotate { 2 } else { 1 }) {
                if round == 1 {
                    let t = Instant::now();
                    let info = d.rotate().await?;
                    eprintln!("rotated to {} in {}", info.exit.label(), secs(t.elapsed()));
                }
                let (status, body, conn, req) = fetch(&d, &url).await?;
                let info = d.exit().unwrap();
                println!(
                    "GET https://{}{} -> HTTP {status} via exit {} (DNS+TCP+TLS {}, request {})",
                    url.host, url.path, info.exit.label(), secs(conn), secs(req)
                );
                show_ip(&o.nym_api, find_ip(&String::from_utf8_lossy(&body))).await;
            }
            d.shutdown().await;
        }
        Cmd::Get { url } => {
            let url = parse_url(url)?;
            let d = dial(o).await?;
            let (status, body, conn, req) = fetch(&d, &url).await?;
            eprintln!("HTTP {status}, {} bytes (DNS+connect{} {}, request {})", body.len(), if url.https { "+TLS" } else { "" }, secs(conn), secs(req));
            tokio::io::stdout().write_all(&body).await.ok();
            d.shutdown().await;
        }
        Cmd::Resolve { names } => {
            let d = dial(o).await?;
            for n in names {
                let t = Instant::now();
                match d.resolve(n).await {
                    Ok(ips) => println!("{n}\t{}\t({})", ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(" "), secs(t.elapsed())),
                    Err(e) => println!("{n}\t{e}\t({})", secs(t.elapsed())),
                }
            }
            d.shutdown().await;
        }
        Cmd::Connect { host, port, tls, events } => {
            let r = connect_cmd(o, host, *port, *tls, *events).await;
            if let Err(e) = &r {
                if *events {
                    emit(&error_event(e));
                }
            }
            r?;
            // stdin is read on a blocking thread that can't be cancelled; don't let it hold the process open
            // after the server has closed the stream.
            std::process::exit(0);
        }
        Cmd::Bench { url, n, interval } => {
            let url = parse_url(url)?;
            let d = dial(o).await?;
            let mut totals = vec![];
            let t0 = Instant::now();
            for i in 0..*n {
                if i > 0 && *interval > 0 {
                    tokio::time::sleep(Duration::from_secs(*interval)).await;
                }
                let t = Instant::now();
                eprint!("[+{:>5.0}s, exit {}] ", t0.elapsed().as_secs_f64(), d.exit().map(|x| x.exit.label()).unwrap_or_default());
                match fetch(&d, &url).await {
                    Ok((status, body, conn, req)) => {
                        println!("{:>3}  HTTP {status}  {:>7} B  connect {}  request {}  total {}", i + 1, body.len(), secs(conn), secs(req), secs(t.elapsed()));
                        totals.push(t.elapsed().as_secs_f64());
                    }
                    Err(e) => println!("{:>3}  error after {}: {e}", i + 1, secs(t.elapsed())),
                }
            }
            if !totals.is_empty() {
                totals.sort_by(|a, b| a.partial_cmp(b).unwrap());
                println!("ok {}/{}  median {:.2}s  min {:.2}s  max {:.2}s", totals.len(), n, totals[totals.len() / 2], totals[0], totals[totals.len() - 1]);
            }
            d.shutdown().await;
        }
        Cmd::Drill { url } => {
            let url = parse_url(url)?;
            let d = dial(o).await?;
            for round in 0..2 {
                if round == 1 {
                    eprintln!("killing the tunnel through {} underneath the dialer", d.exit().unwrap().exit.label());
                    d.drop_tunnel_for_test().await;
                }
                let t = Instant::now();
                match fetch(&d, &url).await {
                    Ok((status, body, conn, req)) => {
                        let info = d.exit().unwrap();
                        println!(
                            "GET {} -> HTTP {status} via exit {} (tunnel #{}; call took {}: DNS+TCP+TLS {}, request {})",
                            url.host, info.exit.label(), info.generation, secs(t.elapsed()), secs(conn), secs(req)
                        );
                        show_ip(&o.nym_api, find_ip(&String::from_utf8_lossy(&body))).await;
                    }
                    Err(e) => println!("GET {} failed after {}: {e}", url.host, secs(t.elapsed())),
                }
            }
            for a in d.attempts().await {
                eprintln!("  attempt: {} {} {}", a.label, secs(a.elapsed), a.error.as_deref().unwrap_or("ok"));
            }
            d.shutdown().await;
        }
        Cmd::WhoamiNr { url, n, interval } => {
            let url = parse_url(url)?;
            whoami_nr(o, &url, *n, *interval).await?;
        }
    }
    Ok(())
}

/// One status line on stderr (JSON, for programs driving `nymdial connect --events`).
fn emit(v: &serde_json::Value) {
    use std::io::Write;
    let mut e = std::io::stderr().lock();
    let _ = writeln!(e, "{v}");
    let _ = e.flush();
}

fn attempt_event(a: &nymdial::rotate::Attempt) -> serde_json::Value {
    serde_json::json!({
        "event": "attempt",
        "node_id": a.node_id,
        "label": a.label,
        "elapsed_s": a.elapsed.as_secs_f64(),
        "ok": a.error.is_none(),
        "error": a.error,
    })
}

fn connected_event(info: &nymdial::ExitInfo, host: &str, port: u16, tls: bool, tunnel: Duration, connect: Duration) -> serde_json::Value {
    serde_json::json!({
        "event": "connected",
        "host": host,
        "port": port,
        "tls": tls,
        "exit": {
            "node_id": info.exit.node_id,
            "country": info.exit.country,
            "identity": info.exit.identity,
            "version": info.exit.version,
            "ips": info.exit.ips,
            "label": info.exit.label(),
        },
        "generation": info.generation,
        "tunnel_s": tunnel.as_secs_f64(),
        "connect_s": connect.as_secs_f64(),
    })
}

fn error_event(e: &Error) -> serde_json::Value {
    let step = match e {
        Error::Directory(_) => "directory",
        Error::NoExit(_) | Error::ExitsExhausted { .. } => "exit",
        Error::Dns { .. } | Error::NoIpv4(_) => "dns",
        Error::ConnectTimeout { .. } | Error::Connect { .. } => "tcp",
        Error::Tls { .. } => "tls",
        Error::Invalid(_) => "input",
    };
    serde_json::json!({ "event": "error", "step": step, "message": e.to_string() })
}

/// Copy `input` to `stream` and `stream` to `output` until the server closes the stream. When `input` ends
/// first, the write side is shut down (TCP FIN / TLS close_notify) and the answer is still read to the end.
/// Returns the bytes sent (`None` if the input was still open) and received.
async fn pipe<S, I, O>(stream: S, mut input: I, mut output: O) -> (Option<u64>, u64)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    I: AsyncRead + Unpin + Send + 'static,
    O: AsyncWrite + Unpin,
{
    let (mut r, mut w) = tokio::io::split(stream);
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    let up = tokio::spawn(async move {
        let n = tokio::io::copy(&mut input, &mut w).await.unwrap_or(0);
        let _ = tx.send(n);
        let _ = w.shutdown().await;
    });
    let down = tokio::io::copy(&mut r, &mut output).await.unwrap_or(0);
    let _ = output.flush().await;
    let sent = rx.try_recv().ok();
    up.abort();
    (sent, down)
}

async fn connect_cmd(o: &Opts, host: &str, port: u16, tls: bool, events: bool) -> Result<(), Error> {
    let t = Instant::now();
    let d = dial(o).await;
    if events {
        // A failed dial has no Dialer to ask; its error carries the attempt count instead.
        if let Ok(d) = &d {
            for a in d.attempts().await {
                emit(&attempt_event(&a));
            }
        }
    }
    let d = d?;
    let tunnel = t.elapsed();
    let t2 = Instant::now();
    let (stdin, stdout) = (tokio::io::stdin(), tokio::io::stdout());
    let r = if tls {
        d.connect_tls(host, port).await.map(|s| Box::new(s) as Box<dyn Stream>)
    } else {
        d.connect(host, port).await.map(|s| Box::new(s) as Box<dyn Stream>)
    };
    let s = match r {
        Ok(s) => s,
        Err(e) => {
            d.shutdown().await;
            return Err(e);
        }
    };
    let info = d.exit().expect("connected");
    if events {
        emit(&connected_event(&info, host, port, tls, tunnel, t2.elapsed()));
    }
    eprintln!("connected to {host}:{port}{} via exit {} in {}", if tls { " (TLS)" } else { "" }, info.exit.label(), secs(t.elapsed()));
    let (sent, recvd) = pipe(s, stdin, stdout).await;
    match sent {
        Some(n) => eprintln!("closed by the server: {n} bytes sent, {recvd} received"),
        None => eprintln!("closed by the server: {recvd} bytes received (input still open)"),
    }
    d.shutdown().await;
    Ok(())
}

trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

/// SOCKS5 CONNECT with a domain name (resolved at the network requester), minimal client.
async fn socks5_connect(proxy: SocketAddr, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
    // Socks5MixnetClient::connect_with returns before its listener is bound; wait for it (up to 30 s).
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut s = loop {
        match tokio::net::TcpStream::connect(proxy).await {
            Ok(s) => break s,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await
            }
            Err(e) => return Err(e),
        }
    };
    s.write_all(&[5, 1, 0]).await?;
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await?;
    if b != [5, 0] {
        return Err(std::io::Error::other(format!("SOCKS5 greeting refused: {b:?}")));
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await?;
    if h[1] != 0 {
        return Err(std::io::Error::other(format!("SOCKS5 CONNECT failed, reply code {}", h[1])));
    }
    let skip = match h[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        _ => return Err(std::io::Error::other("bad SOCKS5 reply")),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).await?;
    Ok(s)
}

async fn whoami_nr(o: &Opts, url: &Url, n: usize, interval: u64) -> Result<(), Error> {
    use nym_sdk::mixnet::{NetworkRequesterSelector, Socks5MixnetClient};
    let sel = if o.countries.is_empty() {
        NetworkRequesterSelector::any()
    } else {
        NetworkRequesterSelector::in_countries(&o.countries).map_err(|e| Error::Invalid(e.to_string()))?
    };
    let bind: SocketAddr = "127.0.0.1:11080".parse().unwrap();
    let t = Instant::now();
    let client = Socks5MixnetClient::connect_with(sel, Some(bind))
        .await
        .map_err(|e| Error::NoExit(format!("nym-sdk SOCKS5 client: {e}")))?;
    let setup = t.elapsed();
    eprintln!("nym-sdk Socks5MixnetClient up in {} (SOCKS5 on {bind})", secs(setup));
    let t0 = Instant::now();
    for i in 0..n.max(1) {
    if i > 0 && interval > 0 {
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
    eprint!("[+{:>5.0}s] ", t0.elapsed().as_secs_f64());
    let t = Instant::now();
    let r = async {
        let tcp = socks5_connect(bind, &url.host, url.port)
            .await
            .map_err(|e| Error::Connect { addr: bind, reason: e.to_string() })?;
        let c = t.elapsed();
        let name = rustls::pki_types::ServerName::try_from(url.host.clone()).map_err(|e| Error::Invalid(e.to_string()))?;
        let tls = nymdial::tls::connector(&[])
            .connect(name, tcp)
            .await
            .map_err(|e| Error::Tls { host: url.host.clone(), reason: e.to_string() })?;
        let c2 = t.elapsed();
        let (status, body) = http_get_bounded(tls, url).await?;
        Ok::<_, Error>((status, body, c, c2))
    };
    let r = tokio::time::timeout(Duration::from_secs(120), r).await;
    match r {
        Ok(Ok((status, body, c, c2))) => {
            println!(
                "GET https://{}{} -> HTTP {status} via network requester (SOCKS5 CONNECT {}, +TLS {}, total {})",
                url.host, url.path, secs(c), secs(c2), secs(t.elapsed())
            );
            show_ip(&o.nym_api, find_ip(&String::from_utf8_lossy(&body))).await;
        }
        Ok(Err(e)) => println!("network requester path failed after {}: {e}", secs(t.elapsed())),
        Err(_) => println!("network requester path: no answer within 120 s"),
    }
    }
    client.disconnect().await;
    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        match cli.opts.verbose {
            0 => "nymdial=warn,error",
            1 => "nymdial=info,nym_sdk::mixnet::socks5_discovery=info,warn",
            _ => "nymdial=debug,info",
        }
        .into()
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_writer(std::io::stderr)
        .init();
    if let Err(e) = run(cli).await {
        eprintln!("nymdial: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("https://blockstream.info/api/blocks/tip/height").unwrap();
        assert!(u.https && u.host == "blockstream.info" && u.port == 443 && u.path == "/api/blocks/tip/height");
        let u = parse_url("http://example.org:8080").unwrap();
        assert!(!u.https && u.port == 8080 && u.path == "/");
        assert!(parse_url("ftp://x").is_err());
        assert!(parse_url("https://").is_err());
    }

    #[tokio::test]
    async fn pipe_sends_input_and_returns_on_server_close() {
        let (client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move {
            let mut req = vec![0u8; 5];
            server.read_exact(&mut req).await.unwrap();
            server.write_all(b"pong:").await.unwrap();
            server.write_all(&req).await.unwrap();
            // server closes; the client's input is still open
        });
        let (input, mut feed) = tokio::io::duplex(64);
        feed.write_all(b"hello").await.unwrap(); // `feed` stays open, like stdin of a live parent
        let mut out = Vec::new();
        let (_, recvd) = tokio::time::timeout(Duration::from_secs(5), pipe(client, input, &mut out)).await.expect("pipe must end when the server closes");
        srv.await.unwrap();
        assert_eq!(out, b"pong:hello");
        assert_eq!(recvd, 10);
        drop(feed);
    }

    #[tokio::test]
    async fn pipe_half_closes_when_input_ends() {
        let (client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move {
            let mut req = Vec::new();
            server.read_to_end(&mut req).await.unwrap(); // only ends if the client shut its write side
            server.write_all(&req).await.unwrap();
        });
        let mut out = Vec::new();
        let (sent, _) = tokio::time::timeout(Duration::from_secs(5), pipe(client, &b"GET / HTTP/1.0\r\n\r\n"[..], &mut out)).await.unwrap();
        srv.await.unwrap();
        assert_eq!(out, b"GET / HTTP/1.0\r\n\r\n");
        assert_eq!(sent, Some(18));
    }

    #[test]
    fn events_are_one_line_json_with_the_exit() {
        let exit = exits::Exit {
            node_id: 2205,
            identity: "GwId".into(),
            ipr_address: "a.b@GwId".into(),
            performance: 1.0,
            version: "1.30.0".into(),
            country: Some("FR".into()),
            ips: vec!["192.0.2.7".parse().unwrap()],
        };
        let info = nymdial::ExitInfo { exit, tunnel_ipv4: "10.0.0.2".parse().unwrap(), setup: Duration::from_secs(5), generation: 1 };
        let v = connected_event(&info, "mempool.space", 443, false, Duration::from_millis(5250), Duration::from_millis(1500));
        let line = v.to_string();
        assert!(!line.contains('\n'));
        assert_eq!(v["event"], "connected");
        assert_eq!(v["exit"]["node_id"], 2205);
        assert_eq!(v["exit"]["country"], "FR");
        assert_eq!(v["exit"]["ips"][0], "192.0.2.7");
        assert_eq!(v["tunnel_s"], 5.25);
        let e = error_event(&Error::Dns { host: "x".into(), reason: "no answer".into() });
        assert_eq!((e["event"].as_str(), e["step"].as_str()), (Some("error"), Some("dns")));
        let e = error_event(&Error::ExitsExhausted { attempts: 3, last: "timeout".into() });
        assert_eq!(e["step"], "exit");
    }

    #[test]
    fn finds_the_ip() {
        assert_eq!(find_ip("fl=1\nh=cloudflare.com\nip=57.131.24.48\nts=1\n"), Some("57.131.24.48".parse().unwrap()));
        assert_eq!(find_ip("{\"ip\":\"85.113.71.124\"}"), Some("85.113.71.124".parse().unwrap()));
        assert_eq!(find_ip("no address here"), None);
    }
}
