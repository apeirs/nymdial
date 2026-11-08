# nymdial

Open TCP and TLS connections through the [Nym mixnet](https://nym.com) from inside your own process. There is no
`nym-socks5-client` to install, init and keep running, and no local proxy port that any program on the machine
could use. A Rust crate plus a small CLI, MIT.

```
nymdial exits                      # the IP Packet Router exits the nym-api offers right now
nymdial whoami                     # fetch an IP-echo page through the mixnet, show which Nym node the server saw
nymdial get https://blockstream.info/api/blocks/tip/height
nymdial resolve electrum.blockstream.info mempool.space
nymdial connect electrum.blockstream.info 50002 --tls     # stdin/stdout pipe, e.g. Electrum JSON-RPC
nymdial --dead-first whoami        # put a dead exit first and watch it fail over
```

```rust
let dialer = nymdial::Dialer::start(nymdial::Config::default()).await?;
let stream = dialer.connect_tls("blockstream.info", 443).await?;   // tokio AsyncRead + AsyncWrite
```

> **Status, 2026-11-08: works, but the IPR path is not reliable enough for a wallet yet.** Every success below
> was a real mainnet stream, and every exit IP checked out as a Nym node. But in my runs, most new IPR tunnels
> (nym-sdk / nym-smolmix 1.21.6) complete the handshake and then carry no traffic. The ones that work stop
> receiving after a few seconds to about a minute. nymdial's health check and failover hide this, at the cost
> of long waits. Details and numbers are in "Proof it works" and "Known problem". Don't ship this in a wallet
> until that is understood.

## Why

A wallet that wants its traffic on the mixnet today has two options. It can ship or require
`nym-socks5-client`: a second binary the user installs, initialises and keeps running, which listens on a
local port. Or it can link Nym's Rust crates. Nym's own [`nym-smolmix`](https://docs.rs/nym-smolmix) already
does the hard part there: a userspace TCP/IP stack (smoltcp) over an IP Packet Router (IPR) exit gateway, with a
`TcpStream` that works with tokio, rustls, hyper and tonic.

What `nym-smolmix` 1.21.6 does not do yet, and what a wallet needs before it can rely on it:

- **Names.** `tcp_connect` takes a `SocketAddr`. Resolving the host with the system resolver would hand every
  server name, with your IP, to your ISP or DNS provider. nymdial resolves names through the mixnet.
- **Exits that don't work.** `nym-smolmix` picks one exit at random, weighted by its directory score, and if
  that exit doesn't answer, setup fails after up to 75 s. In my live runs (below), 28 of 47 exits that
  completed the IPR handshake then carried no traffic at all. nymdial tries exits one after another with a short budget
  each, checks every new tunnel with a real lookup before handing it out, and moves to a new exit when a running
  tunnel stops working.
- **Timeouts.** Without them, a stalled mixnet connect waits forever. Every step in nymdial has a budget, and
  errors say which step failed.

Nym added exit rotation and DNS-over-HTTPS to the browser build of smolmix (mix-fetch) in October 2026. nymdial
is the same idea for native Rust, written so a wallet can use it as a drop-in dialer.

## Use

```toml
[dependencies]
nymdial = { git = "https://github.com/apeirs/nymdial" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

The first build compiles nym-sdk and takes a few minutes (3.5 min on a 16-thread desktop, about 630 crates).

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dialer = nymdial::Dialer::start(nymdial::Config::default()).await?;
    println!("exit: {}", dialer.exit().unwrap().exit.label());          // e.g. "node 2871 (GR)"

    let mut s = dialer.connect_tls("blockstream.info", 443).await?;
    s.write_all(b"GET /api/blocks/tip/height HTTP/1.1\r\nHost: blockstream.info\r\nConnection: close\r\n\r\n").await?;
    let mut out = String::new();
    s.read_to_string(&mut out).await?;

    dialer.shutdown().await;
    Ok(())
}
```

What you get:

| Call | Returns |
|---|---|
| `Dialer::start(Config)` | reads the exit list, brings up a tunnel on the first exit that passes the health check |
| `connect(host, port)` | `nymdial::TcpStream` (tokio `AsyncRead + AsyncWrite`); `host` is a name or an IPv4 literal |
| `connect_tls(host, port)` | rustls stream, certificate checked against `host` with the Mozilla roots (webpki-roots) |
| `connect_tls_alpn(host, port, &[b"h2"])` | the same, offering ALPN (HTTP/2, gRPC) |
| `resolve(host)` | IPv4 addresses, resolved through the mixnet |
| `rotate()` | moves to a different exit now (a fresh mixnet identity and exit, for example per broadcast) |
| `check()` | runs the health check now and fails over if it fails |
| `exit()`, `attempts()` | the exit in use (node id, country, IPs, setup time) and every exit tried so far |

Plugging the stream into other libraries:

- **HTTP (Esplora, mempool.space, block explorers):** `hyper::client::conn::http1::handshake(TokioIo::new(stream))`.
  `nymdial get` does exactly this (`src/bin/nymdial.rs`, `http_get`).
- **Electrum over TLS:** `connect_tls(host, 50002)`, then newline-delimited JSON-RPC. Many Electrum servers use
  self-signed certificates, which `connect_tls` rejects; for those, use `connect` and your own rustls config
  (pin the certificate, as Electrum clients do).
- **gRPC (lightwalletd):** `connect_tls_alpn(host, 443, &[b"h2"])` inside a tonic `Endpoint::connect_with_connector`
  service. I haven't run this recipe yet; it's the next step for zecmix.

The CLI is the reference for each pattern (`get`, `whoami`, `connect --tls`, `bench`).

## What happens on a connect

1. **Exit list.** At start, nymdial reads two documents from the nym-api (`skimmed/exit-gateways/all` and
   `nym-nodes/described`). It keeps the nodes that hold the exit role in this epoch, support the IPR, announce an
   IPR address on their own gateway, and run a release that speaks IPR v9 (≥ 1.30.0). That is the same filter as
   nym-sdk's own discovery, plus node ids, countries and IPs, which nym-sdk doesn't keep. The list is fetched over
   the clearnet, as every Nym client fetches its topology: it tells the API that you use Nym, nothing about where
   you connect.
2. **Order.** The exits are put in a random order weighted by directory performance, without repeats
   (Efraimidis-Spirakis): better exits tend to come first, every allowed exit appears once, and two users don't
   walk the list in the same order. You can filter by country (`selection.countries`), skip low scores
   (`selection.min_performance`), exclude exits, or pin exits to try first (`exits`, with `pinned_only` to use
   nothing else).
3. **Tunnel.** For each exit in turn: a new ephemeral mixnet client (new identity, random entry gateway), then
   the IPR handshake (`nym_smolmix::Tunnel::new_with_ipr`). Each exit gets `attempt_timeout` (45 s), which
   covers the health check too. An attempt that runs over isn't cancelled half-way (a mixnet client dropped
   mid-handshake can leave tasks behind). It finishes in the background, and if it comes up late, nymdial shuts
   it down.
4. **Health check.** The tunnel must carry a real DNS-over-HTTPS lookup (TCP, TLS and HTTP/2 to a resolver,
   then one query) within 12 s per resolver, at most two resolvers. An exit that passes the IPR handshake but
   drops everything after it fails here, not on your first real connection. The resolver connection stays open,
   so the first real lookup is warm.
5. **DNS.** Names are resolved with DNS-over-HTTPS (RFC 8484) through the tunnel. The resolvers are Quad9
   (`9.9.9.9`), Mullvad (`194.242.2.2`) and Cloudflare (`1.1.1.1`), dialed at those pinned IPs and verified by
   hostname, over HTTP/2 connections that stay open. Queries carry ID 0, no client subnet, no cookie, and are
   padded to 128 bytes (RFC 8467). Answers are cached for their TTL (30 s to 1 h). NXDOMAIN is final; if every
   resolver fails, that counts against the tunnel, not the name.
6. **Connect.** TCP through the tunnel within `connect_timeout` (30 s). If it times out, nymdial runs the
   health check. If the tunnel fails it (or the tunnel's channel is closed), nymdial moves to the next exit
   and tries the connect once more. If the tunnel is fine, the error is yours: the server is down, or the
   exit policy blocks the port.

## Proof it works (live, Nym mainnet, 2026-11-08)

Raw output of every run is in `examples/`.

Every "the server saw" line below is an IP-echo service answering through the mixnet, with the IP looked up in
the nym-api node list. My own IP never appeared.

| Run | What happened |
|---|---|
| `whoami` | exit node 2205 (FR) up in 9.3 s incl. health check; Cloudflare saw 103.82.101.72 = **Nym node 2205**; DNS+TCP+TLS 4.4 s, request 0.7 s; 15.2 s wall in all |
| `whoami --rotate` | node 3464 (AT) in 9.9 s, Cloudflare saw 188.137.153.141 = node 3464; `rotate()` to node 3092 (FR) in 5.4 s, then saw 87.106.222.6 = node 3092 |
| `--dead-first whoami` | the forced dead exit (a real IPR client key on a gateway it isn't registered at) timed out at 30 s; node 2296 (IN) came up in 6.0 s; Cloudflare saw 64.227.155.82 = node 2296 |
| `drill` (tunnel killed under the dialer) | request on node 2871 (GR) ok (saw 85.113.71.124 = node 2871); after the kill, the next connect timed out, the health check failed, two exits failed their checks, node 1791 (ES) came up and the same call returned HTTP 200 from 5.188.181.140 = node 1791, **185 s** after it started |
| `bench` Esplora (`blockstream.info/api/blocks/tip/height`) | 2 of 5 requests ok (8.4 s on a fresh tunnel); the others hit dead tunnels and failovers |
| `bench --interval 15` (api.ipify.org) | 5 of 8 ok; one tunnel (node 2570) served 4 requests over about 70 s, 3.3-15 s each, then stopped receiving |
| `connect electrum.blockstream.info 50002 --tls` | **failed**: 6 exits in a row came up and then failed the health check |

Over all runs: **16 of 47 exit attempts gave a working tunnel**, 28 completed the IPR handshake and then
carried nothing (not one DoH answer, even with a 60 s budget per resolver on a re-check), and 3 didn't answer
the handshake in time. A working tunnel came up in a median 8.4 s (5.0-12.7 s) including the health check. On
a warm tunnel, a new HTTPS connection (DoH lookup, TCP, TLS) took 2-4.5 s and a request 0.6-1 s.

The network-requester path for comparison (`nymdial whoami-nr`: nym-sdk's in-process `Socks5MixnetClient`):
setup 1.3-4 s, an HTTPS GET in 2-2.7 s in two runs (api.ipify.org saw 45.154.206.253 = Nym node 2284). In a
third run, `NetworkRequesterSelector::any()` picked a requester on a gateway that isn't in the current topology
("no node with identity … is known"), and nothing could be sent at all. It chooses from all 892 described
nodes, not only the active ones.

## Known problem: IPR tunnels stop receiving

With bridge and IPR debug logs on (`examples/2026-11-08-soak-diag.txt`), the shape is always the same. The
handshake succeeds, packets flow both ways, and then **inbound packets stop**, here 13 s and 5 s after the
tunnel came up, while smoltcp keeps sending (83 packets out, 39 in on the first tunnel). The bridge and the
`IpMixStream` report no error, so the app sees a stalled connection, not a closed one. I haven't found the cause
yet. Candidates: reply-SURB supply to the IPR in stream mode (each outbound message carries 10), the free
"testnet" bandwidth that ephemeral clients claim at the gateway, or the exit's IPR itself. The next step is a
debug run with the gateway's bandwidth and SURB counters, then a report to Nym with the logs. Until then,
nymdial's health check and failover keep it usable for short operations like a broadcast or a lookup, but not
for a long-lived connection.

## Limits, plainly

- **IPv4 only.** The tunnel gets an IPv4 address from the IPR, and AAAA answers are not used (`nym-smolmix`
  limitation).
- **The exit sees where you connect.** It sees the destination IP and port, and with TLS the server name (SNI),
  but not the content. Plain HTTP is readable at the exit: use TLS.
- **One tunnel, one exit, one identity.** Every connection through a tunnel leaves from the same exit IP, so a
  server can link them to each other (not to you). Call `rotate()` between things that must not be linked, for
  example one exit per transaction broadcast.
- **What leaves outside the mixnet:** the nym-api directory fetch, and nym-sdk's own lookup of the entry
  gateway's hostname. Both say "this IP uses Nym", nothing more.
- **Detecting a dead tunnel takes time.** A tunnel that dies quietly gives no error. nymdial notices when a
  connect times out (30 s), then confirms with the health check (up to 24 s). An app that wants faster
  detection can call `check()` on its own schedule. Streams already open on a dead tunnel stall; they are not
  moved to the new one.
- **Exit policy.** Exits enforce the Nym exit policy, so some ports are refused at the exit. The common wallet
  ports (443, 50002) worked in the runs below.
- **Dependency pins.** nym-sdk 1.21.6 asks for its sibling crates as `^1.21.6`, and the 1.22.x siblings that a
  fresh resolution picks don't compile against it. `Cargo.toml` pins the whole nym crate family to 1.21.6 so
  the crate builds as a dependency. Moving to a newer nym-sdk means moving all the pins together.
- **Not audited.** It's a thin layer over Nym's crates (about 1,100 lines of library code, plus the CLI and
  tests), and it hasn't had an external review.

## Tests

`cargo test`: 21 unit tests and 1 doc test, all offline tests (no network): exit parsing against real nym-api records and the SDK's
filter rules, the weighted order (permutation, preference for performance, zero-score exits last, filters),
rotation with fake exits on a paused clock (a dead exit, a failing exit, the attempt cap, a late success that
must be shut down rather than leaked), DoH query building (ID 0, padding, no client subnet) and answer parsing
(CNAME chains, NXDOMAIN, SERVFAIL, garbage), the TTL cache, and URL and IP parsing in the CLI.

## License

MIT
