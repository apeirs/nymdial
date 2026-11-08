//! Minimal liveness repro on raw nym-smolmix 1.21.6, with no nymdial code in the path.
//!
//! For each attempt: `Tunnel::new()` (smolmix's own IPR discovery), then a plain-HTTP probe every `interval`
//! seconds: TCP to 104.16.132.229:80 (cloudflare.com, dialed by IP, no DNS), `GET /cdn-cgi/trace`, read the
//! whole answer. It stops after `max_life` seconds or two failed probes in a row, prints one result line and shuts
//! the tunnel down. Run with `RUST_LOG=nym_smolmix=info,nym_sdk::ip_packet_client=info` to see the exit chosen
//! and the bridge's packet counters.
//!
//! usage: smolmix_repro [attempts=10] [interval_s=5] [max_life_s=120]

use std::net::SocketAddr;
use std::time::Duration;

use nym_smolmix::Tunnel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Instant};

const TARGET: &str = "104.16.132.229:80";
const REQUEST: &[u8] = b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nUser-Agent: smolmix-repro\r\nConnection: close\r\n\r\n";

async fn probe(tunnel: &Tunnel) -> Result<String, String> {
    let addr: SocketAddr = TARGET.parse().unwrap();
    let mut s = tunnel.tcp_connect(addr).await.map_err(|e| format!("connect: {e}"))?;
    s.write_all(REQUEST).await.map_err(|e| format!("write: {e}"))?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.map_err(|e| format!("read: {e}"))?;
    let body = String::from_utf8_lossy(&buf);
    body.lines()
        .find_map(|l| l.strip_prefix("ip="))
        .map(|ip| ip.trim().to_string())
        .ok_or_else(|| format!("no ip= in {} bytes", buf.len()))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "nym_smolmix=info,nym_sdk::ip_packet_client=info,warn".into()))
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<u64> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let attempts = *args.first().unwrap_or(&10);
    let interval = Duration::from_secs(*args.get(1).unwrap_or(&5));
    let max_life = Duration::from_secs(*args.get(2).unwrap_or(&120));

    println!("attempt\tsetup_s\tfirst_probe\tprobes_ok\tprobes_failed\tlast_ok_s\tend\texit_ip");
    for i in 1..=attempts {
        let t = Instant::now();
        let tunnel = match timeout(Duration::from_secs(100), Tunnel::new()).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => {
                println!("{i}\t{:.1}\t-\t0\t0\t-\tsetup error: {e}\t-", t.elapsed().as_secs_f64());
                continue;
            }
            Err(_) => {
                println!("{i}\t>100\t-\t0\t0\t-\tsetup timeout\t-");
                continue;
            }
        };
        let setup = t.elapsed();
        let up = Instant::now();
        let (mut ok, mut failed, mut streak) = (0u32, 0u32, 0u32);
        let mut last_ok: Option<Duration> = None;
        let mut first = String::new();
        let mut ip = String::from("-");
        let end;
        loop {
            if up.elapsed() >= max_life {
                end = "max_life".to_string();
                break;
            }
            let r = timeout(Duration::from_secs(15), probe(&tunnel)).await.unwrap_or_else(|_| Err("timeout 15s".into()));
            match r {
                Ok(seen) => {
                    ok += 1;
                    streak = 0;
                    last_ok = Some(up.elapsed());
                    ip = seen;
                    if first.is_empty() {
                        first = "ok".into();
                    }
                }
                Err(e) => {
                    failed += 1;
                    streak += 1;
                    if first.is_empty() {
                        first = "fail".into();
                    }
                    eprintln!("attempt {i}: probe failed at +{:.0}s: {e}", up.elapsed().as_secs_f64());
                    if streak >= 2 {
                        end = format!("2 fails ({e})");
                        break;
                    }
                }
            }
            tokio::time::sleep(interval).await;
        }
        println!(
            "{i}\t{:.1}\t{first}\t{ok}\t{failed}\t{}\t{end}\t{ip}",
            setup.as_secs_f64(),
            last_ok.map(|d| format!("{:.0}", d.as_secs_f64())).unwrap_or("-".into())
        );
        tunnel.shutdown().await;
    }
}
