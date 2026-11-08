//! # nymdial
//!
//! Open TCP and TLS connections through the [Nym mixnet](https://nym.com) from inside your process: no
//! `nym-socks5-client` to install, no local proxy port. Built on Nym's own
//! [`nym-smolmix`](https://docs.rs/nym-smolmix) tunnel (a userspace TCP/IP stack over an IP Packet Router
//! exit) and `nym-sdk`; nymdial adds what a wallet needs around it:
//!
//! - `connect(host, port)` and `connect_tls(host, port)`, returning tokio `AsyncRead + AsyncWrite` streams;
//! - DNS over the mixnet (DNS-over-HTTPS through the tunnel, pinned resolver IPs, TTL cache);
//! - exit selection from the nym-api (performance-weighted, country filter), a health check on every new
//!   tunnel, rotation past exits that don't answer, and failover to a new exit when a running tunnel dies;
//! - timeouts on every step, and errors that say which step failed.
//!
//! ```no_run
//! # async fn demo() -> Result<(), nymdial::Error> {
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! let dialer = nymdial::Dialer::start(nymdial::Config::default()).await?;
//! let mut s = dialer.connect_tls("blockstream.info", 443).await?;
//! s.write_all(b"GET /api/blocks/tip/height HTTP/1.1\r\nHost: blockstream.info\r\nConnection: close\r\n\r\n").await.unwrap();
//! let mut out = String::new();
//! s.read_to_string(&mut out).await.unwrap();
//! dialer.shutdown().await;
//! # Ok(()) }
//! ```

pub mod dialer;
pub mod dns;
mod error;
pub mod exits;
pub mod rotate;
pub mod tls;

pub use dialer::{Config, Dialer, ExitInfo};
pub use error::Error;
pub use exits::{Exit, Selection};
pub use nym_smolmix::TcpStream;

/// A TLS stream through the mixnet.
pub type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;
