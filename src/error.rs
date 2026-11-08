use std::net::SocketAddr;
use std::time::Duration;

/// Everything nymdial can fail with. Each variant says which step failed, so a wallet can tell "the mixnet is
/// unreachable" from "this server is down".
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The nym-api couldn't be read or parsed.
    #[error("nym-api directory: {0}")]
    Directory(String),

    /// No exit matches the selection (country filter, minimum performance, exclusions).
    #[error("no exit gateway matches: {0}")]
    NoExit(String),

    /// Every exit tried failed to give a working tunnel.
    #[error("no working exit after {attempts} attempts (last: {last})")]
    ExitsExhausted { attempts: usize, last: String },

    /// Name resolution through the mixnet failed at every resolver.
    #[error("DNS over the mixnet for {host}: {reason}")]
    Dns { host: String, reason: String },

    /// The name exists but has no IPv4 address; the tunnel is IPv4-only for now.
    #[error("{0} has no IPv4 address (nym-smolmix tunnels are IPv4-only)")]
    NoIpv4(String),

    /// TCP connect through the tunnel didn't complete in time.
    #[error("TCP connect to {addr} timed out after {after:?}")]
    ConnectTimeout { addr: SocketAddr, after: Duration },

    /// TCP connect through the tunnel failed (refused, reset, tunnel closed).
    #[error("TCP connect to {addr}: {reason}")]
    Connect { addr: SocketAddr, reason: String },

    /// TLS handshake failed (certificate, protocol, timeout).
    #[error("TLS with {host}: {reason}")]
    Tls { host: String, reason: String },

    /// Bad input from the caller.
    #[error("invalid input: {0}")]
    Invalid(String),
}
