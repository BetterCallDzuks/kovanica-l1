//! P2P Peer Reputation and IP Ban Scoring subsystem.
//!
//! Hardens nodes against P2P DDoS, spamming, and protocol violations by tracking
//! connection health, disconnects, and protocol violation penalties per IP/SocketAddr.
//! Banned IPs are blocked at the inbound connection gate before frame buffers or
//! protocol state are allocated.

use std::{
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use libp2p::{
    core::{transport::PortUse, Endpoint},
    swarm::{
        dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
    Multiaddr, PeerId,
};
use parking_lot::RwLock;
use tracing::{debug, info, warn};

/// Cumulative score threshold at or above which an IP is marked banned.
pub const BAN_SCORE_THRESHOLD: u32 = 100;

/// Default ban duration when the penalty threshold is reached (15 minutes).
pub const DEFAULT_BAN_DURATION: Duration = Duration::from_secs(15 * 60);

/// Extract an `IpAddr` from a `Multiaddr` if present.
pub fn extract_ip(addr: &Multiaddr) -> Option<IpAddr> {
    for protocol in addr.iter() {
        match protocol {
            libp2p::multiaddr::Protocol::Ip4(ipv4) => return Some(IpAddr::V4(ipv4)),
            libp2p::multiaddr::Protocol::Ip6(ipv6) => return Some(IpAddr::V6(ipv6)),
            _ => {}
        }
    }
    None
}

/// Extract a `SocketAddr` from a `Multiaddr` if both IP and port are present.
pub fn extract_socket_addr(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut ip = None;
    let mut port = None;
    for protocol in addr.iter() {
        match protocol {
            libp2p::multiaddr::Protocol::Ip4(ipv4) => ip = Some(IpAddr::V4(ipv4)),
            libp2p::multiaddr::Protocol::Ip6(ipv6) => ip = Some(IpAddr::V6(ipv6)),
            libp2p::multiaddr::Protocol::Tcp(p) => port = Some(p),
            libp2p::multiaddr::Protocol::Udp(p) => port = Some(p),
            _ => {}
        }
    }
    match (ip, port) {
        (Some(ip), Some(port)) => Some(SocketAddr::new(ip, port)),
        _ => None,
    }
}

/// Negative score penalties for protocol violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyReason {
    /// Malformed or corrupted handshake or frame header (+50 points).
    MalformedHandshakeOrFrameHeader,
    /// Invalid block header or invalid PoW difficulty (+100 points / instant ban).
    InvalidBlockHeaderOrPow,
    /// Repeated invalid transaction signature or oversized frame (+25 points).
    InvalidTxSignatureOrOversizedFrame,
    /// Unsolicited spam or rate limit violation (+20 points).
    SpamOrRateLimitExceeded,
    /// Custom penalty points.
    Custom(u32),
}

impl PenaltyReason {
    /// Return the penalty points associated with this violation.
    pub const fn points(&self) -> u32 {
        match self {
            Self::MalformedHandshakeOrFrameHeader => 50,
            Self::InvalidBlockHeaderOrPow => 100,
            Self::InvalidTxSignatureOrOversizedFrame => 25,
            Self::SpamOrRateLimitExceeded => 20,
            Self::Custom(pts) => *pts,
        }
    }

    /// Human-readable description of the violation.
    pub const fn description(&self) -> &'static str {
        match self {
            Self::MalformedHandshakeOrFrameHeader => {
                "malformed or corrupted handshake or frame header (+50)"
            }
            Self::InvalidBlockHeaderOrPow => {
                "invalid block header or invalid PoW difficulty (+100 / instant ban)"
            }
            Self::InvalidTxSignatureOrOversizedFrame => {
                "invalid transaction signature or oversized frame (+25)"
            }
            Self::SpamOrRateLimitExceeded => "unsolicited spam or rate limit violation (+20)",
            Self::Custom(_) => "custom protocol violation penalty",
        }
    }
}

/// Configuration options for the peer reputation scorer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerScorerConfig {
    /// Score threshold to trigger an IP ban.
    pub ban_score_threshold: u32,
    /// Duration of an IP ban once the threshold is crossed.
    pub ban_duration: Duration,
}

impl Default for PeerScorerConfig {
    fn default() -> Self {
        Self {
            ban_score_threshold: BAN_SCORE_THRESHOLD,
            ban_duration: DEFAULT_BAN_DURATION,
        }
    }
}

/// In-memory peer reputation record for one remote IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerReputation {
    /// Target IP address.
    pub ip: IpAddr,
    /// Cumulative negative score penalty points.
    pub score: u32,
    /// Disconnect count.
    pub disconnect_count: u32,
    /// Protocol violation points accumulated.
    pub violation_points: u32,
    /// Timestamp until which the IP is banned (if currently banned).
    pub banned_until: Option<Instant>,
    /// Whether this IP is actively banned.
    pub is_banned: bool,
    /// Time of last seen interaction or violation.
    pub last_seen: Instant,
}

impl PeerReputation {
    /// Create a clean reputation record (score = 0, not banned).
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            score: 0,
            disconnect_count: 0,
            violation_points: 0,
            banned_until: None,
            is_banned: false,
            last_seen: Instant::now(),
        }
    }
}

/// Thread-safe peer reputation tracker and IP ban scorer.
#[derive(Debug)]
pub struct PeerScorer {
    config: PeerScorerConfig,
    state: RwLock<HashMap<IpAddr, PeerReputation>>,
}

impl Default for PeerScorer {
    fn default() -> Self {
        Self::new(PeerScorerConfig::default())
    }
}

impl PeerScorer {
    /// Create a new `PeerScorer` with the specified configuration.
    pub fn new(config: PeerScorerConfig) -> Self {
        Self {
            config,
            state: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new `PeerScorer` with custom ban threshold and duration.
    pub fn with_threshold_and_duration(ban_score_threshold: u32, ban_duration: Duration) -> Self {
        Self::new(PeerScorerConfig {
            ban_score_threshold,
            ban_duration,
        })
    }

    /// Return the active configuration.
    pub fn config(&self) -> &PeerScorerConfig {
        &self.config
    }

    /// Check if an IP address is actively banned.
    ///
    /// Automatically purges expired bans on query: if the ban duration has elapsed,
    /// the ban is cleared and false is returned.
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        let now = Instant::now();
        {
            let state = self.state.read();
            if let Some(rep) = state.get(ip) {
                if let Some(until) = rep.banned_until {
                    if now < until {
                        return true;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Ban has expired: acquire write lock to purge it
        let mut state = self.state.write();
        if let Some(rep) = state.get_mut(ip) {
            if let Some(until) = rep.banned_until {
                if now >= until {
                    rep.banned_until = None;
                    rep.is_banned = false;
                    rep.score = 0;
                    debug!(%ip, "cleared expired ban on query");
                    return false;
                } else {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a `SocketAddr` is actively banned.
    pub fn is_addr_banned(&self, addr: &SocketAddr) -> bool {
        self.is_banned(&addr.ip())
    }

    /// Check if a `Multiaddr` is actively banned.
    pub fn is_multiaddr_banned(&self, addr: &Multiaddr) -> bool {
        if let Some(ip) = extract_ip(addr) {
            self.is_banned(&ip)
        } else {
            false
        }
    }

    /// Record a peer disconnect event.
    pub fn record_disconnect(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut state = self.state.write();
        let rep = state.entry(ip).or_insert_with(|| PeerReputation::new(ip));
        rep.last_seen = now;
        rep.disconnect_count = rep.disconnect_count.saturating_add(1);
        debug!(%ip, disconnect_count = rep.disconnect_count, "recorded peer disconnect");
    }

    /// Record a disconnect event from a `SocketAddr`.
    pub fn record_addr_disconnect(&self, addr: &SocketAddr) {
        self.record_disconnect(addr.ip());
    }

    /// Add penalty points to an IP. If cumulative penalty reaches or exceeds
    /// `ban_score_threshold`, marks the IP as banned for `ban_duration`.
    /// Returns `true` if the IP is now banned.
    pub fn add_penalty(&self, ip: IpAddr, points: u32, reason: &str) -> bool {
        let now = Instant::now();
        let mut state = self.state.write();
        let rep = state.entry(ip).or_insert_with(|| PeerReputation::new(ip));
        rep.last_seen = now;
        rep.score = rep.score.saturating_add(points);
        rep.violation_points = rep.violation_points.saturating_add(points);

        if rep.score >= self.config.ban_score_threshold {
            let until = now + self.config.ban_duration;
            rep.banned_until = Some(until);
            rep.is_banned = true;
            warn!(
                %ip,
                score = rep.score,
                threshold = self.config.ban_score_threshold,
                reason,
                duration_secs = self.config.ban_duration.as_secs(),
                "peer IP banned due to reputation penalty threshold"
            );
            true
        } else {
            debug!(
                %ip,
                score = rep.score,
                points,
                reason,
                threshold = self.config.ban_score_threshold,
                "recorded peer violation penalty"
            );
            rep.is_banned
        }
    }

    /// Record a protocol violation penalty using a typed [`PenaltyReason`].
    pub fn record_penalty(&self, ip: IpAddr, reason: PenaltyReason) -> bool {
        self.add_penalty(ip, reason.points(), reason.description())
    }

    /// Record a penalty from a `SocketAddr`.
    pub fn record_addr_penalty(&self, addr: &SocketAddr, reason: PenaltyReason) -> bool {
        self.record_penalty(addr.ip(), reason)
    }

    /// Convenience: record malformed handshake or frame header (+50 points).
    pub fn record_malformed_handshake_or_frame_header(&self, ip: IpAddr) -> bool {
        self.record_penalty(ip, PenaltyReason::MalformedHandshakeOrFrameHeader)
    }

    /// Convenience: record invalid block header or PoW difficulty (+100 points / instant ban).
    pub fn record_invalid_block_or_pow(&self, ip: IpAddr) -> bool {
        self.record_penalty(ip, PenaltyReason::InvalidBlockHeaderOrPow)
    }

    /// Convenience: record invalid transaction signature or oversized frame (+25 points).
    pub fn record_invalid_tx_or_oversized_frame(&self, ip: IpAddr) -> bool {
        self.record_penalty(ip, PenaltyReason::InvalidTxSignatureOrOversizedFrame)
    }

    /// Convenience: record unsolicited spam or rate limit violation (+20 points).
    pub fn record_spam_or_rate_limit(&self, ip: IpAddr) -> bool {
        self.record_penalty(ip, PenaltyReason::SpamOrRateLimitExceeded)
    }

    /// Retrieve the current score for an IP (returns 0 for clean / unseen peer).
    pub fn score(&self, ip: &IpAddr) -> u32 {
        let _ = self.is_banned(ip);
        self.state.read().get(ip).map_or(0, |rep| rep.score)
    }

    /// Retrieve reputation snapshot for an IP (clean reputation if unseen).
    pub fn reputation(&self, ip: &IpAddr) -> PeerReputation {
        let _ = self.is_banned(ip);
        self.state
            .read()
            .get(ip)
            .cloned()
            .unwrap_or_else(|| PeerReputation::new(*ip))
    }

    /// Manually ban an IP for the given duration.
    pub fn ban(&self, ip: IpAddr, duration: Duration) {
        let now = Instant::now();
        let mut state = self.state.write();
        let rep = state.entry(ip).or_insert_with(|| PeerReputation::new(ip));
        rep.last_seen = now;
        rep.score = rep.score.max(self.config.ban_score_threshold);
        rep.banned_until = Some(now + duration);
        rep.is_banned = true;
        warn!(%ip, duration_secs = duration.as_secs(), "explicitly banned peer IP");
    }

    /// Manually ban a `SocketAddr`'s IP.
    pub fn ban_addr(&self, addr: &SocketAddr, duration: Duration) {
        self.ban(addr.ip(), duration);
    }

    /// Manually unban an IP and reset its penalty score.
    pub fn unban(&self, ip: &IpAddr) {
        let mut state = self.state.write();
        if let Some(rep) = state.get_mut(ip) {
            rep.banned_until = None;
            rep.is_banned = false;
            rep.score = 0;
            info!(%ip, "unbanned peer IP and reset reputation score");
        }
    }

    /// Clear all tracking state for an IP.
    pub fn reset(&self, ip: &IpAddr) {
        let mut state = self.state.write();
        state.remove(ip);
    }

    /// Purge all expired bans across all tracked peers and evict stale clean records.
    /// Returns count of purged bans.
    pub fn purge_expired_bans(&self) -> usize {
        const IDLE_EVICT: Duration = Duration::from_secs(3600);
        let now = Instant::now();
        let mut purged = 0;
        let mut state = self.state.write();
        for (ip, rep) in state.iter_mut() {
            if let Some(until) = rep.banned_until {
                if now >= until {
                    rep.banned_until = None;
                    rep.is_banned = false;
                    rep.score = 0;
                    purged += 1;
                    debug!(%ip, "purged expired ban");
                }
            }
        }
        state.retain(|_, rep| {
            rep.banned_until.is_some()
                || rep.score > 0
                || now.duration_since(rep.last_seen) < IDLE_EVICT
        });
        purged
    }

    /// Number of actively banned peers.
    pub fn banned_count(&self) -> usize {
        let now = Instant::now();
        let state = self.state.read();
        state
            .values()
            .filter(|rep| rep.banned_until.is_some_and(|until| now < until))
            .count()
    }
}

/// Error returned when a connection from a banned IP is rejected at the gate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("inbound connection rejected: remote IP {ip} is banned")]
pub struct BannedPeerError {
    /// The banned IP.
    pub ip: IpAddr,
}

/// Inbound connection gate that intercepts incoming connections and drops banned
/// IPs before allocating frame buffers, handshake cryptography, or protocol state.
#[derive(Clone, Debug)]
pub struct InboundGate {
    scorer: Arc<PeerScorer>,
}

impl InboundGate {
    /// Create a new inbound gate backed by a [`PeerScorer`].
    pub fn new(scorer: Arc<PeerScorer>) -> Self {
        Self { scorer }
    }

    /// Access the underlying [`PeerScorer`].
    pub fn scorer(&self) -> &Arc<PeerScorer> {
        &self.scorer
    }

    /// Check if an incoming connection from `ip` is allowed.
    /// Returns `Ok(())` if allowed, or `Err(BannedPeerError)` if banned.
    pub fn check_incoming_ip(&self, ip: &IpAddr) -> Result<(), BannedPeerError> {
        if self.scorer.is_banned(ip) {
            Err(BannedPeerError { ip: *ip })
        } else {
            Ok(())
        }
    }

    /// Check if an incoming connection from `addr` is allowed.
    pub fn check_incoming_addr(&self, addr: &SocketAddr) -> Result<(), BannedPeerError> {
        self.check_incoming_ip(&addr.ip())
    }

    /// Check if an incoming connection from `addr` is allowed.
    pub fn check_incoming_multiaddr(&self, addr: &Multiaddr) -> Result<(), BannedPeerError> {
        if let Some(ip) = extract_ip(addr) {
            self.check_incoming_ip(&ip)
        } else {
            Ok(())
        }
    }

    /// Boolean check: whether an incoming connection from `addr` is allowed.
    pub fn allow_connection(&self, addr: &SocketAddr) -> bool {
        self.check_incoming_addr(addr).is_ok()
    }

    /// Gate an incoming socket: if the remote IP is banned, `socket` is dropped
    /// immediately (terminating the TCP connection) before any buffers or protocol
    /// state are allocated.
    pub fn gate_socket<S>(&self, addr: &SocketAddr, socket: S) -> Result<S, BannedPeerError> {
        match self.check_incoming_addr(addr) {
            Ok(()) => Ok(socket),
            Err(e) => {
                drop(socket);
                Err(e)
            }
        }
    }
}

impl NetworkBehaviour for InboundGate {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        if let Some(ip) = extract_ip(remote_addr) {
            if self.scorer.is_banned(&ip) {
                warn!(
                    %ip,
                    %remote_addr,
                    "inbound connection gate: terminating socket for banned IP immediately before allocating frame buffers"
                );
                return Err(ConnectionDenied::new(BannedPeerError { ip }));
            }
        }
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if let Some(ip) = extract_ip(remote_addr) {
            if self.scorer.is_banned(&ip) {
                return Err(ConnectionDenied::new(BannedPeerError { ip }));
            }
        }
        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _endpoint: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        Ok(vec![])
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _endpoint: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        libp2p::core::util::unreachable(event)
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_peer_starts_with_clean_reputation() {
        let scorer = PeerScorer::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();

        // Must start with clean reputation (score = 0, not banned)
        assert!(!scorer.is_banned(&ip));
        assert_eq!(scorer.score(&ip), 0);
        let rep = scorer.reputation(&ip);
        assert_eq!(rep.score, 0);
        assert_eq!(rep.disconnect_count, 0);
        assert_eq!(rep.violation_points, 0);
        assert!(!rep.is_banned);
        assert_eq!(rep.banned_until, None);

        // Gate must allow connection
        let gate = InboundGate::new(Arc::new(scorer));
        assert!(gate.check_incoming_ip(&ip).is_ok());
        let socket_addr = SocketAddr::new(ip, 8000);
        assert!(gate.allow_connection(&socket_addr));
        assert!(gate.check_incoming_addr(&socket_addr).is_ok());
    }

    #[test]
    fn minor_penalties_accumulate_without_premature_ban() {
        let scorer = PeerScorer::default();
        let ip: IpAddr = "192.0.2.2".parse().unwrap();

        // 1. Spam (+20 points) -> score 20, not banned
        assert!(!scorer.record_spam_or_rate_limit(ip));
        assert_eq!(scorer.score(&ip), 20);
        assert!(!scorer.is_banned(&ip));

        // 2. Invalid transaction signature (+25 points) -> score 45, not banned
        assert!(!scorer.record_invalid_tx_or_oversized_frame(ip));
        assert_eq!(scorer.score(&ip), 45);
        assert!(!scorer.is_banned(&ip));

        // 3. Another invalid tx signature (+25 points) -> score 70, not banned
        assert!(!scorer.record_invalid_tx_or_oversized_frame(ip));
        assert_eq!(scorer.score(&ip), 70);
        assert!(!scorer.is_banned(&ip));

        // 4. Another spam (+20 points) -> score 90, not banned
        assert!(!scorer.record_spam_or_rate_limit(ip));
        assert_eq!(scorer.score(&ip), 90);
        assert!(!scorer.is_banned(&ip));

        // Peer is still allowed to connect
        let gate = InboundGate::new(Arc::new(scorer));
        assert!(gate.check_incoming_ip(&ip).is_ok());
    }

    #[test]
    fn reaching_score_threshold_bans_peer_immediately() {
        let scorer = PeerScorer::default();
        let ip1: IpAddr = "192.0.2.10".parse().unwrap();

        // Accumulate to 90
        scorer.add_penalty(ip1, 90, "minor offenses");
        assert!(!scorer.is_banned(&ip1));

        // Add 20 points -> 110 >= 100 -> bans immediately!
        let banned = scorer.record_spam_or_rate_limit(ip1);
        assert!(banned);
        assert!(scorer.is_banned(&ip1));
        assert_eq!(scorer.score(&ip1), 110);

        // Clean peer 2: Invalid block header (+100) -> instant ban!
        let ip2: IpAddr = "192.0.2.11".parse().unwrap();
        let banned = scorer.record_invalid_block_or_pow(ip2);
        assert!(banned);
        assert!(scorer.is_banned(&ip2));
        assert_eq!(scorer.score(&ip2), 100);

        // Clean peer 3: Corrupted handshake (+50) + (+50) -> banned!
        let ip3: IpAddr = "192.0.2.12".parse().unwrap();
        assert!(!scorer.record_malformed_handshake_or_frame_header(ip3));
        assert_eq!(scorer.score(&ip3), 50);
        assert!(!scorer.is_banned(&ip3));
        assert!(scorer.record_malformed_handshake_or_frame_header(ip3));
        assert_eq!(scorer.score(&ip3), 100);
        assert!(scorer.is_banned(&ip3));
    }

    #[test]
    fn banned_peers_cannot_reconnect_while_ban_is_active() {
        let scorer = Arc::new(PeerScorer::default());
        let gate = InboundGate::new(scorer.clone());
        let ip: IpAddr = "192.0.2.20".parse().unwrap();
        let socket_addr = SocketAddr::new(ip, 9999);
        let multiaddr: Multiaddr = "/ip4/192.0.2.20/tcp/9999".parse().unwrap();

        // Ban the peer
        scorer.record_invalid_block_or_pow(ip);
        assert!(scorer.is_banned(&ip));

        // Gate checks must reject
        assert_eq!(gate.check_incoming_ip(&ip), Err(BannedPeerError { ip }));
        assert_eq!(
            gate.check_incoming_addr(&socket_addr),
            Err(BannedPeerError { ip })
        );
        assert_eq!(
            gate.check_incoming_multiaddr(&multiaddr),
            Err(BannedPeerError { ip })
        );
        assert!(!gate.allow_connection(&socket_addr));

        // Gating a dummy socket must terminate/drop it immediately and return error
        let socket_dummy = vec![1, 2, 3];
        let result = gate.gate_socket(&socket_addr, socket_dummy);
        assert!(result.is_err());
    }

    #[test]
    fn expired_bans_allow_reconnection_once_duration_elapses() {
        // Use a short ban duration of 50ms for deterministic testing
        let scorer = Arc::new(PeerScorer::with_threshold_and_duration(
            100,
            Duration::from_millis(50),
        ));
        let gate = InboundGate::new(scorer.clone());
        let ip: IpAddr = "192.0.2.30".parse().unwrap();
        let socket_addr = SocketAddr::new(ip, 8888);

        // Ban the peer
        scorer.record_invalid_block_or_pow(ip);
        assert!(scorer.is_banned(&ip));
        assert!(!gate.allow_connection(&socket_addr));

        // Sleep until ban elapses
        std::thread::sleep(Duration::from_millis(65));

        // Ban has expired: query should auto-purge and allow connection!
        assert!(!scorer.is_banned(&ip));
        assert_eq!(scorer.score(&ip), 0);
        assert!(gate.allow_connection(&socket_addr));
        assert!(gate.check_incoming_addr(&socket_addr).is_ok());

        // Reconnection is allowed
        let socket_dummy = "connected_ok";
        let accepted = gate.gate_socket(&socket_addr, socket_dummy);
        assert!(accepted.is_ok());
    }

    #[test]
    fn disconnect_counts_track_connection_health() {
        let scorer = PeerScorer::default();
        let ip: IpAddr = "192.0.2.40".parse().unwrap();

        scorer.record_disconnect(ip);
        scorer.record_disconnect(ip);
        scorer.record_disconnect(ip);

        let rep = scorer.reputation(&ip);
        assert_eq!(rep.disconnect_count, 3);
        assert_eq!(rep.score, 0); // Disconnect count doesn't artificially trigger ban threshold alone
        assert!(!rep.is_banned);
    }

    #[test]
    fn manual_ban_and_unban_and_purge() {
        let scorer = PeerScorer::with_threshold_and_duration(100, Duration::from_millis(20));
        let ip1: IpAddr = "192.0.2.50".parse().unwrap();
        let ip2: IpAddr = "192.0.2.51".parse().unwrap();

        scorer.ban(ip1, Duration::from_secs(60));
        scorer.ban(ip2, Duration::from_millis(20));
        assert_eq!(scorer.banned_count(), 2);

        // Unban ip1
        scorer.unban(&ip1);
        assert!(!scorer.is_banned(&ip1));
        assert_eq!(scorer.score(&ip1), 0);

        // Sleep to let ip2 expire
        std::thread::sleep(Duration::from_millis(30));
        let purged = scorer.purge_expired_bans();
        assert_eq!(purged, 1);
        assert!(!scorer.is_banned(&ip2));
    }

    #[test]
    fn multiaddr_ip_extraction() {
        let v4: Multiaddr = "/ip4/198.51.100.42/tcp/1234".parse().unwrap();
        assert_eq!(
            extract_ip(&v4),
            Some("198.51.100.42".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            extract_socket_addr(&v4),
            Some("198.51.100.42:1234".parse::<SocketAddr>().unwrap())
        );

        let v6: Multiaddr = "/ip6/2001:db8::1/tcp/5678".parse().unwrap();
        assert_eq!(
            extract_ip(&v6),
            Some("2001:db8::1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            extract_socket_addr(&v6),
            Some("[2001:db8::1]:5678".parse::<SocketAddr>().unwrap())
        );

        let dns: Multiaddr = "/dns4/example.com/tcp/80".parse().unwrap();
        assert_eq!(extract_ip(&dns), None);
        assert_eq!(extract_socket_addr(&dns), None);
    }
}
