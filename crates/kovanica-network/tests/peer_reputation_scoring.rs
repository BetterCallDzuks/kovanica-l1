//! Integration tests for P2P peer reputation and IP ban scoring.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use kovanica_network::{
    BannedPeerError, InboundGate, PeerScorer, PeerScorerConfig, PenaltyReason, BAN_SCORE_THRESHOLD,
    DEFAULT_BAN_DURATION,
};
use libp2p::Multiaddr;
use tokio::net::{TcpListener, TcpStream};

#[test]
fn test_default_constants() {
    assert_eq!(BAN_SCORE_THRESHOLD, 100);
    assert_eq!(DEFAULT_BAN_DURATION, Duration::from_secs(15 * 60));

    assert_eq!(PenaltyReason::MalformedHandshakeOrFrameHeader.points(), 50);
    assert_eq!(PenaltyReason::InvalidBlockHeaderOrPow.points(), 100);
    assert_eq!(
        PenaltyReason::InvalidTxSignatureOrOversizedFrame.points(),
        25
    );
    assert_eq!(PenaltyReason::SpamOrRateLimitExceeded.points(), 20);
    assert_eq!(PenaltyReason::Custom(42).points(), 42);
}

#[test]
fn test_new_peer_clean_reputation() {
    let scorer = Arc::new(PeerScorer::default());
    let gate = InboundGate::new(scorer.clone());

    let clean_ip: IpAddr = "198.51.100.1".parse().unwrap();
    let clean_addr = SocketAddr::new(clean_ip, 30303);

    // Verify a new peer starts with clean reputation (score = 0, not banned)
    assert_eq!(scorer.score(&clean_ip), 0);
    assert!(!scorer.is_banned(&clean_ip));
    assert!(!scorer.is_addr_banned(&clean_addr));

    let rep = scorer.reputation(&clean_ip);
    assert_eq!(rep.ip, clean_ip);
    assert_eq!(rep.score, 0);
    assert_eq!(rep.disconnect_count, 0);
    assert_eq!(rep.violation_points, 0);
    assert!(!rep.is_banned);
    assert_eq!(rep.banned_until, None);

    // Inbound gate must allow the new clean peer
    assert!(gate.allow_connection(&clean_addr));
    assert!(gate.check_incoming_ip(&clean_ip).is_ok());
    assert!(gate.check_incoming_addr(&clean_addr).is_ok());
}

#[test]
fn test_minor_penalties_accumulate_below_threshold() {
    let scorer = Arc::new(PeerScorer::default());
    let gate = InboundGate::new(scorer.clone());

    let peer_ip: IpAddr = "198.51.100.2".parse().unwrap();
    let peer_addr = SocketAddr::new(peer_ip, 30303);

    // 1. Unsolicited spam / rate limit violation (+20 points)
    let banned = scorer.record_spam_or_rate_limit(peer_ip);
    assert!(!banned);
    assert_eq!(scorer.score(&peer_ip), 20);
    assert!(!scorer.is_banned(&peer_ip));
    assert!(gate.allow_connection(&peer_addr));

    // 2. Repeated invalid transaction signature or oversized frame (+25 points)
    let banned = scorer.record_invalid_tx_or_oversized_frame(peer_ip);
    assert!(!banned);
    assert_eq!(scorer.score(&peer_ip), 45);
    assert!(!scorer.is_banned(&peer_ip));
    assert!(gate.allow_connection(&peer_addr));

    // 3. Another invalid transaction signature (+25 points) -> cumulative 70
    let banned = scorer.record_invalid_tx_or_oversized_frame(peer_ip);
    assert!(!banned);
    assert_eq!(scorer.score(&peer_ip), 70);
    assert!(!scorer.is_banned(&peer_ip));
    assert!(gate.allow_connection(&peer_addr));

    // 4. Another spam (+20 points) -> cumulative 90 < 100 threshold
    let banned = scorer.record_spam_or_rate_limit(peer_ip);
    assert!(!banned);
    assert_eq!(scorer.score(&peer_ip), 90);
    assert!(!scorer.is_banned(&peer_ip));

    // Verify minor penalties accumulated and did not trigger a ban until threshold is crossed
    let rep = scorer.reputation(&peer_ip);
    assert_eq!(rep.score, 90);
    assert_eq!(rep.violation_points, 90);
    assert!(!rep.is_banned);
    assert_eq!(rep.banned_until, None);
    assert!(gate.allow_connection(&peer_addr));
}

#[test]
fn test_reaching_score_threshold_bans_peer_immediately() {
    let scorer = Arc::new(PeerScorer::default());
    let gate = InboundGate::new(scorer.clone());

    // Case A: Accumulating to threshold (90 + 20 = 110 >= 100)
    let peer_a: IpAddr = "198.51.100.10".parse().unwrap();
    scorer.add_penalty(peer_a, 90, "initial infractions");
    assert!(!scorer.is_banned(&peer_a));
    assert_eq!(scorer.score(&peer_a), 90);

    let banned = scorer.record_spam_or_rate_limit(peer_a);
    assert!(banned, "crossing 100 threshold must ban immediately");
    assert!(scorer.is_banned(&peer_a));
    assert_eq!(scorer.score(&peer_a), 110);
    assert!(!gate.allow_connection(&SocketAddr::new(peer_a, 9000)));

    // Case B: Instant ban from invalid block header or PoW (+100)
    let peer_b: IpAddr = "198.51.100.11".parse().unwrap();
    assert_eq!(scorer.score(&peer_b), 0);
    let banned = scorer.record_invalid_block_or_pow(peer_b);
    assert!(
        banned,
        "invalid block header / PoW must trigger instant ban"
    );
    assert!(scorer.is_banned(&peer_b));
    assert_eq!(scorer.score(&peer_b), 100);
    assert!(!gate.allow_connection(&SocketAddr::new(peer_b, 9000)));

    // Case C: Corrupted handshake / frame header (+50) twice -> 100 -> banned
    let peer_c: IpAddr = "198.51.100.12".parse().unwrap();
    assert!(!scorer.record_malformed_handshake_or_frame_header(peer_c));
    assert_eq!(scorer.score(&peer_c), 50);
    assert!(!scorer.is_banned(&peer_c));

    assert!(scorer.record_malformed_handshake_or_frame_header(peer_c));
    assert_eq!(scorer.score(&peer_c), 100);
    assert!(scorer.is_banned(&peer_c));
    assert!(!gate.allow_connection(&SocketAddr::new(peer_c, 9000)));
}

#[test]
fn test_banned_peers_cannot_reconnect_while_ban_active() {
    let scorer = Arc::new(PeerScorer::default());
    let gate = InboundGate::new(scorer.clone());

    let banned_ip: IpAddr = "198.51.100.25".parse().unwrap();
    let socket_addr = SocketAddr::new(banned_ip, 4000);
    let multiaddr: Multiaddr = "/ip4/198.51.100.25/tcp/4000".parse().unwrap();

    // Ban the peer
    scorer.record_invalid_block_or_pow(banned_ip);
    assert!(scorer.is_banned(&banned_ip));

    // Inbound gate checks must immediately reject
    assert_eq!(
        gate.check_incoming_ip(&banned_ip),
        Err(BannedPeerError { ip: banned_ip })
    );
    assert_eq!(
        gate.check_incoming_addr(&socket_addr),
        Err(BannedPeerError { ip: banned_ip })
    );
    assert_eq!(
        gate.check_incoming_multiaddr(&multiaddr),
        Err(BannedPeerError { ip: banned_ip })
    );
    assert!(!gate.allow_connection(&socket_addr));

    // Trying from any port on that banned IP must also be blocked
    let alternate_port_addr = SocketAddr::new(banned_ip, 4001);
    assert!(!gate.allow_connection(&alternate_port_addr));
    assert_eq!(
        gate.check_incoming_addr(&alternate_port_addr),
        Err(BannedPeerError { ip: banned_ip })
    );
}

#[test]
fn test_expired_bans_allow_reconnection_once_duration_elapses() {
    // Test with a short 40ms ban duration
    let short_duration = Duration::from_millis(40);
    let scorer = Arc::new(PeerScorer::new(PeerScorerConfig {
        ban_score_threshold: 100,
        ban_duration: short_duration,
    }));
    let gate = InboundGate::new(scorer.clone());

    let peer_ip: IpAddr = "198.51.100.50".parse().unwrap();
    let socket_addr = SocketAddr::new(peer_ip, 5000);

    // 1. Peer commits critical violation -> banned
    scorer.record_invalid_block_or_pow(peer_ip);
    assert!(scorer.is_banned(&peer_ip));
    assert!(!gate.allow_connection(&socket_addr));
    assert_eq!(
        gate.check_incoming_addr(&socket_addr),
        Err(BannedPeerError { ip: peer_ip })
    );

    // 2. Wait until the ban duration elapses
    std::thread::sleep(Duration::from_millis(60));

    // 3. Query should auto-purge the expired ban and allow reconnection
    assert!(!scorer.is_banned(&peer_ip));
    assert_eq!(scorer.score(&peer_ip), 0);
    assert!(gate.allow_connection(&socket_addr));
    assert!(gate.check_incoming_addr(&socket_addr).is_ok());

    let rep = scorer.reputation(&peer_ip);
    assert!(!rep.is_banned);
    assert_eq!(rep.score, 0);
    assert_eq!(rep.banned_until, None);
}

#[tokio::test]
async fn test_inbound_connection_gate_tcp_socket_termination() {
    let scorer = Arc::new(PeerScorer::with_threshold_and_duration(
        100,
        Duration::from_millis(60),
    ));
    let gate = InboundGate::new(scorer.clone());

    // Bind an ephemeral TCP listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();

    // 1. Initial connection from localhost when clean: succeeds
    let client = TcpStream::connect(listen_addr).await.unwrap();
    let (server_stream, peer_addr) = listener.accept().await.unwrap();

    // Gating clean socket: succeeds
    let gated_stream = gate.gate_socket(&peer_addr, server_stream);
    assert!(gated_stream.is_ok());
    drop(client);
    drop(gated_stream);

    // 2. Ban 127.0.0.1
    let local_ip = peer_addr.ip();
    scorer.record_invalid_block_or_pow(local_ip);
    assert!(scorer.is_banned(&local_ip));

    // Connect again while banned
    let client = TcpStream::connect(listen_addr).await.unwrap();
    let (server_stream, peer_addr) = listener.accept().await.unwrap();

    // Inbound gate rejects and drops the socket immediately
    let gated_result = gate.gate_socket(&peer_addr, server_stream);
    assert!(matches!(gated_result, Err(BannedPeerError { ip }) if ip == local_ip));

    // Reading on the client stream will observe EOF / terminated socket
    let mut buf = [0u8; 16];
    let n = client.try_read(&mut buf);
    // Since server socket was dropped, read will yield Ok(0) (EOF) or error
    if let Ok(bytes) = n {
        assert_eq!(bytes, 0, "socket must be terminated at gate");
    }

    // 3. Sleep to let the ban expire
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Connect again after ban elapses
    let client = TcpStream::connect(listen_addr).await.unwrap();
    let (server_stream, peer_addr) = listener.accept().await.unwrap();

    let gated_result = gate.gate_socket(&peer_addr, server_stream);
    assert!(
        gated_result.is_ok(),
        "reconnection must succeed after ban expires"
    );
    drop(client);
    drop(gated_result);
}
