//! Integration tests for `kovanica-comms-relay`. Spec moved to KovanicaDAG/kovanica-apps (Comms); removed from kovanica-l1 in #247 (former M1 §3–§5).

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use kovanica_comms_crypto::{E2eCipher, PublicKey, SecretSeed, X25519Cipher};
use kovanica_comms_relay::{
    ack_signing_bytes, comms_id_hex, pad_payload, pow_verify, trim_payload, ClientError, Envelope,
    PaymentProof, PowProof, RelayClient, Store, SubmissionWrapper, ALG_V1,
};

/// Serialises tests that read or mutate `KOVANICA_RELAY_ALLOW_UNPAID`.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn solve_pow_from(id_hex: &str, bits: u8, mut nonce: u64) -> (PowProof, u64) {
    loop {
        let nonce_hex = hex::encode(nonce.to_le_bytes());
        if pow_verify(id_hex, &nonce_hex, bits) {
            return (
                PowProof {
                    nonce: nonce_hex,
                    bits,
                },
                nonce + 1,
            );
        }
        nonce += 1;
    }
}

// ---------------------------------------------------------------------------
// Pinned KAT inputs (§5) and the expected cross-language outputs.
//
// The 64-hex KAT constants are written as two concatenated 32-char halves so
// they are not a bare 64-char hex run in source.
// ---------------------------------------------------------------------------

const SENDER_SEED: SecretSeed = [0x01; 32];
const RECIPIENT_SEED: SecretSeed = [0x02; 32];
const EPHEMERAL_SECRET: [u8; 32] = [0x03; 32];
const KAT_NONCE: [u8; 24] = [0x04; 24];
const KAT_SENT_AT: u64 = 1730000000000;
const KAT_EXPIRES_AT: u64 = 1731209600000;
const KAT_PAYLOAD: &[u8] = br#"{"kind":"text","body":"hello kovanica","ts":1730000000000}"#;

/// Independently computed from the §5 pinned inputs (see §5 evidence).
const KAT_ID: &str = concat!(
    "8a4cc33a9753651dd79d7e1ba4802cc0",
    "c5034efbba7b4590b37a6d2c5ad88c3d",
);
/// Ed25519 is deterministic, so the signature is a stable KAT as well.
const KAT_SIG: &str =
    "SPDd52nG1EiZG/azO+dccZktmpCzkZTzPVgSWmDv+Sr7CM/N9Blb8i4DQzxsvnZjZmPi9+jCYAXjYd1NDcNIBQ==";

fn sender_pub() -> PublicKey {
    SigningKey::from_bytes(&SENDER_SEED)
        .verifying_key()
        .to_bytes()
}

fn recipient_pub() -> PublicKey {
    SigningKey::from_bytes(&RECIPIENT_SEED)
        .verifying_key()
        .to_bytes()
}

// ---------------------------------------------------------------------------
// Envelope JSON round-trip.
// ---------------------------------------------------------------------------

#[test]
fn envelope_json_round_trip() {
    let envelope = kovanica_comms_relay::envelope::seal_and_sign(
        &SENDER_SEED,
        &recipient_pub(),
        KAT_PAYLOAD,
        KAT_SENT_AT,
        KAT_EXPIRES_AT,
    )
    .expect("seal_and_sign");

    let json = envelope.to_json().expect("to_json");
    let parsed = Envelope::from_json(json.as_bytes()).expect("from_json");
    assert_eq!(envelope, parsed);

    // Field names are exactly the §3.1 keys.
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    for key in [
        "v",
        "id",
        "to",
        "from",
        "sentAt",
        "expiresAt",
        "alg",
        "epk",
        "nonce",
        "ct",
        "sig",
    ] {
        assert!(value.get(key).is_some(), "missing key {key}");
    }

    // epk/nonce are base64 of 32/24 raw bytes.
    assert_eq!(
        STANDARD
            .decode(value["epk"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        STANDARD
            .decode(value["nonce"].as_str().unwrap())
            .unwrap()
            .len(),
        24
    );
}

#[test]
fn envelope_json_ignores_unknown_keys_and_rejects_missing() {
    let envelope = kovanica_comms_relay::envelope::seal_and_sign(
        &SENDER_SEED,
        &recipient_pub(),
        KAT_PAYLOAD,
        KAT_SENT_AT,
        KAT_EXPIRES_AT,
    )
    .unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&envelope.to_json().unwrap()).unwrap();
    value["futureField"] = serde_json::json!({"nested": true});
    let parsed = Envelope::from_json(value.to_string().as_bytes()).expect("unknown keys ignored");
    assert_eq!(parsed, envelope);

    // Missing a required key → reject.
    value.as_object_mut().unwrap().remove("ct");
    assert!(Envelope::from_json(value.to_string().as_bytes()).is_err());

    // Wrong type for a required key → reject.
    let mut bad: serde_json::Value = serde_json::from_str(&envelope.to_json().unwrap()).unwrap();
    bad["sentAt"] = serde_json::json!("not-a-number");
    assert!(Envelope::from_json(bad.to_string().as_bytes()).is_err());
}

// ---------------------------------------------------------------------------
// Envelope KAT (§5).
// ---------------------------------------------------------------------------

#[test]
fn envelope_kat_matches_pinned_values() {
    let mut cipher =
        X25519Cipher::deterministic_from_seed(&SENDER_SEED, EPHEMERAL_SECRET, KAT_NONCE);
    let envelope = kovanica_comms_relay::envelope::seal_and_sign_with_cipher(
        &mut cipher,
        &SENDER_SEED,
        &recipient_pub(),
        KAT_PAYLOAD,
        KAT_SENT_AT,
        KAT_EXPIRES_AT,
    )
    .expect("seal_and_sign_with_cipher");

    // Pin the intermediate sizes from §5.
    assert_eq!(KAT_PAYLOAD.len(), 58, "payload json must be 58 bytes");
    assert_eq!(envelope.ct.len(), 272, "bucket 256 + 16-byte tag");
    assert_eq!(envelope.alg, ALG_V1);

    assert_eq!(envelope.id, KAT_ID, "envelope id KAT");
    assert_eq!(STANDARD.encode(&envelope.sig), KAT_SIG, "envelope sig KAT");

    // The signature verifies against the sender key, and `from` is its comms id.
    envelope.verify(&sender_pub()).expect("verify");
    assert_eq!(
        envelope.from,
        comms_id_hex(&kovanica_comms_relay::comms_id_bytes(&sender_pub()))
    );
}

#[test]
fn tampered_field_is_rejected() {
    let mut cipher =
        X25519Cipher::deterministic_from_seed(&SENDER_SEED, EPHEMERAL_SECRET, KAT_NONCE);
    let envelope = kovanica_comms_relay::envelope::seal_and_sign_with_cipher(
        &mut cipher,
        &SENDER_SEED,
        &recipient_pub(),
        KAT_PAYLOAD,
        KAT_SENT_AT,
        KAT_EXPIRES_AT,
    )
    .unwrap();
    envelope.verify(&sender_pub()).expect("clean verify");

    // Flip a ciphertext byte: id recomputation and the signature both fail.
    let mut tampered = envelope.clone();
    tampered.ct[0] ^= 0xff;
    assert!(tampered.verify(&sender_pub()).is_err());

    // Tamper a signed field directly and leave `id` stale.
    let mut tampered = envelope.clone();
    tampered.sent_at = envelope.sent_at + 1;
    assert!(tampered.verify(&sender_pub()).is_err());

    // Tamper the signature.
    let mut tampered = envelope.clone();
    tampered.sig[0] ^= 0x01;
    assert!(tampered.verify(&sender_pub()).is_err());

    // Verify against the wrong sender key.
    assert!(envelope.verify(&recipient_pub()).is_err());
}

#[test]
fn comms_id_derivation_matches_canonical_vector() {
    // Cross-check our local BLAKE3 derivation against `kovanica-comms-core`'s
    // published cross-language vector (pubkey = 32 × 0x01).
    assert_eq!(
        comms_id_hex(&kovanica_comms_relay::comms_id_bytes(&[0x01; 32])),
        concat!(
            "6076cc6f05dbd8ad851ba6aa6b7e85c8",
            "dce112186e16d3e267663641d9fa9339",
        )
    );
}

// ---------------------------------------------------------------------------
// Payload padding (§3.2).
// ---------------------------------------------------------------------------

#[test]
fn payload_padding_buckets_and_trim() {
    let padded = pad_payload(KAT_PAYLOAD).unwrap();
    assert_eq!(padded.len(), 256);
    assert_eq!(&padded[..KAT_PAYLOAD.len()], KAT_PAYLOAD);
    assert_eq!(padded[KAT_PAYLOAD.len()], 0);
    assert_eq!(padded.len() - KAT_PAYLOAD.len(), 198);
    let trimmed = trim_payload(&padded).unwrap();
    assert_eq!(trimmed["kind"], "text");
    assert_eq!(trimmed["body"], "hello kovanica");
    assert_eq!(trimmed["ts"], 1730000000000u64);

    // Boundaries: a payload that is exactly a bucket tips into the next one.
    assert_eq!(pad_payload(&[b'x'; 255]).unwrap().len(), 256);
    assert_eq!(pad_payload(&[b'x'; 256]).unwrap().len(), 1024);
    assert_eq!(pad_payload(&[b'x'; 16383]).unwrap().len(), 16384);
    assert!(pad_payload(&[b'x'; 16384]).is_err());
}

// ---------------------------------------------------------------------------
// HTTP end-to-end: POST → GET → ack → GET (§4 + §5 round-trip).
// ---------------------------------------------------------------------------

async fn spawn_relay() -> (Arc<Store>, String) {
    let store = Arc::new(Store::new());
    let app = kovanica_comms_relay::router(store.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (store, format!("http://{addr}"))
}

#[tokio::test]
async fn http_post_get_ack_get_round_trip() {
    let _guard = ENV_LOCK.lock().await;
    std::env::remove_var("KOVANICA_RELAY_ALLOW_UNPAID");

    let (_store, base) = spawn_relay().await;
    let client = RelayClient::new(base.clone());
    let recipient_key = SigningKey::from_bytes(&RECIPIENT_SEED);
    let recipient_id = comms_id_hex(&kovanica_comms_relay::comms_id_bytes(&recipient_pub()));

    // Health starts empty.
    let health = client.health().await.expect("health");
    assert!(health.ok);
    assert_eq!(health.envelopes, 0);

    // A seals → POSTs for B with valid PoW (fresh TTL — the KAT timestamps are in the past).
    let now = kovanica_comms_relay::now_ms();
    let envelope = kovanica_comms_relay::envelope::seal_and_sign(
        &SENDER_SEED,
        &recipient_pub(),
        KAT_PAYLOAD,
        now,
        now + 24 * 60 * 60 * 1000,
    )
    .unwrap();
    let (pow1, next_nonce) = solve_pow_from(&envelope.id, 20, 0);
    let id = client
        .post_submission(&SubmissionWrapper {
            envelope: envelope.clone(),
            pow: Some(pow1),
            payment: None,
        })
        .await
        .expect("post with pow");
    assert_eq!(id, envelope.id);
    // Idempotent re-POST (with a fresh PoW nonce so replay protection allows it).
    let (pow2, _) = solve_pow_from(&envelope.id, 20, next_nonce);
    assert_eq!(
        client
            .post_submission(&SubmissionWrapper {
                envelope: envelope.clone(),
                pow: Some(pow2),
                payment: None,
            })
            .await
            .expect("re-post with fresh pow"),
        id
    );

    // GET returns it (but does not delete). Check the raw wire bytes too.
    let raw = reqwest::get(format!("{base}/v1/inbox/{recipient_id}"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !raw.contains("hello kovanica"),
        "plaintext leaked onto the wire"
    );
    assert!(raw.contains("envelopes"));

    let inbox = client
        .get_inbox(&recipient_id, None, None)
        .await
        .expect("inbox");
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].id, envelope.id);
    // B opens the buffered envelope offline.
    let mut opener = X25519Cipher::from_seed(&RECIPIENT_SEED);
    let aad = kovanica_comms_crypto::e2e_aad(
        &kovanica_comms_relay::comms_id_bytes(&recipient_pub()),
        &kovanica_comms_relay::comms_id_bytes(&sender_pub()),
    );
    let sealed = kovanica_comms_crypto::Sealed {
        alg: inbox[0].alg.clone(),
        epk: inbox[0].epk.clone().try_into().unwrap(),
        nonce: inbox[0].nonce.clone().try_into().unwrap(),
        ct: inbox[0].ct.clone(),
    };
    let plain = opener.open(&sealed, &aad).expect("open");
    let payload = trim_payload(&plain).expect("trim");
    assert_eq!(payload["body"], "hello kovanica");

    // GET again still returns it — GET never deletes.
    assert_eq!(
        client
            .get_inbox(&recipient_id, None, None)
            .await
            .unwrap()
            .len(),
        1
    );

    // Signed ack removes it.
    let deleted = client
        .ack_signed(&recipient_key, &recipient_id, std::slice::from_ref(&envelope.id))
        .await
        .unwrap();
    assert_eq!(deleted, 1);
    assert!(client
        .get_inbox(&recipient_id, None, None)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(client.health().await.unwrap().envelopes, 0);
}

#[tokio::test]
async fn http_rejects_unpaid_envelope_by_default_and_allows_when_enabled() {
    let _guard = ENV_LOCK.lock().await;
    std::env::remove_var("KOVANICA_RELAY_ALLOW_UNPAID");

    let (_store, base) = spawn_relay().await;
    let client = RelayClient::new(base);
    let now = kovanica_comms_relay::now_ms();
    let envelope = kovanica_comms_relay::envelope::seal_and_sign(
        &SENDER_SEED,
        &recipient_pub(),
        KAT_PAYLOAD,
        now,
        now + 60_000,
    )
    .unwrap();

    // Default (unset): bare unpaid envelope is rejected with 429 rate_limited.
    let err = client
        .post_envelope(&envelope)
        .await
        .expect_err("unpaid envelope must be rejected by default");
    match err {
        ClientError::Status { status, code, .. } => {
            assert_eq!(status, 429);
            assert_eq!(code, "rate_limited");
        }
        other => panic!("expected 429 status error, got {other:?}"),
    }

    // Explicit opt-in for dev/test: KOVANICA_RELAY_ALLOW_UNPAID=true permits bare envelope.
    std::env::set_var("KOVANICA_RELAY_ALLOW_UNPAID", "true");
    let res = client.post_envelope(&envelope).await;
    std::env::remove_var("KOVANICA_RELAY_ALLOW_UNPAID");
    assert_eq!(res.expect("allowed when explicitly enabled"), envelope.id);
}

#[tokio::test]
async fn http_rejects_unverified_htlc_payment() {
    let _guard = ENV_LOCK.lock().await;
    std::env::remove_var("KOVANICA_RELAY_ALLOW_UNPAID");

    let (_store, base) = spawn_relay().await;
    let client = RelayClient::new(base);
    let now = kovanica_comms_relay::now_ms();
    let envelope = kovanica_comms_relay::envelope::seal_and_sign(
        &SENDER_SEED,
        &recipient_pub(),
        KAT_PAYLOAD,
        now,
        now + 60_000,
    )
    .unwrap();

    let fake_payment = PaymentProof {
        htlc_id: "00".repeat(32),
        preimage: STANDARD.encode(b"fake-preimage"),
        amount_atoms: 1_000_000,
        expiry: now + 600_000,
        sender_addr: Some("11".repeat(32)),
        claimer_addr: "22".repeat(32),
    };

    let err = client
        .post_submission(&SubmissionWrapper {
            envelope,
            pow: None,
            payment: Some(fake_payment),
        })
        .await
        .expect_err("unverified off-chain HTLC payment must be rejected");
    match err {
        ClientError::Status {
            status,
            code,
            message,
        } => {
            assert_eq!(status, 400);
            assert_eq!(code, "bad_request");
            assert!(
                message.contains("unverified off-chain HTLC payment disabled"),
                "unexpected message: {message}"
            );
        }
        other => panic!("expected 400 status error, got {other:?}"),
    }
}

#[tokio::test]
async fn http_ack_requires_valid_recipient_signature() {
    let _guard = ENV_LOCK.lock().await;
    std::env::remove_var("KOVANICA_RELAY_ALLOW_UNPAID");

    let (_store, base) = spawn_relay().await;
    let client = RelayClient::new(base.clone());
    let sender_key = SigningKey::from_bytes(&SENDER_SEED);
    let recipient_key = SigningKey::from_bytes(&RECIPIENT_SEED);
    let recipient_id = comms_id_hex(&kovanica_comms_relay::comms_id_bytes(&recipient_pub()));

    let now = kovanica_comms_relay::now_ms();
    let envelope = kovanica_comms_relay::envelope::seal_and_sign(
        &SENDER_SEED,
        &recipient_pub(),
        KAT_PAYLOAD,
        now,
        now + 60_000,
    )
    .unwrap();
    let (pow, _) = solve_pow_from(&envelope.id, 20, 0);
    client
        .post_submission(&SubmissionWrapper {
            envelope: envelope.clone(),
            pow: Some(pow),
            payment: None,
        })
        .await
        .expect("post with pow");

    // 1. Unsigned /v1/ack → 401 unauthorized.
    let err = client
        .ack(&recipient_id, std::slice::from_ref(&envelope.id))
        .await
        .expect_err("unsigned ack must fail");
    match err {
        ClientError::Status { status, code, .. } => {
            assert_eq!(status, 401);
            assert_eq!(code, "unauthorized");
        }
        other => panic!("expected 401, got {other:?}"),
    }

    // 2. Signed by wrong key (sender trying to delete recipient's inbox) → 401 unauthorized.
    let err = client
        .ack_signed(&sender_key, &recipient_id, std::slice::from_ref(&envelope.id))
        .await
        .expect_err("wrong-key ack must fail");
    match err {
        ClientError::Status { status, code, .. } => {
            assert_eq!(status, 401);
            assert_eq!(code, "unauthorized");
        }
        other => panic!("expected 401, got {other:?}"),
    }

    // 3. Correct recipient pubkey, but forged/corrupted signature → 401 unauthorized.
    let msg = ack_signing_bytes(&recipient_id, std::slice::from_ref(&envelope.id));
    let mut forged_sig = recipient_key.sign(&msg).to_bytes();
    forged_sig[0] ^= 0xff;
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/ack"))
        .json(&serde_json::json!({
            "to": recipient_id,
            "ids": [envelope.id],
            "pubkey": hex::encode(recipient_pub()),
            "signature": hex::encode(forged_sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "unauthorized");

    // 4. Valid signature over a different id list → 401 unauthorized.
    let other_id = "aa".repeat(32);
    let other_sig = recipient_key
        .sign(&ack_signing_bytes(&recipient_id, std::slice::from_ref(&other_id)))
        .to_bytes();
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/ack"))
        .json(&serde_json::json!({
            "to": recipient_id,
            "ids": [envelope.id],
            "pubkey": hex::encode(recipient_pub()),
            "signature": hex::encode(other_sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);

    // Envelope must still be present after all failed ack attempts.
    assert_eq!(
        client
            .get_inbox(&recipient_id, None, None)
            .await
            .unwrap()
            .len(),
        1
    );

    // 5. Properly signed ack by recipient succeeds and deletes the envelope.
    let deleted = client
        .ack_signed(&recipient_key, &recipient_id, std::slice::from_ref(&envelope.id))
        .await
        .expect("signed ack must succeed");
    assert_eq!(deleted, 1);
    assert!(client
        .get_inbox(&recipient_id, None, None)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn http_unknown_recipient_is_empty_200() {
    let (_store, base) = spawn_relay().await;
    let client = RelayClient::new(base);
    let nobody = comms_id_hex(&[0x42; 32]);
    let inbox = client.get_inbox(&nobody, None, None).await.expect("inbox");
    assert!(inbox.is_empty());
}

#[tokio::test]
async fn http_rejects_bad_id_and_oversized_body() {
    let (_store, base) = spawn_relay().await;

    // Bad comms id → 400 bad_request with a §4 error body.
    let response = reqwest::get(format!("{base}/v1/inbox/not-a-hex-id"))
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "bad_request");

    // Oversized envelope JSON → 413 too_large.
    let oversized = vec![b' '; 64 * 1024 + 1];
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/envelope"))
        .header("content-type", "application/json")
        .body(oversized)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 413);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "too_large");
}
