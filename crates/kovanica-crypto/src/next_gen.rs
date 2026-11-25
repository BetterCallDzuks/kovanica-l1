//! Next-Generation Signature Schemes: Passkey/WebAuthn (Wave C #7) &
//! Post-Quantum ML-DSA-65 Hybrid Envelopes (Wave D #11).

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier as FipsVerifier};
use p256::ecdsa::signature::Verifier as P256Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use serde::{Deserialize, Serialize};

/// Canonical signature scheme tag for typed Kovanica accounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SignatureScheme {
    /// Standard Ed25519 (default, 32-byte pubkey, 64-byte signature).
    Ed25519 = 0,
    /// WebAuthn / Passkey secp256r1 (P-256) hardware biometric credential.
    Secp256r1WebAuthn = 1,
    /// Post-quantum hybrid: Ed25519 + NIST FIPS 204 ML-DSA-65 (Dilithium3).
    MlDsa65Hybrid = 2,
}

/// NIST FIPS 204 ML-DSA-65 public key length in bytes.
pub const ML_DSA_65_PUBKEY_BYTES: usize = 1_952;
/// NIST FIPS 204 ML-DSA-65 signature length in bytes.
pub const ML_DSA_65_SIG_BYTES: usize = 3_309;
/// Compressed secp256r1 (P-256) public key length in bytes.
pub const SECP256R1_COMPRESSED_PUBKEY_BYTES: usize = 33;
/// Uncompressed secp256r1 (P-256) public key length in bytes.
pub const SECP256R1_UNCOMPRESSED_PUBKEY_BYTES: usize = 65;

/// Deterministically derive a 32-byte typed Kovanica address from `(scheme, pubkey_bytes)`.
pub fn derive_typed_address(scheme: SignatureScheme, pubkey_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"KVNC/addr/v2");
    hasher.update(&[scheme as u8]);
    hasher.update(pubkey_bytes);
    *hasher.finalize().as_bytes()
}

/// WebAuthn / Passkey assertion payload for secp256r1 biometric accounts (Wave C #7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnAssertion {
    /// Compressed (33-byte) or uncompressed (65-byte) P-256 public key.
    pub pubkey: Vec<u8>,
    /// Raw WebAuthn `authenticatorData` bytes (>= 37 bytes per W3C WebAuthn).
    pub authenticator_data: Vec<u8>,
    /// Raw UTF-8 `clientDataJSON` bytes containing the base64url tx challenge.
    pub client_data_json: Vec<u8>,
    /// 64-byte raw `r || s` P-256 ECDSA signature.
    pub signature: Vec<u8>,
}

impl WebAuthnAssertion {
    /// Structural validation of a WebAuthn assertion envelope.
    pub fn validate_structure(&self) -> Result<(), &'static str> {
        if self.pubkey.len() != SECP256R1_COMPRESSED_PUBKEY_BYTES
            && self.pubkey.len() != SECP256R1_UNCOMPRESSED_PUBKEY_BYTES
        {
            return Err("invalid secp256r1 public key length");
        }
        if self.authenticator_data.len() < 37 {
            return Err("authenticator_data shorter than 37-byte WebAuthn minimum");
        }
        if self.client_data_json.is_empty() {
            return Err("empty clientDataJSON");
        }
        if self.signature.len() != 64 {
            return Err("expected 64-byte r||s secp256r1 signature");
        }
        Ok(())
    }

    /// Derive the Kovanica 32-byte account address for this Passkey credential.
    pub fn derive_address(&self) -> [u8; 32] {
        derive_typed_address(SignatureScheme::Secp256r1WebAuthn, &self.pubkey)
    }

    /// Compute the deterministic BLAKE3 digest binding `authenticator_data`,
    /// `client_data_json`, and the Kovanica transaction hash.
    pub fn signing_payload_digest(&self, tx_hash: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"KVNC/webauthn/v1");
        h.update(tx_hash);
        h.update(&(self.authenticator_data.len() as u64).to_le_bytes());
        h.update(&self.authenticator_data);
        h.update(&(self.client_data_json.len() as u64).to_le_bytes());
        h.update(&self.client_data_json);
        *h.finalize().as_bytes()
    }

    /// Verify a real secp256r1 (P-256) ECDSA signature over the domain-separated
    /// Kovanica WebAuthn payload digest (`signing_payload_digest(tx_hash)`).
    pub fn verify_p256(&self, tx_hash: &[u8; 32]) -> Result<(), &'static str> {
        self.validate_structure()?;
        let vk = P256VerifyingKey::from_sec1_bytes(&self.pubkey)
            .map_err(|_| "invalid secp256r1 public key point")?;
        let sig = P256Signature::from_slice(&self.signature)
            .map_err(|_| "invalid secp256r1 signature encoding")?;
        let digest = self.signing_payload_digest(tx_hash);
        vk.verify(&digest, &sig)
            .map_err(|_| "secp256r1 ECDSA signature verification failed")
    }
}

/// Post-Quantum Hybrid envelope pairing Ed25519 with NIST FIPS 204 ML-DSA-65 (Wave D #11).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridPqEnvelope {
    /// Classical 32-byte Ed25519 public key.
    pub ed25519_pubkey: [u8; 32],
    /// Classical 64-byte Ed25519 signature over `compute_pq_hybrid_digest`.
    pub ed25519_signature: Vec<u8>,
    /// BLAKE3-256 hash of the 1,952-byte ML-DSA-65 public key.
    pub pq_pubkey_hash: [u8; 32],
    /// Raw ML-DSA-65 signature bytes (3,309 bytes per NIST FIPS 204).
    pub pq_signature: Vec<u8>,
}

impl HybridPqEnvelope {
    /// Domain-separated digest signed by both Ed25519 and ML-DSA-65 keys.
    pub fn hybrid_digest(
        ed25519_pubkey: &[u8; 32],
        pq_pubkey_hash: &[u8; 32],
        tx_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"KVNC/pq-mldsa65-hybrid/v1");
        h.update(ed25519_pubkey);
        h.update(pq_pubkey_hash);
        h.update(tx_hash);
        *h.finalize().as_bytes()
    }

    /// Derive the deterministic 32-byte hybrid PQ account address.
    pub fn derive_address(ed25519_pubkey: &[u8; 32], pq_pubkey_hash: &[u8; 32]) -> [u8; 32] {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(ed25519_pubkey);
        combined[32..].copy_from_slice(pq_pubkey_hash);
        derive_typed_address(SignatureScheme::MlDsa65Hybrid, &combined)
    }

    /// Validate NIST FIPS 204 ML-DSA-65 signature length and verify the classical
    /// Ed25519 signature component over the hybrid digest.
    pub fn validate_and_verify_classical(&self, tx_hash: &[u8; 32]) -> Result<(), &'static str> {
        if self.pq_signature.len() != ML_DSA_65_SIG_BYTES {
            return Err("invalid ML-DSA-65 signature length (expected 3309 bytes)");
        }
        let sig_bytes: [u8; 64] = self
            .ed25519_signature
            .as_slice()
            .try_into()
            .map_err(|_| "invalid Ed25519 signature length")?;
        let digest = Self::hybrid_digest(&self.ed25519_pubkey, &self.pq_pubkey_hash, tx_hash);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&self.ed25519_pubkey)
            .map_err(|_| "invalid Ed25519 public key")?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        vk.verify_strict(&digest, &sig)
            .map_err(|_| "Ed25519 hybrid signature verification failed")
    }

    /// Full hybrid cryptographic verification: verifies BOTH the classical
    /// Ed25519 signature AND the NIST FIPS 204 ML-DSA-65 signature against
    /// the provided 1,952-byte ML-DSA-65 public key (whose BLAKE3 hash must
    /// match `self.pq_pubkey_hash`).
    pub fn verify_hybrid(&self, pq_pubkey: &[u8], tx_hash: &[u8; 32]) -> Result<(), &'static str> {
        if pq_pubkey.len() != ML_DSA_65_PUBKEY_BYTES {
            return Err("invalid ML-DSA-65 public key length (expected 1952 bytes)");
        }
        if blake3::hash(pq_pubkey).as_bytes() != &self.pq_pubkey_hash {
            return Err("ML-DSA-65 public key hash mismatch");
        }
        self.validate_and_verify_classical(tx_hash)?;
        let pk_arr: [u8; ML_DSA_65_PUBKEY_BYTES] = pq_pubkey
            .try_into()
            .map_err(|_| "invalid ML-DSA-65 public key length")?;
        let sig_arr: [u8; ML_DSA_65_SIG_BYTES] = self
            .pq_signature
            .as_slice()
            .try_into()
            .map_err(|_| "invalid ML-DSA-65 signature length")?;
        let ml_pk = ml_dsa_65::PublicKey::try_from_bytes(pk_arr)
            .map_err(|_| "malformed ML-DSA-65 public key")?;
        let digest = Self::hybrid_digest(&self.ed25519_pubkey, &self.pq_pubkey_hash, tx_hash);
        if !ml_pk.verify(&digest, &sig_arr, &[]) {
            return Err("ML-DSA-65 post-quantum signature verification failed");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use fips204::traits::Signer as FipsSigner;

    #[test]
    fn typed_addresses_are_scheme_separated() {
        let pk = [0x55u8; 32];
        let ed = derive_typed_address(SignatureScheme::Ed25519, &pk);
        let p256 = derive_typed_address(SignatureScheme::Secp256r1WebAuthn, &pk);
        let pq = derive_typed_address(SignatureScheme::MlDsa65Hybrid, &pk);
        assert_ne!(ed, p256);
        assert_ne!(p256, pq);
        assert_ne!(ed, pq);
    }

    #[test]
    fn webauthn_p256_real_ecdsa_sign_and_verify() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let vk = sk.verifying_key();
        let pubkey = vk.to_encoded_point(true).as_bytes().to_vec();
        let tx_hash = [0x77u8; 32];

        let mut assertion = WebAuthnAssertion {
            pubkey,
            authenticator_data: vec![0x01; 37],
            client_data_json: br#"{"type":"webauthn.get","challenge":"kovanica"}"#.to_vec(),
            signature: vec![0u8; 64],
        };
        let digest = assertion.signing_payload_digest(&tx_hash);
        let sig: P256Signature = sk.sign(&digest);
        assertion.signature = sig.to_bytes().to_vec();

        assert!(assertion.verify_p256(&tx_hash).is_ok());
        assert!(assertion.verify_p256(&[0x78u8; 32]).is_err());
    }

    #[test]
    fn hybrid_pq_envelope_real_mldsa65_and_ed25519_verify() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key().to_bytes();

        let (ml_pk, ml_sk) = ml_dsa_65::try_keygen().unwrap();
        let ml_pk_bytes = ml_pk.into_bytes();
        let pq_pk_hash = *blake3::hash(&ml_pk_bytes).as_bytes();
        let tx_hash = [0x99u8; 32];
        let digest = HybridPqEnvelope::hybrid_digest(&pk, &pq_pk_hash, &tx_hash);

        let ed_sig = sk.sign(&digest).to_bytes().to_vec();
        let pq_sig = ml_sk.try_sign(&digest, &[]).unwrap().to_vec();

        let valid = HybridPqEnvelope {
            ed25519_pubkey: pk,
            ed25519_signature: ed_sig,
            pq_pubkey_hash: pq_pk_hash,
            pq_signature: pq_sig,
        };
        assert!(valid.verify_hybrid(&ml_pk_bytes, &tx_hash).is_ok());
        assert!(valid.verify_hybrid(&ml_pk_bytes, &[0x98u8; 32]).is_err());
    }
}
