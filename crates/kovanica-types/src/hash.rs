//! BLAKE3-based hash type.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::fmt;

/// 32-byte BLAKE3 hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Compute BLAKE3 hash of the given data.
    pub fn new(data: impl AsRef<[u8]>) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(data.as_ref());
        Self(*hasher.finalize().as_bytes())
    }

    /// Compute BLAKE3 hash with a domain key (domain separation).
    pub fn new_keyed(domain: &[u8], data: impl AsRef<[u8]>) -> Self {
        let mut key = [0u8; 32];
        let len = domain.len().min(32);
        key[..len].copy_from_slice(&domain[..len]);
        let mut hasher = Hasher::new_keyed(&key);
        hasher.update(data.as_ref());
        Self(*hasher.finalize().as_bytes())
    }

    /// Domain tag for block digests.
    pub const DOMAIN_BLOCK: &'static [u8] = b"KVNC-BLOCK-v1";
    /// Domain tag for transactions.
    pub const DOMAIN_TX: &'static [u8] = b"KVNC-TX-v1";
    /// Domain tag for digest/merkle pairing.
    pub const DOMAIN_DIGEST: &'static [u8] = b"KVNC-DIGEST-v1";
    /// Domain tag for merkle tree pairing.
    pub const DOMAIN_MERKLE: &'static [u8] = b"KVNC-MERKLE-v1";
    /// Domain tag for a committed-leader header.
    pub const DOMAIN_HEADER: &'static [u8] = b"KVNC-HEADER-v1";
    /// Domain tag for an account-tree leaf.
    pub const DOMAIN_ACCOUNT: &'static [u8] = b"KVNC-ACCOUNT-v1";
    /// Domain tag for an empty account-tree subtree.
    pub const DOMAIN_ACCOUNT_EMPTY: &'static [u8] = b"KVNC-ACCT-EMPTY";
    /// Domain tag for an account-tree internal node.
    pub const DOMAIN_SMT: &'static [u8] = b"KVNC-SMT-v1";
    /// Domain tag for the committee bound into a commit seal.
    pub const DOMAIN_COMMITTEE: &'static [u8] = b"KVNC-COMMITTEE-v1";
    /// Domain tag for an equivocation-evidence id.
    pub const DOMAIN_EVIDENCE: &'static [u8] = b"KVNC-EVIDENCE-v1";
    /// Domain tag for PoW block header preimage hashing (ADR 0003).
    pub const DOMAIN_POW_HEADER: &'static [u8] = b"KVNC-POW-HDR-v1";

    /// Zero hash (useful for genesis).
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex()[..16]) // short form
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod domain_tests {
    use super::Hash;

    /// Toni's 2026-10-19 decision: every hash domain is `KVNC-*` (chain 4
    /// reset). The tags must also stay pairwise distinct so no two hash uses
    /// can collide.
    #[test]
    fn hash_domains_are_kuna_and_distinct() {
        let domains: [&[u8]; 10] = [
            Hash::DOMAIN_BLOCK,
            Hash::DOMAIN_TX,
            Hash::DOMAIN_DIGEST,
            Hash::DOMAIN_MERKLE,
            Hash::DOMAIN_HEADER,
            Hash::DOMAIN_ACCOUNT,
            Hash::DOMAIN_ACCOUNT_EMPTY,
            Hash::DOMAIN_SMT,
            Hash::DOMAIN_COMMITTEE,
            Hash::DOMAIN_EVIDENCE,
        ];
        for (i, d) in domains.iter().enumerate() {
            assert!(
                d.starts_with(b"KVNC-"),
                "domain {} is not KVNC-*",
                String::from_utf8_lossy(d)
            );
            for other in &domains[i + 1..] {
                assert_ne!(d, other, "duplicate hash domain");
            }
        }
    }

    /// `new_keyed` uses the tag as a 32-byte BLAKE3 key and truncates
    /// anything longer, so two long tags with the same 32-byte prefix would
    /// silently collide. Every tag must fit.
    #[test]
    fn hash_domains_fit_the_32_byte_key() {
        for d in [
            Hash::DOMAIN_BLOCK,
            Hash::DOMAIN_TX,
            Hash::DOMAIN_DIGEST,
            Hash::DOMAIN_MERKLE,
            Hash::DOMAIN_HEADER,
            Hash::DOMAIN_ACCOUNT,
            Hash::DOMAIN_ACCOUNT_EMPTY,
            Hash::DOMAIN_SMT,
            Hash::DOMAIN_COMMITTEE,
            Hash::DOMAIN_EVIDENCE,
        ] {
            assert!(
                d.len() <= 32,
                "{} is longer than 32 B",
                String::from_utf8_lossy(d)
            );
        }
    }

    /// Known-answer digests: `new_keyed(domain, b"kovanica-kat")`, computed
    /// independently (Python `blake3`, key = tag zero-padded to 32 B). A
    /// change to a tag or to the keying shows up here.
    #[test]
    fn hash_domain_known_answers() {
        let expected: [(&[u8], &str); 10] = [
            (
                Hash::DOMAIN_BLOCK,
                "0c95c748046c836ddc3a4006613272825aa9c874e056609bb472e5fecc79920e",
            ),
            (
                Hash::DOMAIN_TX,
                "70f2f9e8b8d2f541a523323664634b1ce048bbe7c38a2b6151fa7ab51bfd1c9b",
            ),
            (
                Hash::DOMAIN_DIGEST,
                "7c83348e9b054cb909c0a0526560cb361ba5bdfaf1a2f67ed368e36fbb3c50d4",
            ),
            (
                Hash::DOMAIN_MERKLE,
                "199ed6659628074389904b2826c52debbf3b3da89d61382c83de131f0ef94ee4",
            ),
            (
                Hash::DOMAIN_HEADER,
                "7614d740c40436dd2e6367af3ace8eb124d385dfb93539f5c6310f40fccba6bd",
            ),
            (
                Hash::DOMAIN_ACCOUNT,
                "93b22b52d3d86edd9e100b6d17461eb534ff4d5c5903e8c51434f5805e7c0c6f",
            ),
            (
                Hash::DOMAIN_ACCOUNT_EMPTY,
                "c03604e800110c65997a843fa3ce781f74d47e85e1e13691a431785d523eed39",
            ),
            (
                Hash::DOMAIN_SMT,
                "9a7b04a92fcf99c2ff7bc7b2e17d146a97e3b0aba8520e5cd435138541b31558",
            ),
            (
                Hash::DOMAIN_COMMITTEE,
                "a71c6b5f54fbf08d42a7f9951112604d0880b431310226322725dc1af2e749f6",
            ),
            (
                Hash::DOMAIN_EVIDENCE,
                "47f083ca243ef4277b41352ea5f1f93a0a4b64b13fa308d66bae383a4f08417a",
            ),
        ];
        for (domain, hex) in expected {
            assert_eq!(
                Hash::new_keyed(domain, b"kovanica-kat").to_hex(),
                hex,
                "{}",
                String::from_utf8_lossy(domain)
            );
        }
    }
}
