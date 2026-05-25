//! Public types for the moderation library.
//!
//! All types in this module are deliberately opaque from a forum-content
//! perspective. The library only manipulates them as bytes / hashes / IDs —
//! it has no business knowing what they represent in any specific forum.

use serde::{Deserialize, Serialize};

/// Identifier for one forum instance.
///
/// Each forum instance has its own membership registry, moderator set, and
/// parameters (K, N-of-M). The library is multi-instance-aware: every
/// operation takes a `ForumId` to scope it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ForumId(pub [u8; 32]);

impl ForumId {
    /// Construct from raw bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// View as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Opaque content identifier — typically a Poseidon hash of the content
/// payload as defined by the forum application.
///
/// **The library MUST NOT inspect or interpret these bytes.** Any code in
/// `moderation-lib/` that branches on the value of a `ContentId` (other than
/// equality checks) is violating the forum-agnostic contract.
///
/// In LP-0016 instances:
/// - Basecamp module computes `ContentId = Poseidon(thread_id || body_bytes)`
/// - Webapp computes `ContentId = Poseidon(post_form_payload)`
///
/// Both forms are unknown to (and irrelevant to) the library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    /// Construct from raw bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// A member's secret key material.
///
/// The caller is responsible for secure storage. The library does not
/// persist key material to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberKey {
    /// 32-byte identity secret (the `a_0` of the Shamir polynomial).
    pub secret: [u8; 32],
    /// 32-byte commitment = Poseidon(secret). Public.
    pub commitment: [u8; 32],
    /// The forum this member belongs to.
    pub forum_id: ForumId,
}

/// A Groth16 ZK proof of post authorship by a registered, non-revoked member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostProof {
    /// Forum instance this proof is for.
    pub forum_id: ForumId,
    /// The content being attested to.
    pub content_id: ContentId,
    /// Encrypted Shamir share for the threshold-decryption ceremony.
    pub encrypted_share: Vec<u8>,
    /// The Groth16 proof bytes.
    pub groth16_proof: Vec<u8>,
    /// Public inputs to the proof (Merkle root, revocation root, etc.)
    pub public_inputs: Vec<u8>,
}

/// One moderator's partial certificate against a post.
///
/// `N` of these aggregate to form one [`FullCertificate`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialCert {
    /// Which forum.
    pub forum_id: ForumId,
    /// Which post is being struck.
    pub post_id: ContentId,
    /// Moderator's public key (for verification).
    pub moderator_pubkey: [u8; 32],
    /// Moderator's signature over `(forum_id, post_id, reason_hash)`.
    pub signature: Vec<u8>,
    /// Partial decryption share of the encrypted Shamir share.
    pub partial_decryption: Vec<u8>,
    /// Moderator's stated reason (free-text, hashed in signature).
    pub reason: String,
}

/// An aggregated certificate from N moderators.
///
/// `K` of these (each against different posts from the same author) trigger a
/// slash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullCertificate {
    /// Which forum.
    pub forum_id: ForumId,
    /// Which post.
    pub post_id: ContentId,
    /// The N participating moderator pubkeys.
    pub moderator_pubkeys: Vec<[u8; 32]>,
    /// Aggregated threshold signature.
    pub aggregate_signature: Vec<u8>,
    /// Decrypted Shamir share (revealed by the threshold-decryption ceremony).
    pub revealed_share_x: [u8; 32],
    /// Decrypted Shamir share y.
    pub revealed_share_y: [u8; 32],
    /// Revealed commitment of the struck author.
    pub revealed_commitment: [u8; 32],
}

/// Opaque on-chain transaction hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxHash(pub [u8; 32]);

impl TxHash {
    /// Construct from raw bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: types round-trip through serde JSON.
    #[test]
    fn types_round_trip_serde() {
        let forum = ForumId([7u8; 32]);
        let json = serde_json::to_string(&forum).unwrap();
        let decoded: ForumId = serde_json::from_str(&json).unwrap();
        assert_eq!(forum, decoded);
    }
}
