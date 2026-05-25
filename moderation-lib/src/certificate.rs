//! Certificate aggregation gates.
//!
//! Two distinct threshold gates live here:
//!
//! 1. **N-of-M partial certificates → one full certificate** ([`aggregate_partials`]).
//!    Implements LP-0016 success criteria F4 (moderator threshold construction)
//!    and F5 (sub-threshold rejection). The N moderators independently
//!    contribute partial decryptions of the post's encrypted Shamir share;
//!    once N partials are collected, the full share is recoverable.
//!
//! 2. **K full certificates → slash readiness** ([`verify_slash_certificates`]).
//!    Implements F6 (slash submission). K certificates against the *same
//!    member commitment* satisfy the slash precondition: their revealed
//!    shares plug into [`crate::shamir::recover_secret`] to reconstruct the
//!    identity secret.
//!
//! ## What is stubbed and why
//!
//! The *aggregation gate logic* (validity checks, threshold counting, member
//! deduplication) is implemented in full. The underlying *cryptographic
//! aggregation* (BLS partial signature combination, threshold ElGamal partial
//! decryption combination) is stubbed — D5-D6 wires in `fastcrypto-tbls`.
//!
//! This separation is intentional: invariant bugs in the gate logic
//! (duplicate moderator slipping through, off-by-one threshold) are the
//! highest-likelihood real-world bugs and are testable today without LEZ
//! dependencies. The crypto math is supplied by audited libraries when we
//! wire them in.

use crate::error::ModerationError;
use crate::types::{ForumId, FullCertificate, PartialCert};
use std::collections::HashSet;

/// Per-forum certificate configuration.
///
/// In the on-chain version, this data lives in the membership registry's
/// per-`forum_id` PDA. Off-chain, the library reads it via LEZ RPC at
/// startup or per-operation.
#[derive(Debug, Clone)]
pub struct CertConfig {
    /// Forum this config applies to.
    pub forum_id: ForumId,
    /// N — the moderator threshold for a single strike.
    pub threshold_n: usize,
    /// M — total moderator pubkeys in the active set.
    pub authorized_moderators: Vec<[u8; 32]>,
}

impl CertConfig {
    /// Convenience: M = `authorized_moderators.len()`.
    #[must_use]
    pub fn m(&self) -> usize {
        self.authorized_moderators.len()
    }

    /// Sanity check: N must be > 0 and ≤ M.
    ///
    /// # Errors
    /// Returns [`ModerationError::Invariant`] if N is out of range.
    pub fn validate(&self) -> Result<(), ModerationError> {
        if self.threshold_n == 0 {
            return Err(ModerationError::Invariant(
                "threshold_n must be >= 1".to_string(),
            ));
        }
        if self.threshold_n > self.m() {
            return Err(ModerationError::Invariant(format!(
                "threshold_n ({}) cannot exceed moderator count ({})",
                self.threshold_n,
                self.m()
            )));
        }
        Ok(())
    }
}

/// Aggregate ≥N partial certificates into one full certificate.
///
/// Performs five gates in order:
///
/// 1. **Count**: at least N partials supplied
/// 2. **Forum**: all partials target this forum
/// 3. **Post**: all partials target the same post_id
/// 4. **Authorization**: every moderator is in the authorized set
/// 5. **Distinct moderators**: no moderator contributes twice
///
/// On success, the first N partials are aggregated into the returned
/// [`FullCertificate`]. The cryptographic aggregation (threshold decryption,
/// signature combination) is currently stubbed — see module docs.
///
/// # Errors
///
/// See [`ModerationError`] variants. Each gate maps to a specific variant for
/// granular error reporting upstream.
pub fn aggregate_partials(
    config: &CertConfig,
    partials: &[PartialCert],
) -> Result<FullCertificate, ModerationError> {
    config.validate()?;

    // Gate 1: count
    if partials.len() < config.threshold_n {
        return Err(ModerationError::BelowThreshold {
            supplied: partials.len(),
            required: config.threshold_n,
        });
    }

    // Gate 2: forum scope
    if !partials.iter().all(|p| p.forum_id == config.forum_id) {
        return Err(ModerationError::Mismatched);
    }

    // Gate 3: same post_id across partials
    let first_post_id = partials[0].post_id;
    if !partials.iter().all(|p| p.post_id == first_post_id) {
        return Err(ModerationError::Mismatched);
    }

    // Gate 4: every moderator is authorized
    let authorized: HashSet<&[u8; 32]> = config.authorized_moderators.iter().collect();
    if !partials
        .iter()
        .all(|p| authorized.contains(&p.moderator_pubkey))
    {
        return Err(ModerationError::NotModerator);
    }

    // Gate 5: no duplicate contributors
    let mut seen = HashSet::with_capacity(partials.len());
    for p in partials {
        if !seen.insert(p.moderator_pubkey) {
            return Err(ModerationError::Invariant(format!(
                "moderator {:?} contributed a duplicate partial",
                hex_short(&p.moderator_pubkey)
            )));
        }
    }

    // Take exactly the first N partials for deterministic aggregation.
    // Any subset of N would work cryptographically (any N-of-M shares
    // recover the same secret); we choose deterministically for testability.
    let selected = &partials[..config.threshold_n];

    Ok(FullCertificate {
        forum_id: config.forum_id,
        post_id: first_post_id,
        moderator_pubkeys: selected.iter().map(|p| p.moderator_pubkey).collect(),
        // STUB: real BLS aggregate signature lives here (D5-D6).
        // Concatenation of partial sigs is NOT a valid aggregate — placeholder only.
        aggregate_signature: Vec::new(),
        // STUB: real threshold decryption outputs the (x, y, commitment) here.
        // For now the caller cannot use this for actual slash reconstruction.
        revealed_share_x: [0u8; 32],
        revealed_share_y: [0u8; 32],
        revealed_commitment: [0u8; 32],
    })
}

/// Verify K certificates form a valid slash precondition.
///
/// Performs four gates:
///
/// 1. **Count**: at least K certificates supplied
/// 2. **Forum**: all target this forum
/// 3. **Same victim**: all certificates reveal the same member commitment
/// 4. **Distinct posts**: no certificate targets the same post twice (replay prevention)
///
/// On success, returns the slashed member's commitment.
///
/// # Errors
///
/// See [`ModerationError`].
pub fn verify_slash_certificates(
    forum_id: ForumId,
    threshold_k: usize,
    certs: &[FullCertificate],
) -> Result<[u8; 32], ModerationError> {
    // Gate 1: count
    if certs.len() < threshold_k {
        return Err(ModerationError::BelowThreshold {
            supplied: certs.len(),
            required: threshold_k,
        });
    }

    // Gate 2: forum scope
    if !certs.iter().all(|c| c.forum_id == forum_id) {
        return Err(ModerationError::Mismatched);
    }

    // Gate 3: all certs target the same victim
    let first_commitment = certs[0].revealed_commitment;
    if !certs
        .iter()
        .all(|c| c.revealed_commitment == first_commitment)
    {
        return Err(ModerationError::Mismatched);
    }

    // Gate 4: distinct post_ids — prevents an attacker from submitting
    // K copies of the same certificate to bypass the per-post strike rule.
    let mut seen_posts: HashSet<crate::types::ContentId> = HashSet::with_capacity(certs.len());
    for c in certs {
        if !seen_posts.insert(c.post_id) {
            return Err(ModerationError::Invariant(format!(
                "certificate against post_id {:?} appears twice",
                hex_short(&c.post_id.0)
            )));
        }
    }

    Ok(first_commitment)
}

/// Short hex format for error messages — 4 bytes is enough to identify a
/// moderator in a debug log without dumping 32 bytes.
fn hex_short(bytes: &[u8; 32]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}...",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContentId, FullCertificate, PartialCert};

    fn make_config(threshold_n: usize, m: usize) -> CertConfig {
        CertConfig {
            forum_id: ForumId([1u8; 32]),
            threshold_n,
            authorized_moderators: (0..m).map(|i| [i as u8 + 10; 32]).collect(),
        }
    }

    fn make_partial(
        forum: [u8; 32],
        post: [u8; 32],
        moderator: [u8; 32],
        reason: &str,
    ) -> PartialCert {
        PartialCert {
            forum_id: ForumId(forum),
            post_id: ContentId(post),
            moderator_pubkey: moderator,
            signature: vec![0xaa; 64],          // stub
            partial_decryption: vec![0xbb; 32], // stub
            reason: reason.to_string(),
        }
    }

    #[test]
    fn validates_threshold_zero_rejected() {
        let cfg = make_config(0, 3);
        assert!(matches!(cfg.validate(), Err(ModerationError::Invariant(_))));
    }

    #[test]
    fn validates_threshold_greater_than_m_rejected() {
        let cfg = make_config(5, 3);
        assert!(matches!(cfg.validate(), Err(ModerationError::Invariant(_))));
    }

    #[test]
    fn aggregate_below_threshold_fails() {
        let cfg = make_config(2, 3);
        let only_one = vec![make_partial(
            [1u8; 32],
            [42u8; 32],
            cfg.authorized_moderators[0],
            "spam",
        )];
        let err = aggregate_partials(&cfg, &only_one).unwrap_err();
        assert!(matches!(
            err,
            ModerationError::BelowThreshold {
                supplied: 1,
                required: 2
            }
        ));
    }

    #[test]
    fn aggregate_at_exact_threshold_succeeds() {
        let cfg = make_config(2, 3);
        let partials = vec![
            make_partial([1u8; 32], [42u8; 32], cfg.authorized_moderators[0], "r1"),
            make_partial([1u8; 32], [42u8; 32], cfg.authorized_moderators[1], "r2"),
        ];
        let cert = aggregate_partials(&cfg, &partials).expect("should succeed");
        assert_eq!(cert.post_id, ContentId([42u8; 32]));
        assert_eq!(cert.moderator_pubkeys.len(), 2);
    }

    #[test]
    fn aggregate_with_extras_takes_first_n() {
        // 5 partials supplied, threshold is 3 — first 3 selected
        let cfg = make_config(3, 5);
        let partials: Vec<_> = (0..5)
            .map(|i| make_partial([1u8; 32], [42u8; 32], cfg.authorized_moderators[i], "r"))
            .collect();
        let cert = aggregate_partials(&cfg, &partials).unwrap();
        assert_eq!(cert.moderator_pubkeys.len(), 3);
        assert_eq!(cert.moderator_pubkeys[0], cfg.authorized_moderators[0]);
        assert_eq!(cert.moderator_pubkeys[2], cfg.authorized_moderators[2]);
    }

    #[test]
    fn aggregate_wrong_forum_fails() {
        let cfg = make_config(2, 3);
        let partials = vec![
            make_partial([1u8; 32], [42u8; 32], cfg.authorized_moderators[0], "r"),
            make_partial([99u8; 32], [42u8; 32], cfg.authorized_moderators[1], "r"), // different forum
        ];
        let err = aggregate_partials(&cfg, &partials).unwrap_err();
        assert!(matches!(err, ModerationError::Mismatched));
    }

    #[test]
    fn aggregate_mismatched_post_ids_fails() {
        let cfg = make_config(2, 3);
        let partials = vec![
            make_partial([1u8; 32], [42u8; 32], cfg.authorized_moderators[0], "r"),
            make_partial([1u8; 32], [99u8; 32], cfg.authorized_moderators[1], "r"), // different post
        ];
        let err = aggregate_partials(&cfg, &partials).unwrap_err();
        assert!(matches!(err, ModerationError::Mismatched));
    }

    #[test]
    fn aggregate_unauthorized_moderator_fails() {
        let cfg = make_config(2, 3);
        let outsider = [99u8; 32]; // NOT in authorized list
        let partials = vec![
            make_partial([1u8; 32], [42u8; 32], cfg.authorized_moderators[0], "r"),
            make_partial([1u8; 32], [42u8; 32], outsider, "r"),
        ];
        let err = aggregate_partials(&cfg, &partials).unwrap_err();
        assert!(matches!(err, ModerationError::NotModerator));
    }

    #[test]
    fn aggregate_duplicate_moderator_fails() {
        let cfg = make_config(2, 3);
        let mod_0 = cfg.authorized_moderators[0];
        let partials = vec![
            make_partial([1u8; 32], [42u8; 32], mod_0, "first vote"),
            make_partial([1u8; 32], [42u8; 32], mod_0, "trying again"),
        ];
        let err = aggregate_partials(&cfg, &partials).unwrap_err();
        assert!(matches!(err, ModerationError::Invariant(_)));
    }

    fn make_cert(forum: [u8; 32], post: [u8; 32], commitment: [u8; 32]) -> FullCertificate {
        FullCertificate {
            forum_id: ForumId(forum),
            post_id: ContentId(post),
            moderator_pubkeys: vec![[1u8; 32], [2u8; 32]],
            aggregate_signature: vec![0xcc; 96],
            revealed_share_x: [0xdd; 32],
            revealed_share_y: [0xee; 32],
            revealed_commitment: commitment,
        }
    }

    #[test]
    fn slash_below_k_fails() {
        let only_one = vec![make_cert([1u8; 32], [10u8; 32], [50u8; 32])];
        let err = verify_slash_certificates(ForumId([1u8; 32]), 2, &only_one).unwrap_err();
        assert!(matches!(
            err,
            ModerationError::BelowThreshold {
                supplied: 1,
                required: 2
            }
        ));
    }

    #[test]
    fn slash_at_k_succeeds() {
        let certs = vec![
            make_cert([1u8; 32], [10u8; 32], [50u8; 32]),
            make_cert([1u8; 32], [11u8; 32], [50u8; 32]),
        ];
        let commitment =
            verify_slash_certificates(ForumId([1u8; 32]), 2, &certs).expect("should succeed");
        assert_eq!(commitment, [50u8; 32]);
    }

    #[test]
    fn slash_mismatched_forum_fails() {
        let certs = vec![
            make_cert([1u8; 32], [10u8; 32], [50u8; 32]),
            make_cert([99u8; 32], [11u8; 32], [50u8; 32]), // different forum
        ];
        let err = verify_slash_certificates(ForumId([1u8; 32]), 2, &certs).unwrap_err();
        assert!(matches!(err, ModerationError::Mismatched));
    }

    #[test]
    fn slash_different_victims_fails() {
        // Two strikes against DIFFERENT members — can't combine for one slash
        let certs = vec![
            make_cert([1u8; 32], [10u8; 32], [50u8; 32]),
            make_cert([1u8; 32], [11u8; 32], [99u8; 32]), // different commitment
        ];
        let err = verify_slash_certificates(ForumId([1u8; 32]), 2, &certs).unwrap_err();
        assert!(matches!(err, ModerationError::Mismatched));
    }

    #[test]
    fn slash_duplicate_post_fails() {
        // Attacker tries to use the same cert twice to slash with K=2
        let certs = vec![
            make_cert([1u8; 32], [10u8; 32], [50u8; 32]),
            make_cert([1u8; 32], [10u8; 32], [50u8; 32]), // same post_id!
        ];
        let err = verify_slash_certificates(ForumId([1u8; 32]), 2, &certs).unwrap_err();
        assert!(matches!(err, ModerationError::Invariant(_)));
    }

    #[test]
    fn slash_with_excess_certs_succeeds() {
        // K=2 but 4 certs supplied — should succeed (excess is fine)
        let certs = vec![
            make_cert([1u8; 32], [10u8; 32], [50u8; 32]),
            make_cert([1u8; 32], [11u8; 32], [50u8; 32]),
            make_cert([1u8; 32], [12u8; 32], [50u8; 32]),
            make_cert([1u8; 32], [13u8; 32], [50u8; 32]),
        ];
        let commitment = verify_slash_certificates(ForumId([1u8; 32]), 2, &certs).unwrap();
        assert_eq!(commitment, [50u8; 32]);
    }
}
