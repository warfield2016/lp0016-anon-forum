//! # moderation-lib
//!
//! Forum-agnostic threshold moderation library with cryptographic membership revocation.
//!
//! This crate is the deliverable described in success criterion **F10** of
//! [LP-0016](https://github.com/logos-co/lambda-prize/blob/master/prizes/LP-0016.md):
//!
//! > a standalone, forum-agnostic moderation library [...] makes no assumptions
//! > about forum content or structure, and uses the Logos stack for all off-chain activity.
//!
//! ## Forum-agnosticism contract
//!
//! The public API operates exclusively on opaque [`ContentId`] hashes. The library
//! has **no knowledge of forum content shape** — posts, threads, reactions, images,
//! audio, etc. are entirely the caller's responsibility. The forum app constructs
//! `ContentId = hash(its_own_content)` and the library treats that as an abstract
//! identifier.
//!
//! Two consumers in this submission demonstrate the contract:
//!
//! 1. **Basecamp Qt module** (native, Logos IPC) — `basecamp-forum-core/`
//! 2. **Next.js webapp on Vercel** (WASM, browser) — `webapp/`
//!
//! Both consumers import this crate unmodified.
//!
//! ## Architecture
//!
//! See `docs/architecture.md` for the system diagram. Headlines:
//!
//! - **Per-post proof**: Circom + Groth16 (sub-second on M-series Mac)
//! - **Slash verifier**: RISC0 zkVM guest on LEZ (verified on-chain)
//! - **Cryptographic primitive**: Shamir Secret Sharing over BN254 with K=2
//!   degree-1 polynomial reconstruction via Lagrange interpolation
//!   (see [`shamir`] module)
//! - **Trust model**: N-of-M moderator threshold for one strike; K accumulated
//!   strikes reconstruct identity secret and trigger slash
//!
//! ## Public API at a glance
//!
//! ```ignore
//! use moderation_lib::*;
//!
//! let lib = ModerationClient::new(config);
//! let member = lib.register(forum_id, stake)?;
//! let proof = lib.create_post_proof(forum_id, content_id)?;
//! let partial = lib.propose_strike(forum_id, post_id, "spam")?;
//! let cert = lib.aggregate_strike(&partials)?;
//! let tx = lib.submit_slash(forum_id, &certs)?;
//! ```

#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// Math identifiers like `a_0`, `a_1`, `x_1` appear unwrapped in docstrings as
// they would in a paper. Forcing backticks makes the math harder to read.
#![allow(clippy::doc_markdown)]
// Test code casts small loop indices to u8 — safe by construction
// (M ≤ 32 in tests, well within u8 range).
#![allow(clippy::cast_possible_truncation)]

pub mod certificate;
pub mod error;
pub mod shamir;
pub mod types;

pub use certificate::{aggregate_partials, verify_slash_certificates, CertConfig};
pub use error::ModerationError;
pub use shamir::{recover_secret_from_two_shares, ShamirShare};
pub use types::{ContentId, ForumId, FullCertificate, MemberKey, PartialCert, PostProof, TxHash};

/// Result type alias used throughout the library.
pub type Result<T> = core::result::Result<T, ModerationError>;

/// The public API contract.
///
/// Implementations of this trait MUST operate on opaque [`ContentId`] hashes
/// without inspecting or assuming structure of underlying forum content. The
/// trait definition enforces this at the type level — there is no path to
/// forum-content types from any method signature.
///
/// # Forum-agnosticism enforcement
///
/// Every method signature uses [`ContentId`] (a `[u8; 32]` newtype) or
/// other library-defined opaque types. Adding a method that takes
/// forum-content-shaped data would constitute a breaking change to the
/// contract and is explicitly out of scope.
pub trait ModerationLibrary {
    /// Register a new member in `forum_id` with the given stake.
    ///
    /// Returns the member's secret key material (caller's responsibility to
    /// store securely).
    ///
    /// # Errors
    /// Returns [`ModerationError::DuplicateRegistration`] if commitment is
    /// already registered, or [`ModerationError::InsufficientStake`] if the
    /// stake is below the forum's minimum.
    fn register(&self, forum_id: ForumId, stake: u64) -> Result<MemberKey>;

    /// Generate an anonymous post proof for the given `content_id`.
    ///
    /// The proof asserts:
    /// - Caller is a registered, non-revoked member of `forum_id`
    /// - One encrypted Shamir share of the caller's identity secret is leaked
    /// - All proof inputs bind to `content_id`
    ///
    /// # Errors
    /// Returns [`ModerationError::NotRegistered`] if caller is not a member,
    /// or [`ModerationError::Revoked`] if caller has been slashed.
    fn create_post_proof(&self, forum_id: ForumId, content_id: ContentId) -> Result<PostProof>;

    /// Verify a post proof. Returns `Ok(true)` if valid.
    ///
    /// # Errors
    /// Returns [`ModerationError::InvalidProof`] for cryptographic verification
    /// failures.
    fn verify_post_proof(&self, forum_id: ForumId, proof: &PostProof) -> Result<bool>;

    /// Moderator proposes a strike against `post_id`. Returns a partial
    /// certificate that must be aggregated with N-1 others to form a full cert.
    ///
    /// # Errors
    /// Returns [`ModerationError::NotModerator`] if caller is not in the
    /// moderator set for `forum_id`.
    fn propose_strike(
        &self,
        forum_id: ForumId,
        post_id: ContentId,
        reason: &str,
    ) -> Result<PartialCert>;

    /// Aggregate N partial certificates into a single full certificate.
    ///
    /// # Errors
    /// Returns [`ModerationError::BelowThreshold`] if fewer than N partials
    /// are supplied, or [`ModerationError::Mismatched`] if partials do not
    /// share the same `post_id`.
    fn aggregate_strike(&self, partials: &[PartialCert]) -> Result<FullCertificate>;

    /// Submit a slash transaction with K full certificates against the same
    /// member. The on-chain registry will reconstruct the identity secret via
    /// Lagrange interpolation and revoke the membership.
    ///
    /// # Errors
    /// Returns [`ModerationError::BelowThreshold`] if fewer than K certificates
    /// supplied, or [`ModerationError::Mismatched`] if certificates do not
    /// target the same member.
    fn submit_slash(&self, forum_id: ForumId, certs: &[FullCertificate]) -> Result<TxHash>;
}
