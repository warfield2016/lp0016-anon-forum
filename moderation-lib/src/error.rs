//! Error types for the moderation library.

use thiserror::Error;

/// Errors that can occur in any [`crate::ModerationLibrary`] operation.
#[derive(Debug, Error)]
pub enum ModerationError {
    /// Attempted to register a commitment that is already in the registry.
    #[error("commitment is already registered in this forum")]
    DuplicateRegistration,

    /// Stake amount is below the forum's configured minimum.
    #[error("stake {provided} is below forum minimum {required}")]
    InsufficientStake {
        /// Amount provided by caller.
        provided: u64,
        /// Minimum required by forum config.
        required: u64,
    },

    /// Caller is not registered in this forum.
    #[error("caller is not a registered member of forum")]
    NotRegistered,

    /// Caller's commitment has been slashed and is in the revocation list.
    #[error("caller's commitment has been revoked")]
    Revoked,

    /// Cryptographic proof verification failed.
    #[error("invalid cryptographic proof: {0}")]
    InvalidProof(String),

    /// Caller is not in the moderator set for this forum.
    #[error("caller is not a moderator of this forum")]
    NotModerator,

    /// Fewer than the required threshold of items supplied.
    #[error("supplied {supplied} items, need at least {required}")]
    BelowThreshold {
        /// Number of items supplied by caller.
        supplied: usize,
        /// Threshold required (N for cert aggregation, K for slash).
        required: usize,
    },

    /// Items supplied do not target the same logical object.
    #[error("supplied items target different objects (post_id, member commitment, etc.)")]
    Mismatched,

    /// Shamir Secret Sharing reconstruction failed.
    #[error("Shamir reconstruction failed: {0}")]
    Shamir(#[from] crate::shamir::ShamirError),

    /// I/O or transport error (Logos Delivery, Logos Storage, LEZ RPC).
    #[error("transport error: {0}")]
    Transport(String),

    /// Generic protocol invariant violation. Should be unreachable in honest
    /// operation; if observed, indicates a bug or adversarial input.
    #[error("protocol invariant violated: {0}")]
    Invariant(String),
}
