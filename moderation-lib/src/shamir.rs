//! Shamir Secret Sharing reconstruction over BN254.
//!
//! This is the cryptographic heart of the slash mechanism. When K moderation
//! strikes accumulate against a member, K shares are revealed and Lagrange
//! interpolation reconstructs the member's identity secret.
//!
//! ## Algebra (K=2, degree-1 polynomial)
//!
//! Each member at registration commits to a polynomial:
//!
//! ```text
//!   f(x) = a_0 + a_1 * x
//! ```
//!
//! where `a_0` is the identity secret (`NSK` in the protocol spec) and
//! `a_1` is a per-external-nullifier value derived as
//! `a_1 = Poseidon(a_0, external_nullifier)`.
//!
//! Each post leaks one share `(x_i, y_i)` where `x_i = Hash(post_id)` and
//! `y_i = f(x_i)`. Two shares from the same external_nullifier form a system
//! of two equations in two unknowns:
//!
//! ```text
//!   y_1 = a_0 + a_1 * x_1
//!   y_2 = a_0 + a_1 * x_2
//! ```
//!
//! Subtracting gives `a_1 = (y_1 - y_2) / (x_1 - x_2)` (valid because the
//! BN254 field is a field — non-zero elements have multiplicative inverses).
//! Back-substituting recovers `a_0`, which is the identity secret.
//!
//! ## Provenance
//!
//! This implementation is a direct port of [`zerokit::protocol::slashing::compute_id_secret`](https://github.com/vacp2p/zerokit/blob/master/rln/src/protocol/slashing.rs),
//! verified during D0+ recon to be in production use within the Waku network.
//! See `docs/CODE_DIVE.md` for the verification trail.
//!
//! ## Higher K
//!
//! For K > 2 (degree-(K-1) polynomial), a generalized Lagrange interpolation
//! is required:
//!
//! ```text
//!   f(0) = Σ_{i=1..K} y_i * Π_{j≠i} (-x_j / (x_i - x_j))
//! ```
//!
//! This is not implemented here — both LP-0016 forum instances ship with K=2.
//! See `docs/ARCHITECTURE.md § REVISED: K-parameterization` for the rationale
//! and γ-path for K > 2 support.

use ark_bn254::Fr;
use ark_ff::Zero;
use thiserror::Error;

/// One share of a Shamir-shared secret.
///
/// In the LP-0016 protocol, each post emits one share. Once K shares from the
/// same external nullifier are collected, the constant term `a_0` (identity
/// secret) can be reconstructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShamirShare {
    /// The x-coordinate of the share, derived from the content being shared.
    pub x: Fr,
    /// The y-coordinate (= polynomial evaluation at `x`).
    pub y: Fr,
}

impl ShamirShare {
    /// Create a new share.
    #[must_use]
    pub fn new(x: Fr, y: Fr) -> Self {
        Self { x, y }
    }

    /// Convenience: deconstruct into a tuple.
    #[must_use]
    pub fn as_tuple(&self) -> (Fr, Fr) {
        (self.x, self.y)
    }
}

/// Errors from Shamir reconstruction.
#[derive(Debug, Error, PartialEq)]
pub enum ShamirError {
    /// Two shares have the same x-coordinate, which makes Lagrange
    /// interpolation impossible (division by zero in the field). Caller
    /// likely supplied duplicate post-share data.
    #[error("two shares share the same x-coordinate (duplicate post or invariant violation)")]
    DuplicateXCoordinate,

    /// Wrong number of shares supplied. Currently only K=2 is supported.
    #[error("expected exactly 2 shares for K=2 reconstruction, got {0}")]
    WrongShareCount(usize),
}

/// Recover the constant term `a_0` of a degree-1 polynomial from two shares
/// `(x_1, y_1)` and `(x_2, y_2)`.
///
/// Returns the identity secret in BN254 field.
///
/// # Errors
///
/// Returns [`ShamirError::DuplicateXCoordinate`] if the two shares have
/// identical x-coordinates (in which case the system has no unique solution).
///
/// # Example
///
/// ```
/// use ark_bn254::Fr;
/// use ark_ff::PrimeField;
/// use moderation_lib::shamir::{recover_secret_from_two_shares, ShamirShare};
///
/// // Construct polynomial f(x) = 42 + 7*x
/// let secret = Fr::from(42u64);
/// let slope = Fr::from(7u64);
///
/// // Sample at x=1 and x=2
/// let x1 = Fr::from(1u64);
/// let y1 = secret + slope * x1;  // 49
/// let x2 = Fr::from(2u64);
/// let y2 = secret + slope * x2;  // 56
///
/// let recovered = recover_secret_from_two_shares(
///     ShamirShare::new(x1, y1),
///     ShamirShare::new(x2, y2),
/// ).unwrap();
///
/// assert_eq!(recovered, secret);
/// ```
pub fn recover_secret_from_two_shares(
    share1: ShamirShare,
    share2: ShamirShare,
) -> Result<Fr, ShamirError> {
    let (x1, y1) = share1.as_tuple();
    let (x2, y2) = share2.as_tuple();

    // System:
    //   y1 = a_0 + a_1 * x1
    //   y2 = a_0 + a_1 * x2
    // Subtract:
    //   y1 - y2 = a_1 * (x1 - x2)
    // ∴ a_1 = (y1 - y2) / (x1 - x2)   (requires x1 ≠ x2)
    // ∴ a_0 = y1 - x1 * a_1
    let denom = x1 - x2;
    if denom.is_zero() {
        return Err(ShamirError::DuplicateXCoordinate);
    }

    let a_1 = (y1 - y2) / denom;
    let a_0 = y1 - x1 * a_1;
    Ok(a_0)
}

/// Recover the constant term from a slice of shares. Currently delegates to
/// the K=2 path; rejects any other count.
///
/// # Errors
///
/// - [`ShamirError::WrongShareCount`] if `shares.len() != 2`
/// - [`ShamirError::DuplicateXCoordinate`] if the two shares collide
pub fn recover_secret(shares: &[ShamirShare]) -> Result<Fr, ShamirError> {
    if shares.len() != 2 {
        return Err(ShamirError::WrongShareCount(shares.len()));
    }
    recover_secret_from_two_shares(shares[0], shares[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    /// Basic recovery: known polynomial, known shares, recovered secret matches.
    #[test]
    fn recover_from_known_polynomial() {
        let secret = Fr::from(42u64);
        let slope = Fr::from(7u64);

        let x1 = Fr::from(1u64);
        let y1 = secret + slope * x1;
        let x2 = Fr::from(2u64);
        let y2 = secret + slope * x2;

        let recovered = recover_secret_from_two_shares(
            ShamirShare::new(x1, y1),
            ShamirShare::new(x2, y2),
        )
        .expect("two distinct x-coords should reconstruct");

        assert_eq!(recovered, secret);
    }

    /// Order of shares should not matter.
    #[test]
    fn recovery_is_symmetric() {
        let secret = Fr::from(100u64);
        let slope = Fr::from(3u64);

        let s1 = ShamirShare::new(Fr::from(5u64), secret + slope * Fr::from(5u64));
        let s2 = ShamirShare::new(Fr::from(11u64), secret + slope * Fr::from(11u64));

        let a = recover_secret_from_two_shares(s1, s2).unwrap();
        let b = recover_secret_from_two_shares(s2, s1).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, secret);
    }

    /// Duplicate x-coordinates → error, not panic.
    #[test]
    fn duplicate_x_returns_error() {
        let x = Fr::from(5u64);
        let s1 = ShamirShare::new(x, Fr::from(100u64));
        let s2 = ShamirShare::new(x, Fr::from(200u64));

        let err = recover_secret_from_two_shares(s1, s2).unwrap_err();
        assert_eq!(err, ShamirError::DuplicateXCoordinate);
    }

    /// recover_secret with wrong count → error.
    #[test]
    fn wrong_share_count_returns_error() {
        let s = ShamirShare::new(Fr::from(1u64), Fr::from(2u64));

        assert_eq!(
            recover_secret(&[]).unwrap_err(),
            ShamirError::WrongShareCount(0)
        );
        assert_eq!(
            recover_secret(&[s]).unwrap_err(),
            ShamirError::WrongShareCount(1)
        );
        assert_eq!(
            recover_secret(&[s, s, s]).unwrap_err(),
            ShamirError::WrongShareCount(3)
        );
    }

    /// Property test: for any polynomial f(x) = a_0 + a_1*x and any two
    /// distinct x-coordinates, recovery yields a_0.
    #[test]
    fn property_random_polynomials_reconstruct() {
        let mut rng = ark_std::test_rng();

        for _ in 0..1000 {
            let secret = Fr::rand(&mut rng);
            let slope = Fr::rand(&mut rng);

            // Generate two distinct x coordinates by adding a non-zero offset
            let x1 = Fr::rand(&mut rng);
            let mut x2 = Fr::rand(&mut rng);
            while x2 == x1 {
                x2 = Fr::rand(&mut rng);
            }

            let y1 = secret + slope * x1;
            let y2 = secret + slope * x2;

            let recovered = recover_secret_from_two_shares(
                ShamirShare::new(x1, y1),
                ShamirShare::new(x2, y2),
            )
            .unwrap();

            assert_eq!(
                recovered, secret,
                "recovery failed for secret={secret:?} slope={slope:?}"
            );
        }
    }

    /// Adversarial: two shares that AREN'T from the same polynomial recover
    /// SOMETHING but it shouldn't equal a sensible secret. This documents
    /// that the function is a pure interpolant and trusts the caller to
    /// supply shares from the same polynomial.
    #[test]
    fn distinct_polynomials_dont_recover_meaningfully() {
        let polynomial_a = (Fr::from(42u64), Fr::from(7u64)); // a_0=42, a_1=7
        let polynomial_b = (Fr::from(99u64), Fr::from(3u64)); // a_0=99, a_1=3

        let x1 = Fr::from(1u64);
        let y1 = polynomial_a.0 + polynomial_a.1 * x1; // from polynomial A
        let x2 = Fr::from(2u64);
        let y2 = polynomial_b.0 + polynomial_b.1 * x2; // from polynomial B

        let recovered = recover_secret_from_two_shares(
            ShamirShare::new(x1, y1),
            ShamirShare::new(x2, y2),
        )
        .unwrap();

        // The function doesn't error — it just returns a garbage value.
        // It's the protocol's responsibility (external_nullifier binding) to
        // ensure both shares are from the same member's polynomial.
        assert_ne!(recovered, polynomial_a.0);
        assert_ne!(recovered, polynomial_b.0);
    }
}
