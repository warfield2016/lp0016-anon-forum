//! Integration tests for the Shamir reconstruction module.
//!
//! These tests simulate the actual LP-0016 slash scenario: a member registers,
//! posts twice, has both posts moderated, and the K=2 shares are reconstructed.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use moderation_lib::shamir::{recover_secret, recover_secret_from_two_shares, ShamirShare};

/// Simulate the full slash arithmetic: identity secret → polynomial → two
/// posts emit two shares → reconstruction yields the original secret.
#[test]
fn lp0016_slash_scenario_k_eq_2() {
    let mut rng = ark_std::test_rng();

    // Member registers with random identity secret (this is the NSK)
    let nsk = Fr::rand(&mut rng);

    // Within one external_nullifier, the slope is fixed
    // (in the real protocol: a_1 = Poseidon(nsk, external_nullifier))
    let a_1 = Fr::rand(&mut rng);

    // Member posts twice. Each post hashes to a distinct x-coordinate.
    // (in the real protocol: x_i = Poseidon(post_id))
    let post_1_x = Fr::from(0xdeadbeefu64);
    let post_2_x = Fr::from(0xcafebabeu64);

    // The polynomial f(x) = nsk + a_1 * x is evaluated at each x:
    let share_1 = ShamirShare::new(post_1_x, nsk + a_1 * post_1_x);
    let share_2 = ShamirShare::new(post_2_x, nsk + a_1 * post_2_x);

    // Both posts get moderated by N moderators each. After K=2 certificates,
    // the slasher has both shares.
    let recovered_nsk = recover_secret_from_two_shares(share_1, share_2)
        .expect("two distinct posts should reconstruct NSK");

    // The on-chain slash verifier asserts the recovered NSK matches the
    // member's commitment (Poseidon(nsk) == registered C). We simulate the
    // recovery here; the Poseidon check happens in the LEZ guest.
    assert_eq!(
        recovered_nsk, nsk,
        "K=2 Lagrange reconstruction must recover the identity secret exactly"
    );
}

/// Slash scenario where the slasher receives shares in arbitrary order.
#[test]
fn slash_reconstruction_is_order_independent() {
    let nsk = Fr::from(0x10000000_00000042u64);
    let a_1 = Fr::from(0x20000000_00000007u64);

    let x1 = Fr::from(13u64);
    let x2 = Fr::from(29u64);

    let shares = vec![
        ShamirShare::new(x1, nsk + a_1 * x1),
        ShamirShare::new(x2, nsk + a_1 * x2),
    ];
    let shares_reversed: Vec<_> = shares.iter().rev().copied().collect();

    let a = recover_secret(&shares).unwrap();
    let b = recover_secret(&shares_reversed).unwrap();

    assert_eq!(a, b);
    assert_eq!(a, nsk);
}

/// If a malicious moderator submits a duplicate of an earlier strike (same
/// post_id → same x), reconstruction fails cleanly rather than succeeding
/// with garbage.
#[test]
fn duplicate_post_id_is_rejected() {
    let post_x = Fr::from(42u64);
    let s1 = ShamirShare::new(post_x, Fr::from(1u64));
    let s2 = ShamirShare::new(post_x, Fr::from(2u64));

    let result = recover_secret_from_two_shares(s1, s2);
    assert!(result.is_err());
}

/// API contract: at K=2, exactly 2 shares are required (not 1, not 3+).
#[test]
fn k_2_requires_exactly_two_shares() {
    let s = ShamirShare::new(Fr::from(1u64), Fr::from(2u64));

    assert!(recover_secret(&[]).is_err());
    assert!(recover_secret(&[s]).is_err());
    assert!(recover_secret(&[s, s, s]).is_err());

    // 2 shares with different x → OK
    let s2 = ShamirShare::new(Fr::from(3u64), Fr::from(4u64));
    assert!(recover_secret(&[s, s2]).is_ok());
}
