# Anonymous Forum with Threshold Moderation (LP-0016)

> A privacy-preserving forum where members post anonymously, moderators act through N-of-M consensus, and K accumulated strikes mathematically reconstruct the offender's identity for trustless slashing. Built on the Logos Execution Zone (LEZ).

**Submission for [LP-0016](https://github.com/logos-co/lambda-prize/blob/master/prizes/LP-0016.md)**

> 🚧 **Status: Day 0+ scaffold** — `moderation-lib` Shamir core + public API contract shipped. LEZ programs, ZK circuit, Basecamp module, and webapp pending sprint commitment.

## What's working today

```bash
cd moderation-lib
cargo test
```

All Shamir reconstruction tests pass, including:
- Known-polynomial recovery
- Order-independence
- Duplicate-x rejection
- 1000-iteration property test on random polynomials
- LP-0016 slash scenario (member → 2 posts → K=2 reconstruction → NSK recovered)
- Adversarial: shares from different polynomials don't accidentally recover

## Roadmap

| Phase | Status | Description |
|---|---|---|
| **D0 — Planning** | ✅ Done | 13 docs in `../docs/`, 13 templates in `../submission-templates/` |
| **D0+ — Crypto core** | ✅ Done | `moderation-lib` Shamir + API contract, this README |
| **D1-D2 — LEZ workspace** | ⏳ | `lgs new`, copy Merkle tree from lez-rln |
| **D3-D4 — Membership registry** | ⏳ | Fork lez-rln, replace voluntary-reveal slash with K-share Lagrange |
| **D5-D6 — Moderation board** | ⏳ | Fork lez-multisig, ChainedCall pattern |
| **D7 — Off-chain glue** | ⏳ | Logos Delivery + Logos Storage adapters |
| **D8 — Full SDK** | ⏳ | Wire moderation-lib API to real LEZ |
| **D9-D10 — Basecamp module** | ⏳ | Fork wallet-ui, 4 QML views |
| **D11 — Testnet deploys** | ⏳ | Two instances, K=2 with different N-of-M |
| **D12 — E2E in CI** | ⏳ | `.rs` test (not `.rs.lez`), `RISC0_DEV_MODE=0` |
| **D13 — Docs + protocol.md** | ⏳ | Match PR #53 quality, don't exceed |
| **D14 — Demo + submit** | ⏳ | Narrated video, open PR |
| **D14b-16 — Vercel webapp** | ⏳ | Second consumer via WASM |

## Architecture (planned)

```
Basecamp Qt/QML module ─┐
                         ├─→ moderation-lib (forum-agnostic Rust SDK)
Next.js webapp (WASM)  ─┘                           │
                                                    ├─→ Groth16 per-post proof (Circom, <1s)
                                                    ├─→ Logos Delivery (moderator cert gossip)
                                                    ├─→ Logos Storage (post bodies, REST)
                                                    └─→ LEZ programs (SPEL):
                                                          ├─ membership_registry (RISC0 slash verifier)
                                                          └─ moderation_board (N-of-M ChainedCall)
```

Full rationale in `../docs/ARCHITECTURE.md`. Per-component decisions in `../docs/CODE_DIVE.md`.

## Cryptographic heart

The slash mechanism uses Shamir Secret Sharing over BN254. Each member at registration commits to a polynomial:

```
f(x) = NSK + a₁·x
```

where `NSK` is the identity secret and `a₁` is per-external-nullifier randomness. Each post leaks one share `(x_i, y_i)` where `x_i = Hash(post_id)`. After K=2 strikes, two shares are revealed via threshold decryption, and Lagrange interpolation recovers `NSK`:

```
a₁ = (y₁ - y₂) / (x₁ - x₂)
NSK = y₁ - x₁ · a₁
```

The on-chain slash verifier asserts `Poseidon(NSK) == C_registered` and revokes the membership. See `moderation-lib/src/shamir.rs` for the implementation, ported from `vacp2p/zerokit`.

## Forum-agnosticism

The `moderation-lib` public API operates exclusively on `ContentId([u8; 32])` opaque hashes. The library has **no knowledge of forum content shape** — posts, threads, reactions, images are entirely the caller's responsibility.

Two consumers in this submission will demonstrate the contract:
1. **Basecamp Qt module** (native, Logos IPC)
2. **Next.js webapp on Vercel** (WASM, browser)

Both will import this crate unmodified.

## License

Apache-2.0. See `LICENSE`.

## Acknowledgments

Builds on:
- `vacp2p/zerokit` — RLN proof system, `compute_id_secret` Lagrange algebra
- `logos-co/lez-multisig` — ChainedCall + PDA-authorized cross-program pattern
- `logos-co/logos-lez-rln` — PDA-sharded Merkle tree
- `logos-co/spel` framework + `logos-co/scaffold` CLI
- `logos-blockchain/logos-execution-zone-wallet-ui` — Basecamp module template
