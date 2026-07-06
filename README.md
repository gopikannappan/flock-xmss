# flock-xmss

XMSS hash-based signature aggregation using standard hashes (SHA-256, BLAKE3),
built on the [Flock](https://github.com/succinctlabs/flock) batch prover.

Post-quantum Ethereum needs to aggregate thousands of hash-based signatures into
one SNARK proof per slot. The current leanSig stack does this with Poseidon, an
algebraic hash chosen because it was assumed cheaper to prove. This repo is the
counter-example: an aggregator for the same signature shape using hashes with
decades of cryptanalysis behind them, and it is faster.

## Numbers (Apple M4 Mac mini, base model, same machine for both systems)

| system | hash | sigs/s aggregated | vs EF 1,000/s target |
|---|---|---:|---:|
| leanVM (end to end) | Poseidon-KoalaBear | 718 | 72% |
| **flock-xmss, sound** | **SHA-256** | **989** | **99%** |
| flock-xmss, v0 | BLAKE3 | 2,000 | 200% |

Verification: 6.5 ms. The soundness glue costs 1.3% of prover time.

## What the proof enforces

Not just correct hash computations. The wiring sumcheck binds the full XMSS
verification structure: Winternitz chain links, pinned pad and IV constants,
chain tops into the leaf hash, the Merkle authentication path, and each
signature's public root. Forged chain links, swapped pads, and wrong roots are
rejected (see `tests/m2_sound_glue.rs` for the adversarial cases).

## Layout

- `src/params.rs`    parameter set (leanSig-w2 shape: 66 chains, base 4, target-sum 117, height-18 tree)
- `src/native.rs`    reference XMSS implementation, the correctness oracle
- `src/backend.rs`   hash backend trait; SHA-256 and BLAKE3 instantiations
- `src/witness.rs`   maps one signature verification to Flock compression instances plus wiring metadata
- `src/aggregate.rs` v0 aggregator (per-compression proofs)
- `src/glue.rs`      the wiring sumcheck that makes proofs sound (SHA-256)

Flock is a pinned, unmodified git dependency.

## Run

```sh
cargo test --release                                    # includes forgery rejection tests
cargo run --release --example xmss_sound_throughput -- 390 4   # sound SHA-256 aggregation
cargo run --release --example xmss_throughput -- 390 4 blake3  # BLAKE3 (v0)
```

## Status and caveats

Research prototype, not production code.

1. BLAKE3 wiring glue is pending (its witness region is not slot-aligned in
   Flock; needs a bit-offset fold). The BLAKE3 number is capacity with the glue
   cost, measured at 1.3% for SHA-256, still to be applied.
2. Chain step positions are fixed per chain (summing to the target-sum) instead
   of message-derived. Total work is identical under target-sum encoding, so
   throughput is representative; enforcing message-derived positions needs
   selector logic in the glue.
3. Parameters mirror leanSig's w2 instantiation shape with 256-bit digests.

## License

MIT OR Apache-2.0
