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
| leanVM (end to end, rate 1/2) | Poseidon-KoalaBear | 718 | 72% |
| leanVM (rate 1/4) | Poseidon-KoalaBear | 507 | 51% |
| **flock-xmss, sound + message-bound** | **SHA-256** | **949** | **95%** |
| flock-xmss, v0 | BLAKE3 | 2,000 | 200% |

Proof size: 409 KiB. Verification: ~15 ms (about 13 ms of that is re-deriving
message encodings through a software SHA; a hardware-SHA encoder cuts it to
roughly 2 ms). The wiring glue costs 1.3% of prover time; message binding
another ~4%.

## What the proof enforces

Not just correct hash computations. The wiring sumcheck binds the full XMSS
verification structure: Winternitz chain links, pinned pad and IV constants,
chain tops into the leaf hash, the Merkle authentication path, each
signature's public root, and the message-derived chain positions. Forged chain
links, swapped pads, wrong roots, and wrong messages are all rejected (see
`tests/m2_sound_glue.rs` for the adversarial cases).

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
2. Chain step positions are message-derived via target-sum rejection sampling
   (the leanSig aborting-encoding pattern), and the aggregate is bound to the
   messages: verifying against a wrong message fails (tested).
3. Parameters mirror leanSig's w2 instantiation shape with 256-bit digests.

## Credits

Designed, implemented, and benchmarked in collaboration with Claude (Anthropic
Claude Code). The Flock prover this builds on was itself developed with the
assistance of Claude coding agents, per its paper. Every number in this README
is reproducible with the commands above; the adversarial tests are the
soundness evidence, not trust in whoever or whatever wrote the code.

## License

MIT OR Apache-2.0
