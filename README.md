# flock-xmss

XMSS hash-based signature aggregation using standard hashes (SHA-256, BLAKE3),
built on the [Flock](https://github.com/succinctlabs/flock) batch prover.

Post-quantum Ethereum needs to aggregate thousands of hash-based signatures into
one SNARK proof per slot. The current leanSig stack does this with Poseidon, an
algebraic hash chosen because it was assumed cheaper to prove. This repo is the
counter-example: an aggregator for the same signature shape using hashes with
decades of cryptanalysis behind them, and it is faster.

## Numbers (Apple M4 Mac mini, base model, same machine for both systems)

| system | hash | sigs/s aggregated | vs leanVM | vs EF 1,000/s target |
|---|---|---:|---:|---:|
| leanVM (end to end, rate 1/2) | Poseidon-KoalaBear | 718 | 1.0x | 72% |
| leanVM (rate 1/4) | Poseidon-KoalaBear | 507 | 0.71x | 51% |
| **flock-xmss, sound + message-bound** | **SHA-256** | **962** | **1.34x** | **96%** |
| **flock-xmss, sound + message-bound** | **BLAKE3** | **1,849** | **2.58x** | **185%** |

Both rows are the full sound protocol (message-bound, forgeries rejected).
Proof size: 409 KiB (SHA-256), 387 KiB (BLAKE3). Verification: ~15-17 ms (most
of that is re-deriving message encodings through a software hash; a hardware
encoder cuts it to roughly 2 ms). The soundness glue costs 2.0% of prover time
for SHA-256 and 6.9% for BLAKE3 (v0 vs sound, same machine, same session:
982 -> 962 and 1,987 -> 1,849).

## What the proof enforces

Not just correct hash computations. The wiring sumcheck binds the full XMSS
verification structure: Winternitz chain links, pinned pad and IV constants,
chain tops into the leaf hash, the Merkle authentication path, each
signature's public root, and the message-derived chain positions. Forged chain
links, swapped pads, wrong roots, and wrong messages are all rejected (see
`tests/m2_sound_glue.rs` for SHA-256). For BLAKE3, the compression's domain
(counter, block length, flags) is additionally pinned to its constant, so a
forged domain that still satisfies the R1CS is rejected too (see
`tests/m3_blake3_sound.rs`).

## Layout

- `src/params.rs`    parameter set (leanSig-w2 shape: 66 chains, base 4, target-sum 117, height-18 tree)
- `src/native.rs`    reference XMSS implementation, the correctness oracle
- `src/backend.rs`   hash backend trait; SHA-256 and BLAKE3 instantiations
- `src/witness.rs`   maps one signature verification to Flock compression instances plus wiring metadata
- `src/aggregate.rs` v0 aggregator (per-compression proofs)
- `src/glue.rs`      the wiring sumcheck that makes proofs sound (SHA-256 and BLAKE3)

Flock is a pinned git dependency (a fork adding a slot-aligned BLAKE3 witness
layout; the SHA-256 side is identical to upstream, PR pending).

## Run

```sh
cargo test --release                                        # includes forgery rejection tests
cargo run --release --example xmss_sound_throughput -- 390 4 sha256   # sound SHA-256
cargo run --release --example xmss_sound_throughput -- 390 4 blake3   # sound BLAKE3
```

## Status and caveats

Research prototype, not production code.

1. Both SHA-256 and BLAKE3 run the full sound wiring glue. BLAKE3 relies on a
   forked Flock with a slot-aligned witness layout (the SHA-256 side is upstream;
   the layout PR is pending). Proof size (409/387 KiB) misses the 128 KiB target;
   recursion is the standard answer, same as for leanVM.
2. Chain step positions are message-derived via target-sum rejection sampling
   (the leanSig aborting-encoding pattern), and the aggregate is bound to the
   messages: verifying against a wrong message fails (tested).
3. Parameters mirror leanSig's w2 instantiation shape with 256-bit digests.
4. Numbers are CPU-only on a base M4 Mac mini (4P+6E); an M4 Max (10 P-cores)
   scales further, as leanVM's own ~2x M4-Max/M4-S ratio shows.

## Credits

Designed, implemented, and benchmarked in collaboration with Claude (Anthropic
Claude Code). The Flock prover this builds on was itself developed with the
assistance of Claude coding agents, per its paper. Every number in this README
is reproducible with the commands above; the adversarial tests are the
soundness evidence, not trust in whoever or whatever wrote the code.

## License

MIT OR Apache-2.0
