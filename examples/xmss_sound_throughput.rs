//! SOUND aggregation throughput (wiring glue enforced), SHA-256 or BLAKE3.
//! Usage: cargo run --release --example xmss_sound_throughput -- [K] [runs] [sha256|blake3]

use std::time::Instant;
use flock_prover::challenger::FsChallenger;
use flock_xmss::backend::{Backend, Blake3Backend, Sha256Backend};
use flock_xmss::glue::{prove_sound, verify_sound};
use flock_xmss::native::{keygen, sign, Rng};
use flock_xmss::params::COMPRESSIONS_PER_SIG;

fn bench<B: Backend>(k: usize, runs: usize) {
    println!("[sound/{}] K={k}, {} compressions, {runs} runs", B::NAME, k * COMPRESSIONS_PER_SIG);
    let keys: Vec<_> = (0..k).map(|i| keygen::<B>(0xF00D + i as u64)).collect();
    let msgs: Vec<_> = (0..k).map(|i| Rng(0xE7 + i as u64).digest()).collect();
    let sigs: Vec<_> = keys.iter().zip(&msgs).map(|(kp, m)| sign::<B>(kp, m)).collect();
    let roots: Vec<_> = keys.iter().map(|kp| kp.root).collect();
    let bits: Vec<_> = sigs.iter().map(|s| s.path_bits).collect();

    let setup = B::setup(k * COMPRESSIONS_PER_SIG);
    let mut best = f64::INFINITY;
    for r in 0..runs {
        let t = Instant::now();
        let mut chp = FsChallenger::new(b"flock-xmss-sound");
        let proof = prove_sound::<B, _>(&setup, &sigs, &msgs, &mut chp);
        let dt = t.elapsed().as_secs_f64();
        best = best.min(dt);
        let tv = Instant::now();
        let mut chv = FsChallenger::new(b"flock-xmss-sound");
        let ok = verify_sound::<B, _>(&setup, &proof, &msgs, &roots, &bits, &mut chv).is_ok();
        let sz = bincode::serialize(&proof).map(|b| b.len()).unwrap_or(0);
        println!("  run {}: prove {:.3}s ({:.1} XMSS/s)  verify {:.1}ms  proof {} KiB  ok={}",
                 r + 1, dt, k as f64 / dt, tv.elapsed().as_secs_f64() * 1e3, sz / 1024, ok);
        assert!(ok);
    }
    println!("best: {:.3}s = {:.1} XMSS/s (SOUND, {})", best, k as f64 / best, B::NAME);
}

fn main() {
    let k: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(390);
    let runs: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(4);
    let hash = std::env::args().nth(3).unwrap_or_else(|| "sha256".into());
    match hash.as_str() {
        "blake3" => bench::<Blake3Backend>(k, runs),
        _ => bench::<Sha256Backend>(k, runs),
    }
}
