//! SOUND aggregation throughput (wiring glue enforced), SHA-256.
//! Usage: cargo run --release --example xmss_sound_throughput -- [K] [runs]

use std::time::Instant;
use flock_prover::challenger::FsChallenger;
use flock_prover::r1cs_hashes::sha2::Sha256HybridSetup;
use flock_xmss::backend::Sha256Backend;
use flock_xmss::glue::{prove_sound, verify_sound};
use flock_xmss::native::keygen;
use flock_xmss::params::COMPRESSIONS_PER_SIG;

fn main() {
    let k: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(390);
    let runs: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(4);
    println!("[sound/sha256] K={k}, {} compressions, {runs} runs", k * COMPRESSIONS_PER_SIG);
    let keys: Vec<_> = (0..k).map(|i| keygen::<Sha256Backend>(0xF00D + i as u64)).collect();
    let msgs: Vec<_> = (0..k).map(|i| flock_xmss::native::Rng(0xE7 + i as u64).digest()).collect();
    let sigs: Vec<_> = keys.iter().zip(&msgs).map(|(kp, m)| flock_xmss::native::sign::<Sha256Backend>(kp, m)).collect();
    let roots: Vec<_> = keys.iter().map(|kp| kp.root).collect();
    let bits: Vec<_> = sigs.iter().map(|s| s.path_bits).collect();

    let setup = Sha256HybridSetup::new(k * COMPRESSIONS_PER_SIG);
    let mut best = f64::INFINITY;
    for r in 0..runs {
        let t = Instant::now();
        let mut chp = FsChallenger::new(b"flock-xmss-sound");
        let proof = prove_sound(&setup, &sigs, &msgs, &mut chp);
        let dt = t.elapsed().as_secs_f64();
        best = best.min(dt);
        let tv = Instant::now();
        let mut chv = FsChallenger::new(b"flock-xmss-sound");
        let ok = verify_sound(&setup, &proof, &msgs, &roots, &bits, &mut chv).is_ok();
        let sz = bincode::serialize(&proof).map(|b| b.len()).unwrap_or(0);
        println!("  run {}: prove {:.3}s ({:.1} XMSS/s)  verify {:.1}ms  proof {} KiB  ok={}",
                 r + 1, dt, k as f64 / dt, tv.elapsed().as_secs_f64() * 1e3, sz / 1024, ok);
        assert!(ok);
    }
    println!("best: {:.3}s = {:.1} XMSS/s (SOUND, sha256)", best, k as f64 / best);
}
