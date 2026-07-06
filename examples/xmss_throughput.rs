//! Aggregation throughput for either backend.
//! Usage: cargo run --release --example xmss_throughput -- [K] [runs] [sha256|blake3]

use std::time::Instant;
use flock_xmss::aggregate::Aggregator;
use flock_xmss::backend::{Backend, Blake3Backend, Sha256Backend};
use flock_xmss::native::keygen;
use flock_xmss::params::COMPRESSIONS_PER_SIG;

fn run<B: Backend>(k: usize, runs: usize) {
    println!("[{}] K={k} signatures, {} compressions, {runs} runs",
             B::NAME, k * COMPRESSIONS_PER_SIG);
    let keys: Vec<_> = (0..k).map(|i| keygen::<B>(0xA5A5_0000 + i as u64)).collect();
    let msgs: Vec<_> = (0..k).map(|i| flock_xmss::native::Rng(0xE7 + i as u64).digest()).collect();
    let sigs: Vec<_> = keys.iter().zip(&msgs).map(|(kp, m)| flock_xmss::native::sign::<B>(kp, m)).collect();
    let roots: Vec<_> = keys.iter().map(|kp| kp.root).collect();

    let agg = Aggregator::<B>::new(k);
    let mut best = f64::INFINITY;
    for r in 0..runs {
        let t = Instant::now();
        let proof = agg.prove(&sigs, &msgs);
        let dt = t.elapsed().as_secs_f64();
        best = best.min(dt);
        let ok = agg.verify(&proof, &roots);
        println!("  run {}: {:.3}s  ({:.1} XMSS/s)  verify={}", r + 1, dt, k as f64 / dt, ok);
        assert!(ok);
    }
    println!("best: {:.3}s = {:.1} XMSS/s ({}, v0)", best, k as f64 / best, B::NAME);
}

fn main() {
    let k: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(64);
    let runs: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let hash = std::env::args().nth(3).unwrap_or_else(|| "sha256".into());
    match hash.as_str() {
        "blake3" => run::<Blake3Backend>(k, runs),
        _ => run::<Sha256Backend>(k, runs),
    }
}
