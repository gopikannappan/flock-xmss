//! Batch R1CS proof round-trip for both backends (v0 path, message-aware).

use flock_xmss::aggregate::Aggregator;
use flock_xmss::backend::{Backend, Blake3Backend, Sha256Backend};
use flock_xmss::native::{keygen, sign, Rng};

fn agg_roundtrip<B: Backend>() {
    let k = 4;
    let keys: Vec<_> = (0..k).map(|i| keygen::<B>(0x5EED + i as u64)).collect();
    let msgs: Vec<_> = (0..k).map(|i| Rng(0xE5 + i as u64).digest()).collect();
    let sigs: Vec<_> = keys.iter().zip(&msgs).map(|(kp, m)| sign::<B>(kp, m)).collect();
    let roots: Vec<_> = keys.iter().map(|kp| kp.root).collect();

    let agg = Aggregator::<B>::new(k);
    let proof = agg.prove(&sigs, &msgs);
    assert!(agg.verify(&proof, &roots), "{} verify", B::NAME);
}

#[test]
fn sha256_aggregate() { agg_roundtrip::<Sha256Backend>(); }
#[test]
fn blake3_aggregate() { agg_roundtrip::<Blake3Backend>(); }
