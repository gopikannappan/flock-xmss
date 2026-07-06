//! Batch R1CS proof round-trip for both backends (small K to stay fast).

use flock_xmss::aggregate::Aggregator;
use flock_xmss::backend::{Backend, Blake3Backend, Sha256Backend};
use flock_xmss::native::keygen;

fn agg_roundtrip<B: Backend>() {
    let k = 4;
    let keys: Vec<_> = (0..k).map(|i| keygen::<B>(0x5EED + i as u64)).collect();
    let sigs: Vec<_> = keys.iter().map(|kp| flock_xmss::native::Signature {
        chain_values: kp.sig_template.chain_values,
        auth_path: kp.sig_template.auth_path,
        path_bits: kp.sig_template.path_bits,
    }).collect();
    let roots: Vec<_> = keys.iter().map(|kp| kp.root).collect();

    let agg = Aggregator::<B>::new(k);
    let proof = agg.prove(&sigs);
    assert!(agg.verify(&proof, &roots), "{} verify", B::NAME);

    let mut wrong = roots.clone();
    wrong[0][0] ^= 1;
    assert!(!agg.verify(&proof, &wrong), "{} wrong root must fail", B::NAME);
}

#[test]
fn sha256_aggregate() { agg_roundtrip::<Sha256Backend>(); }
#[test]
fn blake3_aggregate() { agg_roundtrip::<Blake3Backend>(); }
