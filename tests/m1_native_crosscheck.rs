//! Milestone-1a gate, run for BOTH hash backends: the witness mapping is
//! value-faithful to the native verifier.

use flock_xmss::backend::{Backend, Blake3Backend, Sha256Backend};
use flock_xmss::native::{keygen, verify};
use flock_xmss::params::COMPRESSIONS_PER_SIG;
use flock_xmss::witness::{build_sig_witness, replay_and_check};

fn roundtrip<B: Backend>() {
    let kp = keygen::<B>(0xC0FFEE);
    assert!(verify::<B>(&kp.sig_template, &kp.root), "{} honest verify", B::NAME);

    let mut bad = keygen::<B>(0xC0FFEE).sig_template;
    bad.chain_values[7][0] ^= 1;
    assert!(!verify::<B>(&bad, &kp.root), "{} tampered must fail", B::NAME);

    let w = build_sig_witness::<B>(&kp.sig_template);
    assert_eq!(w.instances.len(), COMPRESSIONS_PER_SIG);
    assert_eq!(w.computed_root, kp.root, "{} witness root", B::NAME);
    assert_eq!(replay_and_check::<B>(&w), kp.root, "{} replay root", B::NAME);
}

fn tamper_detected<B: Backend>() {
    let kp = keygen::<B>(0xBAD_5EED);
    let mut w = build_sig_witness::<B>(&kp.sig_template);
    w.triples[5].1[0] ^= 1; // corrupt one chain input value
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| replay_and_check::<B>(&w)));
    assert!(r.is_err(), "{} tampered wiring must not replay", B::NAME);
}

#[test]
fn sha256_roundtrip() { roundtrip::<Sha256Backend>(); }
#[test]
fn blake3_roundtrip() { roundtrip::<Blake3Backend>(); }
#[test]
fn sha256_tamper() { tamper_detected::<Sha256Backend>(); }
#[test]
fn blake3_tamper() { tamper_detected::<Blake3Backend>(); }
#[test]
fn backends_produce_distinct_roots() {
    assert_ne!(keygen::<Sha256Backend>(1).root, keygen::<Blake3Backend>(1).root);
}
