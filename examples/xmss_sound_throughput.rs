//! SOUND aggregation throughput. Modes:
//!   (default)   per-sig public roots, path public       [glue::prove_sound]
//!   hidden      control-flow hidden (path private)       [glue_hidden::prove_sound_hidden]
//!   mem         hidden + membership to one committed V    [glue_hidden::prove_sound_membership]
//! Usage: cargo run --release --example xmss_sound_throughput -- [K] [runs] [sha256|blake3] [secure] [hidden|mem]

use std::time::Instant;
use flock_prover::challenger::FsChallenger;
use flock_xmss::backend::{Backend, Blake3Backend, Sha256Backend};
use flock_xmss::glue::{prove_sound, verify_sound};
use flock_xmss::glue_hidden::{
    prove_sound_hidden, prove_sound_membership, verify_sound_hidden, verify_sound_membership,
};
use flock_xmss::native::{keygen, sign, Rng};
use flock_xmss::params::COMPRESSIONS_PER_SIG;

#[derive(PartialEq)]
enum Mode { Public, Hidden, Membership }

fn bench<B: Backend>(k: usize, runs: usize, secure: bool, mode: Mode) {
    let sec = if secure { "120-bit/Secure" } else { "100-bit/Fast" };
    let mstr = match mode { Mode::Public => "public roots", Mode::Hidden => "control-flow hidden", Mode::Membership => "hidden + membership (single V)" };
    println!("[sound/{}] K={k}, {} compressions, {runs} runs, {sec}, {mstr}", B::NAME, k * COMPRESSIONS_PER_SIG);
    let keys: Vec<_> = (0..k).map(|i| keygen::<B>(0xF00D + i as u64)).collect();
    let msgs: Vec<_> = (0..k).map(|i| Rng(0xE7 + i as u64).digest()).collect();
    let sigs: Vec<_> = keys.iter().zip(&msgs).map(|(kp, m)| sign::<B>(kp, m)).collect();
    let roots: Vec<_> = keys.iter().map(|kp| kp.root).collect();
    let bits: Vec<_> = sigs.iter().map(|s| s.path_bits).collect();

    let n = k * COMPRESSIONS_PER_SIG;
    let setup = if secure { B::setup_secure(n) } else { B::setup(n) };
    let mut best = f64::INFINITY;
    for r in 0..runs {
        let t = Instant::now();
        let mut chp = FsChallenger::new(b"flock-xmss-sound");
        let (sz, ok) = match mode {
            Mode::Public => {
                let p = prove_sound::<B, _>(&setup, &sigs, &msgs, &mut chp);
                let sz = bincode::serialize(&p).map(|b| b.len()).unwrap_or(0);
                (sz, { best = best.min(t.elapsed().as_secs_f64()); let mut cv = FsChallenger::new(b"flock-xmss-sound"); verify_sound::<B, _>(&setup, &p, &msgs, &roots, &bits, &mut cv).is_ok() })
            }
            Mode::Hidden => {
                let p = prove_sound_hidden::<B, _>(&setup, &sigs, &msgs, &mut chp);
                let sz = bincode::serialize(&p).map(|b| b.len()).unwrap_or(0);
                (sz, { best = best.min(t.elapsed().as_secs_f64()); let mut cv = FsChallenger::new(b"flock-xmss-sound"); verify_sound_hidden::<B, _>(&setup, &p, &msgs, &roots, &mut cv).is_ok() })
            }
            Mode::Membership => {
                let (p, v) = prove_sound_membership::<B, _>(&setup, &sigs, &msgs, &mut chp);
                let sz = bincode::serialize(&p).map(|b| b.len()).unwrap_or(0);
                (sz, { best = best.min(t.elapsed().as_secs_f64()); let mut cv = FsChallenger::new(b"flock-xmss-sound"); verify_sound_membership::<B, _>(&setup, &p, &msgs, v, &mut cv).is_ok() })
            }
        };
        let dt = t.elapsed().as_secs_f64();
        println!("  run {}: prove {:.3}s ({:.1} XMSS/s)  proof {} KiB  ok={}", r + 1, dt, k as f64 / dt, sz / 1024, ok);
        assert!(ok);
    }
    println!("best: {:.3}s = {:.1} XMSS/s (SOUND, {}, {})", best, k as f64 / best, B::NAME, mstr);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let k: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(390);
    let runs: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);
    let hash = args.get(3).cloned().unwrap_or_else(|| "sha256".into());
    let secure = args.iter().any(|a| a == "secure");
    let mode = if args.iter().any(|a| a == "mem") { Mode::Membership }
        else if args.iter().any(|a| a == "hidden") { Mode::Hidden }
        else { Mode::Public };
    match hash.as_str() {
        "blake3" => bench::<Blake3Backend>(k, runs, secure, mode),
        _ => bench::<Sha256Backend>(k, runs, secure, mode),
    }
}
