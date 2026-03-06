#[path = "PostQuantumWallet.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::{wots_keygen, wots_sign};

#[test]
fn test_spend() {
    let seed = [0x42u8; 32];
    let pub_seed = [0x13u8; 32];
    let kp = wots_keygen(Some(&seed), Some(&pub_seed));

    let c = PostQuantumWallet { pubkey: kp.pk.clone() };
    let msg = b"test message";
    let sig = wots_sign(msg, &kp.sk, &kp.pub_seed);
    c.spend(&msg.to_vec(), &sig);
}

#[test]
fn test_spend_wrong_sig() {
    let seed = [0x42u8; 32];
    let pub_seed = [0x13u8; 32];
    let kp = wots_keygen(Some(&seed), Some(&pub_seed));

    let c = PostQuantumWallet { pubkey: kp.pk.clone() };
    let msg = b"test message";
    let mut sig = wots_sign(msg, &kp.sk, &kp.pub_seed);
    sig[0] ^= 0xff; // corrupt signature
    let result = std::panic::catch_unwind(|| c.spend(&msg.to_vec(), &sig));
    assert!(result.is_err(), "expected spend to fail with corrupt signature");
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("PostQuantumWallet.runar.rs"),
        "PostQuantumWallet.runar.rs",
    )
    .unwrap();
}
