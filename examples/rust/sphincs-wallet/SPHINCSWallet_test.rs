#[path = "SPHINCSWallet.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::{slh_keygen, slh_sign, SLH_SHA2_128S};

#[test]
fn test_spend() {
    let params = &SLH_SHA2_128S;
    let seed = vec![0x42u8; 3 * params.n];
    let kp = slh_keygen(params, Some(&seed));

    let msg = b"test message".to_vec();
    let sig = slh_sign(params, &msg, &kp.sk);

    let c = SPHINCSWallet { pubkey: kp.pk };
    c.spend(&msg, &sig);
}

#[test]
fn test_spend_multiple_messages() {
    // SLH-DSA is stateless — same keypair can sign many messages
    let params = &SLH_SHA2_128S;
    let seed = vec![0x42u8; 3 * params.n];
    let kp = slh_keygen(params, Some(&seed));

    let msg1 = b"first message".to_vec();
    let sig1 = slh_sign(params, &msg1, &kp.sk);

    let msg2 = b"second message".to_vec();
    let sig2 = slh_sign(params, &msg2, &kp.sk);

    let c = SPHINCSWallet { pubkey: kp.pk };
    c.spend(&msg1, &sig1);
    c.spend(&msg2, &sig2);
}

#[test]
#[should_panic]
fn test_spend_wrong_sig() {
    let params = &SLH_SHA2_128S;
    let seed = vec![0x42u8; 3 * params.n];
    let kp = slh_keygen(params, Some(&seed));

    let msg = b"test message".to_vec();
    let mut sig = slh_sign(params, &msg, &kp.sk);
    sig[0] ^= 0xff; // corrupt signature

    let c = SPHINCSWallet { pubkey: kp.pk };
    c.spend(&msg, &sig);
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("SPHINCSWallet.runar.rs"),
        "SPHINCSWallet.runar.rs",
    )
    .unwrap();
}
