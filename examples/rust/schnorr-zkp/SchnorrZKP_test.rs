#[path = "SchnorrZKP.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

#[test]
fn test_valid_proof() {
    let priv_key: Bigint = 42;
    let pub_key = ec_mul_gen(priv_key);

    let r: Bigint = 12345;
    let r_point = ec_mul_gen(r);

    let e: Bigint = 7;
    let s = r + e * priv_key;

    let c = SchnorrZKP { pub_key };
    c.verify(&r_point, s, e); // should not panic
}

#[test]
#[should_panic]
fn test_wrong_s() {
    let priv_key: Bigint = 42;
    let pub_key = ec_mul_gen(priv_key);

    let r: Bigint = 12345;
    let r_point = ec_mul_gen(r);

    let e: Bigint = 7;
    let s = r + e * priv_key;

    let c = SchnorrZKP { pub_key };
    c.verify(&r_point, s + 1, e);
}

#[test]
#[should_panic]
fn test_wrong_challenge() {
    let priv_key: Bigint = 42;
    let pub_key = ec_mul_gen(priv_key);

    let r: Bigint = 12345;
    let r_point = ec_mul_gen(r);

    let e: Bigint = 7;
    let s = r + e * priv_key;

    let c = SchnorrZKP { pub_key };
    c.verify(&r_point, s, e + 1);
}

#[test]
fn test_larger_key() {
    let priv_key: Bigint = 999999;
    let pub_key = ec_mul_gen(priv_key);

    let r: Bigint = 54321;
    let r_point = ec_mul_gen(r);

    let e: Bigint = 3;
    let s = r + e * priv_key;

    let c = SchnorrZKP { pub_key };
    c.verify(&r_point, s, e);
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("SchnorrZKP.runar.rs"),
        "SchnorrZKP.runar.rs",
    )
    .unwrap();
}
