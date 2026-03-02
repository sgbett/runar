use runar::prelude::*;

#[runar::contract]
pub struct PriceBet {
    #[readonly]
    pub alice_pub_key: PubKey,
    #[readonly]
    pub bob_pub_key: PubKey,
    #[readonly]
    pub oracle_pub_key: RabinPubKey,
    #[readonly]
    pub strike_price: Bigint,
}

#[runar::methods(PriceBet)]
impl PriceBet {
    #[public]
    pub fn settle(&self, price: Bigint, rabin_sig: &RabinSig, padding: &ByteString, alice_sig: &Sig, bob_sig: &Sig) {
        let msg = num2bin(&price, 8);
        assert!(verify_rabin_sig(&msg, rabin_sig, padding, &self.oracle_pub_key));

        assert!(price > 0);

        if price > self.strike_price {
            assert!(check_sig(alice_sig, &self.alice_pub_key));
        } else {
            assert!(check_sig(bob_sig, &self.bob_pub_key));
        }
    }

    #[public]
    pub fn cancel(&self, alice_sig: &Sig, bob_sig: &Sig) {
        assert!(check_sig(alice_sig, &self.alice_pub_key));
        assert!(check_sig(bob_sig, &self.bob_pub_key));
    }
}
