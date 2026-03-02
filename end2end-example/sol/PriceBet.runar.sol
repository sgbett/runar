pragma runar ^0.1.0;

contract PriceBet is SmartContract {
    PubKey immutable alicePubKey;
    PubKey immutable bobPubKey;
    RabinPubKey immutable oraclePubKey;
    bigint immutable strikePrice;

    constructor(PubKey _alicePubKey, PubKey _bobPubKey, RabinPubKey _oraclePubKey, bigint _strikePrice) {
        alicePubKey = _alicePubKey;
        bobPubKey = _bobPubKey;
        oraclePubKey = _oraclePubKey;
        strikePrice = _strikePrice;
    }

    function settle(bigint price, RabinSig rabinSig, ByteString padding, Sig aliceSig, Sig bobSig) public {
        let ByteString msg = num2bin(price, 8);
        require(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));

        require(price > 0);

        if (price > this.strikePrice) {
            require(checkSig(aliceSig, this.alicePubKey));
        } else {
            require(checkSig(bobSig, this.bobPubKey));
        }
    }

    function cancel(Sig aliceSig, Sig bobSig) public {
        require(checkSig(aliceSig, this.alicePubKey));
        require(checkSig(bobSig, this.bobPubKey));
    }
}
