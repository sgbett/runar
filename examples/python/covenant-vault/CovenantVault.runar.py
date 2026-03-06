from runar import (
    SmartContract, PubKey, Sig, Addr, SigHashPreimage, Bigint,
    public, assert_, check_sig, check_preimage,
)

class CovenantVault(SmartContract):
    owner: PubKey
    recipient: Addr
    min_amount: Bigint

    def __init__(self, owner: PubKey, recipient: Addr, min_amount: Bigint):
        super().__init__(owner, recipient, min_amount)
        self.owner = owner
        self.recipient = recipient
        self.min_amount = min_amount

    @public
    def spend(self, sig: Sig, amount: Bigint, tx_preimage: SigHashPreimage):
        assert_(check_sig(sig, self.owner))
        assert_(check_preimage(tx_preimage))
        assert_(amount >= self.min_amount)
