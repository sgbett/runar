from runar import SmartContract, PubKey, Sig, public, assert_, check_sig

class Escrow(SmartContract):
    buyer: PubKey
    seller: PubKey
    arbiter: PubKey

    def __init__(self, buyer: PubKey, seller: PubKey, arbiter: PubKey):
        super().__init__(buyer, seller, arbiter)
        self.buyer = buyer
        self.seller = seller
        self.arbiter = arbiter

    @public
    def release_by_seller(self, sig: Sig):
        assert_(check_sig(sig, self.seller))

    @public
    def release_by_arbiter(self, sig: Sig):
        assert_(check_sig(sig, self.arbiter))

    @public
    def refund_to_buyer(self, sig: Sig):
        assert_(check_sig(sig, self.buyer))

    @public
    def refund_by_arbiter(self, sig: Sig):
        assert_(check_sig(sig, self.arbiter))
