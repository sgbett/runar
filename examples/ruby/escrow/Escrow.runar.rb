require 'runar'

class Escrow < Runar::SmartContract
  prop :buyer, PubKey
  prop :seller, PubKey
  prop :arbiter, PubKey

  def initialize(buyer, seller, arbiter)
    super(buyer, seller, arbiter)
    @buyer = buyer
    @seller = seller
    @arbiter = arbiter
  end

  runar_public sig: Sig
  def release_by_seller(sig)
    assert check_sig(sig, @seller)
  end

  runar_public sig: Sig
  def release_by_arbiter(sig)
    assert check_sig(sig, @arbiter)
  end

  runar_public sig: Sig
  def refund_to_buyer(sig)
    assert check_sig(sig, @buyer)
  end

  runar_public sig: Sig
  def refund_by_arbiter(sig)
    assert check_sig(sig, @arbiter)
  end
end
