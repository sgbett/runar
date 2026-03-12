require 'runar'

class CovenantVault < Runar::SmartContract
  prop :owner, PubKey
  prop :recipient, Addr
  prop :min_amount, Bigint

  def initialize(owner, recipient, min_amount)
    super(owner, recipient, min_amount)
    @owner = owner
    @recipient = recipient
    @min_amount = min_amount
  end

  runar_public sig: Sig, amount: Bigint, tx_preimage: SigHashPreimage
  def spend(sig, amount, tx_preimage)
    assert check_sig(sig, @owner)
    assert check_preimage(tx_preimage)
    assert amount >= @min_amount
  end
end
