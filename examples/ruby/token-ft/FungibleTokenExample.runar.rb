require 'runar'

class FungibleToken < Runar::StatefulSmartContract
  prop :owner, PubKey
  prop :balance, Bigint
  prop :token_id, ByteString, readonly: true

  def initialize(owner, balance, token_id)
    super(owner, balance, token_id)
    @owner = owner
    @balance = balance
    @token_id = token_id
  end

  runar_public sig: Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint
  def transfer(sig, to, amount, output_satoshis)
    assert check_sig(sig, @owner)
    assert amount > 0
    assert amount <= @balance
    add_output(output_satoshis, to, amount)
    add_output(output_satoshis, @owner, @balance - amount)
  end

  runar_public sig: Sig, to: PubKey, output_satoshis: Bigint
  def send(sig, to, output_satoshis)
    assert check_sig(sig, @owner)
    add_output(output_satoshis, to, @balance)
  end

  runar_public sig: Sig, total_balance: Bigint, output_satoshis: Bigint
  def merge(sig, total_balance, output_satoshis)
    assert check_sig(sig, @owner)
    assert total_balance >= @balance
    add_output(output_satoshis, @owner, total_balance)
  end
end
