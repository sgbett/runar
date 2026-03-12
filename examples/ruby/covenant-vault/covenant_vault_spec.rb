# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'CovenantVault.runar'

RSpec.describe CovenantVault do
  it 'spends with valid signature, preimage, and sufficient amount' do
    c = CovenantVault.new(mock_pub_key, hash160(mock_pub_key), 1000)
    expect { c.spend(mock_sig, 5000, mock_preimage) }.not_to raise_error
  end
end
