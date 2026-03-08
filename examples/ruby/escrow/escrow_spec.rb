# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'Escrow.runar'

RSpec.describe Escrow do
  it 'releases by seller' do
    c = Escrow.new(mock_pub_key, mock_pub_key, mock_pub_key)
    expect { c.release_by_seller(mock_sig) }.not_to raise_error
  end

  it 'releases by arbiter' do
    c = Escrow.new(mock_pub_key, mock_pub_key, mock_pub_key)
    expect { c.release_by_arbiter(mock_sig) }.not_to raise_error
  end

  it 'refunds to buyer' do
    c = Escrow.new(mock_pub_key, mock_pub_key, mock_pub_key)
    expect { c.refund_to_buyer(mock_sig) }.not_to raise_error
  end

  it 'refunds by arbiter' do
    c = Escrow.new(mock_pub_key, mock_pub_key, mock_pub_key)
    expect { c.refund_by_arbiter(mock_sig) }.not_to raise_error
  end
end
