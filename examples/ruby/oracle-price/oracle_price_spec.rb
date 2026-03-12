# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'OraclePriceFeed.runar'

RSpec.describe OraclePriceFeed do
  it 'settles with valid oracle signature and price above threshold' do
    c = OraclePriceFeed.new('00' * 64, mock_pub_key)
    expect { c.settle(60_000, '00' * 64, '00' * 32, mock_sig) }.not_to raise_error
  end
end
