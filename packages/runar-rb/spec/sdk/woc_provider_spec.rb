# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

RSpec.describe Runar::SDK::WhatsOnChainProvider do
  describe '#initialize' do
    it 'defaults to mainnet' do
      provider = described_class.new
      expect(provider.get_network).to eq('mainnet')
    end

    it 'accepts testnet' do
      provider = described_class.new(network: 'testnet')
      expect(provider.get_network).to eq('testnet')
    end
  end

  describe '#get_fee_rate' do
    it 'returns 100 (standard BSV relay fee in sat/KB)' do
      provider = described_class.new
      expect(provider.get_fee_rate).to eq(100)
    end
  end

  describe '#get_network' do
    it 'returns the configured network' do
      expect(described_class.new(network: 'mainnet').get_network).to eq('mainnet')
      expect(described_class.new(network: 'testnet').get_network).to eq('testnet')
    end
  end

  describe 'class hierarchy' do
    it 'is a subclass of Provider' do
      expect(described_class.superclass).to eq(Runar::SDK::Provider)
    end

    it 'responds to all Provider interface methods' do
      provider = described_class.new
      %i[get_transaction broadcast get_utxos get_contract_utxo get_network
         get_raw_transaction get_fee_rate].each do |method|
        expect(provider).to respond_to(method)
      end
    end
  end

  describe 'base URL construction' do
    it 'uses mainnet URL for mainnet' do
      provider = described_class.new(network: 'mainnet')
      # We verify through the instance variable (implementation detail, but useful for unit test)
      expect(provider.instance_variable_get(:@base_url)).to eq('https://api.whatsonchain.com/v1/bsv/main')
    end

    it 'uses testnet URL for testnet' do
      provider = described_class.new(network: 'testnet')
      expect(provider.instance_variable_get(:@base_url)).to eq('https://api.whatsonchain.com/v1/bsv/test')
    end
  end
end
