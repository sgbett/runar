# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

MINIMAL_ARTIFACT_HASH = {
  'version' => '1.0.0',
  'compilerVersion' => '0.4.2',
  'contractName' => 'P2PKH',
  'abi' => {
    'constructor' => {
      'params' => [
        { 'name' => 'pubKeyHash', 'type' => 'Ripemd160' }
      ]
    },
    'methods' => [
      {
        'name' => 'unlock',
        'params' => [
          { 'name' => 'sig', 'type' => 'Sig' },
          { 'name' => 'pubKey', 'type' => 'PubKey' }
        ],
        'isPublic' => true
      }
    ]
  },
  'script' => 'deadbeef',
  'asm' => 'OP_DUP OP_HASH160',
  'stateFields' => [],
  'constructorSlots' => [
    { 'paramIndex' => 0, 'byteOffset' => 4 }
  ],
  'buildTimestamp' => '2024-01-01T00:00:00Z',
  'codeSeparatorIndex' => nil,
  'codeSeparatorIndices' => nil
}.freeze

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK types' do
  # rubocop:enable RSpec/DescribeClass

  describe Runar::SDK::Utxo do
    it 'stores all fields' do
      utxo = described_class.new(
        txid: 'abc123',
        output_index: 0,
        satoshis: 10_000,
        script: '76a914deadbeef88ac'
      )
      expect(utxo.txid).to eq('abc123')
      expect(utxo.output_index).to eq(0)
      expect(utxo.satoshis).to eq(10_000)
      expect(utxo.script).to eq('76a914deadbeef88ac')
    end
  end

  describe Runar::SDK::TxInput do
    it 'defaults sequence to 0xFFFFFFFF' do
      input = described_class.new(txid: 'abc', output_index: 1, script: '')
      expect(input.sequence).to eq(0xFFFFFFFF)
    end

    it 'accepts a custom sequence' do
      input = described_class.new(txid: 'abc', output_index: 0, script: '', sequence: 0)
      expect(input.sequence).to eq(0)
    end
  end

  describe Runar::SDK::TxOutput do
    it 'stores script and satoshis' do
      output = described_class.new(script: '76a914ff88ac', satoshis: 5000)
      expect(output.script).to eq('76a914ff88ac')
      expect(output.satoshis).to eq(5000)
    end
  end

  describe Runar::SDK::Transaction do
    it 'defaults version to 1 and collections to empty' do
      tx = described_class.new(txid: 'deadbeef')
      expect(tx.version).to eq(1)
      expect(tx.inputs).to eq([])
      expect(tx.outputs).to eq([])
      expect(tx.locktime).to eq(0)
      expect(tx.raw).to eq('')
    end
  end

  describe Runar::SDK::RunarArtifact do
    describe '.from_hash' do
      subject(:artifact) { described_class.from_hash(MINIMAL_ARTIFACT_HASH) }

      it 'parses top-level scalar fields' do
        expect(artifact.version).to eq('1.0.0')
        expect(artifact.compiler_version).to eq('0.4.2')
        expect(artifact.contract_name).to eq('P2PKH')
        expect(artifact.script).to eq('deadbeef')
        expect(artifact.asm).to eq('OP_DUP OP_HASH160')
        expect(artifact.build_timestamp).to eq('2024-01-01T00:00:00Z')
      end

      it 'parses constructor params into ABI' do
        expect(artifact.abi.constructor_params.length).to eq(1)
        param = artifact.abi.constructor_params.first
        expect(param.name).to eq('pubKeyHash')
        expect(param.type).to eq('Ripemd160')
      end

      it 'parses ABI methods' do
        expect(artifact.abi.methods.length).to eq(1)
        method = artifact.abi.methods.first
        expect(method.name).to eq('unlock')
        expect(method.is_public).to be true
        expect(method.params.map(&:name)).to eq(%w[sig pubKey])
      end

      it 'parses constructor slots' do
        expect(artifact.constructor_slots.length).to eq(1)
        slot = artifact.constructor_slots.first
        expect(slot.param_index).to eq(0)
        expect(slot.byte_offset).to eq(4)
      end

      it 'parses state fields as empty array' do
        expect(artifact.state_fields).to eq([])
      end

      it 'preserves nil code separator index' do
        expect(artifact.code_separator_index).to be_nil
        expect(artifact.code_separator_indices).to be_nil
      end

      context 'with a stateful contract hash' do
        let(:stateful_hash) do
          MINIMAL_ARTIFACT_HASH.merge(
            'stateFields' => [
              { 'name' => 'count', 'type' => 'bigint', 'index' => 0, 'initialValue' => '0n' }
            ],
            'codeSeparatorIndex' => 42,
            'codeSeparatorIndices' => [42]
          )
        end

        subject(:artifact) { described_class.from_hash(stateful_hash) }

        it 'parses state fields' do
          expect(artifact.state_fields.length).to eq(1)
          field = artifact.state_fields.first
          expect(field.name).to eq('count')
          expect(field.type).to eq('bigint')
          expect(field.index).to eq(0)
          expect(field.initial_value).to eq('0n')
        end

        it 'parses code separator index' do
          expect(artifact.code_separator_index).to eq(42)
          expect(artifact.code_separator_indices).to eq([42])
        end
      end
    end

    describe '.from_json' do
      it 'parses a JSON string into an artifact' do
        require 'json'
        json = JSON.generate(MINIMAL_ARTIFACT_HASH)
        artifact = described_class.from_json(json)
        expect(artifact.contract_name).to eq('P2PKH')
        expect(artifact.abi.constructor_params.length).to eq(1)
      end
    end
  end

  describe Runar::SDK::DeployOptions do
    it 'defaults to 10_000 satoshis and empty change address' do
      opts = described_class.new
      expect(opts.satoshis).to eq(10_000)
      expect(opts.change_address).to eq('')
    end

    it 'accepts keyword arguments' do
      opts = described_class.new(satoshis: 50_000, change_address: '1ABC')
      expect(opts.satoshis).to eq(50_000)
      expect(opts.change_address).to eq('1ABC')
    end
  end

  describe Runar::SDK::CallOptions do
    it 'defaults to 0 satoshis, empty change address, and nil new_state' do
      opts = described_class.new
      expect(opts.satoshis).to eq(0)
      expect(opts.change_address).to eq('')
      expect(opts.new_state).to be_nil
    end

    it 'accepts a new_state hash' do
      opts = described_class.new(new_state: { 'count' => 5 })
      expect(opts.new_state).to eq({ 'count' => 5 })
    end
  end
end
