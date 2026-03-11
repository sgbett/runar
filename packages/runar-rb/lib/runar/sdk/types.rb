# frozen_string_literal: true

# Runar SDK types for deploying and interacting with compiled contracts on BSV.
#
# These structs model the data exchanged between the SDK, the blockchain
# provider, and the signing layer. They mirror the types defined in the Python
# and Go SDKs so all four language implementations are structurally consistent.

module Runar
  module SDK
    # An unspent transaction output.
    Utxo = Struct.new(:txid, :output_index, :satoshis, :script, keyword_init: true)

    # A transaction input.
    TxInput = Struct.new(:txid, :output_index, :script, :sequence, keyword_init: true) do
      def initialize(txid:, output_index:, script:, sequence: 0xFFFFFFFF)
        super
      end
    end

    # A transaction output.
    TxOutput = Struct.new(:script, :satoshis, keyword_init: true)

    # A parsed Bitcoin transaction.
    Transaction = Struct.new(:txid, :version, :inputs, :outputs, :locktime, :raw, keyword_init: true) do
      def initialize(txid:, version: 1, inputs: [], outputs: [], locktime: 0, raw: '')
        super
      end
    end

    # A single ABI parameter.
    ABIParam = Struct.new(:name, :type, keyword_init: true)

    # A contract method descriptor.
    ABIMethod = Struct.new(:name, :params, :is_public, keyword_init: true) do
      def initialize(name:, params: [], is_public: true)
        super
      end
    end

    # Contract ABI: constructor params and method descriptors.
    ABI = Struct.new(:constructor_params, :methods, keyword_init: true) do
      def initialize(constructor_params: [], methods: [])
        super
      end
    end

    # A state field in a stateful contract.
    StateField = Struct.new(:name, :type, :index, :initial_value, keyword_init: true) do
      def initialize(name:, type:, index:, initial_value: nil)
        super
      end
    end

    # Where a constructor placeholder resides in the compiled script.
    ConstructorSlot = Struct.new(:param_index, :byte_offset, keyword_init: true)

    # Compiled output of a Runar compiler.
    #
    # Use RunarArtifact.from_hash to load from a JSON-parsed Hash, or
    # RunarArtifact.from_json to parse a raw JSON string.
    class RunarArtifact
      attr_reader :version, :compiler_version, :contract_name, :abi,
                  :script, :asm, :state_fields, :constructor_slots,
                  :build_timestamp, :code_separator_index, :code_separator_indices

      def initialize(
        version: '',
        compiler_version: '',
        contract_name: '',
        abi: ABI.new,
        script: '',
        asm: '',
        state_fields: [],
        constructor_slots: [],
        build_timestamp: '',
        code_separator_index: nil,
        code_separator_indices: nil
      )
        @version               = version
        @compiler_version      = compiler_version
        @contract_name         = contract_name
        @abi                   = abi
        @script                = script
        @asm                   = asm
        @state_fields          = state_fields
        @constructor_slots     = constructor_slots
        @build_timestamp       = build_timestamp
        @code_separator_index  = code_separator_index
        @code_separator_indices = code_separator_indices
      end

      # Load an artifact from a JSON-parsed Hash (keys may be camelCase strings).
      def self.from_hash(hash)
        abi_raw = hash.fetch('abi', {})

        ctor_params = Array(abi_raw.dig('constructor', 'params')).map do |p|
          ABIParam.new(name: p['name'], type: p['type'])
        end

        methods = Array(abi_raw['methods']).map do |m|
          params = Array(m['params']).map { |p| ABIParam.new(name: p['name'], type: p['type']) }
          ABIMethod.new(name: m['name'], params: params, is_public: m.fetch('isPublic', true))
        end

        state_fields = Array(hash['stateFields']).map do |sf|
          StateField.new(
            name: sf['name'],
            type: sf['type'],
            index: sf['index'],
            initial_value: sf['initialValue']
          )
        end

        constructor_slots = Array(hash['constructorSlots']).map do |cs|
          ConstructorSlot.new(param_index: cs['paramIndex'], byte_offset: cs['byteOffset'])
        end

        new(
          version:               hash.fetch('version', ''),
          compiler_version:      hash.fetch('compilerVersion', ''),
          contract_name:         hash.fetch('contractName', ''),
          abi:                   ABI.new(constructor_params: ctor_params, methods: methods),
          script:                hash.fetch('script', ''),
          asm:                   hash.fetch('asm', ''),
          state_fields:          state_fields,
          constructor_slots:     constructor_slots,
          build_timestamp:       hash.fetch('buildTimestamp', ''),
          code_separator_index:  hash['codeSeparatorIndex'],
          code_separator_indices: hash['codeSeparatorIndices']
        )
      end

      # Load an artifact from a raw JSON string.
      def self.from_json(json_string)
        require 'json'
        from_hash(JSON.parse(json_string))
      end
    end

    # Options for deploying a contract.
    DeployOptions = Struct.new(:satoshis, :change_address, keyword_init: true) do
      def initialize(satoshis: 10_000, change_address: '')
        super
      end
    end

    # Options for calling a contract method.
    CallOptions = Struct.new(:satoshis, :change_address, :new_state, keyword_init: true) do
      def initialize(satoshis: 0, change_address: '', new_state: nil)
        super
      end
    end
  end
end
