# frozen_string_literal: true

require_relative 'test_helper'

class TestParserRuby < Minitest::Test
  def parse(source, file_name = 'Test.runar.rb')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  def test_parses_simple_contract
    source = <<~RB
      require 'runar'

      class Counter < Runar::SmartContract
        prop :count, Bigint

        def initialize(count)
          super(count)
          @count = count
        end

        runar_public
        def increment
          assert true
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message), "should parse without errors"
    refute_nil result.contract
    assert_equal 'Counter', result.contract.name
    assert_equal 1, result.contract.properties.length
    assert_equal 'count', result.contract.properties.first.name
  end

  def test_parses_typed_params
    source = <<~RB
      require 'runar'

      class P2PKH < Runar::SmartContract
        prop :pub_key_hash, Addr

        def initialize(pub_key_hash)
          super(pub_key_hash)
          @pub_key_hash = pub_key_hash
        end

        runar_public sig: Sig, pub_key: PubKey
        def unlock(sig, pub_key)
          assert hash160(pub_key) == @pub_key_hash
          assert check_sig(sig, pub_key)
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    unlock = result.contract.methods.find { |m| m.name == 'unlock' }
    refute_nil unlock
    assert unlock.visibility == 'public'
    assert_equal 2, unlock.params.length
  end

  def test_parses_stateful_contract
    source = <<~RB
      require 'runar'

      class Counter < Runar::StatefulSmartContract
        prop :count, Bigint

        def initialize(count)
          super(count)
          @count = count
        end

        runar_public
        def increment
          @count += 1
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    assert_equal 'StatefulSmartContract', result.contract.parent_class
  end

  def test_snake_case_to_camel_case
    source = <<~RB
      require 'runar'

      class P2PKH < Runar::SmartContract
        prop :pub_key_hash, Addr

        def initialize(pub_key_hash)
          super(pub_key_hash)
          @pub_key_hash = pub_key_hash
        end

        runar_public sig: Sig, pub_key: PubKey
        def unlock(sig, pub_key)
          assert hash160(pub_key) == @pub_key_hash
          assert check_sig(sig, pub_key)
        end
      end
    RB

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    # Ruby snake_case property names should be converted to camelCase in AST
    prop = result.contract.properties.first
    assert_equal 'pubKeyHash', prop.name
  end
end
