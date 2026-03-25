# frozen_string_literal: true

require_relative 'test_helper'

class TestParserTS < Minitest::Test
  def parse(source, file_name = 'Test.runar.ts')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  def test_parses_simple_contract
    source = <<~TS
      import { SmartContract, assert, bigint } from 'runar-lang';

      class Counter extends SmartContract {
        readonly count: bigint;

        constructor(count: bigint) {
          super(count);
          this.count = count;
        }

        public increment(): void {
          assert(true);
        }
      }
    TS

    result = parse(source)
    assert_empty result.errors.map(&:format_message), "should parse without errors"
    refute_nil result.contract, "should produce a contract"
    assert_equal 'Counter', result.contract.name
    assert_equal 1, result.contract.properties.length
    assert_equal 'count', result.contract.properties.first.name
    assert_equal 1, result.contract.methods.length
    assert_equal 'increment', result.contract.methods.first.name
    assert result.contract.methods.first.visibility == 'public'
  end

  def test_parses_multiple_properties
    source = <<~TS
      import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

      class MultiProp extends SmartContract {
        readonly pubKeyHash: Addr;
        readonly amount: bigint;

        constructor(pubKeyHash: Addr, amount: bigint) {
          super(pubKeyHash, amount);
          this.pubKeyHash = pubKeyHash;
          this.amount = amount;
        }

        public check(): void {
          assert(this.amount > 0n);
        }
      }
    TS

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    assert_equal 2, result.contract.properties.length
    assert_equal 'pubKeyHash', result.contract.properties[0].name
    assert_equal 'amount', result.contract.properties[1].name
  end

  def test_parses_private_methods
    source = <<~TS
      import { SmartContract, assert, bigint } from 'runar-lang';

      class WithPrivate extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        private helper(): bigint {
          return this.x + 1n;
        }

        public check(): void {
          assert(this.helper() > 0n);
        }
      }
    TS

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    assert_equal 2, result.contract.methods.length

    helper = result.contract.methods.find { |m| m.name == 'helper' }
    check = result.contract.methods.find { |m| m.name == 'check' }
    refute_nil helper
    refute_nil check
    assert_equal 'private', helper.visibility
    assert_equal 'public', check.visibility
  end

  def test_rejects_invalid_source
    result = parse("this is not valid")
    assert result.errors.any?, "should have parse errors"
  end

  def test_parses_stateful_contract
    source = <<~TS
      import { StatefulSmartContract, assert, bigint } from 'runar-lang';

      class Counter extends StatefulSmartContract {
        count: bigint;

        constructor(count: bigint) {
          super(count);
          this.count = count;
        }

        public increment(): void {
          this.count++;
        }
      }
    TS

    result = parse(source)
    assert_empty result.errors.map(&:format_message)
    assert_equal 'StatefulSmartContract', result.contract.parent_class
  end
end
