# frozen_string_literal: true

require 'ostruct'
require_relative 'test_helper'

class TestCompiler < Minitest::Test
  # Conformance test directory relative to repo root
  CONFORMANCE_DIR = File.expand_path('../../../conformance/tests', __dir__)

  def compile_ts_source(source, file_name = 'Test.runar.ts')
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    raise "parse errors: #{parse_result.error_strings.join('; ')}" if parse_result.errors.any?
    raise "no contract found" if parse_result.contract.nil?

    val_result = RunarCompiler.send(:_validate, parse_result.contract)
    assert_empty val_result.errors.map(&:format_message), "validation errors"

    tc_result = RunarCompiler.send(:_type_check, parse_result.contract)
    assert_empty tc_result.errors.map(&:format_message), "type check errors"

    program = RunarCompiler.send(:_lower_to_anf, parse_result.contract)
    RunarCompiler.compile_from_program(program, disable_constant_folding: true)
  end

  # NOTE: The Ruby compiler's TS and Ruby parsers share a namespace for token
  # constants. Loading both in the same process causes constant collisions that
  # can corrupt tokenization. We compile Ruby-format sources via subprocess to
  # avoid this. This is a known pre-existing issue in the Ruby compiler.
  def compile_rb_source(source, file_name = 'Test.runar.rb')
    require 'tempfile'
    require 'json'

    tmpfile = Tempfile.new([File.basename(file_name, '.*'), '.runar.rb'])
    tmpfile.write(source)
    tmpfile.close

    lib_dir = File.expand_path('../lib', __dir__)
    out = `ruby -I#{lib_dir} -e "
      require 'runar_compiler'
      require 'json'
      a = RunarCompiler.compile_from_source('#{tmpfile.path}', disable_constant_folding: true)
      puts JSON.generate({ name: a.contract_name, script: a.script })
    " 2>&1`

    tmpfile.unlink

    unless $?.success?
      flunk "Ruby compilation failed: #{out}"
    end

    data = JSON.parse(out.lines.last)
    OpenStruct.new(contract_name: data['name'], script: data['script'])
  end

  # ------------------------------------------------------------------
  # Basic compilation tests
  # ------------------------------------------------------------------

  def test_compile_p2pkh_ts
    source = <<~TS
      import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

      class P2PKH extends SmartContract {
        readonly pubKeyHash: Addr;

        constructor(pubKeyHash: Addr) {
          super(pubKeyHash);
          this.pubKeyHash = pubKeyHash;
        }

        public unlock(sig: Sig, pubKey: PubKey): void {
          assert(hash160(pubKey) === this.pubKeyHash);
          assert(checkSig(sig, pubKey));
        }
      }
    TS

    artifact = compile_ts_source(source, 'P2PKH.runar.ts')
    assert_equal 'P2PKH', artifact.contract_name
    assert artifact.script.length > 0, "script should be non-empty"
    # P2PKH script contains OP_DUP (76), OP_HASH160 (a9), OP_CHECKSIG (ac)
    assert_includes artifact.script.downcase, '76'
    assert_includes artifact.script.downcase, 'a9'
    assert_includes artifact.script.downcase, 'ac'
  end

  def test_compile_p2pkh_rb
    source = <<~RB
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

    artifact = compile_rb_source(source, 'P2PKH.runar.rb')
    assert_equal 'P2PKH', artifact.contract_name
    assert artifact.script.length > 0, "script should be non-empty"
  end

  def test_ts_and_rb_produce_same_script
    ts_source = <<~TS
      import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

      class P2PKH extends SmartContract {
        readonly pubKeyHash: Addr;

        constructor(pubKeyHash: Addr) {
          super(pubKeyHash);
          this.pubKeyHash = pubKeyHash;
        }

        public unlock(sig: Sig, pubKey: PubKey): void {
          assert(hash160(pubKey) === this.pubKeyHash);
          assert(checkSig(sig, pubKey));
        }
      }
    TS

    rb_source = <<~RB
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

    ts_artifact = compile_ts_source(ts_source, 'P2PKH.runar.ts')
    rb_artifact = compile_rb_source(rb_source, 'P2PKH.runar.rb')
    assert_equal ts_artifact.script.downcase, rb_artifact.script.downcase,
                 "TS and Ruby parsers should produce identical script"
  end

  # ------------------------------------------------------------------
  # Conformance golden-file tests
  # ------------------------------------------------------------------

  def test_conformance_basic_p2pkh_ts
    return skip("conformance dir not found") unless File.directory?(CONFORMANCE_DIR)

    ts_path = File.join(CONFORMANCE_DIR, 'basic-p2pkh', 'basic-p2pkh.runar.ts')
    expected_hex = File.read(File.join(CONFORMANCE_DIR, 'basic-p2pkh', 'expected-script.hex')).strip
    return skip("conformance files not found") unless File.exist?(ts_path)

    artifact = RunarCompiler.compile_from_source(ts_path, disable_constant_folding: true)
    assert_equal expected_hex.downcase, artifact.script.downcase,
                 "compiled script should match conformance golden file"
  end

  def test_conformance_basic_p2pkh_rb
    return skip("conformance dir not found") unless File.directory?(CONFORMANCE_DIR)

    rb_path = File.join(CONFORMANCE_DIR, 'basic-p2pkh', 'basic-p2pkh.runar.rb')
    expected_hex = File.read(File.join(CONFORMANCE_DIR, 'basic-p2pkh', 'expected-script.hex')).strip
    return skip("conformance files not found") unless File.exist?(rb_path)

    artifact = RunarCompiler.compile_from_source(rb_path, disable_constant_folding: true)
    assert_equal expected_hex.downcase, artifact.script.downcase,
                 "compiled script should match conformance golden file"
  end

  # ------------------------------------------------------------------
  # All 28 conformance golden-file tests
  # ------------------------------------------------------------------
  # Each test loads the source (preferring .runar.ts, falling back to
  # .runar.zig for tests that only have Zig sources), compiles via the
  # Ruby compiler, and compares the hex output to expected-script.hex.

  # Map: test_dir_name => source_file_name
  CONFORMANCE_TESTS = {
    'arithmetic'          => 'arithmetic.runar.ts',
    'auction'             => 'auction.runar.zig',
    'basic-p2pkh'         => 'basic-p2pkh.runar.ts',
    'blake3'              => 'blake3.runar.zig',
    'boolean-logic'       => 'boolean-logic.runar.ts',
    'bounded-loop'        => 'bounded-loop.runar.ts',
    'convergence-proof'   => 'convergence-proof.runar.ts',
    'covenant-vault'      => 'covenant-vault.runar.zig',
    'ec-demo'             => 'ec-demo.runar.ts',
    'ec-primitives'       => 'ec-primitives.runar.ts',
    'escrow'              => 'escrow.runar.zig',
    'function-patterns'   => 'function-patterns.runar.ts',
    'if-else'             => 'if-else.runar.ts',
    'if-without-else'     => 'if-without-else.runar.ts',
    'math-demo'           => 'math-demo.runar.ts',
    'multi-method'        => 'multi-method.runar.ts',
    'oracle-price'        => 'oracle-price.runar.ts',
    'post-quantum-slhdsa' => 'post-quantum-slhdsa.runar.ts',
    'post-quantum-wallet' => 'post-quantum-wallet.runar.ts',
    'post-quantum-wots'   => 'post-quantum-wots.runar.ts',
    'property-initializers' => 'property-initializers.runar.ts',
    'schnorr-zkp'         => 'schnorr-zkp.runar.zig',
    'sphincs-wallet'      => 'sphincs-wallet.runar.ts',
    'stateful'            => 'stateful.runar.ts',
    'stateful-bytestring' => 'stateful-bytestring.runar.ts',
    'stateful-counter'    => 'stateful-counter.runar.ts',
    'token-ft'            => 'token-ft.runar.zig',
    'token-nft'           => 'token-nft.runar.zig',
  }.freeze

  CONFORMANCE_TESTS.each do |test_dir, source_file|
    method_name = "test_conformance_#{test_dir.gsub('-', '_')}"
    define_method(method_name) do
      skip("conformance dir not found") unless File.directory?(CONFORMANCE_DIR)

      source_path = File.join(CONFORMANCE_DIR, test_dir, source_file)
      hex_path = File.join(CONFORMANCE_DIR, test_dir, 'expected-script.hex')
      skip("conformance files not found for #{test_dir}") unless File.exist?(source_path) && File.exist?(hex_path)

      expected_hex = File.read(hex_path).strip
      artifact = RunarCompiler.compile_from_source(source_path, disable_constant_folding: true)
      assert_equal expected_hex.downcase, artifact.script.downcase,
                   "#{test_dir}: compiled script should match conformance golden file"
    end
  end

  # ------------------------------------------------------------------
  # Error handling tests
  # ------------------------------------------------------------------

  def test_parse_error_for_invalid_source
    assert_raises(RuntimeError) do
      compile_ts_source("this is not valid typescript", 'bad.runar.ts')
    end
  end

  def test_artifact_has_expected_structure
    source = <<~TS
      import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

      class P2PKH extends SmartContract {
        readonly pubKeyHash: Addr;

        constructor(pubKeyHash: Addr) {
          super(pubKeyHash);
          this.pubKeyHash = pubKeyHash;
        }

        public unlock(sig: Sig, pubKey: PubKey): void {
          assert(hash160(pubKey) === this.pubKeyHash);
          assert(checkSig(sig, pubKey));
        }
      }
    TS

    artifact = compile_ts_source(source, 'P2PKH.runar.ts')
    assert_respond_to artifact, :contract_name
    assert_respond_to artifact, :script
    assert_respond_to artifact, :abi
    assert_respond_to artifact, :asm
    assert_equal 'P2PKH', artifact.contract_name
    assert_kind_of String, artifact.script

    # ABI should have constructor and methods
    assert artifact.abi.constructor
    assert_kind_of Array, artifact.abi.methods
    assert_equal 1, artifact.abi.methods.length
    assert_equal 'unlock', artifact.abi.methods.first.name
    assert artifact.abi.methods.first.is_public
  end
end
