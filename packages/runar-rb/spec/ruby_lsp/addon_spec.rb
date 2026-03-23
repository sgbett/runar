# frozen_string_literal: true

# Specs for the Runar Ruby LSP addon.
#
# These tests verify the addon and its indexing enhancement in isolation,
# without needing a running LSP server. We stub the minimal ruby-lsp
# interfaces rather than loading the full gem so the spec suite remains
# fast and free of the ruby-lsp runtime dependency.

require 'spec_helper'
require 'ostruct'
require 'uri'

# ---------------------------------------------------------------------------
# Minimal ruby-lsp stubs
#
# We define stub versions of the ruby-lsp constants so that the addon files
# can be required without the actual ruby-lsp gem being installed in the test
# environment. Each stub mirrors only the surface area our code touches.
# ---------------------------------------------------------------------------

unless defined?(RubyLsp::Addon)
  module RubyLsp
    class Addon
      def activate(_global_state, _message_queue); end
      def deactivate; end
      def name; end
      def version; end
    end
  end
end

# Prism node type stubs — used by both our stubs and the is_a? checks in
# indexing.rb. When the real ruby-lsp gem is not loaded, we define the
# minimal set of Prism constants the enhancement code references.
unless defined?(Prism)
  module Prism
    class SymbolNode; end
    class ConstantReadNode; end
    class KeywordHashNode; end
    class AssocNode; end
    class TrueNode; end
  end
end

unless defined?(RubyIndexer::Enhancement)
  module RubyIndexer
    # Minimal Location stub — returns a simple object from from_prism_location
    # so that register_instance_variable can build InstanceVariable entries
    # without the real ruby-lsp gem loaded.
    unless defined?(RubyIndexer::Location)
      class Location
        def self.from_prism_location(prism_loc, _cache = nil)
          new
        end
      end
    end

    class Enhancement
      @enhancements = []

      class << self
        attr_reader :enhancements

        def inherited(child)
          @enhancements << child
          super
        end

        def clear
          @enhancements.clear
        end
      end

      def initialize(listener)
        @listener = listener
      end

      def on_call_node_enter(node); end
      def on_call_node_leave(node); end
    end

    module Entry
      # Minimal Signature stub used when registering methods.
      Signature = Struct.new(:parameters)

      # Minimal RequiredParameter stub.
      RequiredParameter = Struct.new(:name)

      # Minimal InstanceVariable stub.
      InstanceVariable = Struct.new(:configuration, :name, :uri, :location, :comments, :owner)
    end
  end
end

# ---------------------------------------------------------------------------
# Load the addon files after stubs are in place.
# ---------------------------------------------------------------------------

require_relative '../../lib/ruby_lsp/runar/addon'
require_relative '../../lib/ruby_lsp/runar/indexing'

# ---------------------------------------------------------------------------
# Helpers shared across examples
# ---------------------------------------------------------------------------

# Builds a fake DeclarationListener-like object that records add_method calls
# and index.add calls.
def build_listener(uri_string)
  recorded_index_entries = []

  fake_index = Object.new
  fake_index.define_singleton_method(:configuration) { OpenStruct.new }
  fake_index.define_singleton_method(:add) { |entry| recorded_index_entries << entry }
  fake_index.instance_variable_set(:@entries, recorded_index_entries)
  fake_index.define_singleton_method(:entries) { @entries }

  listener = Object.new
  listener.instance_variable_set(:@recorded_methods, [])
  listener.instance_variable_set(:@uri, URI.parse(uri_string))
  listener.instance_variable_set(:@index, fake_index)
  listener.instance_variable_set(:@code_units_cache, nil)
  listener.instance_variable_set(:@owner, OpenStruct.new(name: 'MyContract'))

  listener.define_singleton_method(:current_owner) { @owner }
  listener.define_singleton_method(:add_method) do |name, _loc, _sigs, **_opts|
    @recorded_methods << name
  end
  listener.define_singleton_method(:recorded_methods) { @recorded_methods }
  listener.define_singleton_method(:index) { @index }

  listener
end

# Builds a minimal Prism::SymbolNode stub with a string value.
def symbol_node(value)
  node = Object.new
  node.define_singleton_method(:is_a?) { |klass| klass == Prism::SymbolNode }
  node.define_singleton_method(:value) { value }
  node
end

# Builds a minimal Prism::ConstantReadNode stub.
def constant_node(name)
  node = Object.new
  node.define_singleton_method(:is_a?) { |klass| klass == Prism::ConstantReadNode }
  node.define_singleton_method(:name) { name }
  node
end

# Builds a minimal fake Prism location.
def fake_location
  loc = Object.new
  loc.define_singleton_method(:start_line) { 1 }
  loc.define_singleton_method(:end_line) { 1 }
  loc.define_singleton_method(:start_column) { 0 }
  loc.define_singleton_method(:end_column) { 10 }
  loc
end

# Builds a fake Prism::KeywordHashNode containing `readonly: true`.
def readonly_kwargs_node
  key_node = Object.new
  key_node.define_singleton_method(:is_a?) { |klass| klass == Prism::SymbolNode }
  key_node.define_singleton_method(:value) { 'readonly' }

  value_node = Object.new
  value_node.define_singleton_method(:is_a?) { |klass| klass == Prism::TrueNode }

  pair = Object.new
  pair.define_singleton_method(:is_a?) { |klass| klass == Prism::AssocNode }
  pair.define_singleton_method(:key) { key_node }
  pair.define_singleton_method(:value) { value_node }

  kwargs = Object.new
  kwargs.define_singleton_method(:is_a?) { |klass| klass == Prism::KeywordHashNode }
  kwargs.define_singleton_method(:elements) { [pair] }
  kwargs
end

# Builds a fake CallNode for a `prop :name, Type` call.
def prop_call_node(prop_name, readonly: false)
  args = [symbol_node(prop_name), constant_node('Bigint')]
  args << readonly_kwargs_node if readonly

  args_node = Object.new
  args_node.define_singleton_method(:arguments) { args }

  node = Object.new
  node.define_singleton_method(:name) { :prop }
  node.define_singleton_method(:arguments) { args_node }
  node.define_singleton_method(:location) { fake_location }
  node
end

# Builds a fake CallNode for a non-prop method call.
def non_prop_call_node(method_name)
  node = Object.new
  node.define_singleton_method(:name) { method_name }
  node.define_singleton_method(:arguments) { nil }
  node.define_singleton_method(:location) { fake_location }
  node
end

# ---------------------------------------------------------------------------
# Specs
# ---------------------------------------------------------------------------

RSpec.describe RubyLsp::Runar::Addon do
  subject(:addon) { described_class.new }

  describe '#name' do
    it 'returns "Runar"' do
      expect(addon.name).to eq('Runar')
    end
  end

  describe '#version' do
    it 'returns a non-empty version string' do
      expect(addon.version).to be_a(String)
      expect(addon.version).not_to be_empty
    end
  end

  describe '#activate' do
    it 'activates without raising' do
      global_state  = OpenStruct.new
      message_queue = Queue.new
      expect { addon.activate(global_state, message_queue) }.not_to raise_error
    end
  end

  describe '#deactivate' do
    it 'deactivates without raising' do
      expect { addon.deactivate }.not_to raise_error
    end
  end
end

RSpec.describe RubyLsp::Runar::IndexingEnhancement do
  let(:runar_uri)   { 'file:///contracts/MyContract.runar.rb' }
  let(:regular_uri) { 'file:///lib/my_class.rb' }

  describe '#on_call_node_enter' do
    context 'with a .runar.rb file' do
      let(:listener) { build_listener(runar_uri) }
      subject(:enhancement) { described_class.new(listener) }

      it 'registers a reader method for a prop declaration' do
        enhancement.on_call_node_enter(prop_call_node('count'))
        expect(listener.recorded_methods).to include('count')
      end

      it 'registers a writer method for a non-readonly prop' do
        enhancement.on_call_node_enter(prop_call_node('balance'))
        expect(listener.recorded_methods).to include('balance')
        expect(listener.recorded_methods).to include('balance=')
      end

      it 'does not register a writer for a readonly prop' do
        enhancement.on_call_node_enter(prop_call_node('token_id', readonly: true))
        expect(listener.recorded_methods).to include('token_id')
        expect(listener.recorded_methods).not_to include('token_id=')
      end

      it 'indexes @name as an instance variable' do
        enhancement.on_call_node_enter(prop_call_node('pub_key_hash'))
        ivar_entry = listener.index.entries.find do |e|
          e.respond_to?(:name) && e.name == '@pub_key_hash'
        end
        expect(ivar_entry).not_to be_nil
      end

      it 'indexes @name for a simple prop' do
        enhancement.on_call_node_enter(prop_call_node('count'))
        ivar_entry = listener.index.entries.find { |e| e.respond_to?(:name) && e.name == '@count' }
        expect(ivar_entry).not_to be_nil
      end

      it 'ignores non-prop call nodes' do
        enhancement.on_call_node_enter(non_prop_call_node(:some_other_method))
        expect(listener.recorded_methods).to be_empty
      end

      it 'handles a prop with no arguments gracefully' do
        bare_node = Object.new
        bare_node.define_singleton_method(:name) { :prop }
        bare_node.define_singleton_method(:arguments) { nil }
        bare_node.define_singleton_method(:location) { fake_location }

        expect { enhancement.on_call_node_enter(bare_node) }.not_to raise_error
        expect(listener.recorded_methods).to be_empty
      end
    end

    context 'with a non-.runar.rb file' do
      let(:listener) { build_listener(regular_uri) }
      subject(:enhancement) { described_class.new(listener) }

      it 'does not register any methods' do
        enhancement.on_call_node_enter(prop_call_node('count'))
        expect(listener.recorded_methods).to be_empty
      end

      it 'does not add any index entries' do
        enhancement.on_call_node_enter(prop_call_node('count'))
        expect(listener.index.entries).to be_empty
      end
    end
  end

  describe '#on_call_node_leave' do
    subject(:enhancement) { described_class.new(build_listener(runar_uri)) }

    it 'returns without raising for any node' do
      expect { enhancement.on_call_node_leave(non_prop_call_node(:prop)) }.not_to raise_error
    end
  end
end
