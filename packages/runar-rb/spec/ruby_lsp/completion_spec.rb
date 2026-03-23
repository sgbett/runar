# frozen_string_literal: true

# Specs for the Runar Ruby LSP completion listener.
#
# These tests exercise the Completion listener in isolation, without a running
# LSP server. We stub the minimal ruby-lsp interfaces so the suite remains
# fast and independent of the ruby-lsp runtime.

require 'spec_helper'
require 'uri'

# ---------------------------------------------------------------------------
# Minimal ruby-lsp stubs
#
# Only the surface area touched by completion.rb is stubbed. Guards prevent
# double-definition when running alongside addon_spec.rb or hover_spec.rb.
# ---------------------------------------------------------------------------

unless defined?(RubyLsp::Addon)
  module RubyLsp
    class Addon; end
  end
end

unless defined?(Prism)
  module Prism
    class ConstantReadNode; end
    class CallNode; end
  end
end

# Stub the LSP Interface namespace used to construct completion items.
unless defined?(RubyLsp::Interface::CompletionItem)
  module RubyLsp
    module Interface
      CompletionItem = Struct.new(:label, :filter_text, :text_edit, :kind, :detail, keyword_init: true)
      TextEdit       = Struct.new(:range, :new_text,                                keyword_init: true)
      Range          = Struct.new(:start, :end,                                     keyword_init: true)
      Position       = Struct.new(:line, :character,                                keyword_init: true)
    end
  end
end

# Stub the LSP Constant namespace for CompletionItemKind values.
unless defined?(RubyLsp::Constant::CompletionItemKind)
  module RubyLsp
    module Constant
      module CompletionItemKind
        CONSTANT = 21
        METHOD   = 2
      end
    end
  end
end

require_relative '../../lib/ruby_lsp/runar/completion'

# ---------------------------------------------------------------------------
# Specs
# ---------------------------------------------------------------------------

RSpec.describe RubyLsp::Runar::Completion do
  let(:runar_uri)    { URI.parse('file:///contracts/MyContract.runar.rb') }
  let(:regular_uri)  { URI.parse('file:///lib/my_class.rb') }
  let(:node_context) { Object.new }

  # -------------------------------------------------------------------------
  # Scoped helpers — defined as private methods on the example group so they
  # do not pollute the global namespace and conflict with helpers in sibling
  # spec files (hover_spec.rb, addon_spec.rb).
  # -------------------------------------------------------------------------

  # A simple array-backed response builder stub.
  def completion_response_builder
    items = []
    builder = Object.new
    builder.define_singleton_method(:<<) { |item| items << item }
    builder.define_singleton_method(:items) { items }
    builder
  end

  # A minimal Prism::Dispatcher stub that records registrations and allows
  # tests to fire events directly via #fire(event, node).
  def completion_dispatcher
    dispatcher = Object.new
    dispatcher.instance_variable_set(:@registrations, [])

    dispatcher.define_singleton_method(:register) do |listener, *events|
      events.each { |e| @registrations << { listener: listener, event: e } }
    end

    dispatcher.define_singleton_method(:fire) do |event, node|
      @registrations
        .select { |r| r[:event] == event }
        .each { |r| r[:listener].public_send(event, node) }
    end

    dispatcher.define_singleton_method(:registrations) do
      @registrations
    end

    dispatcher
  end

  # A minimal Prism::Location stub.
  def fake_prism_location(start_line: 1, start_column: 0, end_line: 1, end_column: 5)
    loc = Object.new
    loc.define_singleton_method(:start_line)   { start_line }
    loc.define_singleton_method(:start_column) { start_column }
    loc.define_singleton_method(:end_line)     { end_line }
    loc.define_singleton_method(:end_column)   { end_column }
    loc
  end

  # Builds a fake Prism::ConstantReadNode with the given slice text.
  def completion_constant_node(slice_text)
    node = Object.new
    loc  = fake_prism_location(end_column: slice_text.length)
    node.define_singleton_method(:slice)    { slice_text }
    node.define_singleton_method(:location) { loc }
    node
  end

  # Builds a fake Prism::CallNode for a bare method call (no receiver).
  def completion_call_node(message_text, receiver: nil)
    node = Object.new
    loc  = fake_prism_location(end_column: message_text.length)
    node.define_singleton_method(:receiver)    { receiver }
    node.define_singleton_method(:message)     { message_text }
    node.define_singleton_method(:message_loc) { loc }
    node
  end

  # Builds a fake Prism::CallNode with an explicit receiver object.
  def completion_call_node_with_receiver(message_text)
    recv = Object.new
    completion_call_node(message_text, receiver: recv)
  end

  # Builds a Completion listener, returning [listener, builder, dispatcher].
  def build_completion_listener(uri)
    builder    = completion_response_builder
    dispatcher = completion_dispatcher
    listener   = described_class.new(builder, node_context, dispatcher, uri)
    [listener, builder, dispatcher]
  end

  # -------------------------------------------------------------------------
  # File scoping
  # -------------------------------------------------------------------------

  describe 'file scoping' do
    it 'registers with the dispatcher for .runar.rb files' do
      _, _, dispatcher = build_completion_listener(runar_uri)
      events = dispatcher.registrations.map { |r| r[:event] }
      expect(events).to include(:on_constant_read_node_enter)
      expect(events).to include(:on_call_node_enter)
    end

    it 'does not register with the dispatcher for non-.runar.rb files' do
      _, _, dispatcher = build_completion_listener(regular_uri)
      expect(dispatcher.registrations).to be_empty
    end
  end

  # -------------------------------------------------------------------------
  # Type constant completions
  # -------------------------------------------------------------------------

  describe '#on_constant_read_node_enter' do
    def fire_type_completion(text)
      listener, builder, = build_completion_listener(runar_uri)
      listener.on_constant_read_node_enter(completion_constant_node(text))
      builder.items
    end

    it 'returns no items when the typed text is empty' do
      items = fire_type_completion('')
      expect(items).to be_empty
    end

    it 'suggests Bigint when typing "Big"' do
      labels = fire_type_completion('Big').map(&:label)
      expect(labels).to include('Bigint')
    end

    it 'suggests ByteString when typing "Byte"' do
      labels = fire_type_completion('Byte').map(&:label)
      expect(labels).to include('ByteString')
    end

    it 'suggests both Sig and SigHashPreimage when typing "Sig"' do
      labels = fire_type_completion('Sig').map(&:label)
      expect(labels).to include('Sig')
      expect(labels).to include('SigHashPreimage')
    end

    it 'returns no items for an unrecognized prefix' do
      expect(fire_type_completion('Zzzz')).to be_empty
    end

    it 'assigns CONSTANT kind to type suggestions' do
      item = fire_type_completion('Big').first
      expect(item.kind).to eq(RubyLsp::Constant::CompletionItemKind::CONSTANT)
    end

    it 'sets detail to "Runar type"' do
      item = fire_type_completion('Big').first
      expect(item.detail).to eq('Runar type')
    end

    it 'sets filter_text equal to the label' do
      item = fire_type_completion('Big').first
      expect(item.filter_text).to eq(item.label)
    end
  end

  # -------------------------------------------------------------------------
  # Builtin function completions
  # -------------------------------------------------------------------------

  describe '#on_call_node_enter' do
    def fire_builtin_completion(text, uri: runar_uri)
      listener, builder, = build_completion_listener(uri)
      listener.on_call_node_enter(completion_call_node(text))
      builder.items
    end

    it 'suggests sha256 when typing "sha2"' do
      labels = fire_builtin_completion('sha2').map(&:label)
      expect(labels).to include('sha256')
    end

    it 'suggests multiple sha-prefixed builtins when typing "sha"' do
      labels = fire_builtin_completion('sha').map(&:label)
      expect(labels).to include('sha256')
      expect(labels).to include('sha256_compress')
      expect(labels).to include('sha256_finalize')
    end

    it 'suggests check_sig, check_multi_sig, and check_preimage when typing "check"' do
      labels = fire_builtin_completion('check').map(&:label)
      expect(labels).to include('check_sig')
      expect(labels).to include('check_multi_sig')
      expect(labels).to include('check_preimage')
    end

    it 'returns no items for an unrecognized prefix' do
      expect(fire_builtin_completion('zzz')).to be_empty
    end

    it 'assigns METHOD kind to builtin suggestions' do
      item = fire_builtin_completion('sha2').first
      expect(item.kind).to eq(RubyLsp::Constant::CompletionItemKind::METHOD)
    end

    it 'sets detail to "Runar builtin"' do
      item = fire_builtin_completion('sha2').first
      expect(item.detail).to eq('Runar builtin')
    end

    it 'sets filter_text equal to the label' do
      item = fire_builtin_completion('sha2').first
      expect(item.filter_text).to eq(item.label)
    end

    it 'does not complete calls that have an explicit receiver' do
      listener, builder, = build_completion_listener(runar_uri)
      listener.on_call_node_enter(completion_call_node_with_receiver('sha256'))
      expect(builder.items).to be_empty
    end
  end

  # -------------------------------------------------------------------------
  # Addon integration — create_completion_listener
  # -------------------------------------------------------------------------

  describe 'addon integration' do
    # Verify the delegation contract via a thin inline wrapper, without loading
    # addon.rb (which requires RubyIndexer, unavailable in isolated specs).
    it 'create_completion_listener returns a Completion instance' do
      addon_class = Class.new do
        def create_completion_listener(response_builder, node_context, dispatcher, uri)
          RubyLsp::Runar::Completion.new(response_builder, node_context, dispatcher, uri)
        end
      end

      addon      = addon_class.new
      builder    = completion_response_builder
      dispatcher = completion_dispatcher
      result     = addon.create_completion_listener(builder, node_context, dispatcher, runar_uri)
      expect(result).to be_a(RubyLsp::Runar::Completion)
    end
  end
end
