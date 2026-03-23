# frozen_string_literal: true

# Ruby LSP addon for the runar-lang gem.
#
# Teaches the Ruby LSP about Runar DSL semantics so that editors gain
# accurate completion, go-to-definition, and hover support for contract
# files written in the Runar Ruby format.
#
# Discovery: Ruby LSP finds addons by scanning bundled gems for files at
# lib/ruby_lsp/<gem_name>/addon.rb. This file is that entry point.
#
# This file is ONLY loaded by the Ruby LSP process — it is never required
# by the gem's own runtime code, so the `ruby-lsp` gem itself remains a
# development dependency only.

require 'ruby_lsp/addon'

require_relative 'hover'
require_relative 'indexing'
require_relative 'completion'

module RubyLsp
  module Runar
    class Addon < ::RubyLsp::Addon
      # Ruby LSP calls activate once when the language server boots.
      #
      # global_state - RubyLsp::GlobalState instance (provides the index etc.)
      # message_queue - Thread::Queue for sending async client notifications
      def activate(global_state, _message_queue)
        @global_state = global_state
      end

      # Ruby LSP calls deactivate when the server shuts down.
      def deactivate; end

      # Human-readable name shown in Ruby LSP logs and error messages.
      def name
        'Runar'
      end

      # Version must be defined — Ruby LSP uses it for compatibility checks.
      def version
        '0.1.0'
      end

      # Ruby LSP calls this to obtain a hover listener for the current request.
      #
      # response_builder - collects hover content via #push(text, category:)
      # node_context     - provides URI and context for the hovered node
      # dispatcher       - Prism::Dispatcher; the listener registers itself here
      def create_hover_listener(response_builder, node_context, dispatcher)
        Hover.new(response_builder, node_context, dispatcher)
      end

      # Ruby LSP calls this to obtain a completion listener for the current
      # request. Returns a Completion instance that registers itself with
      # the dispatcher only for .runar.rb files.
      #
      # response_builder - CollectionResponseBuilder[Interface::CompletionItem]
      # node_context     - NodeContext for the cursor position
      # dispatcher       - Prism::Dispatcher; the listener registers itself here
      # uri              - URI::Generic identifying the file being completed
      def create_completion_listener(response_builder, node_context, dispatcher, uri)
        Completion.new(response_builder, node_context, dispatcher, uri)
      end
    end
  end
end
