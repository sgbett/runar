# frozen_string_literal: true

# Structured compiler diagnostics.
#
# This module defines the Diagnostic class used to report errors and warnings
# during compilation. It is a direct port of
# compilers/python/runar_compiler/frontend/diagnostic.py.

require_relative "ast_nodes"

module RunarCompiler
  module Frontend
    # Severity constants for diagnostics.
    module Severity
      ERROR   = "error"
      WARNING = "warning"
    end

    # A single compiler diagnostic (error or warning).
    Diagnostic = Struct.new(:message, :severity, :loc, keyword_init: true) do
      def initialize(message:, severity:, loc: nil)
        super
      end

      # Format with optional file:line:column prefix.
      def format_message
        if loc && !loc.file.empty?
          if loc.column > 0
            return "#{loc.file}:#{loc.line}:#{loc.column}: #{message}"
          end

          return "#{loc.file}:#{loc.line}: #{message}"
        end

        message
      end

      def to_s
        format_message
      end
    end
  end
end
