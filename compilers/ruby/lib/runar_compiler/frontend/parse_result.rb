# frozen_string_literal: true

# ParseResult wraps the output of a parser invocation.
#
# This module is a direct port of the ParseResult class from
# compilers/python/runar_compiler/frontend/parser_dispatch.py.

require_relative "ast_nodes"
require_relative "diagnostic"

module RunarCompiler
  module Frontend
    # The result of parsing a Runar source file. Holds either a parsed
    # ContractNode, a list of Diagnostic errors, or both.
    class ParseResult
      attr_accessor :contract, :errors

      # @param contract [ContractNode, nil] the parsed contract, or nil on failure
      # @param errors [Array<Diagnostic>] diagnostics accumulated during parsing
      def initialize(contract: nil, errors: [])
        @contract = contract
        @errors = errors
      end

      # Return formatted error messages as plain strings.
      #
      # @return [Array<String>]
      def error_strings
        @errors.map(&:format_message)
      end
    end
  end
end
