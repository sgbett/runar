# frozen_string_literal: true

# Runar compile_check — validates contracts through the Runar frontend pipeline.
#
# Runs Parse → Validate → TypeCheck (no ANF lowering or codegen) to verify
# that a contract is valid Runar that will compile to Bitcoin Script.
#
# Requires the runar_compiler gem. If not available, raises LoadError with
# installation instructions.

module Runar
  def self.compile_check(source_or_path, file_name = nil)
    if !source_or_path.include?("\n") && File.file?(source_or_path)
      source = File.read(source_or_path)
      file_name ||= source_or_path
    else
      source = source_or_path
      file_name ||= 'contract.runar.rb'
    end

    begin
      require 'runar_compiler'
    rescue LoadError
      raise LoadError,
            'compile_check requires the runar_compiler gem. ' \
            "Install it with: gem install runar_compiler, or add gem 'runar_compiler' to your Gemfile"
    end

    # Pass 1: Parse
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    unless parse_result.errors.empty?
      raise "parse errors in #{file_name}: #{parse_result.error_strings.join('; ')}"
    end
    raise "no contract found in #{file_name}" if parse_result.contract.nil?

    # Pass 2: Validate
    val_result = RunarCompiler.send(:_validate, parse_result.contract)
    unless val_result.errors.empty?
      raise "validation errors in #{file_name}: #{val_result.error_strings.join('; ')}"
    end

    # Pass 3: Type check
    tc_result = RunarCompiler.send(:_type_check, parse_result.contract)
    unless tc_result.errors.empty?
      raise "type check errors in #{file_name}: #{tc_result.error_strings.join('; ')}"
    end

    true
  end
end
