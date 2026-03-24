# frozen_string_literal: true

# Top-level require file for the Runar Ruby compiler.
#
# Loads the core compiler pipeline and CLI. Frontend and codegen modules
# are lazy-loaded on demand within compiler.rb methods.

require_relative "runar_compiler/ir/types"
require_relative "runar_compiler/ir/loader"
require_relative "runar_compiler/compiler"
require_relative "runar_compiler/cli"
