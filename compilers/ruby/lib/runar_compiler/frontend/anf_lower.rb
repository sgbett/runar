# frozen_string_literal: true

# ANF lowering pass for the Runar compiler.
#
# Lowers a type-checked Runar AST to A-Normal Form IR.
# Direct port of compilers/python/runar_compiler/frontend/anf_lower.py.
#
# This is the most complex frontend pass. Every expression is recursively
# flattened into a sequence of let-bindings (ANFBinding) with fresh temp
# names (t0, t1, ...).

require "json"
require_relative "../ir/types"
require_relative "ast_nodes"

module RunarCompiler
  module Frontend
    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    # Lower a type-checked Runar AST to ANF IR.
    #
    # Matches the TypeScript reference compiler's 04-anf-lower.ts exactly.
    #
    # @param contract [ContractNode]
    # @return [IR::ANFProgram]
    def self.lower_to_anf(contract)
      properties = _lower_properties(contract)
      methods = _lower_methods(contract)

      IR::ANFProgram.new(
        contract_name: contract.name,
        properties: properties,
        methods: methods
      )
    end

    # -------------------------------------------------------------------
    # Byte-typed expression detection
    # -------------------------------------------------------------------

    BYTE_TYPES = %w[
      ByteString PubKey Sig Sha256 Ripemd160 Addr SigHashPreimage
      RabinSig RabinPubKey Point
    ].to_set.freeze
    private_constant :BYTE_TYPES

    BYTE_RETURNING_FUNCTIONS = %w[
      sha256 ripemd160 hash160 hash256 cat substr num2bin reverseBytes
      left right int2str toByteString pack ecAdd ecMul ecMulGen ecNegate
      ecMakePoint ecEncodeCompressed blake3Compress blake3Hash
    ].to_set.freeze
    private_constant :BYTE_RETURNING_FUNCTIONS

    # @param expr [Expression, nil]
    # @param ctx [LoweringContext]
    # @return [Boolean]
    def self._is_byte_typed_expr(expr, ctx)
      return false if expr.nil?

      return true if expr.is_a?(ByteStringLiteral)

      if expr.is_a?(Identifier)
        t = ctx.get_param_type(expr.name)
        return true if t && BYTE_TYPES.include?(t)
        t = ctx.get_property_type(expr.name)
        return true if t && BYTE_TYPES.include?(t)
        return true if ctx.local_byte_var?(expr.name)
        return false
      end

      if expr.is_a?(PropertyAccessExpr)
        t = ctx.get_property_type(expr.property)
        return true if t && BYTE_TYPES.include?(t)
        return false
      end

      if expr.is_a?(MemberExpr)
        if expr.object.is_a?(Identifier) && expr.object.name == "this"
          t = ctx.get_property_type(expr.property)
          return true if t && BYTE_TYPES.include?(t)
        end
        return false
      end

      if expr.is_a?(CallExpr)
        if expr.callee.is_a?(Identifier)
          return true if BYTE_RETURNING_FUNCTIONS.include?(expr.callee.name)
          return true if expr.callee.name.length >= 7 && expr.callee.name[0, 7] == "extract"
        end
        return false
      end

      false
    end
    # Not private: called by LoweringContext methods

    # -------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------

    # @param contract [ContractNode]
    # @return [Array<IR::ANFProperty>]
    def self._lower_properties(contract)
      contract.properties.map do |prop|
        anf_prop = IR::ANFProperty.new(
          name: prop.name,
          type: _type_node_to_string(prop.type),
          readonly: prop.readonly
        )
        unless prop.initializer.nil?
          anf_prop.initial_value = _extract_literal_value(prop.initializer)
        end
        anf_prop
      end
    end
    private_class_method :_lower_properties

    # @param expr [Expression]
    # @return [String, Integer, Boolean, nil]
    def self._extract_literal_value(expr)
      return expr.value if expr.is_a?(BigIntLiteral)
      return expr.value if expr.is_a?(BoolLiteral)
      return expr.value if expr.is_a?(ByteStringLiteral)
      if expr.is_a?(UnaryExpr) && expr.op == "-"
        return -expr.operand.value if expr.operand.is_a?(BigIntLiteral)
      end
      nil
    end
    private_class_method :_extract_literal_value

    # -------------------------------------------------------------------
    # Methods
    # -------------------------------------------------------------------

    # @param contract [ContractNode]
    # @return [Array<IR::ANFMethod>]
    def self._lower_methods(contract)
      result = []

      # Lower constructor
      ctor_ctx = LoweringContext.new(contract)
      ctor_ctx.lower_statements(contract.constructor.body)
      result << IR::ANFMethod.new(
        name: "constructor",
        params: _lower_params(contract.constructor.params),
        body: ctor_ctx.bindings,
        is_public: false
      )

      # Lower each method
      contract.methods.each do |method|
        method_ctx = LoweringContext.new(contract)

        if contract.parent_class == "StatefulSmartContract" && method.visibility == "public"
          # Determine if this method verifies hashOutputs (needs change output support).
          needs_change_output = (
            _method_mutates_state(method, contract) ||
            _method_has_add_output(method)
          )

          # Register implicit parameters
          if needs_change_output
            method_ctx.add_param("_changePKH")
            method_ctx.add_param("_changeAmount")
          end
          # Single-output continuation needs _newAmount to allow changing the UTXO satoshis.
          needs_new_amount = _method_mutates_state(method, contract) && !_method_has_add_output(method)
          if needs_new_amount
            method_ctx.add_param("_newAmount")
          end
          method_ctx.add_param("txPreimage")

          # Inject checkPreimage(txPreimage) at the start
          preimage_ref = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "txPreimage" })
          check_result = method_ctx.emit(IR::ANFValue.new(kind: "check_preimage").tap { |v| v.preimage = preimage_ref })
          method_ctx.emit(_make_assert(check_result))

          # Deserialize mutable state from the preimage's scriptCode
          has_state_prop = contract.properties.any? { |p| !p.readonly }
          if has_state_prop
            preimage_ref3 = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "txPreimage" })
            method_ctx.emit(IR::ANFValue.new(kind: "deserialize_state").tap { |v| v.preimage = preimage_ref3 })
          end

          # Lower the developer's method body
          method_ctx.lower_statements(method.body)

          # Determine state continuation type
          add_output_refs = method_ctx.get_add_output_refs
          if add_output_refs.any? || _method_mutates_state(method, contract)
            # Build the P2PKH change output for hashOutputs verification
            change_pkh_ref = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "_changePKH" })
            change_amount_ref = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "_changeAmount" })
            change_output_ref = method_ctx.emit(_make_call("buildChangeOutput", [change_pkh_ref, change_amount_ref]))

            if add_output_refs.any?
              # Multi-output continuation: concat all outputs + change output, hash
              accumulated = add_output_refs[0]
              (1...add_output_refs.length).each do |i|
                accumulated = method_ctx.emit(_make_call("cat", [accumulated, add_output_refs[i]]))
              end
              accumulated = method_ctx.emit(_make_call("cat", [accumulated, change_output_ref]))
              hash_ref = method_ctx.emit(_make_call("hash256", [accumulated]))
              preimage_ref2 = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "txPreimage" })
              output_hash_ref = method_ctx.emit(_make_call("extractOutputHash", [preimage_ref2]))
              eq_ref = method_ctx.emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
                v.op = "==="
                v.left = hash_ref
                v.right = output_hash_ref
                v.result_type = "bytes"
              end)
              method_ctx.emit(_make_assert(eq_ref))
            else
              # Single-output continuation: build raw output bytes, concat with change, hash
              state_script_ref = method_ctx.emit(IR::ANFValue.new(kind: "get_state_script"))
              preimage_ref2 = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "txPreimage" })
              new_amount_ref = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "_newAmount" })
              contract_output_ref = method_ctx.emit(_make_call("computeStateOutput", [preimage_ref2, state_script_ref, new_amount_ref]))
              all_outputs = method_ctx.emit(_make_call("cat", [contract_output_ref, change_output_ref]))
              hash_ref = method_ctx.emit(_make_call("hash256", [all_outputs]))
              preimage_ref4 = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "txPreimage" })
              output_hash_ref = method_ctx.emit(_make_call("extractOutputHash", [preimage_ref4]))
              eq_ref = method_ctx.emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
                v.op = "==="
                v.left = hash_ref
                v.right = output_hash_ref
                v.result_type = "bytes"
              end)
              method_ctx.emit(_make_assert(eq_ref))
            end
          end

          # Build augmented params list for ABI
          augmented_params = _lower_params(method.params)
          if needs_change_output
            augmented_params << IR::ANFParam.new(name: "_changePKH", type: "Ripemd160")
            augmented_params << IR::ANFParam.new(name: "_changeAmount", type: "bigint")
          end
          if needs_new_amount
            augmented_params << IR::ANFParam.new(name: "_newAmount", type: "bigint")
          end
          augmented_params << IR::ANFParam.new(name: "txPreimage", type: "SigHashPreimage")

          result << IR::ANFMethod.new(
            name: method.name,
            params: augmented_params,
            body: method_ctx.bindings,
            is_public: true
          )
        else
          method_ctx.lower_statements(method.body)
          result << IR::ANFMethod.new(
            name: method.name,
            params: _lower_params(method.params),
            body: method_ctx.bindings,
            is_public: method.visibility == "public"
          )
        end
      end

      result
    end
    private_class_method :_lower_methods

    # @param params [Array<ParamNode>]
    # @return [Array<IR::ANFParam>]
    def self._lower_params(params)
      params.map do |p|
        IR::ANFParam.new(name: p.name, type: _type_node_to_string(p.type))
      end
    end
    private_class_method :_lower_params

    # -------------------------------------------------------------------
    # Lowering context
    # -------------------------------------------------------------------

    # Manages temp variable generation and binding emission.
    #
    # Mirrors the Go lowerCtx struct exactly.
    class LoweringContext
      # @return [Array<IR::ANFBinding>]
      attr_reader :bindings

      # @return [IR::SourceLocation, nil]
      attr_accessor :current_source_loc

      def initialize(contract)
        @bindings = []
        @counter = 0
        @contract = contract
        @local_names = Set.new
        @param_names = Set.new
        @add_output_refs = []
        @local_aliases = {}
        @local_byte_vars = Set.new
        @current_source_loc = nil
      end

      # Generate a fresh temp name.
      # @return [String]
      def fresh_temp
        name = "t#{@counter}"
        @counter += 1
        name
      end

      # Emit a binding and return its name.
      # @param value [IR::ANFValue]
      # @return [String]
      def emit(value)
        name = fresh_temp
        binding = IR::ANFBinding.new(name: name, value: value)
        binding.source_loc = @current_source_loc if @current_source_loc
        @bindings << binding
        name
      end

      # Emit a binding with a specific name.
      # @param name [String]
      # @param value [IR::ANFValue]
      def emit_named(name, value)
        binding = IR::ANFBinding.new(name: name, value: value)
        binding.source_loc = @current_source_loc if @current_source_loc
        @bindings << binding
      end

      # Register a local variable name.
      def add_local(name)
        @local_names.add(name)
      end

      # @return [Boolean]
      def local?(name)
        @local_names.include?(name)
      end

      # Register a parameter name.
      def add_param(name)
        @param_names.add(name)
      end

      # @return [Boolean]
      def param?(name)
        @param_names.include?(name)
      end

      # Set an alias for a local variable (used when if-statement branches
      # reassign the same local).
      def set_local_alias(local_name, binding_name)
        @local_aliases[local_name] = binding_name
      end

      # @return [String]
      def get_local_alias(local_name)
        @local_aliases.fetch(local_name, "")
      end

      # Track an add_output reference.
      def add_output_ref(ref)
        @add_output_refs << ref
      end

      # @return [Array<String>]
      def get_add_output_refs
        @add_output_refs
      end

      # @return [Boolean]
      def property?(name)
        @contract.properties.any? { |p| p.name == name }
      end

      # Look up a parameter type by name across constructor and methods.
      # @return [String, nil]
      def get_param_type(name)
        @contract.constructor.params.each do |p|
          return Frontend._type_node_to_string(p.type) if p.name == name
        end
        @contract.methods.each do |m|
          m.params.each do |p|
            return Frontend._type_node_to_string(p.type) if p.name == name
          end
        end
        nil
      end

      # Look up a property type by name.
      # @return [String, nil]
      def get_property_type(name)
        @contract.properties.each do |p|
          return Frontend._type_node_to_string(p.type) if p.name == name
        end
        nil
      end

      # @return [Boolean]
      def local_byte_var?(name)
        @local_byte_vars.include?(name)
      end

      # Create a sub-context for nested blocks (if/else, loops).
      #
      # The counter continues from the parent. Local names and param names
      # are shared (copied).
      # @return [LoweringContext]
      def sub_context
        sub = LoweringContext.new(@contract)
        sub.instance_variable_set(:@counter, @counter)
        sub.instance_variable_set(:@local_names, @local_names.dup)
        sub.instance_variable_set(:@param_names, @param_names.dup)
        sub.instance_variable_set(:@local_aliases, @local_aliases.dup)
        sub.instance_variable_set(:@local_byte_vars, @local_byte_vars.dup)
        sub
      end

      # Sync the temp counter from a sub-context back to the parent.
      def sync_counter(sub)
        sub_counter = sub.instance_variable_get(:@counter)
        @counter = sub_counter if sub_counter > @counter
      end

      # -----------------------------------------------------------------
      # Statement lowering
      # -----------------------------------------------------------------

      # @param stmts [Array<Statement>]
      def lower_statements(stmts)
        stmts.each_with_index do |stmt, i|
          # Early-return nesting: when an if-statement's then-block ends with a
          # return and there is no else-branch, the remaining statements after the
          # if logically belong in the else-branch.
          if stmt.is_a?(IfStmt) &&
             (stmt.else_.nil? || stmt.else_.empty?) &&
             i + 1 < stmts.length &&
             Frontend._branch_ends_with_return(stmt.then)
            remaining = stmts[(i + 1)..]
            modified_if = IfStmt.new(
              condition: stmt.condition,
              then: stmt.then,
              else_: remaining
            )
            lower_statement(modified_if)
            return
          end
          lower_statement(stmt)
        end
      end

      # @param stmt [Statement]
      def lower_statement(stmt)
        # Propagate source location to emitted ANF bindings
        stmt_loc = stmt.respond_to?(:source_location) ? stmt.source_location : nil
        if stmt_loc
          @current_source_loc = IR::SourceLocation.new(
            file: stmt_loc.file,
            line: stmt_loc.line,
            column: stmt_loc.column
          )
        end

        case stmt
        when VariableDeclStmt
          _lower_variable_decl(stmt)
        when AssignmentStmt
          _lower_assignment(stmt)
        when IfStmt
          _lower_if_statement(stmt)
        when ForStmt
          _lower_for_statement(stmt)
        when ExpressionStmt
          lower_expr_to_ref(stmt.expr)
        when ReturnStmt
          if stmt.value
            ref = lower_expr_to_ref(stmt.value)
            # If the returned ref is not the name of the last emitted binding,
            # emit an explicit load so the return value is the last (top-of-stack)
            # binding.
            if @bindings.any? && @bindings.last.name != ref
              emit(Frontend._make_load_const_string("@ref:#{ref}"))
            end
          end
        end

        @current_source_loc = nil
      end

      # -----------------------------------------------------------------
      # Expression lowering (the core ANF conversion)
      # -----------------------------------------------------------------

      # @param expr [Expression, nil]
      # @return [String] the binding name
      def lower_expr_to_ref(expr)
        return emit(Frontend._make_load_const_int(0)) if expr.nil?

        case expr
        when BigIntLiteral
          emit(Frontend._make_load_const_int(expr.value))
        when BoolLiteral
          emit(Frontend._make_load_const_bool(expr.value))
        when ByteStringLiteral
          emit(Frontend._make_load_const_string(expr.value))
        when Identifier
          _lower_identifier(expr)
        when PropertyAccessExpr
          # this.txPreimage in StatefulSmartContract -> load_param
          if param?(expr.property)
            return emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = expr.property })
          end
          # this.x -> load_prop
          emit(IR::ANFValue.new(kind: "load_prop").tap { |v| v.name = expr.property })
        when MemberExpr
          _lower_member_expr(expr)
        when BinaryExpr
          left_ref = lower_expr_to_ref(expr.left)
          right_ref = lower_expr_to_ref(expr.right)

          result_type = nil
          if %w[=== !==].include?(expr.op) &&
             (Frontend._is_byte_typed_expr(expr.left, self) || Frontend._is_byte_typed_expr(expr.right, self))
            result_type = "bytes"
          end
          # For +, annotate byte-typed operands so stack lowering can emit OP_CAT.
          if expr.op == "+" &&
             (Frontend._is_byte_typed_expr(expr.left, self) || Frontend._is_byte_typed_expr(expr.right, self))
            result_type = "bytes"
          end
          # For bitwise &, |, ^, annotate byte-typed operands.
          if %w[& | ^].include?(expr.op) &&
             (Frontend._is_byte_typed_expr(expr.left, self) || Frontend._is_byte_typed_expr(expr.right, self))
            result_type = "bytes"
          end

          emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
            v.op = expr.op
            v.left = left_ref
            v.right = right_ref
            v.result_type = result_type
          end)
        when UnaryExpr
          operand_ref = lower_expr_to_ref(expr.operand)
          unary_val = IR::ANFValue.new(kind: "unary_op").tap do |v|
            v.op = expr.op
            v.operand = operand_ref
          end
          # For ~, annotate byte-typed operands so downstream passes know the result is bytes.
          if expr.op == "~" && Frontend._is_byte_typed_expr(expr.operand, self)
            unary_val.result_type = "bytes"
          end
          emit(unary_val)
        when CallExpr
          _lower_call_expr(expr)
        when TernaryExpr
          _lower_ternary_expr(expr)
        when IndexAccessExpr
          obj_ref = lower_expr_to_ref(expr.object)
          index_ref = lower_expr_to_ref(expr.index)
          emit(Frontend._make_call("__array_access", [obj_ref, index_ref]))
        when IncrementExpr
          _lower_increment_expr(expr)
        when DecrementExpr
          _lower_decrement_expr(expr)
        when ArrayLiteralExpr
          element_refs = expr.elements.map { |elem| lower_expr_to_ref(elem) }
          emit(IR::ANFValue.new(kind: "array_literal").tap { |v| v.elements = element_refs })
        else
          emit(Frontend._make_load_const_int(0))
        end
      end

      private

      # @param stmt [VariableDeclStmt]
      def _lower_variable_decl(stmt)
        value_ref = lower_expr_to_ref(stmt.init)
        add_local(stmt.name)
        if Frontend._is_byte_typed_expr(stmt.init, self)
          @local_byte_vars.add(stmt.name)
        end
        emit_named(stmt.name, Frontend._make_load_const_string("@ref:#{value_ref}"))
      end

      # @param stmt [AssignmentStmt]
      def _lower_assignment(stmt)
        value_ref = lower_expr_to_ref(stmt.value)

        # this.x = expr -> update_prop
        if stmt.target.is_a?(PropertyAccessExpr)
          emit(Frontend._make_update_prop(stmt.target.property, value_ref))
          return
        end

        # local = expr -> re-bind
        if stmt.target.is_a?(Identifier)
          emit_named(stmt.target.name, Frontend._make_load_const_string("@ref:#{value_ref}"))
          return
        end

        # For other targets, lower the target expression
        lower_expr_to_ref(stmt.target)
      end

      # @param stmt [IfStmt]
      def _lower_if_statement(stmt)
        cond_ref = lower_expr_to_ref(stmt.condition)

        # Lower then-block into sub-context
        then_ctx = sub_context
        then_ctx.lower_statements(stmt.then)
        sync_counter(then_ctx)

        # Lower else-block into sub-context
        else_ctx = sub_context
        if stmt.else_ && stmt.else_.any?
          else_ctx.lower_statements(stmt.else_)
        end
        sync_counter(else_ctx)

        # Propagate addOutput refs from sub-contexts
        then_has_outputs = then_ctx.get_add_output_refs.any?
        else_has_outputs = else_ctx.get_add_output_refs.any?

        if_name = emit(IR::ANFValue.new(kind: "if").tap do |v|
          v.cond = cond_ref
          v.then = then_ctx.bindings
          v.else_ = else_ctx.bindings
        end)

        if then_has_outputs || else_has_outputs
          add_output_ref(if_name)
        end

        # If both branches end by reassigning the same local variable,
        # alias that variable to the if-expression result
        if then_ctx.bindings.any? && else_ctx.bindings.any?
          then_last = then_ctx.bindings.last
          else_last = else_ctx.bindings.last
          if then_last.name == else_last.name && local?(then_last.name)
            set_local_alias(then_last.name, if_name)
          end
        end
      end

      # @param stmt [ForStmt]
      def _lower_for_statement(stmt)
        count = Frontend._extract_loop_count(stmt)

        # Lower body into sub-context
        body_ctx = sub_context
        body_ctx.lower_statements(stmt.body)
        sync_counter(body_ctx)

        emit(IR::ANFValue.new(kind: "loop").tap do |v|
          v.count = count
          v.body = body_ctx.bindings
          v.iter_var = stmt.init ? stmt.init.name : ""
        end)
      end

      # @param id_node [Identifier]
      # @return [String]
      def _lower_identifier(id_node)
        name = id_node.name

        # 'this' is not a value in ANF
        return emit(Frontend._make_load_const_string("@this")) if name == "this"

        # Check if it's a registered parameter (e.g. txPreimage)
        return emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = name }) if param?(name)

        # Check if it's a local variable -- reference it directly
        # (or use its alias if reassigned by an if-statement)
        if local?(name)
          a = get_local_alias(name)
          return a unless a.empty?
          return name
        end

        # Check if it's a contract property
        return emit(IR::ANFValue.new(kind: "load_prop").tap { |v| v.name = name }) if property?(name)

        # Default: treat as parameter (this is how params get loaded lazily)
        emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = name })
      end

      # @param e [MemberExpr]
      # @return [String]
      def _lower_member_expr(e)
        # this.x -> load_prop
        if e.object.is_a?(Identifier) && e.object.name == "this"
          return emit(IR::ANFValue.new(kind: "load_prop").tap { |v| v.name = e.property })
        end

        # SigHash.ALL etc. -> load constant
        if e.object.is_a?(Identifier) && e.object.name == "SigHash"
          sig_hash_values = {
            "ALL"          => 0x01,
            "NONE"         => 0x02,
            "SINGLE"       => 0x03,
            "FORKID"       => 0x40,
            "ANYONECANPAY" => 0x80
          }.freeze
          val = sig_hash_values[e.property]
          return emit(Frontend._make_load_const_int(val)) unless val.nil?
        end

        # General member access
        obj_ref = lower_expr_to_ref(e.object)
        emit(IR::ANFValue.new(kind: "method_call").tap do |v|
          v.object = obj_ref
          v.method = e.property
        end)
      end

      # @param e [CallExpr]
      # @return [String]
      def _lower_call_expr(e)
        callee = e.callee

        # super(...) call -- accepts both Identifier("super") and MemberExpr(super, "")
        is_super = (callee.is_a?(Identifier) && callee.name == "super") ||
                   (callee.is_a?(MemberExpr) && callee.object.is_a?(Identifier) && callee.object.name == "super")
        if is_super
          arg_refs = _lower_args(e.args)
          return emit(Frontend._make_call("super", arg_refs))
        end

        # assert(expr)
        if callee.is_a?(Identifier) && callee.name == "assert"
          if e.args.length >= 1
            value_ref = lower_expr_to_ref(e.args[0])
            return emit(Frontend._make_assert(value_ref))
          end
          false_ref = emit(Frontend._make_load_const_bool(false))
          return emit(Frontend._make_assert(false_ref))
        end

        # checkPreimage(preimage)
        if callee.is_a?(Identifier) && callee.name == "checkPreimage"
          if e.args.length >= 1
            preimage_ref = lower_expr_to_ref(e.args[0])
            return emit(IR::ANFValue.new(kind: "check_preimage").tap { |v| v.preimage = preimage_ref })
          end
        end

        # this.addOutput(satoshis, val1, val2, ...) via PropertyAccessExpr
        if callee.is_a?(PropertyAccessExpr) && callee.property == "addOutput"
          arg_refs = _lower_args(e.args)
          satoshis = arg_refs[0]
          state_values = arg_refs[1..]
          ref = emit(IR::ANFValue.new(kind: "add_output").tap do |v|
            v.satoshis = satoshis
            v.state_values = state_values
            v.preimage = ""
          end)
          add_output_ref(ref)
          return ref
        end

        # this.addRawOutput(satoshis, scriptBytes) via PropertyAccessExpr
        if callee.is_a?(PropertyAccessExpr) && callee.property == "addRawOutput"
          arg_refs = _lower_args(e.args)
          satoshis = arg_refs[0]
          script_bytes_ref = arg_refs[1]
          ref = emit(IR::ANFValue.new(kind: "add_raw_output").tap do |v|
            v.satoshis = satoshis
            v.script_bytes = script_bytes_ref
          end)
          add_output_ref(ref)
          return ref
        end

        # this.addOutput(satoshis, val1, val2, ...) via MemberExpr
        if callee.is_a?(MemberExpr) &&
           callee.object.is_a?(Identifier) &&
           callee.object.name == "this" &&
           callee.property == "addOutput"
          arg_refs = _lower_args(e.args)
          satoshis = arg_refs[0]
          state_values = arg_refs[1..]
          ref = emit(IR::ANFValue.new(kind: "add_output").tap do |v|
            v.satoshis = satoshis
            v.state_values = state_values
            v.preimage = ""
          end)
          add_output_ref(ref)
          return ref
        end

        # this.addRawOutput(satoshis, scriptBytes) via MemberExpr
        if callee.is_a?(MemberExpr) &&
           callee.object.is_a?(Identifier) &&
           callee.object.name == "this" &&
           callee.property == "addRawOutput"
          arg_refs = _lower_args(e.args)
          satoshis = arg_refs[0]
          script_bytes_ref = arg_refs[1]
          ref = emit(IR::ANFValue.new(kind: "add_raw_output").tap do |v|
            v.satoshis = satoshis
            v.script_bytes = script_bytes_ref
          end)
          add_output_ref(ref)
          return ref
        end

        # this.getStateScript() via PropertyAccessExpr
        if callee.is_a?(PropertyAccessExpr) && callee.property == "getStateScript"
          return emit(IR::ANFValue.new(kind: "get_state_script"))
        end

        # this.getStateScript() via MemberExpr
        if callee.is_a?(MemberExpr) &&
           callee.object.is_a?(Identifier) &&
           callee.object.name == "this" &&
           callee.property == "getStateScript"
          return emit(IR::ANFValue.new(kind: "get_state_script"))
        end

        # this.method(...) via PropertyAccessExpr
        if callee.is_a?(PropertyAccessExpr)
          arg_refs = _lower_args(e.args)
          this_ref = emit(Frontend._make_load_const_string("@this"))
          return emit(IR::ANFValue.new(kind: "method_call").tap do |v|
            v.object = this_ref
            v.method = callee.property
            v.args = arg_refs
          end)
        end

        # this.method(...) via MemberExpr
        if callee.is_a?(MemberExpr) &&
           callee.object.is_a?(Identifier) &&
           callee.object.name == "this"
          arg_refs = _lower_args(e.args)
          this_ref = emit(Frontend._make_load_const_string("@this"))
          return emit(IR::ANFValue.new(kind: "method_call").tap do |v|
            v.object = this_ref
            v.method = callee.property
            v.args = arg_refs
          end)
        end

        # Direct function call: sha256(x), checkSig(sig, pk), etc.
        if callee.is_a?(Identifier)
          arg_refs = _lower_args(e.args)
          return emit(Frontend._make_call(callee.name, arg_refs))
        end

        # General call
        callee_ref = lower_expr_to_ref(callee)
        arg_refs = _lower_args(e.args)
        emit(IR::ANFValue.new(kind: "method_call").tap do |v|
          v.object = callee_ref
          v.method = "call"
          v.args = arg_refs
        end)
      end

      # @param args [Array<Expression>]
      # @return [Array<String>]
      def _lower_args(args)
        args.map { |arg| lower_expr_to_ref(arg) }
      end

      # @param e [TernaryExpr]
      # @return [String]
      def _lower_ternary_expr(e)
        cond_ref = lower_expr_to_ref(e.condition)

        then_ctx = sub_context
        then_ctx.lower_expr_to_ref(e.consequent)
        sync_counter(then_ctx)

        else_ctx = sub_context
        else_ctx.lower_expr_to_ref(e.alternate)
        sync_counter(else_ctx)

        emit(IR::ANFValue.new(kind: "if").tap do |v|
          v.cond = cond_ref
          v.then = then_ctx.bindings
          v.else_ = else_ctx.bindings
        end)
      end

      # @param e [IncrementExpr]
      # @return [String]
      def _lower_increment_expr(e)
        operand_ref = lower_expr_to_ref(e.operand)
        one_ref = emit(Frontend._make_load_const_int(1))
        result = emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
          v.op = "+"
          v.left = operand_ref
          v.right = one_ref
        end)

        # If the operand is a named variable, update it
        if e.operand.is_a?(Identifier)
          emit_named(e.operand.name, Frontend._make_load_const_string("@ref:#{result}"))
        end
        if e.operand.is_a?(PropertyAccessExpr)
          emit(Frontend._make_update_prop(e.operand.property, result))
        end

        e.prefix ? result : operand_ref
      end

      # @param e [DecrementExpr]
      # @return [String]
      def _lower_decrement_expr(e)
        operand_ref = lower_expr_to_ref(e.operand)
        one_ref = emit(Frontend._make_load_const_int(1))
        result = emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
          v.op = "-"
          v.left = operand_ref
          v.right = one_ref
        end)

        # If the operand is a named variable, update it
        if e.operand.is_a?(Identifier)
          emit_named(e.operand.name, Frontend._make_load_const_string("@ref:#{result}"))
        end
        if e.operand.is_a?(PropertyAccessExpr)
          emit(Frontend._make_update_prop(e.operand.property, result))
        end

        e.prefix ? result : operand_ref
      end
    end # class LoweringContext

    # -------------------------------------------------------------------
    # ANFValue constructors (module-level helpers)
    # -------------------------------------------------------------------

    # @param val [Integer]
    # @return [IR::ANFValue]
    def self._make_load_const_int(val)
      raw = JSON.generate(val)
      IR::ANFValue.new(kind: "load_const").tap do |v|
        v.raw_value = raw
        v.const_big_int = val
        v.const_int = val
      end
    end

    # @param val [Boolean]
    # @return [IR::ANFValue]
    def self._make_load_const_bool(val)
      raw = JSON.generate(val)
      IR::ANFValue.new(kind: "load_const").tap do |v|
        v.raw_value = raw
        v.const_bool = val
      end
    end

    # @param val [String]
    # @return [IR::ANFValue]
    def self._make_load_const_string(val)
      raw = JSON.generate(val)
      IR::ANFValue.new(kind: "load_const").tap do |v|
        v.raw_value = raw
        v.const_string = val
      end
    end

    # @param func_name [String]
    # @param args [Array<String>]
    # @return [IR::ANFValue]
    def self._make_call(func_name, args)
      IR::ANFValue.new(kind: "call").tap do |v|
        v.func = func_name
        v.args = args
      end
    end

    # @param value_ref [String]
    # @return [IR::ANFValue]
    def self._make_assert(value_ref)
      raw = JSON.generate(value_ref)
      IR::ANFValue.new(kind: "assert").tap do |v|
        v.raw_value = raw
        v.value_ref = value_ref
      end
    end

    # @param name [String]
    # @param value_ref [String]
    # @return [IR::ANFValue]
    def self._make_update_prop(name, value_ref)
      raw = JSON.generate(value_ref)
      IR::ANFValue.new(kind: "update_prop").tap do |v|
        v.name = name
        v.raw_value = raw
        v.value_ref = value_ref
      end
    end

    # -------------------------------------------------------------------
    # State mutation analysis
    # -------------------------------------------------------------------

    # Determine whether a method mutates any mutable (non-readonly) property.
    # Conservative: if ANY code path can mutate state, returns true.
    def self._method_mutates_state(method, contract)
      mutable_props = Set.new
      contract.properties.each do |p|
        mutable_props.add(p.name) unless p.readonly
      end
      return false if mutable_props.empty?
      _body_mutates_state(method.body, mutable_props)
    end
    private_class_method :_method_mutates_state

    # @param stmts [Array<Statement>]
    # @param mutable_props [Set<String>]
    # @return [Boolean]
    def self._body_mutates_state(stmts, mutable_props)
      stmts.any? { |stmt| _stmt_mutates_state(stmt, mutable_props) }
    end
    private_class_method :_body_mutates_state

    # @param stmt [Statement]
    # @param mutable_props [Set<String>]
    # @return [Boolean]
    def self._stmt_mutates_state(stmt, mutable_props)
      if stmt.is_a?(AssignmentStmt)
        if stmt.target.is_a?(PropertyAccessExpr)
          return mutable_props.include?(stmt.target.property)
        end
        return false
      end

      if stmt.is_a?(ExpressionStmt)
        return _expr_mutates_state(stmt.expr, mutable_props)
      end

      if stmt.is_a?(IfStmt)
        return true if _body_mutates_state(stmt.then, mutable_props)
        if stmt.else_ && stmt.else_.any?
          return true if _body_mutates_state(stmt.else_, mutable_props)
        end
        return false
      end

      if stmt.is_a?(ForStmt)
        if stmt.update && _stmt_mutates_state(stmt.update, mutable_props)
          return true
        end
        return _body_mutates_state(stmt.body, mutable_props)
      end

      false
    end
    private_class_method :_stmt_mutates_state

    # @param expr [Expression, nil]
    # @param mutable_props [Set<String>]
    # @return [Boolean]
    def self._expr_mutates_state(expr, mutable_props)
      return false if expr.nil?
      if expr.is_a?(IncrementExpr)
        if expr.operand.is_a?(PropertyAccessExpr)
          return mutable_props.include?(expr.operand.property)
        end
      end
      if expr.is_a?(DecrementExpr)
        if expr.operand.is_a?(PropertyAccessExpr)
          return mutable_props.include?(expr.operand.property)
        end
      end
      false
    end
    private_class_method :_expr_mutates_state

    # -------------------------------------------------------------------
    # addOutput detection for determining change output necessity
    # -------------------------------------------------------------------

    # Check if a method body contains any this.addOutput() calls.
    def self._method_has_add_output(method)
      _body_has_add_output(method.body)
    end
    private_class_method :_method_has_add_output

    # @param stmts [Array<Statement>]
    # @return [Boolean]
    def self._body_has_add_output(stmts)
      stmts.any? { |stmt| _stmt_has_add_output(stmt) }
    end
    private_class_method :_body_has_add_output

    # @param stmt [Statement]
    # @return [Boolean]
    def self._stmt_has_add_output(stmt)
      if stmt.is_a?(ExpressionStmt)
        return _expr_has_add_output(stmt.expr)
      end
      if stmt.is_a?(IfStmt)
        return true if _body_has_add_output(stmt.then)
        if stmt.else_ && stmt.else_.any?
          return true if _body_has_add_output(stmt.else_)
        end
        return false
      end
      if stmt.is_a?(ForStmt)
        return _body_has_add_output(stmt.body)
      end
      false
    end
    private_class_method :_stmt_has_add_output

    # @param expr [Expression, nil]
    # @return [Boolean]
    def self._expr_has_add_output(expr)
      return false if expr.nil?
      if expr.is_a?(CallExpr)
        callee = expr.callee
        if callee.is_a?(PropertyAccessExpr) && %w[addOutput addRawOutput].include?(callee.property)
          return true
        end
        if callee.is_a?(MemberExpr) &&
           callee.object.is_a?(Identifier) &&
           callee.object.name == "this" &&
           %w[addOutput addRawOutput].include?(callee.property)
          return true
        end
      end
      false
    end
    private_class_method :_expr_has_add_output

    # -------------------------------------------------------------------
    # Loop count extraction
    # -------------------------------------------------------------------

    # @param stmt [ForStmt]
    # @return [Integer]
    def self._extract_loop_count(stmt)
      start_val = _extract_bigint_value(stmt.init&.init)

      if stmt.condition.is_a?(BinaryExpr)
        bound_val = _extract_bigint_value(stmt.condition.right)

        if start_val && bound_val
          start = start_val
          bound = bound_val
          op = stmt.condition.op
          return [0, bound - start].max if op == "<"
          return [0, bound - start + 1].max if op == "<="
          return [0, start - bound].max if op == ">"
          return [0, start - bound + 1].max if op == ">="
        end

        if bound_val
          op = stmt.condition.op
          return bound_val if op == "<"
          return bound_val + 1 if op == "<="
        end
      end

      0
    end

    # @param expr [Expression, nil]
    # @return [Integer, nil]
    def self._extract_bigint_value(expr)
      return nil if expr.nil?
      return expr.value if expr.is_a?(BigIntLiteral)
      if expr.is_a?(UnaryExpr) && expr.op == "-"
        inner = _extract_bigint_value(expr.operand)
        return -inner unless inner.nil?
      end
      nil
    end
    private_class_method :_extract_bigint_value

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    # Check whether a statement list always terminates with a return statement.
    # @param stmts [Array<Statement>]
    # @return [Boolean]
    def self._branch_ends_with_return(stmts)
      return false if stmts.nil? || stmts.empty?
      last = stmts.last
      return true if last.is_a?(ReturnStmt)
      # Also handle if-else where both branches return
      if last.is_a?(IfStmt) && last.else_ && last.else_.any?
        return _branch_ends_with_return(last.then) && _branch_ends_with_return(last.else_)
      end
      false
    end

    # Convert a type node to its string representation.
    # @param node [TypeNode, nil]
    # @return [String]
    def self._type_node_to_string(node)
      return "<unknown>" if node.nil?
      return node.name if node.is_a?(PrimitiveType)
      return "#{_type_node_to_string(node.element)}[]" if node.is_a?(FixedArrayType)
      return node.name if node.is_a?(CustomType)
      "<unknown>"
    end
  end
end
