import { describe, it, expect } from 'vitest';
import { parsePythonSource } from '../passes/01-parse-python.js';
import type {
  BinaryExpr,
  CallExpr,
  Identifier,
  BigIntLiteral,
  BoolLiteral,
  UnaryExpr,
  IfStatement,
  ForStatement,
  VariableDeclStatement,
  ExpressionStatement,
  ReturnStatement,
} from '../ir/index.js';

// ---------------------------------------------------------------------------
// Helper: basic P2PKH in Python syntax
// ---------------------------------------------------------------------------

const P2PKH_PY = `
from runar import SmartContract, PubKey, Sig, check_sig, assert_

class P2PKH(SmartContract):
    pk: PubKey

    def __init__(self, pk: PubKey):
        super().__init__(pk)

    @public
    def unlock(self, sig: Sig):
        assert_(check_sig(sig, self.pk))
`;

// ---------------------------------------------------------------------------
// Contract structure
// ---------------------------------------------------------------------------

describe('Python Parser', () => {
  describe('contract structure', () => {
    it('parses a P2PKH contract and returns a ContractNode', () => {
      const result = parsePythonSource(P2PKH_PY, 'P2PKH.runar.py');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.kind).toBe('contract');
      expect(result.contract!.name).toBe('P2PKH');
    });

    it('sets parentClass to SmartContract', () => {
      const result = parsePythonSource(P2PKH_PY, 'P2PKH.runar.py');
      expect(result.contract!.parentClass).toBe('SmartContract');
    });

    it('uses provided fileName as sourceFile', () => {
      const result = parsePythonSource(P2PKH_PY, 'p2pkh.runar.py');
      expect(result.contract!.sourceFile).toBe('p2pkh.runar.py');
    });

    it('uses default fileName contract.runar.py', () => {
      const result = parsePythonSource(P2PKH_PY, 'contract.runar.py');
      expect(result.contract!.sourceFile).toBe('contract.runar.py');
    });

    it('parses StatefulSmartContract', () => {
      const py = `
from runar import StatefulSmartContract

class Counter(StatefulSmartContract):
    count: bigint

    def __init__(self, count: bigint):
        super().__init__(count)

    @public
    def increment(self):
        self.count = self.count + 1
`;
      const result = parsePythonSource(py, 'Counter.runar.py');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract!.parentClass).toBe('StatefulSmartContract');
    });
  });

  // ---------------------------------------------------------------------------
  // Properties
  // ---------------------------------------------------------------------------

  describe('properties', () => {
    it('extracts a property as readonly in SmartContract', () => {
      const result = parsePythonSource(P2PKH_PY, 'P2PKH.runar.py');
      const contract = result.contract!;
      expect(contract.properties).toHaveLength(1);
      const pk = contract.properties[0]!;
      expect(pk.kind).toBe('property');
      expect(pk.name).toBe('pk');
      expect(pk.readonly).toBe(true);
      expect(pk.type).toEqual({ kind: 'primitive_type', name: 'PubKey' });
    });

    it('parses non-readonly property in StatefulSmartContract', () => {
      const py = `
from runar import StatefulSmartContract

class Counter(StatefulSmartContract):
    count: bigint

    def __init__(self, count: bigint):
        super().__init__(count)

    @public
    def increment(self):
        self.count = self.count + 1
`;
      const result = parsePythonSource(py, 'Counter.runar.py');
      const prop = result.contract!.properties[0]!;
      expect(prop.name).toBe('count');
      expect(prop.readonly).toBe(false);
    });

    it('parses Readonly[bigint] as readonly in StatefulSmartContract', () => {
      const py = `
from runar import StatefulSmartContract
from typing import Readonly

class C(StatefulSmartContract):
    owner: Readonly[PubKey]
    count: bigint

    def __init__(self, owner: PubKey, count: bigint):
        super().__init__(owner, count)

    @public
    def increment(self):
        self.count = self.count + 1
`;
      const result = parsePythonSource(py, 'C.runar.py');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const owner = result.contract!.properties.find(p => p.name === 'owner')!;
      expect(owner.readonly).toBe(true);
      const count = result.contract!.properties.find(p => p.name === 'count')!;
      expect(count.readonly).toBe(false);
    });

    it('parses multiple properties', () => {
      const py = `
from runar import SmartContract

class Escrow(SmartContract):
    pk1: PubKey
    pk2: PubKey
    amount: bigint

    def __init__(self, pk1: PubKey, pk2: PubKey, amount: bigint):
        super().__init__(pk1, pk2, amount)

    @public
    def release(self, sig: Sig):
        assert_(check_sig(sig, self.pk1))
`;
      const result = parsePythonSource(py, 'Escrow.runar.py');
      expect(result.contract!.properties).toHaveLength(3);
      expect(result.contract!.properties.map(p => p.name)).toEqual(['pk1', 'pk2', 'amount']);
    });

    it('parses property with initializer', () => {
      const py = `
from runar import StatefulSmartContract

class C(StatefulSmartContract):
    count: bigint = 0

    @public
    def increment(self):
        self.count = self.count + 1
`;
      const result = parsePythonSource(py, 'C.runar.py');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const prop = result.contract!.properties[0]!;
      expect(prop.name).toBe('count');
      expect(prop.initializer).toBeDefined();
      expect(prop.initializer!.kind).toBe('bigint_literal');
      if (prop.initializer!.kind === 'bigint_literal') {
        expect(prop.initializer!.value).toBe(0n);
      }
    });
  });

  // ---------------------------------------------------------------------------
  // snake_case to camelCase conversion
  // ---------------------------------------------------------------------------

  describe('snake_case to camelCase', () => {
    it('converts property names from snake_case to camelCase', () => {
      const py = `
from runar import SmartContract

class P2PKH(SmartContract):
    pub_key_hash: ByteString

    def __init__(self, pub_key_hash: ByteString):
        super().__init__(pub_key_hash)

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(check_sig(sig, pub_key))
`;
      const result = parsePythonSource(py, 'P2PKH.runar.py');
      expect(result.contract!.properties[0]!.name).toBe('pubKeyHash');
    });

    it('converts function call names from snake_case to camelCase', () => {
      const py = `
from runar import SmartContract

class P2PKH(SmartContract):
    pub_key_hash: ByteString

    def __init__(self, pub_key_hash: ByteString):
        super().__init__(pub_key_hash)

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(check_sig(sig, pub_key))
`;
      const result = parsePythonSource(py, 'P2PKH.runar.py');
      const method = result.contract!.methods[0]!;
      // assert_(check_sig(...)) -> assert(checkSig(...))
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      expect((assertCall.callee as Identifier).name).toBe('assert');
      const innerCall = assertCall.args[0] as CallExpr;
      expect((innerCall.callee as Identifier).name).toBe('checkSig');
    });

    it('converts method parameter names from snake_case to camelCase', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    @public
    def verify(self, pub_key: PubKey):
        assert_(true)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;
      expect(method.params[0]!.name).toBe('pubKey');
    });
  });

  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------

  describe('constructor', () => {
    it('parses explicit __init__ as constructor', () => {
      const result = parsePythonSource(P2PKH_PY, 'P2PKH.runar.py');
      const ctor = result.contract!.constructor;
      expect(ctor.kind).toBe('method');
      expect(ctor.name).toBe('constructor');
      expect(ctor.params).toHaveLength(1);
      expect(ctor.params[0]!.name).toBe('pk');
    });

    it('constructor body contains super call', () => {
      const result = parsePythonSource(P2PKH_PY, 'P2PKH.runar.py');
      const ctor = result.contract!.constructor;
      const superStmt = ctor.body.find(s => {
        if (s.kind !== 'expression_statement') return false;
        const expr = s.expression;
        if (expr.kind !== 'call_expr') return false;
        const callee = expr.callee;
        return (callee.kind === 'identifier' && callee.name === 'super');
      });
      expect(superStmt).toBeDefined();
    });

    it('auto-generates constructor when not present', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    @public
    def m(self):
        assert_(true)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      expect(result.contract!.constructor).toBeDefined();
      expect(result.contract!.constructor.name).toBe('constructor');
    });
  });

  // ---------------------------------------------------------------------------
  // Methods
  // ---------------------------------------------------------------------------

  describe('methods', () => {
    it('parses a @public method', () => {
      const result = parsePythonSource(P2PKH_PY, 'P2PKH.runar.py');
      expect(result.contract!.methods).toHaveLength(1);
      const unlock = result.contract!.methods[0]!;
      expect(unlock.name).toBe('unlock');
      expect(unlock.visibility).toBe('public');
    });

    it('defaults to private visibility without @public', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    def helper(self, a: bigint) -> bigint:
        return a + 1

    @public
    def m(self):
        assert_(true)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const helper = result.contract!.methods.find(m => m.name === 'helper');
      expect(helper).toBeDefined();
      expect(helper!.visibility).toBe('private');
    });

    it('parses multiple methods with mixed visibility', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    def helper(self, a: bigint) -> bigint:
        return a + 1

    @public
    def verify(self, a: bigint):
        result: bigint = self.helper(a)
        assert_(result > 0)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      expect(result.contract!.methods).toHaveLength(2);
      const helper = result.contract!.methods.find(m => m.name === 'helper')!;
      const verify = result.contract!.methods.find(m => m.name === 'verify')!;
      expect(helper.visibility).toBe('private');
      expect(verify.visibility).toBe('public');
    });

    it('parses method parameters (self is excluded)', () => {
      const result = parsePythonSource(P2PKH_PY, 'P2PKH.runar.py');
      const unlock = result.contract!.methods[0]!;
      expect(unlock.params).toHaveLength(1);
      expect(unlock.params[0]!.name).toBe('sig');
      expect(unlock.params[0]!.type).toEqual({ kind: 'primitive_type', name: 'Sig' });
    });
  });

  // ---------------------------------------------------------------------------
  // Expressions
  // ---------------------------------------------------------------------------

  describe('expressions', () => {
    it('parses binary arithmetic', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    @public
    def m(self, a: bigint, b: bigint):
        sum: bigint = a + b
        assert_(sum > 0)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      expect(decl.kind).toBe('variable_decl');
      const init = decl.init as BinaryExpr;
      expect(init.kind).toBe('binary_expr');
      expect(init.op).toBe('+');
    });

    it('maps == to === and != to !==', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    @public
    def m(self, a: bigint):
        assert_(a == 42)
        assert_(a != 0)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;

      // First assert: a == 42 -> assert(a === 42)
      const stmt1 = method.body[0] as ExpressionStatement;
      const assert1 = stmt1.expression as CallExpr;
      const cmp1 = assert1.args[0] as BinaryExpr;
      expect(cmp1.op).toBe('===');

      // Second assert: a != 0 -> assert(a !== 0)
      const stmt2 = method.body[1] as ExpressionStatement;
      const assert2 = stmt2.expression as CallExpr;
      const cmp2 = assert2.args[0] as BinaryExpr;
      expect(cmp2.op).toBe('!==');
    });

    it('parses integer division // as / in AST', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    @public
    def m(self, a: bigint, b: bigint):
        result: bigint = a // b
        assert_(result > 0)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      const divExpr = decl.init as BinaryExpr;
      expect(divExpr.kind).toBe('binary_expr');
      expect(divExpr.op).toBe('/');
    });

    it('maps and/or to &&/|| in AST', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    @public
    def m(self, a: bool, b: bool):
        assert_(a and b)
        assert_(a or b)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;

      // and -> &&
      const stmt1 = method.body[0] as ExpressionStatement;
      const assert1 = stmt1.expression as CallExpr;
      const andExpr = assert1.args[0] as BinaryExpr;
      expect(andExpr.op).toBe('&&');

      // or -> ||
      const stmt2 = method.body[1] as ExpressionStatement;
      const assert2 = stmt2.expression as CallExpr;
      const orExpr = assert2.args[0] as BinaryExpr;
      expect(orExpr.op).toBe('||');
    });

    it('maps not to ! in AST', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    @public
    def m(self, flag: bool):
        assert_(not flag)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const notExpr = assertCall.args[0] as UnaryExpr;
      expect(notExpr.kind).toBe('unary_expr');
      expect(notExpr.op).toBe('!');
    });

    it('parses function calls', () => {
      const result = parsePythonSource(P2PKH_PY, 'P2PKH.runar.py');
      const method = result.contract!.methods[0]!;
      // assert_(check_sig(sig, self.pk))
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      expect(assertCall.kind).toBe('call_expr');
      const innerCall = assertCall.args[0] as CallExpr;
      expect(innerCall.kind).toBe('call_expr');
      expect((innerCall.callee as Identifier).name).toBe('checkSig');
    });

    it('parses number literals as bigint', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    @public
    def m(self):
        a: bigint = 42
        assert_(a > 0)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      const lit = decl.init as BigIntLiteral;
      expect(lit.kind).toBe('bigint_literal');
      expect(lit.value).toBe(42n);
    });

    it('parses boolean literals', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    @public
    def m(self):
        assert_(True)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const boolLit = assertCall.args[0] as BoolLiteral;
      expect(boolLit.kind).toBe('bool_literal');
      expect(boolLit.value).toBe(true);
    });

    it('parses ByteString literal b\'\\xaa\\xbb\' as bytestring_literal', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    @public
    def m(self):
        h: ByteString = b'\\xaa\\xbb'
        assert_(True)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;
      const decl = method.body[0] as VariableDeclStatement;
      expect(decl.init.kind).toBe('bytestring_literal');
      if (decl.init.kind === 'bytestring_literal') {
        expect(decl.init.value).toBe('aabb');
      }
    });

    it('parses property access via self.x', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    target: bigint

    def __init__(self, target: bigint):
        super().__init__(target)

    @public
    def m(self, a: bigint):
        assert_(a == self.target)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      const cmp = assertCall.args[0] as BinaryExpr;
      expect(cmp.right.kind).toBe('property_access');
    });
  });

  // ---------------------------------------------------------------------------
  // Statements
  // ---------------------------------------------------------------------------

  describe('statements', () => {
    it('parses assert_(expr) as assert call', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    @public
    def m(self, a: bigint):
        assert_(a > 0)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      expect(assertCall.kind).toBe('call_expr');
      expect((assertCall.callee as Identifier).name).toBe('assert');
    });

    it('parses assert expr (keyword form) as assert call', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    @public
    def m(self, a: bigint):
        assert a > 0
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;
      const stmt = method.body[0] as ExpressionStatement;
      const assertCall = stmt.expression as CallExpr;
      expect(assertCall.kind).toBe('call_expr');
      expect((assertCall.callee as Identifier).name).toBe('assert');
    });

    it('parses if/else statements', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    @public
    def m(self, a: bigint):
        if a > 0:
            assert_(True)
        else:
            assert_(False)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;
      const ifStmt = method.body[0] as IfStatement;
      expect(ifStmt.kind).toBe('if_statement');
      expect(ifStmt.then.length).toBeGreaterThan(0);
      expect(ifStmt.else).toBeDefined();
    });

    it('parses for loop with range', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    @public
    def m(self):
        sum: bigint = 0
        for i in range(10):
            sum = sum + i
        assert_(sum > 0)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const method = result.contract!.methods[0]!;
      const forStmt = method.body[1] as ForStatement;
      expect(forStmt.kind).toBe('for_statement');
      expect(forStmt.init.name).toBe('i');
    });

    it('parses return statements', () => {
      const py = `
from runar import SmartContract

class C(SmartContract):
    x: bigint

    def __init__(self, x: bigint):
        super().__init__(x)

    def helper(self, a: bigint) -> bigint:
        return a + 1

    @public
    def m(self):
        assert_(True)
`;
      const result = parsePythonSource(py, 'C.runar.py');
      const helper = result.contract!.methods.find(m => m.name === 'helper')!;
      const retStmt = helper.body[0] as ReturnStatement;
      expect(retStmt.kind).toBe('return_statement');
      expect(retStmt.value).toBeDefined();
    });

    it('parses stateful assignment (self.count = expr)', () => {
      const py = `
from runar import StatefulSmartContract

class Counter(StatefulSmartContract):
    count: bigint

    def __init__(self, count: bigint):
        super().__init__(count)

    @public
    def increment(self):
        self.count = self.count + 1
`;
      const result = parsePythonSource(py, 'Counter.runar.py');
      const method = result.contract!.methods[0]!;
      const assignStmt = method.body[0]!;
      expect(assignStmt.kind).toBe('assignment');
      if (assignStmt.kind === 'assignment') {
        expect(assignStmt.value.kind).toBe('binary_expr');
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Error handling
  // ---------------------------------------------------------------------------

  describe('error handling', () => {
    it('produces error for invalid syntax (no class declaration)', () => {
      const py = `
def standalone_function():
    pass
`;
      const result = parsePythonSource(py, 'bad.runar.py');
      const errors = result.errors.filter(e => e.severity === 'error');
      expect(errors.length).toBeGreaterThan(0);
    });

    it('produces error for unknown parent class', () => {
      const py = `
class C(SomeOtherClass):
    x: bigint

    @public
    def m(self):
        assert_(True)
`;
      const result = parsePythonSource(py, 'bad.runar.py');
      const errors = result.errors.filter(e => e.severity === 'error');
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  // ---------------------------------------------------------------------------
  // Full contract: Arithmetic conformance
  // ---------------------------------------------------------------------------

  describe('conformance: arithmetic', () => {
    it('parses the arithmetic Python contract', () => {
      const py = `
from runar import SmartContract

class Arithmetic(SmartContract):
    target: bigint

    def __init__(self, target: bigint):
        super().__init__(target)

    @public
    def verify(self, a: bigint, b: bigint):
        sum: bigint = a + b
        diff: bigint = a - b
        prod: bigint = a * b
        quot: bigint = a // b
        result: bigint = sum + diff + prod + quot
        assert_(result == self.target)
`;
      const result = parsePythonSource(py, 'Arithmetic.runar.py');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const contract = result.contract!;
      expect(contract.name).toBe('Arithmetic');
      expect(contract.properties).toHaveLength(1);
      expect(contract.methods).toHaveLength(1);
      expect(contract.methods[0]!.params).toHaveLength(2);
      expect(contract.methods[0]!.body.length).toBeGreaterThanOrEqual(6);
    });
  });

  // -------------------------------------------------------------------------
  // Docstring handling — triple-quoted strings must be skipped
  // -------------------------------------------------------------------------

  describe('docstrings', () => {
    it('handles class-level single-line docstring', () => {
      const py = `
from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig

class P2PKH(SmartContract):
    """Pay-to-Public-Key-Hash contract."""
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
`;
      const result = parsePythonSource(py, 'P2PKH.runar.py');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.name).toBe('P2PKH');
    });

    it('handles multi-line class docstring', () => {
      const py = `
from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig

class P2PKH(SmartContract):
    """P2PKH — Pay-to-Public-Key-Hash.

    The most fundamental Bitcoin spending pattern. Funds are locked to the
    HASH160 of a public key. To spend, the recipient must provide their
    full public key and a valid ECDSA signature.
    """
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
`;
      const result = parsePythonSource(py, 'P2PKH.runar.py');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract!.name).toBe('P2PKH');
      expect(result.contract!.properties).toHaveLength(1);
    });

    it('handles method-level docstrings', () => {
      const py = `
from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig

class P2PKH(SmartContract):
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        """Initialize with the hash of the owner public key."""
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        """Verify the pub_key hashes to the committed hash, then check the signature."""
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
`;
      const result = parsePythonSource(py, 'P2PKH.runar.py');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract!.name).toBe('P2PKH');
      expect(result.contract!.methods).toHaveLength(1);
    });

    it('handles single-quote triple docstrings', () => {
      const py = `
from runar import SmartContract, Bigint, public, assert_

class Test(SmartContract):
    '''Single-quote docstring.'''
    x: Bigint

    def __init__(self, x: Bigint):
        super().__init__(x)
        self.x = x

    @public
    def check(self):
        '''Check that x is positive.'''
        assert_(self.x > 0)
`;
      const result = parsePythonSource(py, 'Test.runar.py');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract!.name).toBe('Test');
    });
  });
});
