import { describe, expect, it } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { parseZigSource } from '../passes/01-parse-zig.js';

function parseContract(source: string) {
  const directResult = parseZigSource(source, 'Contract.runar.zig');
  const dispatchResult = parse(source, 'Contract.runar.zig');

  expect(directResult.errors.filter(error => error.severity === 'error')).toEqual([]);
  expect(dispatchResult.errors.filter(error => error.severity === 'error')).toEqual([]);

  return {
    direct: directResult.contract!,
    dispatch: dispatchResult.contract!,
  };
}

describe('parseZigSource readonly stateful fields', () => {
  it('parses runar.Readonly(T) without a default as readonly in StatefulSmartContract', () => {
    const source = `
      const runar = @import("runar");

      pub const Counter = struct {
        pub const Contract = runar.StatefulSmartContract;

        owner: runar.Readonly(runar.PubKey),
        count: i64 = 0,
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const owner = contract.properties.find(property => property.name === 'owner');
      const count = contract.properties.find(property => property.name === 'count');

      expect(owner?.readonly).toBe(true);
      expect(owner?.initializer).toBeUndefined();
      expect(count?.readonly).toBe(false);
    }
  });

  it('parses runar.Readonly(T) with a default as readonly in StatefulSmartContract', () => {
    const source = `
      const runar = @import("runar");

      pub const Counter = struct {
        pub const Contract = runar.StatefulSmartContract;

        prefix: runar.Readonly(runar.ByteString) = "abc",
        count: i64 = 0,
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const prefix = contract.properties.find(property => property.name === 'prefix');
      const count = contract.properties.find(property => property.name === 'count');

      expect(prefix?.readonly).toBe(true);
      expect(prefix?.initializer).toMatchObject({ kind: 'bytestring_literal', value: 'abc' });
      expect(count?.readonly).toBe(false);
    }
  });

  it('keeps unwrapped uninitialized stateful fields readonly', () => {
    const source = `
      const runar = @import("runar");

      pub const Counter = struct {
        pub const Contract = runar.StatefulSmartContract;

        count: i64,
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      expect(contract.properties[0]?.readonly).toBe(true);
    }
  });
});

describe('parseZigSource bytes equality lowering', () => {
  it('parses runar.bytesEq(a, b) as byte equality instead of a builtin call', () => {
    const source = `
      const runar = @import("runar");

      pub const EqContract = struct {
        pub const Contract = runar.SmartContract;

        pub fn unlock(self: EqContract, a: runar.ByteString, b: runar.ByteString) {
          _ = self;
          return runar.bytesEq(a, b);
        }
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const unlock = contract.methods.find(method => method.name === 'unlock');
      expect(unlock?.body).toHaveLength(1);

      const ret = unlock?.body[0];
      expect(ret?.kind).toBe('return_statement');

      if (ret?.kind === 'return_statement') {
        expect(ret.value).toEqual({
          kind: 'binary_expr',
          op: '===',
          left: { kind: 'identifier', name: 'a' },
          right: { kind: 'identifier', name: 'b' },
        });
      }
    }
  });
});

describe('parseZigSource bigint surface', () => {
  it('parses runar.Bigint as the normal bigint contract type', () => {
    const source = `
      const runar = @import("runar");

      pub const SchnorrZKP = struct {
        pub const Contract = runar.SmartContract;

        pubKey: runar.Point,

        pub fn verify(self: *const SchnorrZKP, rPoint: runar.Point, s: runar.Bigint) void {
          _ = self;
          _ = rPoint;
          _ = s;
        }
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const verify = contract.methods.find(method => method.name === 'verify');
      expect(verify?.params.map(param => [param.name, param.type])).toEqual([
        ['rPoint', { kind: 'primitive_type', name: 'Point' }],
        ['s', { kind: 'primitive_type', name: 'bigint' }],
      ]);
    }
  });
});

describe('parseZigSource @builtin expressions', () => {
  it('parses @divTrunc as binary division', () => {
    const source = `
      const runar = @import("runar");

      pub const Arithmetic = struct {
        pub const Contract = runar.SmartContract;

        target: i64,

        pub fn init(target: i64) Arithmetic {
          return .{ .target = target };
        }

        pub fn verify(self: *const Arithmetic, a: i64, b: i64) void {
          const quot = @divTrunc(a, b);
          runar.assert(quot == self.target);
        }
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const verify = contract.methods.find(method => method.name === 'verify');
      expect(verify).toBeDefined();
      // First statement should be variable_decl with a binary_expr (division)
      const quotDecl = verify!.body.find(s => s.kind === 'variable_decl' && s.name === 'quot');
      expect(quotDecl).toBeDefined();
      expect(quotDecl!.init).toMatchObject({ kind: 'binary_expr', op: '/' });
    }
  });

  it('parses @mod as binary modulo', () => {
    const source = `
      const runar = @import("runar");

      pub const Modulo = struct {
        pub const Contract = runar.SmartContract;

        target: i64,

        pub fn init(target: i64) Modulo {
          return .{ .target = target };
        }

        pub fn verify(self: *const Modulo, a: i64, b: i64) void {
          const rem = @mod(a, b);
          runar.assert(rem == self.target);
        }
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const verify = contract.methods.find(method => method.name === 'verify');
      const remDecl = verify!.body.find(s => s.kind === 'variable_decl' && s.name === 'rem');
      expect(remDecl).toBeDefined();
      expect(remDecl!.init).toMatchObject({ kind: 'binary_expr', op: '%' });
    }
  });
});
