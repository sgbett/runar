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
