import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'PriceBet.runar.sol'), 'utf8');
const FILE_NAME = 'PriceBet.runar.sol';

const ALICE_PK = '02' + 'aa'.repeat(32);
const BOB_PK = '02' + 'bb'.repeat(32);
const ORACLE_PK = 12345n;
const STRIKE = 50000n;
const ALICE_SIG = '30' + 'aa'.repeat(35);
const BOB_SIG = '30' + 'bb'.repeat(35);
const RABIN_SIG = 99999n;
const PADDING = 'aabbccdd';

describe('PriceBet (Solidity)', () => {
  function makeBet() {
    return TestContract.fromSource(source, {
      alicePubKey: ALICE_PK,
      bobPubKey: BOB_PK,
      oraclePubKey: ORACLE_PK,
      strikePrice: STRIKE,
    }, FILE_NAME);
  }

  it('settles to Alice when price exceeds strike', () => {
    const bet = makeBet();
    const result = bet.call('settle', {
      price: 60000n,
      rabinSig: RABIN_SIG,
      padding: PADDING,
      aliceSig: ALICE_SIG,
      bobSig: BOB_SIG,
    });
    expect(result.success).toBe(true);
  });

  it('settles to Bob when price is below strike', () => {
    const bet = makeBet();
    const result = bet.call('settle', {
      price: 30000n,
      rabinSig: RABIN_SIG,
      padding: PADDING,
      aliceSig: ALICE_SIG,
      bobSig: BOB_SIG,
    });
    expect(result.success).toBe(true);
  });

  it('settles to Bob when price equals strike', () => {
    const bet = makeBet();
    const result = bet.call('settle', {
      price: 50000n,
      rabinSig: RABIN_SIG,
      padding: PADDING,
      aliceSig: ALICE_SIG,
      bobSig: BOB_SIG,
    });
    expect(result.success).toBe(true);
  });

  it('rejects settlement when price is zero', () => {
    const bet = makeBet();
    const result = bet.call('settle', {
      price: 0n,
      rabinSig: RABIN_SIG,
      padding: PADDING,
      aliceSig: ALICE_SIG,
      bobSig: BOB_SIG,
    });
    expect(result.success).toBe(false);
  });

  it('cancel succeeds with both signatures', () => {
    const bet = makeBet();
    const result = bet.call('cancel', {
      aliceSig: ALICE_SIG,
      bobSig: BOB_SIG,
    });
    expect(result.success).toBe(true);
  });
});
