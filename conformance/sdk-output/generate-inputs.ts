import { execFileSync } from 'child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, basename, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '../..');
const TESTS_DIR = join(__dirname, 'tests');

interface TestSpec {
  name: string;
  source: string; // relative to ROOT
  constructorArgs: Array<{ type: string; value: string }>;
}

// Standard test values
const PK = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const ADDR = '751e76e8199196d454941c45d1b3a323f1433bd6';
const HASH32 = '0000000000000000000000000000000000000000000000000000000000000001';
const POINT = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
const HELLO = '48656c6c6f';

const TEST_SPECS: TestSpec[] = [
  // ===== Example contracts (examples/ts/) =====

  {
    name: 'auction',
    source: 'examples/ts/auction/Auction.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'PubKey', value: PK },
      { type: 'bigint', value: '0' },
      { type: 'bigint', value: '1000000' },
    ],
  },
  {
    name: 'babybear',
    source: 'examples/ts/babybear/BabyBearDemo.runar.ts',
    constructorArgs: [],
  },
  {
    name: 'blake3',
    source: 'examples/ts/blake3/Blake3Test.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'convergence-proof',
    source: 'examples/ts/convergence-proof/ConvergenceProof.runar.ts',
    constructorArgs: [
      { type: 'Point', value: POINT },
      { type: 'Point', value: POINT },
    ],
  },
  {
    name: 'covenant-vault',
    source: 'examples/ts/covenant-vault/CovenantVault.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'Addr', value: ADDR },
      { type: 'bigint', value: '10000' },
    ],
  },
  {
    name: 'cross-covenant',
    source: 'examples/ts/cross-covenant/CrossCovenantRef.runar.ts',
    constructorArgs: [
      { type: 'Sha256', value: HASH32 },
    ],
  },
  {
    name: 'ec-demo',
    source: 'examples/ts/ec-demo/ECDemo.runar.ts',
    constructorArgs: [
      { type: 'Point', value: POINT },
    ],
  },
  {
    name: 'escrow',
    source: 'examples/ts/escrow/Escrow.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'PubKey', value: PK },
      { type: 'PubKey', value: PK },
    ],
  },
  {
    name: 'function-patterns',
    source: 'examples/ts/function-patterns/FunctionPatterns.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'bigint', value: '1000' },
    ],
  },
  {
    name: 'math-demo',
    source: 'examples/ts/math-demo/MathDemo.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '100' },
    ],
  },
  {
    name: 'merkle-proof',
    source: 'examples/ts/merkle-proof/MerkleProofDemo.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'message-board',
    source: 'examples/ts/message-board/MessageBoard.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HELLO },
      { type: 'PubKey', value: PK },
    ],
  },
  {
    name: 'oracle-price',
    source: 'examples/ts/oracle-price/OraclePriceFeed.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '12345678901234567890' },
      { type: 'PubKey', value: PK },
    ],
  },
  {
    name: 'p2blake3pkh',
    source: 'examples/ts/p2blake3pkh/P2Blake3PKH.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'p2pkh',
    source: 'examples/ts/p2pkh/P2PKH.runar.ts',
    constructorArgs: [
      { type: 'Addr', value: ADDR },
    ],
  },
  {
    name: 'post-quantum-wallet',
    source: 'examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts',
    constructorArgs: [
      { type: 'Addr', value: ADDR },
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'property-initializers',
    source: 'examples/ts/property-initializers/BoundedCounter.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '100' },
    ],
  },
  {
    name: 'schnorr-zkp',
    source: 'examples/ts/schnorr-zkp/SchnorrZKP.runar.ts',
    constructorArgs: [
      { type: 'Point', value: POINT },
    ],
  },
  {
    name: 'sha256-compress',
    source: 'examples/ts/sha256-compress/Sha256CompressTest.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'sha256-finalize',
    source: 'examples/ts/sha256-finalize/Sha256FinalizeTest.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'sphincs-wallet',
    source: 'examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts',
    constructorArgs: [
      { type: 'Addr', value: ADDR },
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'state-covenant',
    source: 'examples/ts/state-covenant/StateCovenant.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
      { type: 'bigint', value: '0' },
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'stateful-counter',
    source: 'examples/ts/stateful-counter/Counter.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '0' },
    ],
  },
  {
    name: 'tic-tac-toe',
    source: 'examples/ts/tic-tac-toe/TicTacToe.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'bigint', value: '10000' },
    ],
  },
  {
    name: 'token-ft',
    source: 'examples/ts/token-ft/FungibleTokenExample.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'bigint', value: '1000' },
      { type: 'bigint', value: '0' },
      { type: 'ByteString', value: HELLO },
    ],
  },
  {
    name: 'token-nft',
    source: 'examples/ts/token-nft/NFTExample.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'ByteString', value: HELLO },
      { type: 'ByteString', value: HELLO },
    ],
  },

  // ===== Conformance-only contracts =====

  {
    name: 'arithmetic',
    source: 'conformance/tests/arithmetic/arithmetic.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '42' },
    ],
  },
  {
    name: 'babybear-ext4',
    source: 'conformance/tests/babybear-ext4/babybear-ext4.runar.ts',
    constructorArgs: [],
  },
  {
    name: 'basic-p2pkh',
    source: 'conformance/tests/basic-p2pkh/basic-p2pkh.runar.ts',
    constructorArgs: [
      { type: 'Addr', value: '89abcdefabbaabbaabbaabbaabbaabbaabbaabba' },
    ],
  },
  {
    name: 'boolean-logic',
    source: 'conformance/tests/boolean-logic/boolean-logic.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '10' },
    ],
  },
  {
    name: 'bounded-loop',
    source: 'conformance/tests/bounded-loop/bounded-loop.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '25' },
    ],
  },
  {
    name: 'ec-primitives',
    source: 'conformance/tests/ec-primitives/ec-primitives.runar.ts',
    constructorArgs: [
      { type: 'Point', value: POINT },
    ],
  },
  {
    name: 'if-else',
    source: 'conformance/tests/if-else/if-else.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '10' },
    ],
  },
  {
    name: 'if-without-else',
    source: 'conformance/tests/if-without-else/if-without-else.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '5' },
    ],
  },
  {
    name: 'multi-method',
    source: 'conformance/tests/multi-method/multi-method.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'PubKey', value: PK },
    ],
  },
  {
    name: 'post-quantum-slhdsa',
    source: 'conformance/tests/post-quantum-slhdsa/post-quantum-slhdsa.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'post-quantum-wots',
    source: 'conformance/tests/post-quantum-wots/post-quantum-wots.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'stateful',
    source: 'conformance/tests/stateful/stateful.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '0' },
      { type: 'bigint', value: '100' },
    ],
  },
  {
    name: 'stateful-bytestring',
    source: 'conformance/tests/stateful-bytestring/stateful-bytestring.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HELLO },
      { type: 'PubKey', value: PK },
    ],
  },
];

const TMP_DIR = join(__dirname, '.tmp');
if (!existsSync(TMP_DIR)) mkdirSync(TMP_DIR, { recursive: true });

for (const spec of TEST_SPECS) {
  const sourcePath = join(ROOT, spec.source);
  console.log(`Compiling ${spec.name}...`);
  try {
    execFileSync(
      'npx',
      ['tsx', 'packages/runar-cli/src/bin.ts', 'compile', sourcePath, '-o', TMP_DIR],
      { cwd: ROOT, stdio: 'pipe' },
    );
  } catch (err: any) {
    console.error(`  FAILED to compile ${spec.name}: ${err.stderr?.toString().slice(0, 200)}`);
    continue;
  }

  const sourceBase = basename(spec.source, '.ts');
  const artifactPath = join(TMP_DIR, `${sourceBase}.json`);
  if (!existsSync(artifactPath)) {
    console.error(`  No artifact found for ${spec.name} at ${artifactPath}`);
    continue;
  }
  const artifact = JSON.parse(readFileSync(artifactPath, 'utf-8'));

  // Strip fields not needed by SDK tools
  delete artifact.ir;
  delete artifact.anf;
  delete artifact.asm;
  delete artifact.sourceMap;
  delete artifact.buildTimestamp;

  const input = { artifact, constructorArgs: spec.constructorArgs };
  const testDir = join(TESTS_DIR, spec.name);
  if (!existsSync(testDir)) mkdirSync(testDir, { recursive: true });
  writeFileSync(join(testDir, 'input.json'), JSON.stringify(input, null, 2) + '\n');
  console.log(`  Wrote ${spec.name}/input.json`);
}

console.log('\nDone. Run SDK tools to generate expected-locking.hex files.');
