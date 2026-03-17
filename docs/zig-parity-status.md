# Zig Parity Status

Legend:

- `🟩` strong / natural
- `🟨` acceptable compromise
- `🟧` works but awkward
- `🟥` real gap

## Cross-Language Matrix

| Area | TS | Go | Rust | Python | Zig | Meaning |
|---|---|---|---|---|---|---|
| Compiler correctness | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | Zig is fully green on compiler tests and conformance |
| Native frontend syntax | 🟩 | 🟨 | 🟨 | 🟨 | 🟨 | Zig parses and compiles well, but the surface is not yet fully plain-Zig natural |
| Native helper/runtime package | 🟩 | 🟩 | 🟩 | 🟩 | 🟨 | `packages/runar-zig` exists and works, but it is still a young surface |
| Example inventory parity | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | Zig now has the same 21-example tree |
| Adjacent native tests | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | Zig now has tests beside the contracts |
| Real contract execution in tests | 🟩 | 🟩 | 🟩 | 🟩 | 🟥 | This is the biggest remaining gap |
| Stateful contract model fit | 🟨 | 🟨 | 🟨 | 🟨 | 🟥 | Zig suffers most because fake inheritance does not fit the language |
| Byte/string equality fit | 🟩 | 🟩 | 🟩 | 🟩 | 🟥 | Zig cannot honestly pretend slice `==` means content equality |
| Failure/assertion model fit | 🟩 | 🟨 | 🟨 | 🟨 | 🟧 | Zig needs a more deliberate contract-failure story |
| Test quality vs mirrors | 🟩 | 🟩 | 🟩 | 🟩 | 🟥 | Many Zig tests still validate mirrors, not the actual contract module |

## Language-Specific Boundaries

| Language | Main Native Challenge | What We Accept | What We Should Not Accept |
|---|---|---|---|
| TypeScript | DSL pressure, reference-compiler complexity | AST/reference role, stronger tooling assumptions | Hidden semantics that diverge from source language expectations |
| Go | No classes, less expression-heavy syntax | struct tags, explicit helper calls, embedded support types | unnatural OO emulation |
| Rust | Macro-heavy ergonomics | attributes/macros if explicit and type-safe | opaque macro magic that hides contract behavior |
| Python | dynamic runtime, decorators | decorators and runtime helpers | relying on dynamic behavior with weak compile guarantees |
| Zig | no inheritance, strict slice semantics, visible ownership | explicit helpers, wrappers, composition, comptime type helpers | fake inheritance, operator overloading-by-convention, hidden runtime magic |

## Where Zig Is Being Shoehorned

| Zig Area | Current State | Rating | Why |
|---|---|---|---|
| `pub const Contract = runar.StatefulSmartContract;` | treated like base-class inheritance | 🟥 | Zig does not work that way |
| `self.addOutput(...)`, `self.txPreimage` | expected to appear magically on contract structs | 🟥 | this is compiler/runtime fiction, not natural Zig |
| byte/content equality in contract syntax | written as if plain operators can carry DSL meaning | 🟥 | misleading to Zig users |
| `runar.Readonly(T)` | explicit type-level marker | 🟩 | this fits Zig reasonably well |
| `packages/runar-zig` as helper/runtime layer | explicit package boundary | 🟨 | good direction, still immature |
| adjacent example tests | present and runnable | 🟨 | structure is right, many assertions still target mirrors |

## Zig-Specific Decision Matrix

| Topic | Current Approach | Problem | Better Zig-Shaped Direction | Status |
|---|---|---|---|---|
| Contract base model | pseudo-inheritance via `pub const Contract = ...` | implies hidden fields/methods | explicit composition or explicit helper surface | Open |
| Stateful helpers | `self.addOutput`, `self.txPreimage`, `self.getStateScript` | not naturally present on plain Zig structs | explicit embedded runtime field or helper API that is visible in the type | Open |
| Bytes equality | compiler-level semantics on plain operators | misleading in plain Zig | explicit helper such as `runar.bytesEq(a, b)` or a wrapped bytes type with honest API | Open |
| Readonly fields | `runar.Readonly(T)` | acceptable, but needs consistent examples/docs | keep, refine, and document as the canonical explicit marker | Good |
| Contract failure model | mostly piggybacks on `runar.assert` | not yet clearly designed for Zig-native tests | explicit, documented assertion/failure behavior for `zig test` | Partial |
| Ownership/allocation | hidden in helper calls | can become noisy or surprising | keep high-level helpers but make ownership rules explicit and boring | Partial |
| Example tests | many mirror implementations | proves less than real contract execution | migrate priority examples to direct contract tests as semantics become natural | Open |

## Target Model

What “good” should look like for Zig:

1. A Zig developer can open a `.runar.zig` contract and it reads like honest Zig.
2. The runtime surface the contract depends on is explicit in the code, not implied by fake inheritance.
3. If a construct has special contract semantics, the syntax should signal that clearly.
4. Adjacent Zig tests should mostly exercise the real contract modules, not mirrors.
5. `packages/runar-zig` should feel like a coherent native helper/runtime package, not a grab bag of compiler accommodations.

## What Is Already Strong

- Compiler correctness and conformance are green.
- The Zig frontend now has explicit readonly syntax.
- `packages/runar-zig` exists and runs cleanly.
- The full 21-contract Zig example tree exists with adjacent tests.
- The public docs now describe the Zig package and example runner accurately.

## What Still Needs Real Improvement

### 1. Plain-Zig Executability

This is the biggest remaining gap.

Today some `.runar.zig` contracts compile through the Rúnar frontend correctly, but are not naturally executable as ordinary Zig modules because they rely on Rúnar-level semantics that Zig itself does not provide directly.

Representative issues:

- content equality on byte slices
- hidden stateful helper surface
- contract-style assertions/failure expectations

### 2. Stateful Surface Design

We need one clear answer for how stateful contracts access runtime features in Zig.

The two most likely acceptable shapes are:

- explicit embedded runtime field
- explicit helper functions that receive runtime context

The unacceptable shape is:

- pretending Zig has class inheritance and injected members

### 3. Direct Example Testing

The test tree shape is now correct, but the quality bar is not met until the important examples are mostly testing the real contracts.

Priority contracts to move first:

- `p2pkh`
- `function-patterns`
- `math-demo`
- `token-ft`
- `tic-tac-toe`
- `ec-demo`
- `post-quantum-wallet`
- `sphincs-wallet`

## Priority Ladder

| Priority | Work Item | Why |
|---|---|---|
| P0 | redesign the Zig stateful/runtime access model | this is the root semantic mismatch |
| P0 | settle the honest bytes/content equality API | this blocks natural direct execution |
| P1 | convert `p2pkh` to a direct real-contract test | smallest proof that the model works |
| P1 | convert `function-patterns`, `math-demo`, `token-ft` | these reveal most helper/runtime flaws quickly |
| P1 | convert `tic-tac-toe` | best stress test for stateful design |
| P2 | convert EC/PQ examples to real-contract tests | important, but dependent on cleaner core semantics |
| P2 | reduce mirror-test usage across the tree | cleanup after the core model is right |

## Acceptance Criteria

We should consider Zig “one of the best implementations” only when most of these are true:

- `packages/runar-zig` is the obvious native way to support Zig contracts and tests
- stateful Zig contracts use an explicit, understandable runtime access model
- byte/content comparisons are expressed honestly
- at least the priority example set runs as real contract tests under `zig test`
- mirrors are the exception, not the default
- docs can explain the Zig model without caveats that sound like compiler escape hatches

## Phased Roadmap

### Phase 1: Make It Honest

- finalize runtime/stateful access design
- finalize byte/content equality design
- remove the most misleading pseudo-inheritance assumptions

### Phase 2: Make It Direct

- convert the priority examples to real-contract tests
- keep compile-check coverage, but stop leaning on mirrors for core confidence

### Phase 3: Make It Excellent

- refine ergonomics
- tighten failure/assertion behavior
- improve advanced EC/PQ example testing quality
- reduce any leftover runtime awkwardness in `packages/runar-zig`

## Bottom Line

| Question | Answer |
|---|---|
| Is the compiler work good enough? | Yes |
| Is the Zig package/test surface useful already? | Yes |
| Is it fully natural and up to the same standard as Go/Rust/Python? | No |
| What most needs improvement? | direct execution model for `.runar.zig` contracts, especially stateful/runtime semantics |
| What should we protect no matter what? | no fake inheritance, no dishonest operator semantics, no mirror-heavy tests as the final state |

## Guiding Standard

If a Zig developer reads the code, it should look like honest Zig with explicit Rúnar helpers, not Zig-shaped syntax carrying hidden compiler-only meanings.
