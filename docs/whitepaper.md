# AEON: A Programming Language with Integrated Formal Verification

**Technical Report — Draft**

## Abstract

We present AEON, a statically-typed programming language designed to integrate formal verification directly into the compilation process. AEON distinguishes between pure computations and effectful operations at the type level, supports algebraic data types with exhaustive pattern matching, and verifies function contracts at compile time using SMT solving. The language explores a design point where verification is a language primitive — not an external tool applied post-hoc — and where the effect system makes it possible to reason compositionally about program behavior.

This document describes the language design, the compiler architecture, the formal foundations of each verification pass, and the current limitations of the implementation.

## 1. Introduction

Most programming languages treat verification as an afterthought. Testing, linting, and static analysis are bolted on after the fact, operating on code that was designed without verification in mind. Formal verification tools (Dafny, F*, Why3, Lean) take the opposite approach — verification is central — but they require programmers to work in a proof-centric paradigm that differs substantially from mainstream software development.

AEON explores a middle path: a language that looks and feels like a conventional systems language (with curly braces, let bindings, and familiar control flow), but where formal contracts are first-class syntax and the compiler verifies them automatically.

### 1.1 Design Goals

1. **Verification as compilation.** Contract checking is not a separate tool — it is a compiler pass. If the program compiles, its contracts hold.
2. **Effect discipline.** The type system distinguishes between `pure` functions (no side effects) and `task` functions (declared effects). This separation enables compositional reasoning: pure functions can be memoized, reordered, and parallelized without changing program behavior.
3. **Algebraic data types as first-class citizens.** Sum types (`enum`) and product types (`data`) with pattern matching enable the kind of precise domain modeling that makes verification tractable.
4. **Incremental adoption.** Individual verification engines can be enabled independently. A project can start with basic type checking and gradually add contract verification, abstract interpretation, and deeper analyses as the codebase matures.

### 1.2 Non-Goals (Honest Limitations)

- AEON is not a proof assistant. It cannot express arbitrary mathematical theorems.
- The verification is not complete — SMT solvers can time out, abstract domains lose precision, and many analyses are conservative approximations.
- The module system is currently rudimentary (parsed but not resolved).
- Generic type inference requires explicit annotations in many cases.
- The language is a research prototype, not production-ready.

## 2. Language Design

### 2.1 Three Primitives

AEON has three top-level declaration forms:

**`pure`** — A function with no side effects.

```
pure factorial(n: Int) -> Int {
    requires: n >= 0
    ensures:  result >= 1
    if n <= 1 { return 1 }
    return n * factorial(n - 1)
}
```

The `pure` keyword is a promise: the function performs no I/O, allocates no mutable state visible outside its scope, and depends only on its arguments. The compiler can safely memoize, inline, or parallelize pure functions.

Semantically, pure functions correspond to morphisms in a Cartesian Closed Category, though this is more of a design principle than a mechanized proof.

**`task`** — A function with declared effects.

```
task queryDatabase(id: Int) -> User {
    effects: [Database.Read]
    return db.find(id)
}
```

The `effects` clause declares which side effects a task function may perform. The compiler checks that a task function only calls other task functions with compatible effects (or pure functions, which have no effects).

**`data`** — A product type (record/struct).

```
data Point {
    x: Int
    y: Int
}
```

Data definitions are immutable by default. Fields are accessed by name (`p.x`). Construction uses named fields: `Point { x: 1, y: 2 }`.

### 2.2 Algebraic Data Types

AEON supports sum types via `enum`:

```
enum Option<T> {
    Some(value: T),
    None
}

enum Result<T, E> {
    Ok(value: T),
    Err(error: E)
}
```

Variants may carry data (like `Some(value: T)`) or be unit variants (like `None`). Pattern matching provides the only way to destructure enum values:

```
pure unwrap(opt: Option<Int>, default: Int) -> Int {
    match opt {
        Some(v) => { return v }
        None => { return default }
    }
}
```

### 2.3 Pattern Matching

Match expressions support:

- **Constructor patterns**: `Some(x)`, `Cons(h, t)`
- **Literal patterns**: `0`, `"hello"`, `true`
- **Wildcard patterns**: `_`
- **Variable binding**: `x` (lowercase identifier)

### 2.4 Traits and Implementations

```
trait Eq {
    pure eq(self, other: Int) -> Bool { return false }
}

impl Point {
    pure translate(self, dx: Int, dy: Int) -> Point {
        return Point { x: self.x + dx, y: self.y + dy }
    }
}

impl Eq for Point {
    pure eq(self, other: Int) -> Bool {
        return self.x == other
    }
}
```

### 2.5 Additional Constructs

- **For loops**: `for x in collection { ... }`
- **Pipeline operator**: `x |> f |> g` (desugars to `g(f(x))`)
- **Lambda expressions**: `fn(x: Int) -> Int => x + 1`
- **Type aliases**: `type UserId = Int`
- **Module imports**: `use std::collections`
- **Ownership**: `move x`, `borrow x` (linear resource management)
- **Unsafe blocks**: `unsafe { ... }` with optional audit notes

## 3. Compiler Architecture

AEON uses a three-pass compiler:

### 3.1 Lexer and Parser

The lexer (hand-written, no generator) produces a flat token stream with source locations. The parser is an LL(1) recursive-descent parser — no backtracking, no ambiguity. Every construct has exactly one parse.

Token types include 20+ keywords (`pure`, `task`, `data`, `enum`, `trait`, `impl`, `match`, `fn`, `type`, `use`, `for`, `in`, `spawn`, `await`, etc.), standard operators, and delimiters.

### 3.2 Pass 1: Prove

The first pass performs:

1. **Declaration registration**: All types and function signatures are registered before any bodies are checked.
2. **Type checking**: Bidirectional type inference in a scoped environment. Each `let` binding, function parameter, and return type is resolved and checked.
3. **Contract verification**: For each function with `requires`/`ensures` clauses, a verification condition is generated and discharged to Z3.
4. **Ownership analysis**: Move and borrow operations are checked for linearity violations.
5. **Effect checking**: Task functions are checked to ensure they only perform declared effects.
6. **Optional deep analyses**: When enabled via CLI flags, additional engines (abstract interpretation, symbolic execution, etc.) run on the verified AST.

### 3.3 Pass 2: Flatten

Lowers the AST to a flat IR — a directed acyclic graph of typed operations. Each node has an ID, an operation kind (e.g., `ADD`, `CALL`, `BRANCH`), input references, and a type annotation. The IR is JSON-serializable.

This pass eliminates nesting: nested expressions become sequences of let-bound operations. The resulting flat form is suitable for further analysis, optimization, and code generation.

### 3.4 Pass 3: Emit

Converts the flat IR to LLVM IR using llvmlite. LLVM handles all backend optimizations: vectorization, inlining, register allocation, instruction selection.

## 4. Verification Engines

Each verification engine is based on a specific result from the formal methods literature. We describe the engines that are substantially implemented, their theoretical foundations, and their known limitations.

### 4.1 Hoare Logic (Dijkstra 1975, Hoare 1969)

**What it does.** Verifies `requires`/`ensures` contracts by computing the weakest precondition of the function body with respect to the postcondition, then checking that the precondition implies the weakest precondition.

**How it works.** Backward analysis via the wp-calculus:
- `wp(x := e, Q) = Q[x/e]`
- `wp(S1; S2, Q) = wp(S1, wp(S2, Q))`
- `wp(if b then S1 else S2, Q) = (b => wp(S1,Q)) ∧ (¬b => wp(S2,Q))`

Verification conditions are discharged to Z3. Loop invariants are inferred using Houdini's algorithm (Flanagan & Leino 2001) from a set of candidate templates.

**Implementation**: `aeon/hoare.py` (~3,800 lines)

**Known limitations.** Loop invariant inference is template-based; complex invariants may require manual annotation. Z3 timeout is 5 seconds per query; timed-out queries are treated conservatively.

### 4.2 Abstract Interpretation (Cousot & Cousot 1977)

**What it does.** Computes sound over-approximations of program behavior using abstract domains.

**How it works.** Three abstract domains are implemented:
- **Interval domain**: `[lo, hi]` bounds for each variable
- **Sign domain**: `{neg, zero, pos, top, bot}`
- **Congruence domain**: `a (mod m)`

Fixpoint computation uses widening (∇) for convergence and narrowing (Δ) for precision. A reduced product combines all three domains via mutual reduction.

**Implementation**: `aeon/abstract_interp.py` (~1,400 lines)

**Known limitations.** Widening uses a fixed threshold set, which loses precision for large-stride loops. An octagon domain is implemented but not wired into the main fixpoint.

### 4.3 Refinement Types (Rondon et al. 2008)

**What it does.** Infers refinement types — base types annotated with logical predicates (e.g., `{v: Int | v >= 0}`) — and verifies subtyping via Z3.

**How it works.** CEGAR fixpoint: initialize all refinement variables to the conjunction of all qualifier templates, then iteratively remove qualifiers falsified by Z3 counterexamples.

**Implementation**: `aeon/refinement_types.py` (~1,000 lines)

**Known limitations.** Only nullary and unary qualifier templates by default. Z3 timeout treated as valid (fail-open).

### 4.4 Size-Change Termination (Lee et al. 2001)

**What it does.** Decides termination for programs whose recursive calls decrease some well-founded measure.

**How it works.** Builds size-change graphs at each call site, computes the transitive closure, and checks that every idempotent self-loop has a strict decrease. Sound and complete for size-change termination (PSPACE-complete in theory, polynomial in practice).

**Implementation**: `aeon/size_change.py`

### 4.5 Additional Engines

The following engines are also implemented at varying levels of maturity:

| Engine | Module | Status |
|--------|--------|--------|
| Symbolic execution | `symbolic_execution.py` | Functional — bounded loop unrolling |
| Separation logic | `separation_logic.py` | Functional — frame rule, bi-abduction |
| Taint analysis | `taint_analysis.py` | Functional — source/sink tracking |
| Information flow | `information_flow.py` | Functional — security lattice |
| Concurrency verification | `concurrency.py` | Functional — lockset analysis |
| Shape analysis | `shape_analysis.py` | Functional — 3-valued logic |
| Bounded model checking | `model_checking.py` | Functional — CTL, SAT encoding |
| Algebraic effects | `effect_algebra.py` | Functional — row polymorphism |
| Dependent types | `dependent_types.py` | Partial — Pi/Sigma types, basic checking |
| Certified compilation | `certified_compilation.py` | Partial — simulation proof framework |

See `docs/soundness.md` for formal soundness theorems and documented approximations for each engine.

## 5. Related Work

AEON draws inspiration from several existing systems:

- **Dafny** (Leino 2010): Contract-based verification with SMT solving. AEON's contract system is similar but embedded in a more conventional language surface.
- **F*** (Swamy et al. 2016): Dependent types with effects. AEON's effect system is simpler (no monadic encoding) but less expressive.
- **Liquid Haskell** (Vazou et al. 2014): Refinement types for Haskell. AEON integrates the same CEGAR-based inference algorithm.
- **Rust**: Ownership and borrow checking. AEON adopts similar semantics but with a simpler model.
- **Koka** (Leijen 2017): Algebraic effects with row polymorphism. AEON's effect tracking is similar in spirit.
- **Why3** (Filliatre & Paskevich 2013): Multi-prover verification platform. AEON is more opinionated (Z3 only) but offers a complete language rather than a specification layer.

The key difference is that AEON is designed as a standalone programming language rather than an extension of an existing one. Whether this is a net benefit (cohesive design) or a net cost (smaller ecosystem) remains an open question.

## 6. Evaluation and Honest Assessment

### What AEON Does Well

1. **Contract verification works.** For straight-line code and simple loops, the Hoare logic engine reliably verifies contracts. The proof trace output (SMTLIB2 queries + Z3 results) provides transparency.
2. **The language design is coherent.** The pure/task/data triple provides a clean separation between computation and effects.
3. **Multiple analysis passes compose.** Running abstract interpretation followed by Hoare logic catches more bugs than either alone, and the reduced product of abstract domains provides tighter bounds.
4. **The surface syntax is approachable.** The language reads like a familiar imperative language with contracts, which lowers the barrier to entry.

### Honest Limitations

1. **Scalability is unknown.** The system has been tested on small programs (< 500 lines). How the verification engines perform on large codebases is untested.
2. **Generic type inference is weak.** AEON currently requires explicit type annotations in many places where Hindley-Milner inference would suffice.
3. **Pattern matching exhaustiveness is not checked.** The parser accepts match expressions but does not verify that all cases are covered.
4. **The module system is syntactic only.** `use` declarations are parsed but not resolved — there is no linking or separate compilation.
5. **Many verification engines are conservative.** They report false positives when the abstract domain is too coarse or when the SMT solver times out.
6. **No standard library.** There is no prelude, no IO library, and no package manager.
7. **Single-target compilation.** The LLVM backend produces x86-64 code only.

## 7. Future Work

- **Exhaustive pattern matching checks** — verify that match expressions cover all constructors
- **Module resolution and separate compilation** — resolve `use` declarations and support multi-file projects
- **Stronger generic inference** — Algorithm W with let-generalization
- **Proof export** — emit Lean 4 or Coq proof terms for external verification
- **Interactive mode** — REPL with incremental type checking
- **Benchmark suite** — standardized benchmarks for verification engine performance

## References

[1] Hoare, C.A.R. "An Axiomatic Basis for Computer Programming." CACM 12(10), 1969.
[2] Dijkstra, E.W. "Guarded Commands, Nondeterminacy and Formal Derivation of Programs." CACM 18(8), 1975.
[3] Cousot, P. and Cousot, R. "Abstract Interpretation: A Unified Lattice Model for Static Analysis of Programs." POPL, 1977.
[4] King, J.C. "Symbolic Execution and Program Testing." CACM 19(7), 1976.
[5] Rondon, P.M., Kawaguchi, M., and Jhala, R. "Liquid Types." PLDI, 2008.
[6] Lee, C.S., Jones, N.D., and Ben-Amram, A.M. "The Size-Change Principle for Program Termination." POPL, 2001.
[7] Plotkin, G.D. and Pretnar, M. "Handlers of Algebraic Effects." ESOP, 2009.
[8] Reynolds, J.C. "Separation Logic: A Logic for Shared Mutable Data Structures." LICS, 2002.
[9] Volpano, D., Smith, G., and Irvine, C. "A Sound Type System for Secure Flow Analysis." JCS 4(2-3), 1996.
[10] Martin-Lof, P. "Intuitionistic Type Theory." Bibliopolis, 1984.
[11] Leroy, X. "Formal Verification of a Realistic Compiler." CACM 52(7), 2009.
[12] Schwartz, E.J., Avgerinos, T., and Brumley, D. "All You Ever Wanted to Know About Dynamic Taint Analysis and Forward Symbolic Execution." IEEE S&P, 2010.
[13] Flanagan, C. and Leino, K.R.M. "Houdini, an Annotation Assistant for ESC/Java." FME, 2001.
[14] Sagiv, M., Reps, T., and Wilhelm, R. "Parametric Shape Analysis via 3-Valued Logic." TOPLAS 24(3), 2002.
[15] Clarke, E.M., Emerson, E.A., and Sistla, A.P. "Automatic Verification of Finite-State Concurrent Systems Using Temporal Logic Specifications." TOPLAS 8(2), 1986.
[16] Moggi, E. "Notions of Computation and Monads." Information and Computation 93(1), 1991.
[17] Leino, K.R.M. "Dafny: An Automatic Program Verifier for Functional Correctness." LPAR, 2010.
[18] Swamy, N. et al. "Dependent Types and Multi-Monadic Effects in F*." POPL, 2016.
[19] Vazou, N. et al. "Refinement Types for Haskell." ICFP, 2014.
[20] Leijen, D. "Type Directed Compilation of Row-Typed Algebraic Effects." POPL, 2017.
[21] Filliatre, J.-C. and Paskevich, A. "Why3 — Where Programs Meet Provers." ESOP, 2013.
