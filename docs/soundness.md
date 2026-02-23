# AEON Formal Soundness Documentation

This document links each verification engine in AEON to its soundness theorem,
the implementation that realises it, and any known approximations or deviations
from the published result.

---

## 1. Abstract Interpretation — Interval / Sign / Congruence Domains

**Soundness theorem** (Cousot & Cousot 1977, Theorem 1):
> Let (α, γ) be a Galois connection between the concrete domain (℘(Σ), ⊆)
> and the abstract domain (A, ⊑).  If F# is a sound abstract transformer for
> F (i.e. α ∘ F ∘ γ ⊑ F#), then the abstract fixpoint lfp F# over-approximates
> the concrete collecting semantics: γ(lfp F#) ⊇ lfp F.

**Implementation**: `aeon/abstract_interp.py`
- `Interval`, `Sign`, `Congruence` — abstract domain elements (complete lattices)
- `AbstractInterpreter._analyze_function` — fixpoint computation with widening (∇) and narrowing (Δ)
- `ReducedProduct.reduce()` — mutual reduction between domains for precision

**Galois connections**:
- Interval: α(S) = [min S, max S],  γ([lo,hi]) = {n ∈ ℤ | lo ≤ n ≤ hi}
- Sign: α(S) = join { sign(n) | n ∈ S },  γ(pos) = {n > 0}, γ(neg) = {n < 0}, γ(zero) = {0}
- Congruence: α(S) = (a mod gcd(S−a)),  γ(a,m) = {a + km | k ∈ ℤ}

**Known approximations**:
- Loop widening uses threshold set {−1000, −100, −10, −1, 0, 1, 10, 100, 1000} rather than the full integer lattice.  This is sound but may lose precision for loops with large strides.
- Octagon domain (`OctagonDomain`) is implemented but not yet wired into the main fixpoint; it is available for manual use.

**Property-based tests**: `tests/properties/test_lattice_laws.py`
- `TestIntervalLattice` — 14 lattice law tests + Galois soundness + arithmetic soundness
- `TestSignLattice` — 7 lattice law tests + addition/multiplication soundness
- `TestCongruenceLattice` — 5 lattice law tests + Galois soundness
- `TestWideningConvergence` — convergence of ascending chains

---

## 2. Liquid Type Inference (Refinement Types)

**Soundness theorem** (Rondon, Kawaguchi, Jhala 2008, Theorem 3.1):
> If the liquid type inference algorithm assigns type {v:T|p} to expression e
> in environment Γ, then for all substitutions σ satisfying Γ,
> the concrete value [[e]]σ satisfies p.

**Implementation**: `aeon/refinement_types.py`
- `LiquidTypeSolver.solve()` — CEGAR fixpoint: initialise all kvars to ⋀Q, iteratively remove qualifiers falsified by Z3
- `RefinementTypeChecker.check_program()` — constraint generation
- `_check_implication()` — SMT validity check via Z3 (checks UNSAT of negation)

**Algorithm** (Section 3 of paper):
1. Parse qualifier templates Q = {q₁, …, qₙ}
2. Initialise sol(kᵢ) = ⋀Q for each refinement variable kᵢ
3. For each constraint Γ ⊢ {v:T|p₁} <: {v:T|p₂}: check Γ ∧ p₁ ⇒ p₂ via Z3
4. Remove qualifiers that fail; repeat until fixpoint

**Known approximations**:
- Only nullary and unary qualifier templates are instantiated by default (arity ≤ 2).  Binary templates (v == x+y) are included but not all combinations are tried for performance.
- Z3 timeout is 5 seconds per query; timed-out queries are treated as valid (fail-open).

---

## 3. Hoare Logic / Weakest Precondition Calculus

**Soundness theorem** (Hoare 1969, Dijkstra 1975):
> {P} S {Q} is valid iff P ⇒ wp(S, Q).
> The wp-calculus rules are:
>   wp(x := e, Q)           = Q[x/e]
>   wp(S₁; S₂, Q)           = wp(S₁, wp(S₂, Q))
>   wp(if b then S₁ else S₂, Q) = (b ⇒ wp(S₁,Q)) ∧ (¬b ⇒ wp(S₂,Q))
>   wp(while b do S, Q)     = I ∧ (I ∧ ¬b ⇒ Q)  [requires loop invariant I]

**Implementation**: `aeon/hoare.py`
- `WPCalculator.wp()` / `wp_block()` — backward wp computation
- `VCGenerator._verify_function()` — generates VC: requires ⇒ wp(body, ensures)
- `VCGenerator._discharge_vc()` — discharges VC to Z3 (checks SAT of negation)
- `verify_contracts_hoare_with_trace()` — returns `ProofTrace` with SMTLIB2 queries

**Loop invariant inference**: Houdini-style (Flanagan & Leino 2001)
- Candidate invariants from templates: `v ≥ 0`, `v ≤ bound`, `v == init`, etc.
- Iteratively remove candidates not preserved by the loop body

**Known approximations**:
- Loop invariants are inferred from a finite template set; loops without matching templates receive `I = true` (sound but imprecise).
- Quantified formulas (∀x. P(x)) are not fully supported; arrays are abstracted.

---

## 4. Symbolic Execution

**Soundness theorem** (King 1976):
> If symbolic execution explores path π with path condition PC(π), and
> PC(π) ∧ ¬property is SAT with model σ, then the concrete execution with
> inputs σ violates the property along path π.

**Implementation**: `aeon/symbolic_execution.py`
- `SymbolicExecutor.execute_program()` — explores all feasible paths up to depth bound
- `SymbolicState.is_feasible()` — Z3 SAT check on path condition
- `SymbolicState.get_model()` — extracts concrete witness from Z3 model
- `_check_div_by_zero()` — checks PC ∧ (divisor == 0) is SAT

**Known approximations**:
- Loop unrolling is bounded (default depth 10); paths beyond the bound are not explored.
- Function calls are summarised as returning a fresh symbolic value (no interprocedural analysis).

---

## 5. Separation Logic

**Soundness theorem** (Reynolds 2002, Frame Rule):
> {P} C {Q}  implies  {P * R} C {Q * R}
> where * is the separating conjunction (heap splits into disjoint parts).

**Implementation**: `aeon/separation_logic.py`
- Heap model with separating conjunction for pointer safety
- Detects use-after-free, double-free, dangling pointers, memory leaks

---

## 6. Information Flow / Noninterference

**Soundness theorem** (Volpano, Smith, Irvine 1996, Theorem 4.2):
> If Γ ⊢ c : cmd under security type system, then c satisfies noninterference:
> for any two memories agreeing on public variables, executing c produces
> memories that agree on public variables.

**Implementation**: `aeon/information_flow.py`
- Security lattice: PUBLIC ≤ INTERNAL ≤ SECRET ≤ TOP_SECRET
- Explicit flow detection: `x_PUBLIC = y_SECRET` → violation
- Implicit flow detection: `if (secret) { x_PUBLIC = 1 }` → violation (pc is SECRET)

---

## 7. Size-Change Termination

**Soundness theorem** (Lee, Jones, Ben-Amram 2001, Theorem 1):
> A program terminates if and only if every idempotent size-change graph
> in the transitive closure of the call graph has a strict decrease on
> some argument.  This is decidable by Ramsey's theorem.

**Implementation**: `aeon/size_change.py`
- Builds size-change graphs (SCGs) at each call site
- Computes transitive closure under graph composition
- Checks idempotent SCGs for strict decrease

---

## 8. Dependent Types / Curry-Howard

**Soundness theorem** (Martin-Löf 1984; Coquand & Huet 1988):
> The Calculus of Constructions is strongly normalising and consistent:
> every well-typed term has a normal form, and there is no proof of ⊥.
> Via Curry-Howard, every well-typed program is a proof of its type.

**Implementation**: `aeon/dependent_types.py`
- Pi types (dependent function types)
- Sigma types (dependent pair types)
- Bidirectional type checking with beta/eta normalisation
- Universe hierarchy (Type₀ : Type₁ : …) to avoid Russell's paradox

---

## 9. Certified Compilation (CompCert-style)

**Soundness theorem** (Leroy 2009, Theorem 1):
> The compiled program is observationally equivalent to the source program:
> for every source execution producing observable behaviour B,
> the compiled execution produces the same B.

**Implementation**: `aeon/certified_compilation.py`
- Forward simulation proofs for each compiler pass
- Invariant tracking: DAG property, type preservation, effect preservation
- Translation validation: each individual compilation is checked

---

## 10. Taint Analysis

**Soundness theorem** (Schwartz et al. 2010):
> If a taint-tracking system is sound, then any untrusted data reaching
> a sensitive sink is detected.  Soundness requires over-approximating
> taint propagation (all possible flows are tracked).

**Implementation**: `aeon/taint_analysis.py`
- Taint sources: HTTP parameters, user input, file reads, env vars
- Taint sinks: SQL queries, HTML output, OS commands, file paths
- Propagation through assignments, operations, function calls

---

## 11. Concurrency Verification

**Soundness theorem** (Owicki & Gries 1976):
> A parallel program {P₁} S₁ ‖ S₂ {P₂} is correct if each component
> is correct in isolation and the proofs are interference-free.

**Implementation**: `aeon/concurrency.py`
- Lockset analysis (Eraser / Savage et al. 1997): tracks locks held during shared access
- Happens-before (Lamport 1978): partial order on concurrent events
- Deadlock detection: cycle detection in lock-order graphs

---

## 12. Shape Analysis

**Soundness theorem** (Sagiv, Reps, Wilhelm 2002):
> The 3-valued logic abstraction is sound: if the abstract analysis
> reports a property as definitely true (value 1), it holds in all
> concrete executions.

**Implementation**: `aeon/shape_analysis.py`
- Three-valued logic: 0 (false), 1 (true), 1/2 (maybe)
- Canonical abstraction: merge nodes by predicates
- Shape predicates: reach(x,y), cycle(x), shared(x), sorted(x)

---

## 13. Bounded Model Checking

**Soundness theorem** (Biere et al. 1999):
> If the BMC formula for bound k is UNSAT, no counterexample of length ≤ k exists.
> If SAT, the model provides a concrete counterexample trace.

**Implementation**: `aeon/model_checking.py`
- Unrolls program to bound k, encodes as SMT formula
- Temporal logic (CTL): AG P (safety), AF P (liveness), EF P (reachability)

---

## 14. Algebraic Effects with Row Polymorphism

**Soundness theorem** (Plotkin & Pretnar 2009):
> The effect type system is sound: if a computation has effect type E,
> it can only perform effects in E.  Effect handlers are correct if
> they handle all operations in the effect signature.

**Implementation**: `aeon/effect_algebra.py`
- Effect rows: `<Database.Read, Network.Write | ρ>` with row variable polymorphism
- Commutativity analysis: automatically parallelises commuting effects
- Fixpoint inference: computes principal effect types via forward dataflow

---

## 15. Category-Theoretic Semantics

**Soundness theorem** (Moggi 1991):
> Every well-typed AEON program denotes a morphism in the Kleisli category
> of the graded monad T_E.  Compiler correctness follows from functor laws:
> F(g ∘ f) = F(g) ∘ F(f)  and  F(id) = id.

**Implementation**: `aeon/category_semantics.py`
- Pure functions → morphisms in a Cartesian Closed Category (CCC)
- Task functions → Kleisli morphisms in graded monad T_E
- Data types → initial algebras of polynomial functors
- Compiler passes → functors; functor law verification proves compiler correctness

---

## Proof Artifact Export

AEON can export proof artifacts for independent verification:

```bash
# Emit Hoare-logic proof obligations with SMTLIB2 queries
aeon proof-trace examples/contracts.aeon --format smtlib2 > proof.smt2

# Emit LaTeX verification report
aeon proof-trace examples/contracts.aeon --format latex > report.tex

# Emit per-statement abstract domain states
aeon abstract-trace examples/contracts.aeon --format json > trace.json

# Emit counterexample witnesses
aeon proof-trace examples/contracts.aeon --emit-witnesses
```

---

## References

1. Cousot, Cousot. *Abstract Interpretation*. POPL 1977.
2. Rondon, Kawaguchi, Jhala. *Liquid Types*. PLDI 2008.
3. Hoare. *An Axiomatic Basis for Computer Programming*. CACM 1969.
4. Dijkstra. *Guarded Commands, Nondeterminacy and Formal Derivation*. CACM 1975.
5. Flanagan, Leino. *Houdini, an Annotation Assistant for ESC/Java*. FME 2001.
6. King. *Symbolic Execution and Program Testing*. CACM 1976.
7. Reynolds. *Separation Logic*. LICS 2002.
8. O'Hearn. *Incorrectness Logic*. POPL 2019.
9. Volpano, Smith, Irvine. *A Sound Type System for Secure Flow Analysis*. JCS 1996.
10. Lee, Jones, Ben-Amram. *The Size-Change Principle for Program Termination*. POPL 2001.
11. Martin-Löf. *Intuitionistic Type Theory*. Bibliopolis 1984.
12. Coquand, Huet. *The Calculus of Constructions*. Inf. & Comp. 1988.
13. Leroy. *Formal Verification of a Realistic Compiler*. CACM 2009.
14. Schwartz, Avgerinos, Brumley. *All You Ever Wanted to Know About Dynamic Taint Analysis*. IEEE S&P 2010.
15. Owicki, Gries. *An Axiomatic Proof Technique for Parallel Programs*. Acta Informatica 1976.
16. Sagiv, Reps, Wilhelm. *Parametric Shape Analysis via 3-Valued Logic*. TOPLAS 2002.
17. Biere et al. *Symbolic Model Checking without BDDs*. TACAS 1999.
18. Plotkin, Pretnar. *Handlers of Algebraic Effects*. ESOP 2009.
19. Moggi. *Notions of Computation and Monads*. Inf. & Comp. 1991.
20. Mine. *The Octagon Abstract Domain*. HOSC 2006.
