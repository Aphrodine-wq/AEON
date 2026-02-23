# AEON

**A research programming language with integrated formal verification.**

AEON is a statically-typed programming language built around three primitives (`pure`, `task`, `data`) with first-class support for algebraic data types, pattern matching, algebraic effects, ownership semantics, and formal contracts. The compiler verifies function contracts at compile time using SMT solving and abstract interpretation, then emits native code via LLVM.

This is a research project exploring what happens when formal verification is a language primitive rather than an external tool.

## Language Overview

AEON's type system distinguishes between pure computations and effectful operations at the language level:

```
// Pure functions — no side effects, freely parallelizable
pure gcd(a: Int, b: Int) -> Int {
    requires: a > 0
    requires: b > 0
    ensures:  result > 0
    let mut x: Int = a
    let mut y: Int = b
    while y != 0 {
        let temp: Int = y
        y = x % y
        x = temp
    }
    return x
}

// Task functions — effects declared and tracked
task saveUser(user: User) -> Bool {
    requires: validateEmail(user.email)
    effects:  [Database.Write]
    return db.insert(user)
}
```

### Key Language Features

| Feature | Description |
|---------|-------------|
| **Three primitives** | `pure` (no effects), `task` (declared effects), `data` (product types) |
| **Algebraic data types** | `enum` with variants, `data` with named fields |
| **Pattern matching** | Exhaustive `match` expressions with constructor, literal, and wildcard patterns |
| **Traits and impls** | Ad-hoc polymorphism via `trait` definitions and `impl` blocks |
| **Contracts** | `requires` (preconditions) and `ensures` (postconditions) verified by Z3 |
| **Effect tracking** | `effects: [Database.Write, Network.Read]` — statically checked |
| **Ownership** | Move semantics and borrow checking (Rust-inspired) |
| **Pipeline operator** | `x \|> f \|> g` for left-to-right composition |
| **Lambda expressions** | `fn(x: Int) -> Int => x + 1` |
| **Type aliases** | `type UserId = Int` |
| **Module system** | `use std::collections` |
| **Generics** | `data Pair<A, B> { first: A, second: B }` |
| **LLVM backend** | Compiles to native code via llvmlite |

## Examples

### Algebraic Data Types and Pattern Matching

```
enum Option<T> {
    Some(value: T),
    None
}

enum IntList {
    Cons(head: Int, tail: IntList),
    Nil
}

pure length(xs: IntList) -> Int {
    ensures: result >= 0
    match xs {
        Nil => { return 0 }
        Cons(_, t) => { return 1 + length(t) }
    }
}

pure unwrapOr(opt: Option<Int>, default: Int) -> Int {
    match opt {
        Some(v) => { return v }
        None => { return default }
    }
}
```

### Traits and Implementations

```
data Point {
    x: Int
    y: Int
}

trait Show {
    pure show(self) -> String {
        return ""
    }
}

impl Point {
    pure translate(self, dx: Int, dy: Int) -> Point {
        return Point { x: self.x + dx, y: self.y + dy }
    }

    pure manhattan(self) -> Int {
        ensures: result >= 0
        let ax: Int = self.x
        let ay: Int = self.y
        if ax < 0 { ax = 0 - ax }
        if ay < 0 { ay = 0 - ay }
        return ax + ay
    }
}
```

### Effects and Concurrency

```
data User {
    id:    Int
    name:  String
    email: String
}

pure validateEmail(email: String) -> Bool {
    return true  // simplified
}

task createUser(name: String, email: String) -> User {
    requires: validateEmail(email)
    effects:  [Database.Write, Console.Write]

    let user: User = User { id: 0, name: name, email: email }
    saveUser(user)
    print("User created")
    return user
}
```

### Pipelines, Lambdas, and For Loops

```
pure double(x: Int) -> Int {
    ensures: result == x * 2
    return x * 2
}

pure square(x: Int) -> Int {
    return x * x
}

pure transform(x: Int) -> Int {
    return x |> double |> square
}

pure sumList(xs: List<Int>) -> Int {
    let mut total: Int = 0
    for x in xs {
        total = total + x
    }
    return total
}

pure applyTwice(x: Int) -> Int {
    let f = fn(n: Int) -> Int => n * 2
    return f(f(x))
}
```

## Compiler Architecture

AEON uses a three-pass compiler:

```
Source (.aeon) → [Lexer] → Tokens → [Parser] → AST
    → [Pass 1: Prove] → Verified AST
    → [Pass 2: Flatten] → Flat IR (DAG)
    → [Pass 3: Emit] → LLVM IR → Native Binary
```

### Pass 1 — Prove

Type checking, ownership analysis, effect checking, and contract verification. The verification pipeline is modular — individual analyses can be enabled independently:

- **Type checking**: Bidirectional type inference with generics
- **Ownership**: Move semantics and borrow checking
- **Effects**: Verifying declared vs. actual effects
- **Contracts**: `requires`/`ensures` clauses verified via Z3 SMT solver
- **Hoare logic**: Weakest-precondition calculus (Dijkstra 1975)
- **Abstract interpretation**: Interval, sign, and congruence domains (Cousot & Cousot 1977)
- **Refinement types**: Liquid type inference (Rondon et al. 2008)
- **Size-change termination**: Ramsey's theorem decision procedure (Lee et al. 2001)
- **Separation logic**: Heap safety via frame rule (Reynolds 2002)
- **Symbolic execution**: Path-sensitive analysis with Z3 (King 1976)
- **Taint analysis**: Injection vulnerability detection (Schwartz et al. 2010)
- **Information flow**: Noninterference type system (Volpano et al. 1996)

### Pass 2 — Flatten

Lowers the AST to a typed flat IR — a directed acyclic graph of data-flow operations. No nesting, no ambiguity.

### Pass 3 — Emit

Converts flat IR to LLVM IR via llvmlite. LLVM handles all backend optimization (vectorization, inlining, register allocation).

## Installation

```bash
# From source
git clone <repo-url>
cd AEON_LANG
pip install -e .

# Verify an AEON file
python -m aeon.cli check examples/aeon/pure_function.aeon --verify

# Compile to native binary (requires llvmlite)
python -m aeon.cli compile examples/aeon/pure_function.aeon -o output

# Run all verification engines
python -m aeon.cli check examples/aeon/contracts.aeon --deep-verify

# Emit flat IR as JSON
python -m aeon.cli ir examples/aeon/pure_function.aeon

# View proof trace (Hoare logic VCs and Z3 results)
python -m aeon.cli proof-trace examples/aeon/contracts.aeon

# View abstract interpretation trace
python -m aeon.cli abstract-trace examples/aeon/pure_function.aeon
```

## Grammar (Informal)

```
program     ::= declaration*
declaration ::= data_def | enum_def | pure_func | task_func
              | trait_def | impl_block | type_alias | use_decl

data_def    ::= 'data' NAME type_params? '{' field_def* '}'
enum_def    ::= 'enum' NAME type_params? '{' variant_def (',' variant_def)* '}'
pure_func   ::= 'pure' NAME type_params? '(' params ')' ('->' type)? '{' contracts body '}'
task_func   ::= 'task' NAME type_params? '(' params ')' ('->' type)? '{' contracts effects body '}'
trait_def   ::= 'trait' NAME type_params? '{' (pure_func | task_func)* '}'
impl_block  ::= 'impl' NAME type_args? ('for' NAME)? '{' (pure_func | task_func)* '}'
type_alias  ::= 'type' NAME type_params? '=' type
use_decl    ::= 'use' NAME ('::' NAME)* ('as' NAME)?

contracts   ::= ('requires' ':' expr | 'ensures' ':' expr)*
effects     ::= 'effects' ':' '[' effect (',' effect)* ']'
type_params ::= '<' NAME (',' NAME)* '>'

statement   ::= 'return' expr? | 'let' 'mut'? NAME (':' type)? ('=' expr)?
              | 'if' expr '{' body '}' ('else' '{' body '}')?
              | 'while' expr '{' body '}' | 'for' NAME 'in' expr '{' body '}'
              | 'match' expr '{' match_arm* '}' | 'unsafe' '{' body '}'
              | expr ('=' expr)?

expr        ::= pipe
pipe        ::= or ('|>' or)*
or          ::= and ('||' and)*
and         ::= equality ('&&' equality)*
equality    ::= comparison (('==' | '!=') comparison)*
comparison  ::= additive (('<' | '>' | '<=' | '>=') additive)*
additive    ::= multiplicative (('+' | '-') multiplicative)*
multiplicative ::= unary (('*' | '/' | '%') unary)*
unary       ::= ('-' | '!' | 'spawn' | 'await') unary | postfix
postfix     ::= primary ('.' NAME | '(' args ')' | '.' NAME '(' args ')')*
primary     ::= INT | FLOAT | STRING | 'true' | 'false' | NAME
              | NAME '{' fields '}' | '(' expr ')' | '[' exprs ']'
              | 'match' expr '{' arms '}' | 'fn' '(' params ')' ('->' type)? '=>' expr
              | 'move' NAME | 'borrow' NAME

pattern     ::= '_' | INT | STRING | 'true' | 'false'
              | NAME ('(' pattern (',' pattern)* ')')? | name
```

## Verification Engines

AEON integrates multiple formal analysis passes, each based on peer-reviewed research. All are optional and can be enabled individually or via `--deep-verify`.

| Engine | Flag | Foundation |
|--------|------|------------|
| Contract verification | `--verify` | Z3 SMT solver |
| Hoare logic | `--hoare` | Dijkstra 1975, Hoare 1969 |
| Abstract interpretation | `--abstract-interp` | Cousot & Cousot 1977 |
| Refinement types | `--refinement-types` | Rondon et al. 2008 |
| Size-change termination | `--size-change` | Lee et al. 2001 |
| Algebraic effects | `--algebraic-effects` | Plotkin & Pretnar 2009 |
| Information flow | `--info-flow` | Volpano et al. 1996 |
| Dependent types | `--dependent-types` | Martin-Lof 1984 |
| Symbolic execution | `--symbolic` | King 1976 |
| Separation logic | `--separation-logic` | Reynolds 2002 |
| Taint analysis | `--taint` | Schwartz et al. 2010 |
| Concurrency | `--concurrency` | Owicki & Gries 1976 |
| Shape analysis | `--shape` | Sagiv et al. 2002 |
| Model checking | `--model-check` | Clarke et al. 1986 |

See `docs/soundness.md` for formal soundness theorems and known approximations for each engine.

## Project Status

AEON is a research prototype. The language, compiler, and verification engines are functional but not production-hardened. Contributions and feedback are welcome.

### What Works

- Full lexer, parser (LL(1) recursive descent), and type checker
- Algebraic data types, pattern matching, traits, impls, for loops, lambdas, pipelines
- Three-pass compiler (Prove → Flatten → Emit) with LLVM backend
- Hoare logic verification with Z3 proof discharge and proof trace output
- Abstract interpretation with interval, sign, and congruence domains
- Refinement type inference via CEGAR
- Multiple additional analysis engines (symbolic execution, separation logic, taint analysis, etc.)

### Known Limitations

- Generic type inference is basic — explicit type annotations often required
- Pattern matching exhaustiveness checking is not yet implemented
- Module system (`use` declarations) is parsed but not resolved
- Trait method dispatch is name-based, not fully resolved via vtable
- LLVM emit for struct types is simplified (no full GEP)
- Many analysis engines are implemented as conservative approximations — see `docs/soundness.md` for details

## References

Key papers that inform AEON's design:

1. Hoare, C.A.R. *An Axiomatic Basis for Computer Programming.* CACM, 1969.
2. Dijkstra, E.W. *Guarded Commands, Nondeterminacy and Formal Derivation of Programs.* CACM, 1975.
3. Cousot, P. & Cousot, R. *Abstract Interpretation: A Unified Lattice Model.* POPL, 1977.
4. King, J.C. *Symbolic Execution and Program Testing.* CACM, 1976.
5. Rondon, P., Kawaguchi, M., & Jhala, R. *Liquid Types.* PLDI, 2008.
6. Lee, C.S., Jones, N.D., & Ben-Amram, A.M. *The Size-Change Principle for Program Termination.* POPL, 2001.
7. Plotkin, G.D. & Pretnar, M. *Handlers of Algebraic Effects.* ESOP, 2009.
8. Moggi, E. *Notions of Computation and Monads.* Information and Computation, 1991.
9. Volpano, D., Smith, G., & Irvine, C. *A Sound Type System for Secure Flow Analysis.* JCS, 1996.
10. Martin-Lof, P. *Intuitionistic Type Theory.* Bibliopolis, 1984.
11. Leroy, X. *Formal Verification of a Realistic Compiler.* CACM, 2009.
12. Reynolds, J.C. *Separation Logic: A Logic for Shared Mutable Data Structures.* LICS, 2002.
13. Schwartz, E.J., Avgerinos, T., & Brumley, D. *All You Ever Wanted to Know About Dynamic Taint Analysis.* IEEE S&P, 2010.
14. Flanagan, C. & Leino, K.R.M. *Houdini, an Annotation Assistant for ESC/Java.* FME, 2001.
15. Clarke, E.M., Emerson, E.A., & Sistla, A.P. *Automatic Verification of Finite-State Concurrent Systems.* TOPLAS, 1986.
16. Sagiv, M., Reps, T., & Wilhelm, R. *Parametric Shape Analysis via 3-Valued Logic.* TOPLAS, 2002.
17. Owicki, S. & Gries, D. *An Axiomatic Proof Technique for Parallel Programs.* Acta Informatica, 1976.

## License

MIT
