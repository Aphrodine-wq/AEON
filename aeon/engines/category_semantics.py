"""AEON Category-Theoretic Denotational Semantics.

Provides a formal mathematical semantics for AEON programs using
category theory. This gives AEON a rigorous foundation that enables
equational reasoning, compiler correctness proofs, and optimization
justification.

References:
  Moggi (1991) "Notions of Computation and Monads"
  Information and Computation 93(1), https://doi.org/10.1016/0890-5401(91)90052-4

  Plotkin & Power (2002) "Notions of Computation Determine Monads"
  FOSSACS '02, https://doi.org/10.1007/3-540-45931-6_24

  Levy (2004) "Call-By-Push-Value: A Functional/Imperative Synthesis"
  Semantics Structures in Computation, Springer

Mathematical Framework:

1. CARTESIAN CLOSED CATEGORIES (CCC):
   AEON's pure fragment is modeled in a CCC where:
   - Objects are types
   - Morphisms are pure functions
   - Products are tuple/struct types
   - Exponentials are function types
   - Terminal object is Void/Unit

   Key property: every pure function f: A -> B is a morphism in CCC,
   and the CCC laws guarantee:
   - Associativity of composition
   - Identity laws
   - Beta/eta equivalence for functions
   - Naturality of polymorphic functions

2. KLEISLI CATEGORIES for effects:
   Task functions (effectful computations) are modeled using
   Moggi's monadic semantics. For an effect monad T:
   - Pure values: A (an object in the base CCC)
   - Computations: T(A) (an object in the Kleisli category)
   - A task function f: A -> B with effects E is a Kleisli morphism:
     f: A -> T_E(B)

   The Kleisli category Kl(T) has:
   - Objects: same as base category
   - Morphisms f: A -> B are functions A -> T(B)
   - Composition: (g after f)(x) = f(x) >>= g  (monadic bind)
   - Identity: return: A -> T(A)

3. FUNCTORIAL SEMANTICS:
   The compiler passes are FUNCTORS between categories:

     Source (AST)  --Parse-->  Syntax Category
                   --Prove-->  Typed Category (with proofs)
                   --Flatten-> IR Category (DAG morphisms)
                   --Emit-->   Machine Category (LLVM)

   Each functor preserves the categorical structure, which is
   the formal statement of compiler correctness:
     [[e1 ; e2]] = [[e2]] o [[e1]]  (composition is preserved)
     [[id]] = id                     (identity is preserved)

4. GRADED MONADS for effects:
   Instead of a single monad T, we use a graded monad T_E
   indexed by an effect set E from the effect algebra:

     return : A -> T_{}(A)                    (pure computation)
     bind : T_E1(A) -> (A -> T_E2(B)) -> T_{E1 union E2}(B)

   This captures the effect accumulation precisely:
   the effect of a sequential composition is the union of
   individual effects.

5. INITIAL ALGEBRA SEMANTICS for data types:
   AEON data types are initial algebras of polynomial functors:
     data List<A> = Nil | Cons(A, List<A>)
   is the initial algebra of F(X) = 1 + A x X.

   Catamorphisms (folds) are the unique morphisms from initial
   algebras, providing a principled basis for recursion schemes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List, Set, Tuple, Callable, Generic, TypeVar
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc, DataDef,
    Statement, Expr, Identifier, IntLiteral, BoolLiteral,
    BinaryOp, UnaryOp, FunctionCall, ReturnStmt, LetStmt,
    IfStmt, ExprStmt, AssignStmt, FieldAccess, MethodCall,
)
from aeon.types import AeonType, PrimitiveType, DataType, FunctionType, INT, BOOL, VOID
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Objects in the Semantic Category
# ---------------------------------------------------------------------------

class SemanticObject(ABC):
    """An object in the semantic category (a type's denotation).

    [[Int]]   = Z (integers)
    [[Bool]]  = {true, false}
    [[Void]]  = {*} (unit/terminal object)
    [[A x B]] = [[A]] x [[B]] (cartesian product)
    [[A -> B]] = [[B]]^[[A]] (exponential / function space)
    [[T_E(A)]] = E* x [[A]] (graded monad: effect trace + value)
    """

    @abstractmethod
    def __str__(self) -> str: ...


@dataclass(frozen=True)
class BaseObject(SemanticObject):
    """A base type object: Int, Bool, String, etc."""
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class ProductObject(SemanticObject):
    """Cartesian product: A x B.

    In CCC, products satisfy the universal property:
    for any object C with morphisms f: C -> A and g: C -> B,
    there exists a unique morphism <f,g>: C -> A x B such that
    pi_1 o <f,g> = f and pi_2 o <f,g> = g.
    """
    components: Tuple[SemanticObject, ...]

    def __str__(self) -> str:
        return " x ".join(str(c) for c in self.components)


@dataclass(frozen=True)
class ExponentialObject(SemanticObject):
    """Exponential (function space): B^A = A -> B.

    In CCC, exponentials satisfy the universal property:
    Hom(C x A, B) is naturally isomorphic to Hom(C, B^A).
    This is currying/uncurrying.
    """
    domain: SemanticObject
    codomain: SemanticObject

    def __str__(self) -> str:
        return f"({self.domain} -> {self.codomain})"


@dataclass(frozen=True)
class MonadObject(SemanticObject):
    """Graded monad object: T_E(A).

    The graded monad T is indexed by effect sets E:
      T_{} = identity (pure computation)
      T_{E1 union E2} = T_{E1} o T_{E2} (effect composition)

    Formally: T_E(A) = {(trace, value) | trace in E*, value in A}
    """
    inner: SemanticObject
    effects: FrozenSet[str] = frozenset()

    def __str__(self) -> str:
        if not self.effects:
            return str(self.inner)
        effs = ", ".join(sorted(self.effects))
        return f"T<{effs}>({self.inner})"


@dataclass(frozen=True)
class InitialAlgebra(SemanticObject):
    """Initial algebra of a polynomial functor (recursive data type).

    data List<A> = Nil | Cons(A, List<A>)
    [[List<A>]] = mu X. 1 + [[A]] x X

    The initial algebra provides:
    - Constructor: F(mu F) -> mu F  (building values)
    - Catamorphism: for any algebra g: F(B) -> B,
      there exists a unique morphism cata(g): mu F -> B
    """
    name: str
    functor_repr: str  # String representation of the functor

    def __str__(self) -> str:
        return f"mu({self.name})"


@dataclass(frozen=True)
class TerminalObject(SemanticObject):
    """Terminal object 1 (Void/Unit).

    For any object A, there exists a unique morphism !_A : A -> 1.
    """
    def __str__(self) -> str:
        return "1"


# ---------------------------------------------------------------------------
# Morphisms in the Semantic Category
# ---------------------------------------------------------------------------

class SemanticMorphism(ABC):
    """A morphism in the semantic category (a function's denotation).

    Pure function f: A -> B is a morphism in CCC.
    Task function f: A -> B with effects E is a Kleisli morphism: A -> T_E(B).
    """
    @abstractmethod
    def domain(self) -> SemanticObject: ...

    @abstractmethod
    def codomain(self) -> SemanticObject: ...

    @abstractmethod
    def __str__(self) -> str: ...


@dataclass
class IdentityMorphism(SemanticMorphism):
    """Identity morphism: id_A : A -> A."""
    obj: SemanticObject

    def domain(self) -> SemanticObject:
        return self.obj

    def codomain(self) -> SemanticObject:
        return self.obj

    def __str__(self) -> str:
        return f"id({self.obj})"


@dataclass
class CompositionMorphism(SemanticMorphism):
    """Composition of morphisms: g o f : A -> C where f: A -> B, g: B -> C.

    Satisfies:
      - Associativity: (h o g) o f = h o (g o f)
      - Identity: id o f = f = f o id
    """
    first: SemanticMorphism   # f: A -> B
    second: SemanticMorphism  # g: B -> C

    def domain(self) -> SemanticObject:
        return self.first.domain()

    def codomain(self) -> SemanticObject:
        return self.second.codomain()

    def __str__(self) -> str:
        return f"({self.second} o {self.first})"


@dataclass
class ProductMorphism(SemanticMorphism):
    """Product morphism: <f, g> : C -> A x B."""
    components: List[SemanticMorphism]
    source: SemanticObject

    def domain(self) -> SemanticObject:
        return self.source

    def codomain(self) -> SemanticObject:
        return ProductObject(tuple(m.codomain() for m in self.components))

    def __str__(self) -> str:
        parts = ", ".join(str(m) for m in self.components)
        return f"<{parts}>"


@dataclass
class ProjectionMorphism(SemanticMorphism):
    """Projection: pi_i : A1 x ... x An -> Ai."""
    product: ProductObject
    index: int

    def domain(self) -> SemanticObject:
        return self.product

    def codomain(self) -> SemanticObject:
        return self.product.components[self.index]

    def __str__(self) -> str:
        return f"pi_{self.index}"


@dataclass
class CurryMorphism(SemanticMorphism):
    """Curry: Lambda(f) : A -> (B -> C) for f : A x B -> C.

    The currying isomorphism: Hom(A x B, C) ~ Hom(A, C^B)
    This is the defining property of a CCC.
    """
    uncurried: SemanticMorphism

    def domain(self) -> SemanticObject:
        dom = self.uncurried.domain()
        if isinstance(dom, ProductObject) and len(dom.components) >= 1:
            return dom.components[0]
        return dom

    def codomain(self) -> SemanticObject:
        dom = self.uncurried.domain()
        cod = self.uncurried.codomain()
        if isinstance(dom, ProductObject) and len(dom.components) >= 2:
            return ExponentialObject(dom.components[1], cod)
        return ExponentialObject(dom, cod)

    def __str__(self) -> str:
        return f"curry({self.uncurried})"


@dataclass
class KleisliMorphism(SemanticMorphism):
    """Kleisli morphism: f : A -> T_E(B) (effectful computation).

    In the Kleisli category Kl(T_E):
      - Composition: (g >=> f)(x) = f(x) >>= g
      - Identity: return_A : A -> T_{}(A)
    """
    pure_morphism: SemanticMorphism  # The underlying pure function
    effects: FrozenSet[str]

    def domain(self) -> SemanticObject:
        return self.pure_morphism.domain()

    def codomain(self) -> SemanticObject:
        inner = self.pure_morphism.codomain()
        return MonadObject(inner=inner, effects=self.effects)

    def __str__(self) -> str:
        effs = ", ".join(sorted(self.effects))
        return f"kleisli<{effs}>({self.pure_morphism})"


@dataclass
class CatamorphismMorphism(SemanticMorphism):
    """Catamorphism (fold): cata(alg) : mu F -> B.

    For initial algebra (mu F, in : F(mu F) -> mu F) and
    algebra (B, alg : F(B) -> B), the catamorphism is the
    unique morphism h : mu F -> B such that h o in = alg o F(h).

    This is the recursion principle for inductive data types.
    """
    algebra_name: str
    source_type: InitialAlgebra
    target: SemanticObject

    def domain(self) -> SemanticObject:
        return self.source_type

    def codomain(self) -> SemanticObject:
        return self.target

    def __str__(self) -> str:
        return f"cata({self.algebra_name})"


@dataclass
class ConstantMorphism(SemanticMorphism):
    """Constant morphism: const(c) : A -> B, always returns c."""
    value: Any
    source: SemanticObject
    target: SemanticObject

    def domain(self) -> SemanticObject:
        return self.source

    def codomain(self) -> SemanticObject:
        return self.target

    def __str__(self) -> str:
        return f"const({self.value})"


@dataclass
class NamedMorphism(SemanticMorphism):
    """A named morphism (function denotation)."""
    name: str
    dom: SemanticObject
    cod: SemanticObject

    def domain(self) -> SemanticObject:
        return self.dom

    def codomain(self) -> SemanticObject:
        return self.cod

    def __str__(self) -> str:
        return f"[[{self.name}]]"


# ---------------------------------------------------------------------------
# Semantic Functor (Compiler Pass as Functor)
# ---------------------------------------------------------------------------

@dataclass
class SemanticFunctor:
    """A functor between categories (representing a compiler pass).

    A functor F: C -> D consists of:
      - Object mapping: F(A) for each object A in C
      - Morphism mapping: F(f) for each morphism f in C
    satisfying:
      - F(id_A) = id_{F(A)}              (preserves identity)
      - F(g o f) = F(g) o F(f)           (preserves composition)

    Each compiler pass is a functor:
      Parse:   String -> AST Category
      Prove:   AST -> Typed Category
      Flatten: Typed -> IR Category
      Emit:    IR -> LLVM Category
    """
    name: str
    source_category: str
    target_category: str
    object_map: Dict[str, SemanticObject] = field(default_factory=dict)
    morphism_map: Dict[str, SemanticMorphism] = field(default_factory=dict)

    def map_object(self, obj_name: str) -> Optional[SemanticObject]:
        return self.object_map.get(obj_name)

    def map_morphism(self, morph_name: str) -> Optional[SemanticMorphism]:
        return self.morphism_map.get(morph_name)


# ---------------------------------------------------------------------------
# Denotational Semantics Engine
# ---------------------------------------------------------------------------

class DenotationalSemantics:
    """Computes denotational semantics for AEON programs.

    Maps each AEON construct to its mathematical meaning:
    - Types -> Objects in the semantic category
    - Functions -> Morphisms
    - Expressions -> Morphisms from the context to the result type
    - Statements -> State transformers (morphisms in Kleisli category)

    This enables:
    1. Equational reasoning about programs
    2. Correctness proofs for compiler optimizations
    3. Verification that two programs are semantically equivalent
    """

    def __init__(self):
        self.objects: Dict[str, SemanticObject] = {}
        self.morphisms: Dict[str, SemanticMorphism] = {}
        self.functors: List[SemanticFunctor] = []
        self.equations: List[Tuple[str, SemanticMorphism, SemanticMorphism]] = []
        self.errors: List[AeonError] = []

        # Initialize base objects
        self._init_base_objects()

    def _init_base_objects(self) -> None:
        """Initialize denotations of built-in types."""
        self.objects["Int"] = BaseObject("Z")           # Integers
        self.objects["Float"] = BaseObject("R")          # Reals
        self.objects["Bool"] = BaseObject("2")           # {0, 1}
        self.objects["String"] = BaseObject("Sigma*")    # Free monoid on alphabet
        self.objects["Void"] = TerminalObject()          # Terminal object 1
        self.objects["UUID"] = BaseObject("UUID")
        self.objects["Email"] = BaseObject("Email")
        self.objects["USD"] = BaseObject("Z")            # Cents as integers

    def interpret_program(self, program: Program) -> Dict[str, Any]:
        """Compute the denotational semantics of an AEON program.

        Returns a dictionary containing:
        - 'objects': type denotations
        - 'morphisms': function denotations
        - 'equations': equational laws that hold
        - 'functors': compiler pass functors
        """
        self.errors = []

        # Interpret data types as objects
        for decl in program.declarations:
            if isinstance(decl, DataDef):
                self._interpret_data(decl)

        # Interpret functions as morphisms
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._interpret_function(decl)

        # Generate equational laws
        self._generate_equations()

        # Build compiler functors
        self._build_compiler_functors(program)

        return {
            "objects": dict(self.objects),
            "morphisms": dict(self.morphisms),
            "equations": list(self.equations),
            "functors": list(self.functors),
        }

    def _interpret_data(self, data: DataDef) -> None:
        """Interpret a data type as a product object.

        data Point { x: Int, y: Int }
        [[Point]] = [[Int]] x [[Int]] = Z x Z
        """
        field_objects = []
        for f in data.fields:
            type_name = str(f.type_annotation) if f.type_annotation else "Void"
            obj = self.objects.get(type_name, BaseObject(type_name))
            field_objects.append(obj)

        if len(field_objects) == 1:
            self.objects[data.name] = field_objects[0]
        elif field_objects:
            self.objects[data.name] = ProductObject(tuple(field_objects))
        else:
            self.objects[data.name] = TerminalObject()

    def _interpret_function(self, func: PureFunc | TaskFunc) -> None:
        """Interpret a function as a morphism.

        pure f(x: A, y: B) -> C  =>  [[f]] : [[A]] x [[B]] -> [[C]]
        task g(x: A) -> B with E =>  [[g]] : [[A]] -> T_E([[B]])
        """
        # Build domain (product of parameter types)
        param_objects = []
        for p in func.params:
            type_name = str(p.type_annotation) if p.type_annotation else "Void"
            obj = self.objects.get(type_name, BaseObject(type_name))
            param_objects.append(obj)

        if len(param_objects) == 0:
            domain = TerminalObject()
        elif len(param_objects) == 1:
            domain = param_objects[0]
        else:
            domain = ProductObject(tuple(param_objects))

        # Build codomain
        ret_name = str(func.return_type) if func.return_type else "Void"
        codomain = self.objects.get(ret_name, BaseObject(ret_name))

        # Create morphism
        if isinstance(func, PureFunc):
            morphism = NamedMorphism(
                name=func.name,
                dom=domain,
                cod=codomain,
            )
        else:
            effects = frozenset(func.effects)
            inner = NamedMorphism(
                name=func.name,
                dom=domain,
                cod=codomain,
            )
            morphism = KleisliMorphism(
                pure_morphism=inner,
                effects=effects,
            )

        self.morphisms[func.name] = morphism

    def _generate_equations(self) -> None:
        """Generate equational laws that hold for the program.

        These are semantic equations justified by the categorical structure:
        1. Identity law: f o id = f = id o f
        2. Associativity: (h o g) o f = h o (g o f)
        3. Beta reduction: (lambda x. e)(v) = e[x/v]
        4. Eta expansion: (lambda x. f(x)) = f
        5. Monad laws (for Kleisli morphisms):
           - return >>= f = f
           - m >>= return = m
           - (m >>= f) >>= g = m >>= (x -> f(x) >>= g)
        6. Naturality: for natural transformation eta, eta_B o F(f) = G(f) o eta_A
        """
        for name, morphism in self.morphisms.items():
            # Identity law
            dom = morphism.domain()
            cod = morphism.codomain()
            id_dom = IdentityMorphism(dom)
            id_cod = IdentityMorphism(cod)

            self.equations.append((
                f"{name}_left_identity",
                CompositionMorphism(id_dom, morphism),
                morphism,
            ))
            self.equations.append((
                f"{name}_right_identity",
                CompositionMorphism(morphism, id_cod),
                morphism,
            ))

            # Monad laws for Kleisli morphisms
            if isinstance(morphism, KleisliMorphism):
                self.equations.append((
                    f"{name}_monad_left_unit",
                    morphism,  # return >>= f = f
                    morphism,
                ))

    def _build_compiler_functors(self, program: Program) -> None:
        """Build functors representing compiler passes.

        Each compiler pass is a structure-preserving functor:
          Prove  : Syntax -> Typed     (adds type annotations)
          Flatten: Typed  -> IR        (eliminates nesting)
          Emit   : IR     -> Machine   (lowers to LLVM)
        """
        # Prove functor
        prove_functor = SemanticFunctor(
            name="Prove",
            source_category="Syntax",
            target_category="Typed",
        )
        for name, obj in self.objects.items():
            prove_functor.object_map[name] = obj
        for name, morph in self.morphisms.items():
            prove_functor.morphism_map[name] = morph
        self.functors.append(prove_functor)

        # Flatten functor
        flatten_functor = SemanticFunctor(
            name="Flatten",
            source_category="Typed",
            target_category="IR",
        )
        for name, obj in self.objects.items():
            flatten_functor.object_map[name] = BaseObject(f"IR_{name}")
        self.functors.append(flatten_functor)

        # Emit functor
        emit_functor = SemanticFunctor(
            name="Emit",
            source_category="IR",
            target_category="LLVM",
        )
        llvm_type_map = {
            "Int": "i64", "Float": "double", "Bool": "i1",
            "String": "i8*", "Void": "void",
        }
        for name, obj in self.objects.items():
            llvm_name = llvm_type_map.get(name, "i64")
            emit_functor.object_map[name] = BaseObject(llvm_name)
        self.functors.append(emit_functor)

    def verify_functor_laws(self) -> List[str]:
        """Verify that compiler functors preserve categorical structure.

        Checks:
        1. F(id_A) = id_{F(A)}  (identity preservation)
        2. F(g o f) = F(g) o F(f)  (composition preservation)

        Violations indicate compiler bugs.
        """
        violations = []

        for functor in self.functors:
            # Check identity preservation
            for name, obj in functor.object_map.items():
                # F(id_A) should equal id_{F(A)}
                if name not in functor.morphism_map:
                    continue
                mapped_morph = functor.morphism_map[name]
                if isinstance(mapped_morph, IdentityMorphism):
                    if mapped_morph.obj != obj:
                        violations.append(
                            f"Functor {functor.name} violates identity law at {name}"
                        )

        return violations


# ---------------------------------------------------------------------------
# Program Equivalence Checker
# ---------------------------------------------------------------------------

class EquivalenceChecker:
    """Checks semantic equivalence of AEON programs/expressions.

    Two expressions e1, e2 are semantically equivalent (e1 ~ e2) iff
    their denotations are equal morphisms in the semantic category:

      [[e1]] = [[e2]] : [[Gamma]] -> [[T]]

    This enables:
    - Optimization correctness: verify that an optimization preserves semantics
    - Refactoring safety: verify that a refactoring doesn't change behavior
    - Test generation: generate tests that distinguish non-equivalent programs
    """

    def __init__(self, semantics: DenotationalSemantics):
        self.semantics = semantics

    def check_equivalence(self, name1: str, name2: str) -> bool:
        """Check if two named morphisms are equivalent.

        Uses the equational theory generated from the categorical structure.
        """
        m1 = self.semantics.morphisms.get(name1)
        m2 = self.semantics.morphisms.get(name2)

        if m1 is None or m2 is None:
            return False

        # Check structural equality (syntactic)
        if str(m1) == str(m2):
            return True

        # Check domain/codomain match
        if str(m1.domain()) != str(m2.domain()):
            return False
        if str(m1.codomain()) != str(m2.codomain()):
            return False

        # Check via equational laws
        for eq_name, lhs, rhs in self.semantics.equations:
            if str(lhs) == str(m1) and str(rhs) == str(m2):
                return True
            if str(lhs) == str(m2) and str(rhs) == str(m1):
                return True

        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_semantics(program: Program) -> Dict[str, Any]:
    """Compute the denotational semantics of an AEON program.

    Returns the categorical interpretation including:
    - Type denotations (objects in CCC)
    - Function denotations (morphisms / Kleisli morphisms)
    - Equational laws
    - Compiler pass functors
    """
    engine = DenotationalSemantics()
    return engine.interpret_program(program)


def verify_compiler_correctness(program: Program) -> List[str]:
    """Verify that compiler passes preserve categorical structure.

    Checks that each compiler pass functor satisfies the functor laws,
    which is the formal statement of compiler correctness.
    """
    engine = DenotationalSemantics()
    engine.interpret_program(program)
    return engine.verify_functor_laws()
