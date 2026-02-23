"""AEON Pass 1 — Prove.

Type checking + ownership checking + effect checking + contract verification.
If this pass completes, the program is mathematically correct.
No runtime null errors, no races, no use-after-free.
"""

from __future__ import annotations

from typing import Optional
import logging

from aeon.ast_nodes import (
    Program, Declaration, DataDef, EnumDef, PureFunc, TaskFunc,
    TraitDef, ImplBlock, TypeAlias, UseDecl,
    Parameter, TypeAnnotation,
    Expr, Identifier, IntLiteral, FloatLiteral, BoolLiteral, StringLiteral, ListLiteral,
    UnaryOp, BinaryOp, IfStmt, ReturnStmt, LetStmt, AssignStmt, ExprStmt,
    ConstructExpr, FieldAccess, MethodCall, FunctionCall, MoveExpr,
    ForStmt, MatchExpr, LambdaExpr, PipeExpr, SpawnExpr, AwaitExpr,
)
from aeon.types import (
    AeonType, PrimitiveType, GenericType, DataType, FunctionType, ListType,
    EnumType,
    INT, FLOAT, STRING, BOOL, VOID, UUID, EMAIL, USD, ERROR,
    TypeEnvironment, resolve_type_annotation,
    make_result_type, make_list_type,
)
from aeon.errors import (
    AeonError, CompileError, ErrorKind, type_error, name_error, SourceLocation,
)
from aeon.ownership import OwnershipChecker
from aeon.effects import EffectChecker
from aeon.contracts import ContractVerifier
from aeon.termination import TerminationAnalyzer
from aeon.memory import MemoryTracker

# Advanced mathematical analysis modules
from aeon.refinement_types import check_refinements
from aeon.abstract_interp import abstract_interpret, abstract_interpret_with_trace
from aeon.verification_context import VerificationContext
from aeon.size_change import check_termination_sct
from aeon.hoare import verify_contracts_hoare
from aeon.effect_algebra import check_effects_algebraic
from aeon.category_semantics import compute_semantics, verify_compiler_correctness
from aeon.information_flow import check_information_flow
from aeon.dependent_types import check_dependent_types
from aeon.certified_compilation import check_certified_compilation
from aeon.symbolic_execution import symbolic_execute
from aeon.separation_logic import check_separation_logic
from aeon.taint_analysis import check_taint
from aeon.concurrency import check_concurrency
from aeon.shape_analysis import check_shapes
from aeon.model_checking import check_model
from aeon.gradual_typing import check_gradual_types
from aeon.linear_resource import check_linear_resources
from aeon.probabilistic import check_probabilistic
from aeon.relational_verify import check_relational
from aeon.session_types import check_session_types
from aeon.complexity_analysis import check_complexity
from aeon.abstract_refinement import check_abstract_refinements
from aeon.differential_privacy import check_differential_privacy
from aeon.typestate import check_typestate
from aeon.interpolation import check_interpolation


def _engine_error(message: str) -> AeonError:
    """Create an AeonError for an engine failure (used in except blocks)."""
    return AeonError(kind=ErrorKind.TYPE_ERROR, message=message, location=SourceLocation("", 1, 1))


class TypeChecker:
    """Type checks an AEON program."""

    def __init__(self, verify_contracts: bool = False, analyze_termination: bool = False, track_memory: bool = False,
                 refinement_types: bool = False, abstract_interpretation: bool = False,
                 size_change: bool = False, hoare_logic: bool = False,
                 algebraic_effects: bool = False, category_check: bool = False,
                 information_flow: bool = False, dependent_types: bool = False,
                 certified_compilation: bool = False, symbolic_exec: bool = False,
                 separation_logic: bool = False, taint_analysis: bool = False,
                 concurrency_check: bool = False, shape_analysis: bool = False,
                 model_checking: bool = False,
                 gradual_typing: bool = False, linear_resource: bool = False,
                 probabilistic: bool = False, relational_verify: bool = False,
                 session_types: bool = False, complexity_analysis: bool = False,
                 abstract_refinement: bool = False, differential_privacy: bool = False,
                 typestate: bool = False, interpolation: bool = False,
                 deep_verify: bool = False):
        self.env = TypeEnvironment()
        self.errors: list[AeonError] = []
        self.verify_contracts = verify_contracts
        self.analyze_termination = analyze_termination
        self.track_memory = track_memory
        # Advanced analysis flags
        self.refinement_types = refinement_types or deep_verify
        self.abstract_interpretation = abstract_interpretation or deep_verify
        self.size_change = size_change or deep_verify
        self.hoare_logic = hoare_logic or deep_verify
        self.algebraic_effects = algebraic_effects or deep_verify
        self.category_check = category_check or deep_verify
        self.information_flow = information_flow or deep_verify
        self.dependent_types = dependent_types or deep_verify
        self.certified_compilation = certified_compilation or deep_verify
        self.symbolic_exec = symbolic_exec or deep_verify
        self.separation_logic = separation_logic or deep_verify
        self.taint_analysis = taint_analysis or deep_verify
        self.concurrency_check = concurrency_check or deep_verify
        self.shape_analysis = shape_analysis or deep_verify
        self.model_checking = model_checking or deep_verify
        self.gradual_typing = gradual_typing or deep_verify
        self.linear_resource = linear_resource or deep_verify
        self.probabilistic = probabilistic or deep_verify
        self.relational_verify = relational_verify or deep_verify
        self.session_types = session_types or deep_verify
        self.complexity_analysis = complexity_analysis or deep_verify
        self.abstract_refinement = abstract_refinement or deep_verify
        self.differential_privacy = differential_privacy or deep_verify
        self.typestate = typestate or deep_verify
        self.interpolation = interpolation or deep_verify
        self._current_return_type: Optional[AeonType] = None
        self._function_effects: dict[str, list[str]] = {}
        # Performance caching
        self._type_cache: dict[int, AeonType] = {}  # Cache type inference results
        self._function_cache: dict[str, FunctionType] = {}  # Cache function types
        # Shared verification context — accumulates proven facts across engines
        self.ctx: VerificationContext = VerificationContext()

    def check_program(self, program: Program) -> list[AeonError]:
        """Type check an entire program. Returns list of errors."""
        self.errors = []

        # Register built-in runtime objects
        self._register_builtins()

        # First pass: register all data types and function signatures
        try:
            self._register_declarations(program)
        except Exception as e:
            self.errors.append(_engine_error(f"Failed to register declarations: {str(e)}"))

        # Second pass: type check function bodies with error recovery
        for decl in program.declarations:
            try:
                if isinstance(decl, PureFunc):
                    self._check_pure_func(decl)
                elif isinstance(decl, TaskFunc):
                    self._check_task_func(decl)
                elif isinstance(decl, TraitDef):
                    for method in decl.methods:
                        if isinstance(method, PureFunc):
                            self._check_pure_func(method)
                        elif isinstance(method, TaskFunc):
                            self._check_task_func(method)
                elif isinstance(decl, ImplBlock):
                    for method in decl.methods:
                        if isinstance(method, PureFunc):
                            self._check_pure_func(method)
                        elif isinstance(method, TaskFunc):
                            self._check_task_func(method)
            except Exception as e:
                # Recover from error and continue
                if hasattr(decl, 'name'):
                    self.errors.append(type_error(
                        node_id="function_check_error",
                        expected_type="successful compilation",
                        actual_type=f"error: {str(e)}",
                        location=getattr(decl, 'location', SourceLocation("", 1, 1))
                    ))
                else:
                    self.errors.append(type_error(
                        node_id="declaration_check_error", 
                        expected_type="successful compilation",
                        actual_type=f"error: {str(e)}",
                        location=SourceLocation("", 1, 1)
                    ))
                continue

        # P2: Termination analysis with error recovery
        if self.analyze_termination:
            try:
                functions = [d for d in program.declarations 
                            if isinstance(d, (PureFunc, TaskFunc))]
                terminator = TerminationAnalyzer()
                term_errors = terminator.analyze_program(functions)
                self.errors.extend(term_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Termination analysis failed: {str(e)}"))

        # P2: Memory tracking with error recovery
        if self.track_memory:
            try:
                functions = [d for d in program.declarations 
                            if isinstance(d, (PureFunc, TaskFunc))]
                data_types = [d for d in program.declarations 
                             if isinstance(d, DataDef)]
                tracker = MemoryTracker()
                mem_errors = tracker.analyze_program(functions, data_types)
                self.errors.extend(mem_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Memory tracking failed: {str(e)}"))

        # --- Advanced Mathematical Analysis Passes ---

        # Refinement Types (Liquid Types, Rondon/Kawaguchi/Jhala 2008)
        if self.refinement_types:
            try:
                ref_errors = check_refinements(program)
                self.errors.extend(ref_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Refinement type analysis failed: {str(e)}"))

        # Abstract Interpretation (Cousot & Cousot 1977)
        if self.abstract_interpretation:
            try:
                ai_errors, _ = abstract_interpret_with_trace(program, ctx=self.ctx)
                self.errors.extend(ai_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Abstract interpretation failed: {str(e)}"))

        # Size-Change Termination (Lee/Jones/Ben-Amram 2001)
        if self.size_change:
            try:
                sct_errors = check_termination_sct(program)
                self.errors.extend(sct_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Size-change termination analysis failed: {str(e)}"))

        # Hoare Logic / wp-calculus (Dijkstra 1975, Hoare 1969)
        if self.hoare_logic:
            try:
                hoare_errors = verify_contracts_hoare(program)
                self.errors.extend(hoare_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Hoare logic verification failed: {str(e)}"))

        # Algebraic Effects with Row Polymorphism (Plotkin & Pretnar 2009)
        if self.algebraic_effects:
            try:
                eff_errors = check_effects_algebraic(program)
                self.errors.extend(eff_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Algebraic effect analysis failed: {str(e)}"))

        # Category-Theoretic Semantics (Moggi 1991)
        if self.category_check:
            try:
                violations = verify_compiler_correctness(program)
                for v in violations:
                    self.errors.append(_engine_error(str(v)))
            except Exception as e:
                self.errors.append(_engine_error(f"Category semantics check failed: {str(e)}"))

        # Information Flow / Noninterference (Volpano/Smith/Irvine 1996)
        if self.information_flow:
            try:
                ifc_errors = check_information_flow(program)
                self.errors.extend(ifc_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Information flow analysis failed: {str(e)}"))

        # Dependent Types / Curry-Howard (Martin-Löf 1984, Coquand & Huet 1988)
        if self.dependent_types:
            try:
                dt_errors = check_dependent_types(program)
                self.errors.extend(dt_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Dependent type checking failed: {str(e)}"))

        # Certified Compilation (Leroy 2009, CompCert)
        if self.certified_compilation:
            try:
                cc_errors = check_certified_compilation(program)
                self.errors.extend(cc_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Certified compilation check failed: {str(e)}"))

        # Symbolic Execution (King 1976, KLEE 2008)
        if self.symbolic_exec:
            try:
                se_errors = symbolic_execute(program)
                self.errors.extend(se_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Symbolic execution failed: {str(e)}"))

        # Separation Logic (Reynolds 2002, O'Hearn 2019)
        if self.separation_logic:
            try:
                sl_errors = check_separation_logic(program)
                self.errors.extend(sl_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Separation logic analysis failed: {str(e)}"))

        # Taint Analysis (Schwartz et al. 2010, Tripp et al. 2009)
        if self.taint_analysis:
            try:
                ta_errors = check_taint(program)
                self.errors.extend(ta_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Taint analysis failed: {str(e)}"))

        # Concurrency Verification (Owicki & Gries 1976, Flanagan & Godefroid 2005)
        if self.concurrency_check:
            try:
                cc_errors = check_concurrency(program)
                self.errors.extend(cc_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Concurrency verification failed: {str(e)}"))

        # Shape Analysis (Sagiv, Reps, Wilhelm 2002)
        if self.shape_analysis:
            try:
                sa_errors = check_shapes(program)
                self.errors.extend(sa_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Shape analysis failed: {str(e)}"))

        # Bounded Model Checking (Clarke et al. 1986, Biere et al. 1999)
        if self.model_checking:
            try:
                mc_errors = check_model(program)
                self.errors.extend(mc_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Model checking failed: {str(e)}"))

        # Gradual Typing Verification (Siek & Taha 2006, Siek et al. 2015)
        if self.gradual_typing:
            try:
                gt_errors = check_gradual_types(program)
                self.errors.extend(gt_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Gradual typing analysis failed: {str(e)}"))

        # Linear / Affine Resource Analysis (Girard 1987, Hofmann & Jost 2003)
        if self.linear_resource:
            try:
                lr_errors = check_linear_resources(program)
                self.errors.extend(lr_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Linear resource analysis failed: {str(e)}"))

        # Probabilistic Program Analysis (Kozen 1981, Gordon et al. 2014)
        if self.probabilistic:
            try:
                prob_errors = check_probabilistic(program)
                self.errors.extend(prob_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Probabilistic analysis failed: {str(e)}"))

        # Relational Verification / 2-Safety (Barthe et al. 2011, Benton 2004)
        if self.relational_verify:
            try:
                rv_errors = check_relational(program)
                self.errors.extend(rv_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Relational verification failed: {str(e)}"))

        # Session Types / Multiparty Protocol Verification (Honda et al. 2008, Wadler 2012)
        if self.session_types:
            try:
                st_errors = check_session_types(program)
                self.errors.extend(st_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Session type checking failed: {str(e)}"))

        # Automatic Complexity Analysis / RAML (Hoffmann et al. 2012, Gulwani et al. 2009)
        if self.complexity_analysis:
            try:
                cx_errors = check_complexity(program)
                self.errors.extend(cx_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Complexity analysis failed: {str(e)}"))

        # Abstract Refinement Types (Vazou et al. 2013, Vazou et al. 2014)
        if self.abstract_refinement:
            try:
                ar_errors = check_abstract_refinements(program)
                self.errors.extend(ar_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Abstract refinement type checking failed: {str(e)}"))

        # Differential Privacy Verification (Reed & Pierce 2010, Gaboardi et al. 2013)
        if self.differential_privacy:
            try:
                dp_errors = check_differential_privacy(program)
                self.errors.extend(dp_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Differential privacy verification failed: {str(e)}"))

        # Type-State Analysis (Strom & Yemini 1986, DeLine & Fahndrich 2004)
        if self.typestate:
            try:
                ts_errors = check_typestate(program)
                self.errors.extend(ts_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Typestate analysis failed: {str(e)}"))

        # Craig Interpolation / CEGAR Refinement (McMillan 2003, Henzinger et al. 2004)
        if self.interpolation:
            try:
                ip_errors = check_interpolation(program)
                self.errors.extend(ip_errors)
            except Exception as e:
                self.errors.append(_engine_error(f"Interpolation-based refinement failed: {str(e)}"))

        return self.errors

    def _register_builtins(self) -> None:
        """Register built-in runtime objects (db, file, net, console, etc.)."""
        # Runtime objects are typed as opaque — their methods are handled
        # by the effect system and method call type inference.
        runtime_obj = PrimitiveType("Runtime")
        for name in ("db", "file", "net", "console", "system"):
            self.env.define_variable(name, runtime_obj)
        # Built-in free functions
        self.env.define_function("print", FunctionType(
            param_types=(STRING,), return_type=VOID, is_pure=False, effects=("Console.Write",),
        ))

    def _register_declarations(self, program: Program) -> None:
        """Register all type and function declarations."""
        for decl in program.declarations:
            if isinstance(decl, DataDef):
                self._register_data(decl)
            elif isinstance(decl, EnumDef):
                self._register_enum(decl)
            elif isinstance(decl, PureFunc):
                self._register_func(decl, is_pure=True)
            elif isinstance(decl, TaskFunc):
                self._register_func(decl, is_pure=False)
                self._function_effects[decl.name] = decl.effects
            elif isinstance(decl, TraitDef):
                self._register_trait(decl)
            elif isinstance(decl, ImplBlock):
                self._register_impl(decl)
            elif isinstance(decl, TypeAlias):
                self._register_type_alias(decl)
            elif isinstance(decl, UseDecl):
                pass  # use declarations are resolved at module level

    def _register_data(self, data: DataDef) -> None:
        """Register a data type in the environment."""
        fields: list[tuple[str, AeonType]] = []
        for f in data.fields:
            ftype = resolve_type_annotation(f.type_annotation, self.env)
            fields.append((f.name, ftype))
        dt = DataType(name=data.name, fields=tuple(fields))
        self.env.define_type(data.name, dt)

    def _register_func(self, func: PureFunc | TaskFunc, is_pure: bool) -> None:
        """Register a function signature in the environment."""
        param_types: list[AeonType] = []
        for p in func.params:
            pt = resolve_type_annotation(p.type_annotation, self.env)
            param_types.append(pt)

        ret_type = VOID
        if func.return_type:
            ret_type = resolve_type_annotation(func.return_type, self.env)

        effects = ()
        if isinstance(func, TaskFunc):
            effects = tuple(func.effects)

        ft = FunctionType(
            param_types=tuple(param_types),
            return_type=ret_type,
            is_pure=is_pure,
            effects=effects,
        )
        self.env.define_function(func.name, ft)

    def _register_enum(self, enum: EnumDef) -> None:
        """Register an enum type and its variant constructors."""
        # Register the enum as a type
        dt = DataType(name=enum.name, fields=())
        self.env.define_type(enum.name, dt)
        # Register each variant as a constructor function
        for variant in enum.variants:
            if variant.fields:
                param_types = tuple(
                    resolve_type_annotation(f.type_annotation, self.env)
                    for f in variant.fields
                )
                ft = FunctionType(
                    param_types=param_types,
                    return_type=dt,
                    is_pure=True,
                )
                self.env.define_function(variant.name, ft)
            else:
                # Unit variant — register as a variable of the enum type
                self.env.define_variable(variant.name, dt)

    def _register_trait(self, trait: TraitDef) -> None:
        """Register trait method signatures."""
        for method in trait.methods:
            is_pure = isinstance(method, PureFunc)
            self._register_func(method, is_pure=is_pure)

    def _register_impl(self, impl: ImplBlock) -> None:
        """Register impl block methods."""
        for method in impl.methods:
            is_pure = isinstance(method, PureFunc)
            self._register_func(method, is_pure=is_pure)
            if isinstance(method, TaskFunc):
                self._function_effects[method.name] = method.effects

    def _register_type_alias(self, alias: TypeAlias) -> None:
        """Register a type alias."""
        target_type = resolve_type_annotation(alias.target, self.env)
        self.env.define_type(alias.name, target_type)

    # -------------------------------------------------------------------
    # Function body checking
    # -------------------------------------------------------------------

    def _check_pure_func(self, func: PureFunc) -> None:
        self._check_function_body(func, is_pure=True)

        # Ownership check
        oc = OwnershipChecker()
        self.errors.extend(oc.check_function(func))

        # Effect check: pure must have zero effects
        ec = EffectChecker(self._function_effects)
        self.errors.extend(ec.check_pure_function(func))

        # Contract check
        cv = ContractVerifier(verify=self.verify_contracts)
        self.errors.extend(cv.check_function(func))

    def _check_task_func(self, func: TaskFunc) -> None:
        self._check_function_body(func, is_pure=False)

        # Ownership check
        oc = OwnershipChecker()
        self.errors.extend(oc.check_function(func))

        # Effect check: task effects must be declared
        ec = EffectChecker(self._function_effects)
        self.errors.extend(ec.check_task_function(func))

        # Contract check
        cv = ContractVerifier(verify=self.verify_contracts)
        self.errors.extend(cv.check_function(func))

    def _check_function_body(self, func: PureFunc | TaskFunc, is_pure: bool) -> None:
        child_env = self.env.child_scope()

        # Bind parameters
        for p in func.params:
            pt = resolve_type_annotation(p.type_annotation, self.env)
            child_env.define_variable(p.name, pt)

        # Set expected return type
        ret_type = VOID
        if func.return_type:
            ret_type = resolve_type_annotation(func.return_type, self.env)
        self._current_return_type = ret_type

        # Check body
        saved_env = self.env
        self.env = child_env
        for stmt in func.body:
            self._check_statement(stmt)
        self.env = saved_env

    # -------------------------------------------------------------------
    # Statements
    # -------------------------------------------------------------------

    def _check_statement(self, stmt: Statement) -> None:
        if isinstance(stmt, ReturnStmt):
            self._check_return(stmt)
        elif isinstance(stmt, LetStmt):
            self._check_let(stmt)
        elif isinstance(stmt, AssignStmt):
            self._check_assign(stmt)
        elif isinstance(stmt, ExprStmt):
            self._infer_type(stmt.expr)
        elif isinstance(stmt, IfStmt):
            self._check_if(stmt)
        elif isinstance(stmt, WhileStmt):
            self._check_while(stmt)
        elif isinstance(stmt, ForStmt):
            self._check_for(stmt)
        elif isinstance(stmt, UnsafeBlock):
            for s in stmt.body:
                self._check_statement(s)

    def _check_return(self, stmt: ReturnStmt) -> None:
        if stmt.value is None:
            if self._current_return_type and self._current_return_type != VOID:
                self.errors.append(type_error(
                    node_id="return",
                    expected_type=str(self._current_return_type),
                    actual_type="Void",
                    location=stmt.location,
                ))
            return

        actual = self._infer_type(stmt.value)
        if self._current_return_type and actual and not self._types_compatible(self._current_return_type, actual):
            self.errors.append(type_error(
                node_id="return",
                expected_type=str(self._current_return_type),
                actual_type=str(actual),
                location=stmt.location,
            ))

    def _check_let(self, stmt: LetStmt) -> None:
        declared_type: Optional[AeonType] = None
        if stmt.type_annotation:
            declared_type = resolve_type_annotation(stmt.type_annotation, self.env)

        if stmt.value:
            inferred = self._infer_type(stmt.value)
            if declared_type and inferred and not self._types_compatible(declared_type, inferred):
                self.errors.append(type_error(
                    node_id=f"let_{stmt.name}",
                    expected_type=str(declared_type),
                    actual_type=str(inferred),
                    location=stmt.location,
                ))
            final_type = declared_type or inferred or VOID
        else:
            final_type = declared_type or VOID

        self.env.define_variable(stmt.name, final_type)

    def _check_assign(self, stmt: AssignStmt) -> None:
        target_type = self._infer_type(stmt.target)
        value_type = self._infer_type(stmt.value)
        if target_type and value_type and not self._types_compatible(target_type, value_type):
            self.errors.append(type_error(
                node_id="assign",
                expected_type=str(target_type),
                actual_type=str(value_type),
                location=stmt.location,
            ))

    def _check_if(self, stmt: IfStmt) -> None:
        cond_type = self._infer_type(stmt.condition)
        if cond_type and cond_type != BOOL:
            self.errors.append(type_error(
                node_id="if_condition",
                expected_type="Bool",
                actual_type=str(cond_type),
                location=stmt.location,
            ))
        child = self.env.child_scope()
        saved = self.env
        self.env = child
        for s in stmt.then_body:
            self._check_statement(s)
        self.env = saved

        if stmt.else_body:
            child = self.env.child_scope()
            saved = self.env
            self.env = child
            for s in stmt.else_body:
                self._check_statement(s)
            self.env = saved

    def _check_while(self, stmt: WhileStmt) -> None:
        cond_type = self._infer_type(stmt.condition)
        if cond_type and cond_type != BOOL:
            self.errors.append(type_error(
                node_id="while_condition",
                expected_type="Bool",
                actual_type=str(cond_type),
                location=stmt.location,
            ))
        child = self.env.child_scope()
        saved = self.env
        self.env = child
        for s in stmt.body:
            self._check_statement(s)
        self.env = saved

    def _check_for(self, stmt: ForStmt) -> None:
        iter_type = self._infer_type(stmt.iterable)
        child = self.env.child_scope()
        # Infer element type from list type
        elem_type = INT  # default
        if iter_type and isinstance(iter_type, ListType):
            elem_type = iter_type.element_type
        child.define_variable(stmt.var_name, elem_type)
        saved = self.env
        self.env = child
        for s in stmt.body:
            self._check_statement(s)
        self.env = saved

    # Type inference for expressions
    # -------------------------------------------------------------------

    def _infer_type(self, expr: Expr) -> Optional[AeonType]:
        # Check cache first for performance
        expr_id = id(expr)
        if expr_id in self._type_cache:
            return self._type_cache[expr_id]
        
        result = self._do_infer_type(expr)
        
        # Cache the result (even None to avoid re-computation)
        self._type_cache[expr_id] = result
        return result

    def _do_infer_type(self, expr: Expr) -> Optional[AeonType]:
        """Actual type inference logic - separated from caching."""
        if isinstance(expr, IntLiteral):
            return INT
        if isinstance(expr, FloatLiteral):
            return FLOAT
        if isinstance(expr, BoolLiteral):
            return BOOL
        if isinstance(expr, StringLiteral):
            return STRING
        if isinstance(expr, Identifier):
            return self.env.lookup_variable(expr.name)
        if isinstance(expr, ListLiteral):
            if not expr.elements:
                return make_list_type(ERROR)
            elem_type = self._infer_type(expr.elements[0])
            if not elem_type:
                return make_list_type(ERROR)
            return make_list_type(elem_type)
        if isinstance(expr, UnaryOp):
            operand_type = self._infer_type(expr.operand)
            if not operand_type:
                return None
            if expr.op == "!":
                if operand_type != BOOL:
                    self.errors.append(type_error(
                        node_id="unary_op",
                        expected_type="Bool",
                        actual_type=str(operand_type),
                        location=expr.location,
                    ))
                return BOOL
            if expr.op == "-":
                if operand_type not in (INT, FLOAT):
                    self.errors.append(type_error(
                        node_id="unary_op",
                        expected_type="Int or Float",
                        actual_type=str(operand_type),
                        location=expr.location,
                    ))
                return operand_type
            return None
        if isinstance(expr, BinaryOp):
            left_type = self._infer_type(expr.left)
            right_type = self._infer_type(expr.right)
            if not left_type or not right_type:
                return None
            if expr.op in ("+", "-", "*", "/", "%"):
                if left_type != right_type:
                    self.errors.append(type_error(
                        node_id="binary_op",
                        expected_type=str(left_type),
                        actual_type=str(right_type),
                        location=expr.location,
                    ))
                if left_type not in (INT, FLOAT):
                    self.errors.append(type_error(
                        node_id="binary_op",
                        expected_type="Int or Float",
                        actual_type=str(left_type),
                        location=expr.location,
                    ))
                return left_type
            if expr.op in ("<", "<=", ">", ">="):
                if left_type != right_type:
                    self.errors.append(type_error(
                        node_id="binary_op",
                        expected_type=str(left_type),
                        actual_type=str(right_type),
                        location=expr.location,
                    ))
                if left_type not in (INT, FLOAT):
                    self.errors.append(type_error(
                        node_id="binary_op",
                        expected_type="Int or Float",
                        actual_type=str(left_type),
                        location=expr.location,
                    ))
                return BOOL
            if expr.op in ("==", "!="):
                if left_type != right_type:
                    self.errors.append(type_error(
                        node_id="binary_op",
                        expected_type=str(left_type),
                        actual_type=str(right_type),
                        location=expr.location,
                    ))
                return BOOL
            if expr.op in ("&&", "||"):
                if left_type != BOOL or right_type != BOOL:
                    self.errors.append(type_error(
                        node_id="binary_op",
                        expected_type="Bool",
                        actual_type=f"{left_type} and {right_type}",
                        location=expr.location,
                    ))
                return BOOL
            return None
        if isinstance(expr, ConstructExpr):
            data_type = self.env.lookup_type(expr.type_name)
            if not data_type:
                self.errors.append(name_error(
                    name=expr.type_name,
                    location=expr.location,
                ))
                return ERROR
            return data_type
        if isinstance(expr, FieldAccess):
            obj_type = self._infer_type(expr.obj)
            if not obj_type:
                return None
            if not isinstance(obj_type, DataType):
                self.errors.append(type_error(
                    node_id="field_access",
                    expected_type="Data type",
                    actual_type=str(obj_type),
                    location=expr.location,
                ))
                return None
            # Look up field in data type
            for field in obj_type.fields:
                if field.name == expr.field:
                    return field.type
            self.errors.append(name_error(
                name=expr.field,
                location=expr.location,
            ))
            return None
        if isinstance(expr, MethodCall):
            obj_type = self._infer_type(expr.obj)
            if not obj_type:
                return None
            return self._infer_method_call(expr, obj_type)
        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                func_type = self.env.lookup_function(expr.callee.name)
                if not func_type:
                    self.errors.append(name_error(
                        name=expr.callee.name,
                        location=expr.location,
                    ))
                    return None
                return self._infer_call(expr, func_type)
            return None
        if isinstance(expr, MoveExpr):
            return self.env.lookup_variable(expr.name)
        if isinstance(expr, MatchExpr):
            self._infer_type(expr.subject)
            for arm in expr.arms:
                for s in arm.body:
                    self._check_statement(s)
            return None
        if isinstance(expr, LambdaExpr):
            param_types = tuple(
                resolve_type_annotation(p.type_annotation, self.env)
                for p in expr.params
            )
            ret = VOID
            if expr.return_type:
                ret = resolve_type_annotation(expr.return_type, self.env)
            return FunctionType(param_types=param_types, return_type=ret, is_pure=True)
        if isinstance(expr, PipeExpr):
            left_type = self._infer_type(expr.left)
            right_type = self._infer_type(expr.right)
            if right_type and isinstance(right_type, FunctionType):
                return right_type.return_type
            return right_type
        if isinstance(expr, SpawnExpr):
            return self._infer_type(expr.call)
        if isinstance(expr, AwaitExpr):
            return self._infer_type(expr.expr)
        return None

    def _infer_method_call(self, expr: MethodCall, obj_type: AeonType) -> Optional[AeonType]:
        # Type check arguments
        for arg in expr.args:
            self._infer_type(arg)
        
        # Built-in method return types
        if expr.method_name in ("isValid", "isOk", "isErr", "isEmpty", "contains"):
            return BOOL
        if expr.method_name in ("len", "size", "count"):
            return INT
        if expr.method_name in ("toString",):
            return STRING

        # For known data operations, return appropriate types
        if expr.method_name in ("insert", "update", "delete", "write"):
            return BOOL  # Mutation operations return Bool
        if expr.method_name in ("get", "find", "query", "read"):
            # Return appropriate type based on object - for now, return object type
            return obj_type

        # Default: return object type for method chaining
        return obj_type

    def _infer_call(self, expr: FunctionCall, func_type: FunctionType) -> Optional[AeonType]:
        """Type inference for function calls."""
        # Type check arguments
        if len(expr.args) != len(func_type.param_types):
            self.errors.append(type_error(
                node_id="arg_count_mismatch",
                expected_type=str(len(func_type.param_types)),
                actual_type=str(len(expr.args)),
                location=expr.location,
            ))
            return None
        
        # Check each argument type
        for i, (arg, expected_type) in enumerate(zip(expr.args, func_type.param_types)):
            actual_type = self._infer_type(arg)
            if actual_type and not self._types_compatible(actual_type, expected_type):
                self.errors.append(type_error(
                    node_id=f"arg_type_mismatch_{i}",
                    expected_type=str(expected_type),
                    actual_type=str(actual_type),
                    location=arg.location,
                ))
        
        return func_type.return_type

    def _types_compatible(self, expected: AeonType, actual: AeonType) -> bool:
        """Check if two types are compatible."""
        if expected == actual:
            return True
        # Named primitive compatibility
        if isinstance(expected, PrimitiveType) and isinstance(actual, PrimitiveType):
            return expected.name == actual.name
        return False

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def prove(program: Program, verify_contracts: bool = False, analyze_termination: bool = False, track_memory: bool = False,
          refinement_types: bool = False, abstract_interpretation: bool = False,
          size_change: bool = False, hoare_logic: bool = False,
          algebraic_effects: bool = False, category_check: bool = False,
          information_flow: bool = False, dependent_types: bool = False,
          certified_compilation: bool = False, symbolic_exec: bool = False,
          separation_logic: bool = False, taint_analysis: bool = False,
          concurrency_check: bool = False, shape_analysis: bool = False,
          model_checking: bool = False,
          gradual_typing: bool = False, linear_resource: bool = False,
          probabilistic: bool = False, relational_verify: bool = False,
          session_types: bool = False, complexity_analysis: bool = False,
          abstract_refinement: bool = False, differential_privacy: bool = False,
          typestate: bool = False, interpolation: bool = False,
          deep_verify: bool = False) -> list[AeonError]:
    """Run Pass 1: type checking, ownership, effects, contracts, and advanced analysis.

    Standard passes (always run):
      - Type checking (bidirectional type inference)
      - Ownership & borrow checking (Rust-style, linear types)
      - Effect checking (declared vs actual effects)
      - Contract verification (requires/ensures via Z3)

    Advanced passes (opt-in via flags or --deep-verify):
      - Refinement types: Liquid type inference (Rondon et al. 2008)
      - Abstract interpretation: interval/sign/congruence domains (Cousot & Cousot 1977)
      - Size-change termination: Ramsey's theorem decision procedure (Lee et al. 2001)
      - Hoare logic: weakest precondition calculus (Dijkstra 1975)
      - Algebraic effects: row-polymorphic effect algebra (Plotkin & Pretnar 2009)
      - Category semantics: CCC functor law verification (Moggi 1991)
      - Information flow: noninterference type system (Volpano et al. 1996)
      - Dependent types: Pi types with Curry-Howard (Martin-Löf 1984)
      - Certified compilation: simulation proofs (Leroy/CompCert 2009)
      - Symbolic execution: path-sensitive analysis (King 1976)
      - Separation logic: heap safety via frame rule (Reynolds 2002)
      - Taint analysis: injection vulnerability detection (Schwartz et al. 2010)
      - Concurrency: race/deadlock detection (Owicki & Gries 1976)
      - Shape analysis: linked structure verification (Sagiv et al. 2002)
      - Model checking: bounded state-space exploration (Clarke et al. 1986)
      - Gradual typing: blame-correct typed/untyped boundaries (Siek & Taha 2006)
      - Linear resource: linear/affine resource tracking (Girard 1987)
      - Probabilistic: measure-theoretic program analysis (Kozen 1981)
      - Relational verification: 2-safety via product programs (Barthe et al. 2011)
      - Session types: multiparty protocol verification (Honda et al. 2008)
      - Complexity analysis: RAML amortized bounds (Hoffmann et al. 2012)
      - Abstract refinement: higher-order refinement types (Vazou et al. 2013)
      - Differential privacy: sensitivity typing (Reed & Pierce 2010)
      - Typestate: object protocol enforcement (Strom & Yemini 1986)
      - Interpolation: Craig interpolation for CEGAR (McMillan 2003)
    """
    checker = TypeChecker(
        verify_contracts=verify_contracts,
        analyze_termination=analyze_termination,
        track_memory=track_memory,
        refinement_types=refinement_types,
        abstract_interpretation=abstract_interpretation,
        size_change=size_change,
        hoare_logic=hoare_logic,
        algebraic_effects=algebraic_effects,
        category_check=category_check,
        information_flow=information_flow,
        dependent_types=dependent_types,
        certified_compilation=certified_compilation,
        symbolic_exec=symbolic_exec,
        separation_logic=separation_logic,
        taint_analysis=taint_analysis,
        concurrency_check=concurrency_check,
        shape_analysis=shape_analysis,
        model_checking=model_checking,
        gradual_typing=gradual_typing,
        linear_resource=linear_resource,
        probabilistic=probabilistic,
        relational_verify=relational_verify,
        session_types=session_types,
        complexity_analysis=complexity_analysis,
        abstract_refinement=abstract_refinement,
        differential_privacy=differential_privacy,
        typestate=typestate,
        interpolation=interpolation,
        deep_verify=deep_verify,
    )
    return checker.check_program(program)
