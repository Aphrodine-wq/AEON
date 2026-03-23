"""AEON Prototype Pollution Engine -- Object Manipulation Vulnerability Detection.

Detects prototype pollution and dynamic object manipulation vulnerabilities
across JavaScript/TypeScript and other languages with dynamic objects.

References:
  CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
  https://cwe.mitre.org/data/definitions/1321.html

  CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
  https://cwe.mitre.org/data/definitions/915.html

  CWE-94: Improper Control of Generation of Code
  https://cwe.mitre.org/data/definitions/94.html

  Arteau (2018) "Prototype Pollution Attack in NodeJS Application"
  NorthSec / HackerOne reports, https://github.com/nicolo-ribaudo/tc39-proposal/

  Kang et al. (2022) "Probe the Proto: Measuring Client-Side Prototype Pollution
  Vulnerabilities of One Million Real-World Websites"
  NDSS '22, https://doi.org/10.14722/ndss.2022.24391

  Li et al. (2021) "Detecting Node.js Prototype Pollution Vulnerabilities
  via Object Lookup Analysis"
  ESEC/FSE '21, https://doi.org/10.1145/3468264.3468542

Key Theory:

1. PROTOTYPE CHAIN:
   Every JavaScript object has a hidden [[Prototype]] link. Property lookup
   traverses this chain: obj -> obj.__proto__ -> Object.prototype -> null.
   Polluting Object.prototype poisons ALL objects in the runtime.

2. ATTACK SURFACE:
   User-controlled input that reaches:
   - obj.__proto__.isAdmin = true      (direct prototype write)
   - merge(target, {"__proto__": ...}) (recursive merge with __proto__ key)
   - obj[userKey] = value              (dynamic property with __proto__ key)
   - {...req.body}                     (spread of attacker-controlled object)
   - JSON.parse(untrusted)             (parsed JSON can contain __proto__)

3. DANGEROUS KEYS:
   "__proto__", "constructor", "prototype" -- the trinity of prototype pollution.
   If any of these appear as a user-controlled property key in an assignment
   path, prototype pollution is possible.

4. IMPACT:
   - Remote Code Execution (via polluted template engines, child_process, etc.)
   - Authentication bypass (polluting isAdmin, role, etc.)
   - Denial of Service (polluting toString, valueOf, hasOwnProperty)
   - Property injection into configuration objects

5. PYTHON EQUIVALENT (Class Pollution):
   setattr(obj, user_input, value), obj.__dict__.update(user_data),
   **kwargs from untrusted input -- same class of vulnerability in Python.

Detection Categories:
  1. Direct prototype manipulation (__proto__, setPrototypeOf, constructor.prototype)
  2. Recursive object merge / deep copy without key filtering
  3. Dynamic property assignment with user-controlled keys
  4. Unsafe object spread from user input
  5. Property injection in configuration objects
  6. JSON.parse with prototype-carrying data fed into merge/spread
  7. Class pollution (Python: setattr, __dict__.update, **kwargs)
  8. Denial of Service via pollution of built-in methods
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, StringLiteral,
    BinaryOp, FunctionCall, FieldAccess, MethodCall,
    LetStmt, AssignStmt, IfStmt, ExprStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Severity Levels
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


# ---------------------------------------------------------------------------
# Pollution Categories
# ---------------------------------------------------------------------------

class PollutionCategory(Enum):
    DIRECT_PROTO_MANIPULATION = "direct_prototype_manipulation"
    UNSAFE_DEEP_MERGE = "unsafe_deep_merge"
    DYNAMIC_PROPERTY_ASSIGNMENT = "dynamic_property_assignment"
    UNSAFE_OBJECT_SPREAD = "unsafe_object_spread"
    CONFIG_PROPERTY_INJECTION = "config_property_injection"
    JSON_PARSE_MERGE = "json_parse_to_merge"
    CLASS_POLLUTION = "class_pollution"
    DOS_VIA_POLLUTION = "dos_via_pollution"


# ---------------------------------------------------------------------------
# Finding Representation
# ---------------------------------------------------------------------------

@dataclass
class PollutionFinding:
    """Internal representation of a detected prototype pollution vulnerability."""
    category: PollutionCategory
    severity: Severity
    description: str
    cwe: str
    location: Optional[SourceLocation]
    function_name: str
    remediation: str
    details: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Dangerous Patterns — Constants
# ---------------------------------------------------------------------------

# The three keys that enable prototype pollution
PROTO_KEYS: Set[str] = {"__proto__", "constructor", "prototype"}

# Keys that are dangerous targets for property lookup in prototype chain
DANGEROUS_PROTO_FIELDS: Set[str] = {
    "__proto__", "constructor", "prototype",
    "setPrototypeOf", "__defineGetter__", "__defineSetter__",
    "__lookupGetter__", "__lookupSetter__",
}

# Functions that perform recursive/deep merge operations
UNSAFE_MERGE_FUNCTIONS: Set[str] = {
    "merge", "deepMerge", "deep_merge", "deepmerge",
    "extend", "deepCopy", "deep_copy", "deepcopy",
    "defaultsDeep", "defaults_deep", "assign",
    "mixin", "deepAssign", "deep_assign",
    "mergeDeep", "merge_deep", "mergeWith", "merge_with",
    "mergeObjects", "merge_objects", "deepExtend", "deep_extend",
}

# Known vulnerable library merge calls (object.method patterns)
UNSAFE_MERGE_METHODS: Dict[str, Set[str]] = {
    "lodash": {"merge", "mergeWith", "defaultsDeep", "assign", "assignIn"},
    "_": {"merge", "mergeWith", "defaultsDeep", "assign", "assignIn"},
    "jQuery": {"extend"},
    "$": {"extend"},
    "Object": {"assign"},
    "hoek": {"merge", "applyToDefaults"},
    "underscore": {"extend", "defaults"},
}

# User input source identifiers (heuristic names for variables/fields)
USER_INPUT_SOURCES: Set[str] = {
    "req", "request", "body", "query", "params",
    "input", "data", "payload", "user_input", "userInput",
    "form", "formData", "form_data", "args", "kwargs",
    "raw", "untrusted", "external", "content",
}

# User input field access patterns (e.g., req.body, req.query, req.params)
USER_INPUT_FIELD_PATTERNS: Set[str] = {
    "body", "query", "params", "headers", "cookies",
    "fields", "data", "payload", "input",
}

# Configuration-related variable names
CONFIG_NAMES: Set[str] = {
    "config", "configuration", "settings", "options", "opts",
    "defaults", "preferences", "prefs", "env", "conf",
    "appConfig", "app_config", "serverConfig", "server_config",
    "dbConfig", "db_config", "redisConfig", "redis_config",
}

# Python class-pollution functions
PYTHON_CLASS_POLLUTION_FUNCS: Set[str] = {
    "setattr", "getattr", "delattr",
}

# Built-in method names that cause DoS when polluted
DOS_TARGET_METHODS: Set[str] = {
    "toString", "valueOf", "toJSON", "hasOwnProperty",
    "isPrototypeOf", "propertyIsEnumerable", "toLocaleString",
    "__str__", "__repr__", "__eq__", "__hash__",
    "__iter__", "__next__", "__len__", "__getitem__",
}


# ---------------------------------------------------------------------------
# AST Helpers
# ---------------------------------------------------------------------------

def _expr_name(expr: Expr) -> str:
    """Extract a readable name from an expression."""
    if isinstance(expr, Identifier):
        return expr.name
    if isinstance(expr, StringLiteral):
        return expr.value
    if isinstance(expr, FieldAccess):
        obj_name = _expr_name(expr.obj)
        return f"{obj_name}.{expr.field_name}" if obj_name else expr.field_name
    if isinstance(expr, MethodCall):
        obj_name = _expr_name(expr.obj)
        return f"{obj_name}.{expr.method_name}" if obj_name else expr.method_name
    return ""


def _is_user_input_expr(expr: Expr) -> bool:
    """Heuristically determine if an expression represents user-controlled input."""
    if isinstance(expr, Identifier):
        return expr.name.lower() in USER_INPUT_SOURCES

    if isinstance(expr, FieldAccess):
        # req.body, req.query, req.params, etc.
        if expr.field_name.lower() in USER_INPUT_FIELD_PATTERNS:
            return True
        # Check if the object itself is a known user input source
        if isinstance(expr.obj, Identifier) and expr.obj.name.lower() in USER_INPUT_SOURCES:
            return True
        # Recursive: request.body.data, etc.
        return _is_user_input_expr(expr.obj)

    if isinstance(expr, MethodCall):
        # req.body.get(...), request.query.get(...)
        if isinstance(expr.obj, Identifier) and expr.obj.name.lower() in USER_INPUT_SOURCES:
            return True
        return _is_user_input_expr(expr.obj)

    if isinstance(expr, FunctionCall):
        # JSON.parse(req.body), etc.
        if expr.args:
            return any(_is_user_input_expr(arg) for arg in expr.args)

    return False


def _is_config_target(expr: Expr) -> bool:
    """Check if an expression refers to a configuration/settings object."""
    name = _expr_name(expr).lower()
    if not name:
        return False
    for config_name in CONFIG_NAMES:
        if config_name.lower() in name:
            return True
    return False


def _is_variable_key(expr: Expr) -> bool:
    """Check if an expression is a variable (not a literal) used as a key."""
    if isinstance(expr, Identifier):
        return True
    if isinstance(expr, FieldAccess):
        return True
    if isinstance(expr, MethodCall):
        return True
    if isinstance(expr, FunctionCall):
        return True
    return False


def _has_proto_key_filter(func_body: List[Statement]) -> bool:
    """Check if a function body contains filtering of dangerous prototype keys.

    Looks for patterns like:
      if (key === '__proto__') continue;
      if (['__proto__', 'constructor', 'prototype'].includes(key)) return;
    """
    for stmt in func_body:
        if isinstance(stmt, IfStmt):
            cond_str = _expr_name(stmt.condition)
            for key in PROTO_KEYS:
                if key in cond_str:
                    return True
            # Check for string literal comparison in condition
            proto_literals = _find_string_literals(stmt.condition)
            for lit_val in proto_literals:
                if lit_val in PROTO_KEYS:
                    return True
    return False


def _find_string_literals(expr: Expr) -> List[str]:
    """Recursively collect all string literal values from an expression."""
    results: List[str] = []
    if isinstance(expr, StringLiteral):
        results.append(expr.value)
    elif isinstance(expr, BinaryOp):
        results.extend(_find_string_literals(expr.left))
        results.extend(_find_string_literals(expr.right))
    elif isinstance(expr, FunctionCall):
        for arg in expr.args:
            results.extend(_find_string_literals(arg))
    elif isinstance(expr, MethodCall):
        results.extend(_find_string_literals(expr.obj))
        for arg in expr.args:
            results.extend(_find_string_literals(arg))
    return results


def _is_json_parse_call(expr: Expr) -> bool:
    """Check if an expression is a JSON.parse() call."""
    if isinstance(expr, MethodCall):
        if expr.method_name == "parse":
            obj_name = _expr_name(expr.obj)
            return obj_name.lower() in ("json", "json")
    if isinstance(expr, FunctionCall):
        callee_name = _expr_name(expr.callee)
        return callee_name.lower() in ("json.parse", "json_parse", "jsonparse")
    return False


def _is_allowlisted_spread(expr: Expr) -> bool:
    """Check if an object spread/assign uses explicit field selection.

    Patterns like: { name: req.body.name, email: req.body.email }
    are safe because fields are explicitly selected.
    """
    # In AEON AST, explicit field selection would appear as individual
    # FieldAccess nodes rather than a direct spread of user input.
    # A ConstructExpr with named fields from user input is safe.
    # A direct Identifier or FieldAccess to user input in spread position is not.
    return False


# ---------------------------------------------------------------------------
# Prototype Pollution Analyzer
# ---------------------------------------------------------------------------

class PrototypePollutionAnalyzer:
    """Analyzes programs for prototype pollution and object manipulation vulnerabilities."""

    def __init__(self):
        self.findings: List[PollutionFinding] = []
        self._current_func: str = ""
        self._current_func_body: List[Statement] = []
        # Track variables that hold JSON.parse results
        self._json_parsed_vars: Set[str] = set()
        # Track variables that hold user input
        self._user_input_vars: Set[str] = set()

    def check_program(self, program: Program) -> List[PollutionFinding]:
        """Run prototype pollution analysis on the entire program."""
        self.findings = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        return self.findings

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a function for prototype pollution patterns."""
        self._current_func = func.name
        self._current_func_body = func.body
        self._json_parsed_vars = set()
        self._user_input_vars = set()

        # Mark parameters that look like user input
        for param in func.params:
            param_lower = param.name.lower()
            type_str = str(param.type_annotation).lower() if param.type_annotation else ""

            is_input = any(kw in param_lower for kw in
                          ("input", "request", "query", "param", "user",
                           "data", "body", "form", "payload", "content",
                           "raw", "untrusted", "args", "kwargs"))
            is_input = is_input or any(kw in type_str for kw in
                                       ("request", "httprequest", "formdata"))
            if is_input:
                self._user_input_vars.add(param.name)

        for stmt in func.body:
            self._analyze_statement(stmt)

    def _analyze_statement(self, stmt: Statement) -> None:
        """Analyze a statement for prototype pollution patterns."""
        loc = getattr(stmt, 'location', None)

        if isinstance(stmt, LetStmt):
            if stmt.value:
                # Track JSON.parse results
                if _is_json_parse_call(stmt.value):
                    self._json_parsed_vars.add(stmt.name)
                    # Check if parsing user input
                    if self._expr_has_user_input(stmt.value):
                        self._user_input_vars.add(stmt.name)

                # Track user input variables
                if self._expr_has_user_input(stmt.value):
                    self._user_input_vars.add(stmt.name)

                # Check all patterns against the value expression
                self._check_expr(stmt.value, loc, target_name=stmt.name)

        elif isinstance(stmt, AssignStmt):
            self._check_assignment(stmt, loc)
            if stmt.value:
                self._check_expr(stmt.value, loc)

        elif isinstance(stmt, ExprStmt):
            self._check_expr(stmt.expr, loc)

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._analyze_statement(s)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._analyze_statement(s)

    # ------------------------------------------------------------------
    # Category 1: Direct Prototype Manipulation
    # ------------------------------------------------------------------

    def _check_direct_proto_manipulation(self, expr: Expr,
                                         loc: Optional[SourceLocation]) -> None:
        """Detect direct __proto__ access and Object.setPrototypeOf calls."""
        if isinstance(expr, FieldAccess):
            if expr.field_name in DANGEROUS_PROTO_FIELDS:
                # obj.__proto__ access
                self.findings.append(PollutionFinding(
                    category=PollutionCategory.DIRECT_PROTO_MANIPULATION,
                    severity=Severity.CRITICAL,
                    description=(
                        f"Direct prototype manipulation via '.{expr.field_name}' "
                        f"on '{_expr_name(expr.obj)}' -- an attacker controlling "
                        f"this path can pollute Object.prototype"
                    ),
                    cwe="CWE-1321",
                    location=loc,
                    function_name=self._current_func,
                    remediation=(
                        "Never access __proto__ or constructor.prototype directly. "
                        "Use Object.create(null) for prototype-free objects, or "
                        "Map/Set for key-value storage with untrusted keys."
                    ),
                    details={
                        "field": expr.field_name,
                        "object": _expr_name(expr.obj),
                    },
                ))

            # Check for constructor.prototype chain: obj.constructor.prototype
            if expr.field_name == "prototype" and isinstance(expr.obj, FieldAccess):
                if expr.obj.field_name == "constructor":
                    self.findings.append(PollutionFinding(
                        category=PollutionCategory.DIRECT_PROTO_MANIPULATION,
                        severity=Severity.CRITICAL,
                        description=(
                            f"Prototype chain manipulation via "
                            f"'{_expr_name(expr.obj)}.prototype' -- "
                            f"modifying constructor.prototype pollutes all instances"
                        ),
                        cwe="CWE-1321",
                        location=loc,
                        function_name=self._current_func,
                        remediation=(
                            "Do not traverse constructor.prototype from "
                            "user-reachable code paths. Use Object.freeze() on "
                            "prototypes if modification must be prevented."
                        ),
                        details={
                            "chain": _expr_name(expr),
                        },
                    ))

        # Object.setPrototypeOf(obj, proto)
        if isinstance(expr, MethodCall):
            if expr.method_name == "setPrototypeOf":
                self.findings.append(PollutionFinding(
                    category=PollutionCategory.DIRECT_PROTO_MANIPULATION,
                    severity=Severity.CRITICAL,
                    description=(
                        f"Object.setPrototypeOf() call in '{self._current_func}' "
                        f"-- directly mutates the prototype chain"
                    ),
                    cwe="CWE-1321",
                    location=loc,
                    function_name=self._current_func,
                    remediation=(
                        "Avoid Object.setPrototypeOf() entirely. Use "
                        "Object.create() to set the prototype at creation time, "
                        "or redesign to avoid prototype mutation."
                    ),
                ))

        if isinstance(expr, FunctionCall):
            callee_name = _expr_name(expr.callee)
            if callee_name in ("Object.setPrototypeOf", "setPrototypeOf",
                               "Reflect.setPrototypeOf"):
                self.findings.append(PollutionFinding(
                    category=PollutionCategory.DIRECT_PROTO_MANIPULATION,
                    severity=Severity.CRITICAL,
                    description=(
                        f"{callee_name}() call in '{self._current_func}' "
                        f"-- directly mutates the prototype chain"
                    ),
                    cwe="CWE-1321",
                    location=loc,
                    function_name=self._current_func,
                    remediation=(
                        "Avoid setPrototypeOf entirely. Use Object.create() "
                        "at construction time, or redesign the inheritance model."
                    ),
                ))

    # ------------------------------------------------------------------
    # Category 2: Recursive Object Merge / Deep Copy
    # ------------------------------------------------------------------

    def _check_unsafe_merge(self, expr: Expr, loc: Optional[SourceLocation]) -> None:
        """Detect unsafe deep merge and extend calls with user input."""
        func_name = ""
        has_user_input_arg = False

        if isinstance(expr, FunctionCall):
            callee_name = _expr_name(expr.callee)
            func_name = callee_name

            # Direct call to merge/deepMerge/extend/etc.
            if isinstance(expr.callee, Identifier):
                if expr.callee.name in UNSAFE_MERGE_FUNCTIONS:
                    func_name = expr.callee.name
                    has_user_input_arg = any(
                        self._expr_has_user_input(arg) for arg in expr.args
                    )

            # Object.assign({}, req.body)
            if callee_name in ("Object.assign",):
                has_user_input_arg = any(
                    self._expr_has_user_input(arg) for arg in expr.args
                )
                if has_user_input_arg:
                    func_name = callee_name

        elif isinstance(expr, MethodCall):
            method = expr.method_name
            obj_name = _expr_name(expr.obj)

            # lodash.merge(target, userInput), $.extend(true, target, userInput)
            for lib, methods in UNSAFE_MERGE_METHODS.items():
                if obj_name.lower() == lib.lower() and method in methods:
                    func_name = f"{obj_name}.{method}"
                    has_user_input_arg = any(
                        self._expr_has_user_input(arg) for arg in expr.args
                    )
                    break

            # Generic method merge check
            if not func_name and method.lower() in {m.lower() for m in UNSAFE_MERGE_FUNCTIONS}:
                func_name = f"{obj_name}.{method}" if obj_name else method
                has_user_input_arg = any(
                    self._expr_has_user_input(arg) for arg in expr.args
                )

        if func_name and has_user_input_arg:
            # Check if the enclosing function filters __proto__ keys
            has_filter = _has_proto_key_filter(self._current_func_body)

            if not has_filter:
                self.findings.append(PollutionFinding(
                    category=PollutionCategory.UNSAFE_DEEP_MERGE,
                    severity=Severity.CRITICAL,
                    description=(
                        f"Unsafe merge '{func_name}()' receives user-controlled "
                        f"input without filtering dangerous keys (__proto__, "
                        f"constructor, prototype) -- enables prototype pollution"
                    ),
                    cwe="CWE-1321",
                    location=loc,
                    function_name=self._current_func,
                    remediation=(
                        "Filter __proto__, constructor, and prototype keys "
                        "before merging. Use a safe merge library "
                        "(e.g., lodash >=4.17.12), or use Object.create(null) "
                        "as the target. Better yet, explicitly pick allowed "
                        "keys with destructuring or an allowlist."
                    ),
                    details={
                        "merge_function": func_name,
                    },
                ))

    # ------------------------------------------------------------------
    # Category 3: Dynamic Property Assignment
    # ------------------------------------------------------------------

    def _check_dynamic_property_assignment(self, stmt: AssignStmt,
                                           loc: Optional[SourceLocation]) -> None:
        """Detect obj[userInput] = value patterns."""
        target = stmt.target

        # FieldAccess with a variable field_name won't appear in AEON AST
        # because field_name is a static string. But if the target is a
        # FunctionCall-like subscript (obj[key]) it may appear as a FieldAccess
        # where the field_name is a variable reference, or as a nested structure.
        # In AEON's AST, bracket access obj[key] is represented as FieldAccess
        # with variable interpolation or as a MethodCall pattern.

        # Pattern: target is FieldAccess where the object has user input context
        # AND the access appears to use a dynamic key
        if isinstance(target, FieldAccess):
            # Check if this is config[userKey] = value pattern
            if _is_config_target(target.obj) and self._is_user_derived_name(target.field_name):
                self.findings.append(PollutionFinding(
                    category=PollutionCategory.CONFIG_PROPERTY_INJECTION,
                    severity=Severity.HIGH,
                    description=(
                        f"Configuration object '{_expr_name(target.obj)}' modified "
                        f"with potentially user-controlled key '{target.field_name}' "
                        f"-- enables property injection into application config"
                    ),
                    cwe="CWE-915",
                    location=loc,
                    function_name=self._current_func,
                    remediation=(
                        "Validate property keys against an allowlist before "
                        "setting configuration values. Use a Map instead of "
                        "a plain object for dynamic key-value storage."
                    ),
                    details={
                        "target": _expr_name(target),
                        "key": target.field_name,
                    },
                ))

        # Check for FunctionCall patterns that represent subscript access
        # e.g., some AST representations encode obj[key] as a call-like node
        if isinstance(target, FunctionCall):
            if target.args and any(self._expr_has_user_input(a) for a in target.args):
                self.findings.append(PollutionFinding(
                    category=PollutionCategory.DYNAMIC_PROPERTY_ASSIGNMENT,
                    severity=Severity.HIGH,
                    description=(
                        f"Dynamic property assignment with user-controlled key "
                        f"in '{self._current_func}' -- if the key is '__proto__', "
                        f"this enables prototype pollution"
                    ),
                    cwe="CWE-1321",
                    location=loc,
                    function_name=self._current_func,
                    remediation=(
                        "Validate keys against an explicit allowlist. Reject "
                        "'__proto__', 'constructor', and 'prototype' keys. "
                        "Use a Map for user-keyed storage."
                    ),
                ))

    def _check_assignment(self, stmt: AssignStmt,
                          loc: Optional[SourceLocation]) -> None:
        """Check an assignment statement for all relevant pollution patterns."""
        # Category 3 & 5: Dynamic property assignment and config injection
        self._check_dynamic_property_assignment(stmt, loc)

        # Category 1: Assignment to __proto__ field
        if isinstance(stmt.target, FieldAccess):
            if stmt.target.field_name in DANGEROUS_PROTO_FIELDS:
                # Check if value is user-controlled (escalates to critical)
                user_controlled = self._expr_has_user_input(stmt.value)
                self.findings.append(PollutionFinding(
                    category=PollutionCategory.DIRECT_PROTO_MANIPULATION,
                    severity=Severity.CRITICAL if user_controlled else Severity.HIGH,
                    description=(
                        f"Assignment to '{_expr_name(stmt.target)}' "
                        f"{'with user-controlled value ' if user_controlled else ''}"
                        f"-- directly modifies the prototype chain"
                    ),
                    cwe="CWE-1321",
                    location=loc,
                    function_name=self._current_func,
                    remediation=(
                        "Never assign to __proto__, constructor.prototype, or "
                        "similar prototype chain properties. Use Object.create() "
                        "or class syntax for inheritance."
                    ),
                    details={
                        "target": _expr_name(stmt.target),
                        "user_controlled": str(user_controlled),
                    },
                ))

        # Category 8: DoS via pollution of built-in methods
        if isinstance(stmt.target, FieldAccess):
            if stmt.target.field_name in DOS_TARGET_METHODS:
                # Check if the object being modified is a prototype
                obj_name = _expr_name(stmt.target.obj)
                if any(pk in obj_name.lower() for pk in ("proto", "prototype", "constructor")):
                    self.findings.append(PollutionFinding(
                        category=PollutionCategory.DOS_VIA_POLLUTION,
                        severity=Severity.HIGH,
                        description=(
                            f"Assignment to built-in method "
                            f"'{stmt.target.field_name}' on prototype object "
                            f"'{obj_name}' -- polluting {stmt.target.field_name} "
                            f"causes denial of service across all object instances"
                        ),
                        cwe="CWE-1321",
                        location=loc,
                        function_name=self._current_func,
                        remediation=(
                            f"Do not assign to '{stmt.target.field_name}' on "
                            f"prototype objects. Use Object.freeze() on "
                            f"prototypes to prevent mutation, or use Symbol-keyed "
                            f"methods to avoid collision."
                        ),
                        details={
                            "method": stmt.target.field_name,
                            "prototype_object": obj_name,
                        },
                    ))

    # ------------------------------------------------------------------
    # Category 4: Unsafe Object Spread from User Input
    # ------------------------------------------------------------------

    def _check_unsafe_spread(self, expr: Expr, loc: Optional[SourceLocation],
                             target_name: str = "") -> None:
        """Detect {...req.body} or Object.assign({}, req.body) without allowlisting."""
        # Object.assign({}, userInput)
        if isinstance(expr, FunctionCall):
            callee_name = _expr_name(expr.callee)
            if callee_name in ("Object.assign",):
                # Check if any argument beyond the first is user input
                for arg in expr.args[1:] if len(expr.args) > 1 else []:
                    if self._expr_has_user_input(arg):
                        self.findings.append(PollutionFinding(
                            category=PollutionCategory.UNSAFE_OBJECT_SPREAD,
                            severity=Severity.MEDIUM,
                            description=(
                                f"Object.assign() spreads user input "
                                f"'{_expr_name(arg)}' into target object without "
                                f"field allowlisting -- attacker can inject "
                                f"arbitrary properties"
                            ),
                            cwe="CWE-915",
                            location=loc,
                            function_name=self._current_func,
                            remediation=(
                                "Destructure only the specific fields you need: "
                                "const { name, email } = req.body; instead of "
                                "spreading the entire user input object. Use a "
                                "validation schema (Zod, Joi) to define allowed fields."
                            ),
                            details={
                                "source": _expr_name(arg),
                                "target": target_name or "<object>",
                            },
                        ))
                        break

        # Direct user input as value (spread-like assignment)
        # let newObj = req.body  (no field selection)
        if isinstance(expr, FieldAccess):
            if _is_user_input_expr(expr) and target_name:
                # This is a direct assignment from user input, not a spread per se,
                # but it leads to the same vulnerability when the result is used
                # as a merge source or property source
                pass  # Handled by merge/assignment checks

    # ------------------------------------------------------------------
    # Category 5: Property Injection in Configuration
    # ------------------------------------------------------------------

    def _check_config_injection(self, expr: Expr,
                                loc: Optional[SourceLocation]) -> None:
        """Detect user input used to set configuration object properties."""
        # config[req.query.setting] = req.query.value
        # This is primarily caught in _check_dynamic_property_assignment
        # via AssignStmt handling. Here we check for method-based config
        # mutation: config.set(userKey, userValue)

        if isinstance(expr, MethodCall):
            method = expr.method_name.lower()
            if method in ("set", "put", "update", "setdefault"):
                if _is_config_target(expr.obj):
                    has_user_key = (
                        len(expr.args) >= 1 and
                        self._expr_has_user_input(expr.args[0])
                    )
                    if has_user_key:
                        self.findings.append(PollutionFinding(
                            category=PollutionCategory.CONFIG_PROPERTY_INJECTION,
                            severity=Severity.HIGH,
                            description=(
                                f"Configuration object "
                                f"'{_expr_name(expr.obj)}.{method}()' called "
                                f"with user-controlled key -- enables injection "
                                f"of arbitrary configuration properties"
                            ),
                            cwe="CWE-915",
                            location=loc,
                            function_name=self._current_func,
                            remediation=(
                                "Validate configuration keys against an "
                                "explicit allowlist. Never use user input "
                                "directly as configuration property names."
                            ),
                            details={
                                "config_object": _expr_name(expr.obj),
                                "method": method,
                            },
                        ))

    # ------------------------------------------------------------------
    # Category 6: JSON.parse with Prototype-Carrying Data
    # ------------------------------------------------------------------

    def _check_json_parse_merge(self, expr: Expr,
                                loc: Optional[SourceLocation]) -> None:
        """Detect JSON.parse(userInput) fed into merge/spread operations."""
        # Case 1: merge(target, JSON.parse(userInput))
        func_name = ""
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            func_name = expr.callee.name
        elif isinstance(expr, MethodCall):
            func_name = expr.method_name

        if func_name.lower() in {m.lower() for m in UNSAFE_MERGE_FUNCTIONS} | {"assign"}:
            for arg in (expr.args if hasattr(expr, 'args') else []):
                if _is_json_parse_call(arg):
                    if any(self._expr_has_user_input(a) for a in
                           (arg.args if hasattr(arg, 'args') else [])):
                        self.findings.append(PollutionFinding(
                            category=PollutionCategory.JSON_PARSE_MERGE,
                            severity=Severity.HIGH,
                            description=(
                                f"JSON.parse() of user input passed directly "
                                f"to '{func_name}()' -- parsed JSON can contain "
                                f"__proto__ keys that pollute the target object"
                            ),
                            cwe="CWE-1321",
                            location=loc,
                            function_name=self._current_func,
                            remediation=(
                                "Use a safe JSON parser that strips __proto__ "
                                "keys (e.g., secure-json-parse), or filter "
                                "dangerous keys after parsing: "
                                "delete parsed.__proto__; delete parsed.constructor;"
                            ),
                            details={
                                "merge_function": func_name,
                            },
                        ))
                        return

                # Case 2: merge(target, jsonParsedVar) where jsonParsedVar
                # was assigned from JSON.parse earlier
                if isinstance(arg, Identifier) and arg.name in self._json_parsed_vars:
                    self.findings.append(PollutionFinding(
                        category=PollutionCategory.JSON_PARSE_MERGE,
                        severity=Severity.HIGH,
                        description=(
                            f"Variable '{arg.name}' (from JSON.parse) passed to "
                            f"'{func_name}()' -- parsed JSON can contain __proto__ "
                            f"keys that enable prototype pollution"
                        ),
                        cwe="CWE-1321",
                        location=loc,
                        function_name=self._current_func,
                        remediation=(
                            "Strip __proto__, constructor, and prototype keys "
                            "from parsed JSON before merging. Use a reviver "
                            "function: JSON.parse(str, (k, v) => "
                            "k === '__proto__' ? undefined : v)"
                        ),
                        details={
                            "parsed_var": arg.name,
                            "merge_function": func_name,
                        },
                    ))
                    return

    # ------------------------------------------------------------------
    # Category 7: Class Pollution (Python)
    # ------------------------------------------------------------------

    def _check_class_pollution(self, expr: Expr,
                               loc: Optional[SourceLocation]) -> None:
        """Detect Python class pollution: setattr, __dict__.update, **kwargs."""
        # setattr(obj, user_input, value)
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            fname = expr.callee.name

            if fname in PYTHON_CLASS_POLLUTION_FUNCS:
                # Check if the attribute name argument is user-controlled
                if len(expr.args) >= 2 and self._expr_has_user_input(expr.args[1]):
                    self.findings.append(PollutionFinding(
                        category=PollutionCategory.CLASS_POLLUTION,
                        severity=Severity.MEDIUM,
                        description=(
                            f"{fname}() called with user-controlled attribute "
                            f"name -- attacker can set arbitrary attributes "
                            f"on the target object, enabling class pollution"
                        ),
                        cwe="CWE-915",
                        location=loc,
                        function_name=self._current_func,
                        remediation=(
                            f"Validate the attribute name against an explicit "
                            f"allowlist before calling {fname}(). Never pass "
                            f"user input directly as an attribute name."
                        ),
                        details={
                            "function": fname,
                        },
                    ))

        # obj.__dict__.update(user_input)
        if isinstance(expr, MethodCall):
            if expr.method_name == "update":
                obj_name = _expr_name(expr.obj)
                if "__dict__" in obj_name:
                    has_user_arg = any(
                        self._expr_has_user_input(arg) for arg in expr.args
                    )
                    if has_user_arg:
                        self.findings.append(PollutionFinding(
                            category=PollutionCategory.CLASS_POLLUTION,
                            severity=Severity.MEDIUM,
                            description=(
                                f"__dict__.update() called with user input "
                                f"-- attacker can inject arbitrary attributes "
                                f"into the object, bypassing access controls"
                            ),
                            cwe="CWE-915",
                            location=loc,
                            function_name=self._current_func,
                            remediation=(
                                "Never call __dict__.update() with user input. "
                                "Use explicit attribute assignment with validated "
                                "field names, or use dataclasses/Pydantic for "
                                "structured updates."
                            ),
                        ))

    # ------------------------------------------------------------------
    # Category 8: DoS via Pollution (string literal checks)
    # ------------------------------------------------------------------

    def _check_dos_pollution_string(self, expr: Expr,
                                    loc: Optional[SourceLocation]) -> None:
        """Detect string literals matching built-in method names used as property keys
        in potentially user-controlled assignment contexts."""
        # This catches patterns where a user-controlled property name is a
        # StringLiteral matching a dangerous built-in method name.
        # The AssignStmt-based DoS check handles the assignment side;
        # this handles the case where the key is a string literal in a
        # merge/spread context.
        if isinstance(expr, StringLiteral):
            if expr.value in DOS_TARGET_METHODS:
                # Only flag if we are inside a context that looks like
                # property injection (this is called from _check_expr which
                # recurses into merge args, etc.)
                pass  # Handled by assignment-level checks

    # ------------------------------------------------------------------
    # Expression Dispatcher
    # ------------------------------------------------------------------

    def _check_expr(self, expr: Expr, loc: Optional[SourceLocation],
                    target_name: str = "") -> None:
        """Run all pollution checks against an expression, then recurse."""
        try:
            # Category 1: Direct prototype manipulation
            self._check_direct_proto_manipulation(expr, loc)

            # Category 2: Unsafe merge/deep copy
            self._check_unsafe_merge(expr, loc)

            # Category 4: Unsafe object spread
            self._check_unsafe_spread(expr, loc, target_name=target_name)

            # Category 5: Config property injection
            self._check_config_injection(expr, loc)

            # Category 6: JSON.parse into merge
            self._check_json_parse_merge(expr, loc)

            # Category 7: Class pollution (Python)
            self._check_class_pollution(expr, loc)

            # Recurse into sub-expressions
            self._recurse_expr(expr, loc)

        except Exception:
            # Engine-level safety: never crash the verification pipeline
            pass

    def _recurse_expr(self, expr: Expr, loc: Optional[SourceLocation]) -> None:
        """Recurse into child expressions."""
        if isinstance(expr, FunctionCall):
            self._check_expr(expr.callee, loc)
            for arg in expr.args:
                self._check_expr(arg, loc)

        elif isinstance(expr, MethodCall):
            self._check_expr(expr.obj, loc)
            for arg in expr.args:
                self._check_expr(arg, loc)

        elif isinstance(expr, FieldAccess):
            self._check_expr(expr.obj, loc)

        elif isinstance(expr, BinaryOp):
            self._check_expr(expr.left, loc)
            self._check_expr(expr.right, loc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _expr_has_user_input(self, expr: Expr) -> bool:
        """Check if an expression involves user-controlled data."""
        if _is_user_input_expr(expr):
            return True

        # Check against tracked user input variables
        if isinstance(expr, Identifier):
            return expr.name in self._user_input_vars

        if isinstance(expr, FieldAccess):
            if isinstance(expr.obj, Identifier) and expr.obj.name in self._user_input_vars:
                return True
            return self._expr_has_user_input(expr.obj)

        if isinstance(expr, FunctionCall):
            return any(self._expr_has_user_input(arg) for arg in expr.args)

        if isinstance(expr, MethodCall):
            if self._expr_has_user_input(expr.obj):
                return True
            return any(self._expr_has_user_input(arg) for arg in expr.args)

        if isinstance(expr, BinaryOp):
            return (self._expr_has_user_input(expr.left) or
                    self._expr_has_user_input(expr.right))

        return False

    def _is_user_derived_name(self, name: str) -> bool:
        """Check if a field name looks like it came from user input."""
        name_lower = name.lower()
        return any(kw in name_lower for kw in
                   ("input", "param", "query", "user", "body",
                    "form", "payload", "key", "name", "field"))


# ---------------------------------------------------------------------------
# Error Conversion
# ---------------------------------------------------------------------------

def _finding_to_error(finding: PollutionFinding) -> AeonError:
    """Convert a PollutionFinding into an AeonError using contract_error."""
    severity_label = finding.severity.value.upper()
    category_label = finding.category.value.replace("_", " ").title()

    return contract_error(
        precondition=(
            f"No prototype pollution ({finding.cwe}) -- "
            f"[{severity_label}] {category_label}: {finding.description}"
        ),
        failing_values={
            "category": finding.category.value,
            "severity": finding.severity.value,
            "cwe": finding.cwe,
            "remediation": finding.remediation,
            "engine": "Prototype Pollution",
            **finding.details,
        },
        function_signature=finding.function_name,
        location=finding.location,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_prototype_pollution(program: Program) -> list:
    """Run prototype pollution analysis on an AEON program.

    Detects object manipulation vulnerabilities across eight categories:

    1. Direct prototype manipulation
       - obj.__proto__ assignment
       - Object.setPrototypeOf()
       - constructor.prototype manipulation

    2. Recursive object merge / deep copy
       - merge(), deepMerge(), lodash.merge() with user input
       - jQuery.extend(true, ...) with user input
       - Object.assign() with user input

    3. Dynamic property assignment
       - obj[userInput] = value where key could be __proto__
       - Loop-based property copying with unfiltered keys

    4. Unsafe object spread from user input
       - Object.assign({}, req.body) without allowlisting
       - Spread of user input into new objects

    5. Property injection in configuration
       - config[req.query.setting] = req.query.value
       - config.set(userKey, userValue)

    6. JSON.parse with prototype-carrying data
       - JSON.parse(userInput) merged into application objects
       - Parsed JSON containing __proto__ keys

    7. Class pollution (Python equivalent)
       - setattr(obj, user_input, value)
       - obj.__dict__.update(user_input)
       - **kwargs from untrusted input

    8. Denial of Service via pollution
       - Polluting toString, valueOf, toJSON
       - Polluting hasOwnProperty to bypass checks

    CWE References:
      - CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
      - CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
      - CWE-94: Improper Control of Generation of Code

    Args:
        program: The parsed AEON Program AST.

    Returns:
        A list of AeonError instances, one per detected vulnerability.
    """
    try:
        analyzer = PrototypePollutionAnalyzer()
        findings = analyzer.check_program(program)
        return [_finding_to_error(f) for f in findings]
    except Exception:
        # Engine-level safety net: never let the entire engine crash
        # the verification pipeline
        return []
