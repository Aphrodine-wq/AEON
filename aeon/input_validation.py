"""AEON Input Validation Engine -- Deep Input Validation Vulnerability Detection.

Detects input validation vulnerabilities that go beyond basic type checking.
These are structural patterns where user-supplied data is accepted, compared,
or processed without adequate validation, enabling a range of attacks from
buffer overflows to authentication bypass.

References:
  CWE-20: Improper Input Validation
  https://cwe.mitre.org/data/definitions/20.html

  CWE-843: Access of Resource Using Incompatible Type (Type Confusion)
  https://cwe.mitre.org/data/definitions/843.html

  CWE-176: Improper Handling of Unicode Encoding
  https://cwe.mitre.org/data/definitions/176.html

  CWE-185: Incorrect Regular Expression
  https://cwe.mitre.org/data/definitions/185.html

  CWE-626: Null Byte Interaction Error (Poison Null Byte)
  https://cwe.mitre.org/data/definitions/626.html

  CWE-235: Improper Handling of Extra Parameters
  https://cwe.mitre.org/data/definitions/235.html

  CWE-915: Improperly Controlled Modification of Dynamically-Determined
           Object Attributes ('Mass Assignment')
  https://cwe.mitre.org/data/definitions/915.html

  CWE-94: Improper Control of Generation of Code ('Code Injection')
  https://cwe.mitre.org/data/definitions/94.html

  CWE-190: Integer Overflow or Wraparound
  https://cwe.mitre.org/data/definitions/190.html

  OWASP Input Validation Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

  Davis et al. (2019) "Testing Regex Generalizability And Its Implications:
  A Large-Scale Many-Language Empirical Study"
  ASE '19, https://doi.org/10.1109/ASE.2019.00040

  Bui & Younan (2021) "Mass Assignment Vulnerabilities in Node.js
  Applications" IEEE S&P Workshops

Detection Categories:
  1.  Missing length limits (CWE-20)
  2.  Type coercion bypass (CWE-843)
  3.  Unicode normalization attacks (CWE-176)
  4.  Regex validation bypass (CWE-185)
  5.  Null byte injection (CWE-626)
  6.  HTTP parameter pollution (CWE-235)
  7.  Mass assignment via input (CWE-915)
  8.  JSON injection via concatenation (CWE-94)
  9.  Email validation bypass (CWE-20)
  10. Integer boundary issues (CWE-190)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, StringLiteral,
    BinaryOp, FunctionCall, FieldAccess, MethodCall,
    LetStmt, AssignStmt, IfStmt, ExprStmt, ForStmt, WhileStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Vulnerability Categories
# ---------------------------------------------------------------------------

class InputVulnCategory(Enum):
    MISSING_LENGTH_LIMIT = "missing_length_limit"
    TYPE_COERCION_BYPASS = "type_coercion_bypass"
    UNICODE_NORMALIZATION = "unicode_normalization"
    REGEX_BYPASS = "regex_validation_bypass"
    NULL_BYTE_INJECTION = "null_byte_injection"
    HTTP_PARAM_POLLUTION = "http_parameter_pollution"
    MASS_ASSIGNMENT = "mass_assignment"
    JSON_INJECTION = "json_injection"
    EMAIL_VALIDATION_BYPASS = "email_validation_bypass"
    INTEGER_BOUNDARY = "integer_boundary"


# CWE mapping
CWE_MAP: Dict[InputVulnCategory, str] = {
    InputVulnCategory.MISSING_LENGTH_LIMIT: "CWE-20",
    InputVulnCategory.TYPE_COERCION_BYPASS: "CWE-843",
    InputVulnCategory.UNICODE_NORMALIZATION: "CWE-176",
    InputVulnCategory.REGEX_BYPASS: "CWE-185",
    InputVulnCategory.NULL_BYTE_INJECTION: "CWE-626",
    InputVulnCategory.HTTP_PARAM_POLLUTION: "CWE-235",
    InputVulnCategory.MASS_ASSIGNMENT: "CWE-915",
    InputVulnCategory.JSON_INJECTION: "CWE-94",
    InputVulnCategory.EMAIL_VALIDATION_BYPASS: "CWE-20",
    InputVulnCategory.INTEGER_BOUNDARY: "CWE-190",
}

# OWASP category mapping
OWASP_MAP: Dict[InputVulnCategory, str] = {
    InputVulnCategory.MISSING_LENGTH_LIMIT: "A03:2021 Injection",
    InputVulnCategory.TYPE_COERCION_BYPASS: "A03:2021 Injection",
    InputVulnCategory.UNICODE_NORMALIZATION: "A07:2021 Identification and Authentication Failures",
    InputVulnCategory.REGEX_BYPASS: "A03:2021 Injection",
    InputVulnCategory.NULL_BYTE_INJECTION: "A03:2021 Injection",
    InputVulnCategory.HTTP_PARAM_POLLUTION: "A03:2021 Injection",
    InputVulnCategory.MASS_ASSIGNMENT: "A08:2021 Software and Data Integrity Failures",
    InputVulnCategory.JSON_INJECTION: "A03:2021 Injection",
    InputVulnCategory.EMAIL_VALIDATION_BYPASS: "A07:2021 Identification and Authentication Failures",
    InputVulnCategory.INTEGER_BOUNDARY: "A03:2021 Injection",
}

# Severity per category
SEVERITY_MAP: Dict[InputVulnCategory, str] = {
    InputVulnCategory.MISSING_LENGTH_LIMIT: "medium",
    InputVulnCategory.TYPE_COERCION_BYPASS: "high",
    InputVulnCategory.UNICODE_NORMALIZATION: "high",
    InputVulnCategory.REGEX_BYPASS: "medium",
    InputVulnCategory.NULL_BYTE_INJECTION: "high",
    InputVulnCategory.HTTP_PARAM_POLLUTION: "medium",
    InputVulnCategory.MASS_ASSIGNMENT: "critical",
    InputVulnCategory.JSON_INJECTION: "high",
    InputVulnCategory.EMAIL_VALIDATION_BYPASS: "medium",
    InputVulnCategory.INTEGER_BOUNDARY: "medium",
}

# Remediation guidance per category
REMEDIATION_MAP: Dict[InputVulnCategory, str] = {
    InputVulnCategory.MISSING_LENGTH_LIMIT: (
        "Enforce maximum length on all string inputs before processing. "
        "Use schema validation (Zod, Joi, Pydantic) with .max() constraints, "
        "or explicitly check .length / len() and reject oversized input. "
        "This prevents buffer-related attacks and resource exhaustion."
    ),
    InputVulnCategory.TYPE_COERCION_BYPASS: (
        "Use strict equality (=== / !==) instead of loose equality (== / !=) "
        "for all security-sensitive comparisons. Always pass the radix to "
        "parseInt (e.g., parseInt(value, 10)). Validate input types before "
        "comparison to prevent type confusion attacks."
    ),
    InputVulnCategory.UNICODE_NORMALIZATION: (
        "Normalize Unicode strings before comparison or lookup using "
        "NFC or NFKC normalization (.normalize('NFC') in JS, "
        "unicodedata.normalize('NFC', s) in Python). This prevents "
        "homoglyph attacks where Cyrillic or other lookalike characters "
        "bypass identity checks."
    ),
    InputVulnCategory.REGEX_BYPASS: (
        "Anchor all validation regex patterns with ^ and $ (or \\A and \\z) "
        "to ensure the entire input is matched, not just a substring. "
        "Without anchors, an attacker can bypass validation by prepending "
        "or appending malicious content."
    ),
    InputVulnCategory.NULL_BYTE_INJECTION: (
        "Strip or reject null bytes (\\x00, \\0) from all user input before "
        "using it in file paths, database queries, or system calls. Null "
        "bytes can truncate strings in C-based libraries, causing the "
        "application to process a different value than what was validated."
    ),
    InputVulnCategory.HTTP_PARAM_POLLUTION: (
        "Explicitly handle the case where a query parameter appears multiple "
        "times. Use req.query as an array-aware accessor and validate that "
        "the parameter is a string (not an array). Frameworks differ in how "
        "they handle duplicate params -- always normalize to a single value."
    ),
    InputVulnCategory.MASS_ASSIGNMENT: (
        "Never spread or assign the entire user input object to a model. "
        "Use an explicit allowlist of fields: destructure only the "
        "specific properties you need, or use a validation schema (Zod, "
        "Joi, Pydantic) that defines the exact shape and strips unknown "
        "fields. ORM-level protection (e.g., Django's .only(), Mongoose "
        "strict mode) also helps."
    ),
    InputVulnCategory.JSON_INJECTION: (
        "Never build JSON by string concatenation with user input. Always "
        "use JSON.stringify() (JS), json.dumps() (Python), or equivalent "
        "serializers that handle escaping. String interpolation into JSON "
        "allows an attacker to inject keys, break out of strings, or alter "
        "the JSON structure."
    ),
    InputVulnCategory.EMAIL_VALIDATION_BYPASS: (
        "Use a well-tested email validation library (e.g., validator.js, "
        "email-validator for Python) instead of a custom regex. If the email "
        "is used in SMTP context, check for header injection characters "
        "(newlines, carriage returns) that could inject additional headers."
    ),
    InputVulnCategory.INTEGER_BOUNDARY: (
        "Validate integer inputs against explicit min/max bounds before use. "
        "Check for NaN (Number.isNaN), Infinity, and negative values where "
        "they are not expected. For pagination, clamp page/offset/limit to "
        "reasonable ranges. For array indices, verify the index is within "
        "bounds. Use Math.min/Math.max or clamp utilities."
    ),
}


# ---------------------------------------------------------------------------
# Finding Representation
# ---------------------------------------------------------------------------

@dataclass
class InputValidationFinding:
    """Internal finding before conversion to AeonError."""
    category: InputVulnCategory
    description: str
    location: Optional[SourceLocation]
    function_name: str
    details: Dict[str, str] = field(default_factory=dict)
    severity_override: Optional[str] = None  # For frontend severity lowering


# ---------------------------------------------------------------------------
# Constants & Pattern Definitions
# ---------------------------------------------------------------------------

# User input sources (variable names and field access objects)
USER_INPUT_SOURCES: Set[str] = {
    "req", "request", "body", "query", "params",
    "input", "data", "payload", "user_input", "userInput",
    "form", "formData", "form_data", "args", "kwargs",
    "raw", "untrusted", "external", "content",
}

# User input field access patterns
USER_INPUT_FIELD_PATTERNS: Set[str] = {
    "body", "query", "params", "headers", "cookies",
    "fields", "data", "payload", "input",
}

# React / client-side UI patterns -- presence in a function body means
# the function is almost certainly a UI component, not a server endpoint.
REACT_UI_PATTERNS: Set[str] = {
    # React hooks
    "useState", "useEffect", "useCallback", "useMemo", "useRef",
    "useContext", "useReducer", "useNavigate", "useRouter", "useParams",
    "useSearchParams", "useForm", "useQuery", "useMutation",
    # State setters
    "setState", "dispatch",
    # Navigation
    "navigate", "router.push", "router.replace", "router.back",
    # UI feedback
    "toast", "toast.success", "toast.error", "alert",
    "setOpen", "setLoading", "setError", "setVisible", "setShow",
    "setSelected", "setActive", "setDisabled", "setEditing",
    # JSX / DOM
    "onClick", "onChange", "onSubmit", "onBlur", "onFocus",
    "onKeyDown", "onKeyUp", "onMouseEnter", "onMouseLeave",
    "className", "preventDefault", "stopPropagation",
    "e.target", "event.target", "ref.current",
}

# Length validation patterns -- if these appear near a user input variable,
# we consider the length validated
LENGTH_CHECK_PATTERNS: Set[str] = {
    "length", "maxlength", "maxLength", "max_length",
    "truncate", "slice", "substring", "substr", "limit",
    "MAX_LENGTH", "MAX_LEN", "maxLen",
}

# Schema validation methods that imply length constraints
SCHEMA_VALIDATORS: Set[str] = {
    "parse", "safeParse", "validate", "validateSync",
    "parseAsync", "safeParseAsync",
}

# Schema builder methods that accept max constraints
SCHEMA_MAX_METHODS: Set[str] = {
    "max", "maxLength", "max_length", "maxlength",
    "truncate", "limit",
}

# Security-sensitive comparison contexts
SECURITY_COMPARISON_CONTEXTS: Set[str] = {
    "password", "token", "secret", "key", "hash",
    "role", "admin", "isAdmin", "is_admin", "permission",
    "auth", "authenticated", "authorized", "session",
    "otp", "pin", "code", "verify", "check",
    "id", "userId", "user_id", "accountId", "account_id",
}

# Identity field names (for Unicode normalization checks)
IDENTITY_FIELDS: Set[str] = {
    "username", "user_name", "userName", "login", "loginName",
    "email", "emailAddress", "email_address",
    "name", "displayName", "display_name", "nickname",
    "handle", "slug", "alias",
}

# Mass assignment dangerous patterns
MASS_ASSIGNMENT_FUNCTIONS: Set[str] = {
    "create", "update", "updateOne", "updateMany",
    "findOneAndUpdate", "findAndModify",
    "insert", "insertOne", "insertMany",
    "upsert", "bulkCreate", "bulkUpdate",
    "save", "build", "new",
}

# ORM/model patterns (Elixir cast, Sequelize, Mongoose, etc.)
CAST_FUNCTIONS: Set[str] = {
    "cast", "changeset", "cast_assoc", "cast_embed",
}

# File/path operation functions (for null byte injection)
FILE_PATH_FUNCTIONS: Set[str] = {
    "readFile", "readFileSync", "writeFile", "writeFileSync",
    "open", "createReadStream", "createWriteStream",
    "readdir", "readdirSync", "stat", "statSync",
    "unlink", "unlinkSync", "rename", "renameSync",
    "access", "accessSync", "exists", "existsSync",
    "resolve", "join", "normalize", "basename", "dirname",
    "realpath", "realpathSync",
    # Python
    "Path", "os.path.join", "os.path.exists",
    "os.open", "os.remove", "os.rename",
    "shutil.copy", "shutil.move",
}

# SQL/query operations (for null byte injection)
QUERY_FUNCTIONS: Set[str] = {
    "query", "execute", "exec", "run",
    "prepare", "raw", "rawQuery",
    "where", "find", "findOne", "findAll",
    "select", "from", "filter",
}

# Email sending functions (for email validation bypass context)
EMAIL_SEND_FUNCTIONS: Set[str] = {
    "sendMail", "send_mail", "sendEmail", "send_email",
    "transport.sendMail", "transporter.sendMail",
    "smtp.send", "smtp.sendmail", "smtplib.sendmail",
    "mailer.send", "mail.send",
    "sendgrid.send", "mailgun.send", "ses.sendEmail",
}

# parseInt / Number conversion functions
INTEGER_PARSE_FUNCTIONS: Set[str] = {
    "parseInt", "parseFloat", "Number", "BigInt",
    "int", "float",  # Python
    "Integer.parseInt", "Integer.valueOf",  # Java
    "strconv.Atoi", "strconv.ParseInt",  # Go
    "String.to_integer", "String.to_float",  # Elixir
}

# JSON key-like patterns in string literals (for JSON injection detection)
_JSON_KEY_PATTERN = re.compile(r'["\']?\w+["\']?\s*:\s*["\']?')


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class InputValidationAnalyzer:
    """Detects deep input validation vulnerabilities through AST analysis.

    Analyzes function bodies for patterns where user input is accepted,
    compared, or processed without adequate validation. Goes beyond
    surface-level type checking to find structural validation gaps.
    """

    def __init__(self):
        self.findings: List[InputValidationFinding] = []
        self._user_vars: Set[str] = set()
        self._length_checked_vars: Set[str] = set()
        self._schema_validated_vars: Set[str] = set()
        self._type_checked_vars: Set[str] = set()
        self._null_byte_filtered_vars: Set[str] = set()
        self._normalized_vars: Set[str] = set()
        self._range_checked_vars: Set[str] = set()
        self._current_func: str = ""
        self._current_func_body: List[Statement] = []
        self._is_frontend: bool = False

    def check_program(self, program: Program) -> List[InputValidationFinding]:
        """Run all input validation checks across the program."""
        self.findings = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        return self.findings

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a single function for input validation issues."""
        self._current_func = func.name
        self._current_func_body = func.body
        self._user_vars = set()
        self._length_checked_vars = set()
        self._schema_validated_vars = set()
        self._type_checked_vars = set()
        self._null_byte_filtered_vars = set()
        self._normalized_vars = set()
        self._range_checked_vars = set()

        # Detect frontend context
        self._is_frontend = self._detect_frontend_context(func)

        # Identify user-input parameters
        for param in func.params:
            if self._is_user_input_param(param):
                self._user_vars.add(param.name)

        # First pass: collect validation facts (what is already validated)
        for stmt in func.body:
            self._collect_validation_facts(stmt)

        # Second pass: detect vulnerabilities
        for stmt in func.body:
            self._analyze_statement(stmt)

    def _detect_frontend_context(self, func: PureFunc | TaskFunc) -> bool:
        """Detect if a function is a React/frontend component."""
        body_names = self._collect_body_names(func.body)
        body_text = " ".join(body_names).lower()
        return any(pat.lower() in body_text for pat in REACT_UI_PATTERNS)

    def _collect_body_names(self, stmts: List[Statement]) -> List[str]:
        """Collect all identifier and field names from statements."""
        names: List[str] = []
        for stmt in stmts:
            self._collect_names_from_stmt(stmt, names)
        return names

    def _collect_names_from_stmt(self, stmt: Statement, names: List[str]) -> None:
        """Recursively collect names from a statement."""
        if isinstance(stmt, LetStmt):
            names.append(stmt.name)
            if stmt.value:
                self._collect_names_from_expr(stmt.value, names)
        elif isinstance(stmt, AssignStmt):
            self._collect_names_from_expr(stmt.target, names)
            self._collect_names_from_expr(stmt.value, names)
        elif isinstance(stmt, ExprStmt):
            self._collect_names_from_expr(stmt.expr, names)
        elif isinstance(stmt, IfStmt):
            self._collect_names_from_expr(stmt.condition, names)
            for s in stmt.then_body:
                self._collect_names_from_stmt(s, names)
            for s in stmt.else_body:
                self._collect_names_from_stmt(s, names)
        elif isinstance(stmt, (ForStmt, WhileStmt)):
            body = stmt.body
            for s in body:
                self._collect_names_from_stmt(s, names)

    def _collect_names_from_expr(self, expr: Expr, names: List[str]) -> None:
        """Recursively collect names from an expression."""
        if isinstance(expr, Identifier):
            names.append(expr.name)
        elif isinstance(expr, FieldAccess):
            names.append(expr.field_name)
            self._collect_names_from_expr(expr.obj, names)
        elif isinstance(expr, MethodCall):
            names.append(expr.method_name)
            self._collect_names_from_expr(expr.obj, names)
            for arg in expr.args:
                self._collect_names_from_expr(arg, names)
        elif isinstance(expr, FunctionCall):
            self._collect_names_from_expr(expr.callee, names)
            for arg in expr.args:
                self._collect_names_from_expr(arg, names)
        elif isinstance(expr, BinaryOp):
            self._collect_names_from_expr(expr.left, names)
            self._collect_names_from_expr(expr.right, names)

    def _is_user_input_param(self, param) -> bool:
        """Determine if a parameter likely carries user input."""
        name_lower = param.name.lower()
        type_str = str(param.type_annotation).lower() if param.type_annotation else ""

        if any(kw in name_lower for kw in
               ("input", "request", "query", "param", "user",
                "data", "body", "form", "payload", "content",
                "raw", "untrusted", "args", "kwargs")):
            return True
        if any(kw in type_str for kw in
               ("request", "httprequest", "formdata",
                "params", "body", "httpservletrequest",
                "servletrequest", "context", "ctx")):
            return True
        return False

    # ------------------------------------------------------------------
    # First Pass: Collect Validation Facts
    # ------------------------------------------------------------------

    def _collect_validation_facts(self, stmt: Statement) -> None:
        """Pre-scan the function body for validation patterns."""
        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._check_validation_in_expr(stmt.value, stmt.name)
                # Track taint propagation
                if self._expr_uses_user_var(stmt.value):
                    self._user_vars.add(stmt.name)

        elif isinstance(stmt, AssignStmt):
            if isinstance(stmt.target, Identifier):
                if self._expr_uses_user_var(stmt.value):
                    self._user_vars.add(stmt.target.name)
                self._check_validation_in_expr(stmt.value, stmt.target.name)

        elif isinstance(stmt, IfStmt):
            self._check_condition_validation(stmt.condition)
            for s in stmt.then_body:
                self._collect_validation_facts(s)
            for s in stmt.else_body:
                self._collect_validation_facts(s)

        elif isinstance(stmt, ExprStmt):
            self._check_validation_in_expr(stmt.expr, "")

        elif isinstance(stmt, (ForStmt, WhileStmt)):
            for s in stmt.body:
                self._collect_validation_facts(s)

    def _check_validation_in_expr(self, expr: Expr, target_var: str) -> None:
        """Check if an expression represents validation of user input."""
        # Schema validation: schema.parse(input) / schema.safeParse(input)
        if isinstance(expr, MethodCall):
            if expr.method_name in SCHEMA_VALIDATORS:
                for arg in expr.args:
                    var_name = self._identify_user_var(arg)
                    if var_name:
                        self._schema_validated_vars.add(var_name)
                if target_var:
                    self._schema_validated_vars.add(target_var)

            # Length limiting methods: input.slice(0, max), input.substring(0, max)
            if expr.method_name in ("slice", "substring", "substr", "truncate"):
                obj_var = self._identify_user_var(expr.obj)
                if obj_var:
                    self._length_checked_vars.add(obj_var)

            # Normalize calls: input.normalize('NFC')
            if expr.method_name == "normalize":
                obj_var = self._identify_user_var(expr.obj)
                if obj_var:
                    self._normalized_vars.add(obj_var)
                if target_var:
                    self._normalized_vars.add(target_var)

            # Null byte filtering: input.replace(/\0/g, '')
            if expr.method_name in ("replace", "replaceAll"):
                obj_var = self._identify_user_var(expr.obj)
                if obj_var and expr.args:
                    if isinstance(expr.args[0], StringLiteral):
                        if "\\0" in expr.args[0].value or "\\x00" in expr.args[0].value:
                            self._null_byte_filtered_vars.add(obj_var)

        # Function calls: parseInt(input, 10) with radix is OK for type check
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            fname = expr.callee.name
            if fname in ("parseInt", "parseFloat", "Number", "int", "float"):
                for arg in expr.args:
                    var_name = self._identify_user_var(arg)
                    if var_name:
                        self._type_checked_vars.add(var_name)

        # Recurse into sub-expressions
        if isinstance(expr, MethodCall):
            self._check_validation_in_expr(expr.obj, "")
            for arg in expr.args:
                self._check_validation_in_expr(arg, "")
        elif isinstance(expr, FunctionCall):
            for arg in expr.args:
                self._check_validation_in_expr(arg, "")
        elif isinstance(expr, BinaryOp):
            self._check_validation_in_expr(expr.left, "")
            self._check_validation_in_expr(expr.right, "")

    def _check_condition_validation(self, condition: Expr) -> None:
        """Detect validation patterns in if-conditions."""
        # Length checks: if (input.length > MAX) or if (input.length <= 255)
        if isinstance(condition, BinaryOp):
            if isinstance(condition.left, FieldAccess):
                if condition.left.field_name in ("length", "len", "size", "count"):
                    var_name = self._identify_user_var(condition.left.obj)
                    if var_name:
                        self._length_checked_vars.add(var_name)

            if isinstance(condition.right, FieldAccess):
                if condition.right.field_name in ("length", "len", "size", "count"):
                    var_name = self._identify_user_var(condition.right.obj)
                    if var_name:
                        self._length_checked_vars.add(var_name)

            # typeof checks: if (typeof x === 'string')
            if condition.op in ("===", "=="):
                left_name = _expr_name(condition.left)
                if "typeof" in left_name.lower():
                    # Extract the variable from the typeof expression
                    if isinstance(condition.left, FunctionCall):
                        for arg in condition.left.args:
                            var_name = self._identify_user_var(arg)
                            if var_name:
                                self._type_checked_vars.add(var_name)

            # Range checks: if (x >= 0 && x <= MAX) or if (x > 0)
            if condition.op in (">", ">=", "<", "<="):
                left_var = self._identify_user_var(condition.left)
                if left_var:
                    self._range_checked_vars.add(left_var)
                right_var = self._identify_user_var(condition.right)
                if right_var:
                    self._range_checked_vars.add(right_var)

            # Recurse into logical operators: && / ||
            if condition.op in ("&&", "||", "and", "or"):
                self._check_condition_validation(condition.left)
                self._check_condition_validation(condition.right)

        # Method call conditions: if (Number.isFinite(x))
        if isinstance(condition, MethodCall):
            if condition.method_name in ("isFinite", "isNaN", "isInteger",
                                         "isSafeInteger"):
                for arg in condition.args:
                    var_name = self._identify_user_var(arg)
                    if var_name:
                        self._range_checked_vars.add(var_name)

        if isinstance(condition, FunctionCall) and isinstance(condition.callee, Identifier):
            if condition.callee.name in ("isFinite", "isNaN"):
                for arg in condition.args:
                    var_name = self._identify_user_var(arg)
                    if var_name:
                        self._range_checked_vars.add(var_name)

    # ------------------------------------------------------------------
    # Second Pass: Detect Vulnerabilities
    # ------------------------------------------------------------------

    def _analyze_statement(self, stmt: Statement) -> None:
        """Analyze a statement for input validation vulnerabilities."""
        loc = getattr(stmt, 'location', None)

        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._check_all_patterns(stmt.value, loc, target_name=stmt.name)

        elif isinstance(stmt, AssignStmt):
            self._check_all_patterns(stmt.value, loc)
            # Mass assignment via assignment
            self._check_mass_assignment_assign(stmt, loc)

        elif isinstance(stmt, ExprStmt):
            self._check_all_patterns(stmt.expr, loc)

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._analyze_statement(s)
            for s in stmt.else_body:
                self._analyze_statement(s)

        elif isinstance(stmt, (ForStmt, WhileStmt)):
            for s in stmt.body:
                self._analyze_statement(s)

    def _check_all_patterns(self, expr: Expr, loc: Optional[SourceLocation],
                            target_name: str = "") -> None:
        """Run all input validation checks against an expression."""
        try:
            self._check_missing_length_limit(expr, loc, target_name)
            self._check_type_coercion(expr, loc)
            self._check_unicode_normalization(expr, loc)
            self._check_regex_bypass(expr, loc)
            self._check_null_byte_injection(expr, loc)
            self._check_http_param_pollution(expr, loc)
            self._check_mass_assignment(expr, loc, target_name)
            self._check_json_injection(expr, loc)
            self._check_email_validation(expr, loc)
            self._check_integer_boundary(expr, loc, target_name)

            # Recurse into sub-expressions
            self._recurse_expr(expr, loc)
        except Exception:
            # Engine-level safety: never crash the verification pipeline
            pass

    def _recurse_expr(self, expr: Expr, loc: Optional[SourceLocation]) -> None:
        """Recurse into child expressions."""
        if isinstance(expr, FunctionCall):
            for arg in expr.args:
                self._check_all_patterns(arg, loc)
        elif isinstance(expr, MethodCall):
            for arg in expr.args:
                self._check_all_patterns(arg, loc)
        elif isinstance(expr, BinaryOp):
            # Don't recurse BinaryOp for type coercion -- handled at top level
            pass

    # ------------------------------------------------------------------
    # 1. Missing Length Limits (CWE-20)
    # ------------------------------------------------------------------

    def _check_missing_length_limit(self, expr: Expr,
                                    loc: Optional[SourceLocation],
                                    target_name: str = "") -> None:
        """Detect string inputs accepted without max length validation."""
        # Skip if this is a frontend context
        if self._is_frontend:
            return

        # Look for user input field access used directly (req.body.field)
        if not self._is_user_input_access(expr):
            return

        var_name = self._identify_user_var(expr)
        if not var_name:
            return

        # Skip if already length-checked or schema-validated
        if var_name in self._length_checked_vars:
            return
        if var_name in self._schema_validated_vars:
            return

        # Check if there is a length check anywhere in the function body
        # for this variable or any of its parent objects
        if self._has_length_check_in_body(var_name):
            return

        # Only flag if the field name suggests a string value
        field_name = self._get_leaf_field(expr)
        if field_name and field_name.lower() in (
            "id", "page", "limit", "offset", "count", "size",
            "sort", "order", "skip", "take",
        ):
            return  # Likely numeric, not string

        self.findings.append(InputValidationFinding(
            category=InputVulnCategory.MISSING_LENGTH_LIMIT,
            description=(
                f"User input '{_expr_name(expr)}' is used without a maximum "
                f"length check. An attacker can submit arbitrarily long strings "
                f"to cause memory exhaustion, database overflow, or exploit "
                f"downstream systems that assume bounded input."
            ),
            location=loc,
            function_name=self._current_func,
            details={
                "input_field": _expr_name(expr),
                "variable": var_name,
            },
        ))

    def _has_length_check_in_body(self, var_name: str) -> bool:
        """Check if the function body contains a length check for the variable."""
        body_names = self._collect_body_names(self._current_func_body)
        body_text = " ".join(body_names).lower()
        var_lower = var_name.lower()

        # Check for length-related patterns near the variable name
        for pattern in LENGTH_CHECK_PATTERNS:
            if pattern.lower() in body_text and var_lower in body_text:
                return True

        return False

    # ------------------------------------------------------------------
    # 2. Type Coercion Bypass (CWE-843)
    # ------------------------------------------------------------------

    def _check_type_coercion(self, expr: Expr,
                             loc: Optional[SourceLocation]) -> None:
        """Detect loose type comparisons and parseInt without radix."""
        if self._is_frontend:
            return

        # Loose equality (== or !=) with user input in security context
        if isinstance(expr, BinaryOp) and expr.op in ("==", "!="):
            # Check if either side involves user input
            left_user = self._expr_uses_user_var(expr.left)
            right_user = self._expr_uses_user_var(expr.right)

            if not (left_user or right_user):
                return

            # Check if this is a security-sensitive comparison
            left_name = _expr_name(expr.left).lower()
            right_name = _expr_name(expr.right).lower()
            combined = left_name + " " + right_name

            is_security_context = any(
                ctx in combined for ctx in SECURITY_COMPARISON_CONTEXTS
            )

            if is_security_context:
                self.findings.append(InputValidationFinding(
                    category=InputVulnCategory.TYPE_COERCION_BYPASS,
                    description=(
                        f"Loose equality operator '{expr.op}' used in "
                        f"security-sensitive comparison involving user input. "
                        f"JavaScript's == performs type coercion, allowing "
                        f"attacks like [] == false, '0' == 0, null == undefined. "
                        f"An attacker can exploit type confusion to bypass "
                        f"authentication or authorization checks."
                    ),
                    location=loc,
                    function_name=self._current_func,
                    details={
                        "operator": expr.op,
                        "left": _expr_name(expr.left),
                        "right": _expr_name(expr.right),
                    },
                ))

        # parseInt without radix
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            if expr.callee.name == "parseInt":
                has_user_arg = any(self._expr_uses_user_var(a) for a in expr.args)
                if has_user_arg and len(expr.args) < 2:
                    self.findings.append(InputValidationFinding(
                        category=InputVulnCategory.TYPE_COERCION_BYPASS,
                        description=(
                            f"parseInt() called with user input but no radix "
                            f"parameter. Without an explicit radix, parseInt "
                            f"interprets leading '0x' as hex and leading '0' as "
                            f"octal (in older engines), enabling attackers to "
                            f"cause unexpected numeric values. Always use "
                            f"parseInt(value, 10)."
                        ),
                        location=loc,
                        function_name=self._current_func,
                        details={
                            "function": "parseInt",
                            "missing": "radix parameter",
                        },
                    ))

    # ------------------------------------------------------------------
    # 3. Unicode Normalization Attacks (CWE-176)
    # ------------------------------------------------------------------

    def _check_unicode_normalization(self, expr: Expr,
                                     loc: Optional[SourceLocation]) -> None:
        """Detect string comparisons on identity fields without normalization."""
        # Look for comparisons (=== or ==) involving identity fields
        if not isinstance(expr, BinaryOp):
            return
        if expr.op not in ("===", "==", "!==", "!="):
            return

        left_name = _expr_name(expr.left).lower()
        right_name = _expr_name(expr.right).lower()
        combined = left_name + " " + right_name

        # Check if this involves an identity field
        involves_identity = any(
            field in combined for field in IDENTITY_FIELDS
        )
        if not involves_identity:
            return

        # Check if either side is user input
        if not (self._expr_uses_user_var(expr.left) or
                self._expr_uses_user_var(expr.right)):
            return

        # Check if the compared variables have been normalized
        left_var = self._identify_user_var(expr.left)
        right_var = self._identify_user_var(expr.right)
        if left_var and left_var in self._normalized_vars:
            return
        if right_var and right_var in self._normalized_vars:
            return

        # Check if normalize appears in the function body at all for this context
        body_names = self._collect_body_names(self._current_func_body)
        body_text = " ".join(body_names).lower()
        if "normalize" in body_text:
            return  # Conservative: normalize is present somewhere

        severity = SEVERITY_MAP[InputVulnCategory.UNICODE_NORMALIZATION]
        if self._is_frontend:
            severity = "low"

        self.findings.append(InputValidationFinding(
            category=InputVulnCategory.UNICODE_NORMALIZATION,
            description=(
                f"Identity field comparison ({_expr_name(expr.left)} "
                f"{expr.op} {_expr_name(expr.right)}) without Unicode "
                f"normalization. An attacker can use Cyrillic or other "
                f"visually identical characters (homoglyphs) to register "
                f"a username that looks identical to an existing user, "
                f"bypassing uniqueness checks and enabling impersonation."
            ),
            location=loc,
            function_name=self._current_func,
            details={
                "comparison": f"{_expr_name(expr.left)} {expr.op} {_expr_name(expr.right)}",
                "field_type": "identity",
            },
            severity_override=severity,
        ))

    # ------------------------------------------------------------------
    # 4. Regex Validation Bypass (CWE-185)
    # ------------------------------------------------------------------

    def _check_regex_bypass(self, expr: Expr,
                            loc: Optional[SourceLocation]) -> None:
        """Detect validation regex patterns without proper anchoring."""
        # Look for RegExp construction or regex function calls
        func_name = ""
        regex_arg: Optional[StringLiteral] = None

        if isinstance(expr, FunctionCall):
            callee_name = _get_callable_name(expr)
            if callee_name and callee_name.lower() in (
                "regexp", "new regexp", "re.compile", "re.match",
                "re.search", "re.findall", "pattern.compile",
                "regexp.compile", "regexp.new",
            ):
                func_name = callee_name
                # Find the pattern argument (first string literal)
                for arg in expr.args:
                    if isinstance(arg, StringLiteral):
                        regex_arg = arg
                        break

        elif isinstance(expr, MethodCall):
            if expr.method_name.lower() in (
                "match", "test", "search", "exec",
                "replace", "replaceall", "split",
            ):
                # Check if the argument is a regex pattern string
                for arg in expr.args:
                    if isinstance(arg, StringLiteral):
                        regex_arg = arg
                        func_name = expr.method_name
                        break

        if not regex_arg or not func_name:
            return

        pattern = regex_arg.value
        if not pattern:
            return

        # Skip if already anchored
        has_start_anchor = pattern.startswith("^") or pattern.startswith("\\A")
        has_end_anchor = pattern.endswith("$") or pattern.endswith("\\z") or pattern.endswith("\\Z")

        if has_start_anchor and has_end_anchor:
            return

        # Skip trivially simple patterns that are likely not used for validation
        # (e.g., simple word matching, short patterns)
        if len(pattern) < 3:
            return

        # Only flag patterns that look like they are being used for input validation
        # (contain character classes, quantifiers, or alternation)
        is_validation_pattern = any(c in pattern for c in ("[", "+", "*", "{", "|", "\\d", "\\w"))
        if not is_validation_pattern:
            return

        # Determine which anchor is missing
        missing = []
        if not has_start_anchor:
            missing.append("start anchor (^ or \\A)")
        if not has_end_anchor:
            missing.append("end anchor ($ or \\z)")

        self.findings.append(InputValidationFinding(
            category=InputVulnCategory.REGEX_BYPASS,
            description=(
                f"Validation regex '/{pattern}/' used in '{func_name}' is "
                f"missing {' and '.join(missing)}. Without full anchoring, "
                f"an attacker can bypass validation by embedding a valid "
                f"substring within malicious input (e.g., 'valid<script>' "
                f"would match an unanchored alphanumeric pattern)."
            ),
            location=loc,
            function_name=self._current_func,
            details={
                "pattern": pattern[:80],
                "function": func_name,
                "missing_anchors": ", ".join(missing),
            },
        ))

    # ------------------------------------------------------------------
    # 5. Null Byte Injection (CWE-626)
    # ------------------------------------------------------------------

    def _check_null_byte_injection(self, expr: Expr,
                                   loc: Optional[SourceLocation]) -> None:
        """Detect file/path/query operations with user input lacking null byte filtering."""
        if self._is_frontend:
            return

        func_name = _get_callable_name(expr)
        if not func_name:
            return

        # Check if this is a file, path, or query operation
        func_base = func_name.split(".")[-1] if "." in func_name else func_name
        is_sensitive_op = (
            func_base in FILE_PATH_FUNCTIONS or
            func_base in QUERY_FUNCTIONS or
            func_name in FILE_PATH_FUNCTIONS or
            func_name in QUERY_FUNCTIONS
        )

        if not is_sensitive_op:
            return

        # Check if any argument contains user-derived data
        args = _get_call_args(expr)
        for arg in args:
            if self._expr_uses_user_var(arg):
                user_var = self._identify_user_var(arg)
                if not user_var:
                    continue

                # Skip if null bytes have been filtered
                if user_var in self._null_byte_filtered_vars:
                    continue

                # Check if the function body has null byte filtering
                body_names = self._collect_body_names(self._current_func_body)
                body_text = " ".join(body_names).lower()
                if any(p in body_text for p in ("\\x00", "\\0", "null_byte", "nullbyte")):
                    continue

                self.findings.append(InputValidationFinding(
                    category=InputVulnCategory.NULL_BYTE_INJECTION,
                    description=(
                        f"User input '{user_var}' is passed to '{func_name}' "
                        f"without null byte filtering. In C-based runtimes and "
                        f"libraries, a null byte (\\x00) truncates the string, "
                        f"causing the system to operate on a different value "
                        f"than what was validated. For example, 'image.png\\x00.exe' "
                        f"may pass an extension check but execute as .exe."
                    ),
                    location=loc,
                    function_name=self._current_func,
                    details={
                        "user_input": user_var,
                        "sink": func_name,
                    },
                ))
                return  # One finding per call site

    # ------------------------------------------------------------------
    # 6. HTTP Parameter Pollution (CWE-235)
    # ------------------------------------------------------------------

    def _check_http_param_pollution(self, expr: Expr,
                                    loc: Optional[SourceLocation]) -> None:
        """Detect req.query.param access without array handling."""
        if self._is_frontend:
            return

        # Look for req.query.param patterns
        if not isinstance(expr, FieldAccess):
            return

        # Pattern: req.query.someParam
        if not isinstance(expr.obj, FieldAccess):
            return

        inner = expr.obj
        if inner.field_name != "query":
            return

        # Check if the root object is a request-like variable
        if isinstance(inner.obj, Identifier):
            if inner.obj.name.lower() not in ("req", "request", "ctx"):
                return
        else:
            return

        param_name = expr.field_name

        # Check if the function body handles array parameters
        body_names = self._collect_body_names(self._current_func_body)
        body_text = " ".join(body_names).lower()

        has_array_handling = any(p in body_text for p in (
            "array.isarray", "isarray", "typeof",
            "tostring", "string(", "firstordefault",
            "[0]", "flat", "flatten",
        ))

        if has_array_handling:
            return

        self.findings.append(InputValidationFinding(
            category=InputVulnCategory.HTTP_PARAM_POLLUTION,
            description=(
                f"Query parameter '{param_name}' accessed via "
                f"'{_expr_name(expr)}' without handling duplicate parameters. "
                f"When a URL contains '?{param_name}=a&{param_name}=b', "
                f"Express returns an array ['a', 'b'] instead of a string. "
                f"This can cause type errors, bypass validation, or lead to "
                f"unexpected behavior when the code assumes a string."
            ),
            location=loc,
            function_name=self._current_func,
            details={
                "parameter": param_name,
                "access_pattern": _expr_name(expr),
            },
        ))

    # ------------------------------------------------------------------
    # 7. Mass Assignment via Input (CWE-915)
    # ------------------------------------------------------------------

    def _check_mass_assignment(self, expr: Expr,
                               loc: Optional[SourceLocation],
                               target_name: str = "") -> None:
        """Detect object spread or direct assignment from user input without allowlisting."""
        if self._is_frontend:
            return

        # Pattern 1: Object.assign(model, req.body)
        if isinstance(expr, FunctionCall):
            callee_name = _get_callable_name(expr)
            if callee_name in ("Object.assign",):
                # Check if any argument beyond the first is user input
                for arg in expr.args[1:] if len(expr.args) > 1 else []:
                    if self._expr_uses_user_var(arg):
                        self.findings.append(InputValidationFinding(
                            category=InputVulnCategory.MASS_ASSIGNMENT,
                            description=(
                                f"Object.assign() merges user input "
                                f"'{_expr_name(arg)}' into target object "
                                f"without field allowlisting. An attacker can "
                                f"inject fields like 'role', 'isAdmin', "
                                f"'verified', or 'balance' to escalate "
                                f"privileges or manipulate data."
                            ),
                            location=loc,
                            function_name=self._current_func,
                            details={
                                "function": callee_name,
                                "user_input": _expr_name(arg),
                            },
                        ))
                        return

        # Pattern 2: Model.create(req.body) / Model.update(req.body)
        if isinstance(expr, MethodCall):
            method_lower = expr.method_name.lower()
            if method_lower in {m.lower() for m in MASS_ASSIGNMENT_FUNCTIONS}:
                for arg in expr.args:
                    if self._expr_uses_user_var(arg):
                        obj_name = _expr_name(expr.obj)
                        self.findings.append(InputValidationFinding(
                            category=InputVulnCategory.MASS_ASSIGNMENT,
                            description=(
                                f"'{obj_name}.{expr.method_name}()' receives "
                                f"unfiltered user input '{_expr_name(arg)}'. "
                                f"Without an explicit allowlist of permitted "
                                f"fields, an attacker can modify protected "
                                f"fields (e.g., role, permissions, price) by "
                                f"adding extra properties to the request body."
                            ),
                            location=loc,
                            function_name=self._current_func,
                            details={
                                "method": f"{obj_name}.{expr.method_name}",
                                "user_input": _expr_name(arg),
                            },
                        ))
                        return

            # Pattern 3: Elixir cast(params, fields) with overly broad field list
            if expr.method_name in CAST_FUNCTIONS:
                for arg in expr.args:
                    if self._expr_uses_user_var(arg):
                        obj_name = _expr_name(expr.obj)
                        self.findings.append(InputValidationFinding(
                            category=InputVulnCategory.MASS_ASSIGNMENT,
                            description=(
                                f"'{obj_name}.{expr.method_name}()' receives "
                                f"user input '{_expr_name(arg)}'. Verify that "
                                f"the permitted fields list does not include "
                                f"sensitive fields (role, permissions, verified)."
                            ),
                            location=loc,
                            function_name=self._current_func,
                            details={
                                "method": f"{obj_name}.{expr.method_name}",
                                "user_input": _expr_name(arg),
                            },
                        ))
                        return

        # Pattern 4: FunctionCall where callee is cast/changeset
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            if expr.callee.name in CAST_FUNCTIONS:
                for arg in expr.args:
                    if self._expr_uses_user_var(arg):
                        self.findings.append(InputValidationFinding(
                            category=InputVulnCategory.MASS_ASSIGNMENT,
                            description=(
                                f"'{expr.callee.name}()' receives user input "
                                f"'{_expr_name(arg)}'. Ensure the permitted "
                                f"fields list does not include sensitive or "
                                f"privileged attributes."
                            ),
                            location=loc,
                            function_name=self._current_func,
                            details={
                                "function": expr.callee.name,
                                "user_input": _expr_name(arg),
                            },
                        ))
                        return

    def _check_mass_assignment_assign(self, stmt: AssignStmt,
                                      loc: Optional[SourceLocation]) -> None:
        """Detect direct spread assignment: model = {...req.body}."""
        if self._is_frontend:
            return

        # Check if the value is a direct user input reference being
        # assigned to what looks like a model/entity
        if not self._expr_uses_user_var(stmt.value):
            return

        target_name = _expr_name(stmt.target).lower()
        if not target_name:
            return

        # Only flag if the target looks like a model/entity
        model_keywords = (
            "model", "entity", "record", "user", "account",
            "profile", "item", "product", "order", "payment",
            "document", "doc", "row", "entry",
        )
        is_model = any(kw in target_name for kw in model_keywords)

        if is_model:
            user_var = self._identify_user_var(stmt.value)
            self.findings.append(InputValidationFinding(
                category=InputVulnCategory.MASS_ASSIGNMENT,
                description=(
                    f"Direct assignment of user input '{_expr_name(stmt.value)}' "
                    f"to model '{_expr_name(stmt.target)}' without field "
                    f"allowlisting. An attacker can inject arbitrary fields "
                    f"to escalate privileges or modify protected data."
                ),
                location=loc,
                function_name=self._current_func,
                details={
                    "target": _expr_name(stmt.target),
                    "user_input": user_var or _expr_name(stmt.value),
                },
            ))

    # ------------------------------------------------------------------
    # 8. JSON Injection (CWE-94)
    # ------------------------------------------------------------------

    def _check_json_injection(self, expr: Expr,
                              loc: Optional[SourceLocation]) -> None:
        """Detect JSON strings built by concatenation with user input."""
        if not isinstance(expr, BinaryOp):
            return
        if expr.op not in ("+", "++", "~", "..", "<>"):
            return

        # Check if the concatenation involves a JSON-like string literal
        # AND user input
        has_json_fragment = self._has_json_key_literal(expr)
        has_user_input = self._expr_uses_user_var(expr)

        if not (has_json_fragment and has_user_input):
            return

        user_var = self._identify_user_var(expr)

        self.findings.append(InputValidationFinding(
            category=InputVulnCategory.JSON_INJECTION,
            description=(
                f"JSON string built by concatenation with user input "
                f"'{user_var or '<user_input>'}'. An attacker can inject "
                f"additional JSON keys, break out of string values, or "
                f"alter the JSON structure. Use JSON.stringify() or "
                f"equivalent serializers that properly escape values."
            ),
            location=loc,
            function_name=self._current_func,
            details={
                "user_input": user_var or "<user_input>",
                "pattern": "string concatenation into JSON",
            },
        ))

    def _has_json_key_literal(self, expr: Expr) -> bool:
        """Check if an expression tree contains a JSON key-like string literal."""
        if isinstance(expr, StringLiteral):
            # Look for patterns like: '{"key":' or '"key":"' or 'key":'
            return bool(_JSON_KEY_PATTERN.search(expr.value))

        if isinstance(expr, BinaryOp):
            return (self._has_json_key_literal(expr.left) or
                    self._has_json_key_literal(expr.right))

        return False

    # ------------------------------------------------------------------
    # 9. Email Validation Bypass (CWE-20)
    # ------------------------------------------------------------------

    def _check_email_validation(self, expr: Expr,
                                loc: Optional[SourceLocation]) -> None:
        """Detect email used in SMTP context with only regex or no validation."""
        if self._is_frontend:
            return

        func_name = _get_callable_name(expr)
        if not func_name:
            return

        # Check if this is an email sending function
        func_base = func_name.split(".")[-1] if "." in func_name else func_name
        is_email_func = (
            func_name in EMAIL_SEND_FUNCTIONS or
            func_base in {f.split(".")[-1] for f in EMAIL_SEND_FUNCTIONS}
        )

        if not is_email_func:
            return

        # Check if any argument contains user-derived data
        args = _get_call_args(expr)
        for arg in args:
            if self._expr_uses_user_var(arg):
                user_var = self._identify_user_var(arg)
                if not user_var:
                    continue

                # Check if the function body has library-based email validation
                body_names = self._collect_body_names(self._current_func_body)
                body_text = " ".join(body_names).lower()

                has_library_validation = any(p in body_text for p in (
                    "validator.isemail", "isemail", "email_validator",
                    "validate_email", "emailvalidator",
                    "zod", "parse", "safeparse",
                    "joi", "yup",
                ))

                if has_library_validation:
                    return

                # Check for header injection filtering
                has_header_protection = any(p in body_text for p in (
                    "\\r", "\\n", "crlf", "newline", "header",
                    "replace", "sanitize",
                ))

                if has_header_protection:
                    return

                self.findings.append(InputValidationFinding(
                    category=InputVulnCategory.EMAIL_VALIDATION_BYPASS,
                    description=(
                        f"User input '{user_var}' is used in email sending "
                        f"function '{func_name}' without library-based "
                        f"validation. Regex-only email validation is prone to "
                        f"bypass. An attacker can inject SMTP headers via "
                        f"newline characters (e.g., 'user@evil.com\\r\\n"
                        f"Bcc: victim@target.com') to send emails to "
                        f"arbitrary recipients."
                    ),
                    location=loc,
                    function_name=self._current_func,
                    details={
                        "user_input": user_var,
                        "email_function": func_name,
                    },
                ))
                return

    # ------------------------------------------------------------------
    # 10. Integer Boundary Issues (CWE-190)
    # ------------------------------------------------------------------

    def _check_integer_boundary(self, expr: Expr,
                                loc: Optional[SourceLocation],
                                target_name: str = "") -> None:
        """Detect user-supplied integers used without range checking."""
        if self._is_frontend:
            return

        # Look for parseInt/Number calls on user input
        if not isinstance(expr, FunctionCall):
            return

        callee_name = ""
        if isinstance(expr.callee, Identifier):
            callee_name = expr.callee.name
        elif isinstance(expr.callee, FieldAccess):
            callee_name = _expr_name(expr.callee)

        if callee_name not in INTEGER_PARSE_FUNCTIONS:
            return

        # Check if any argument is user-derived
        has_user_arg = any(self._expr_uses_user_var(a) for a in expr.args)
        if not has_user_arg:
            return

        user_var = None
        for arg in expr.args:
            user_var = self._identify_user_var(arg)
            if user_var:
                break

        if not user_var:
            return

        # Check if the result is range-checked
        result_var = target_name or user_var
        if result_var in self._range_checked_vars:
            return

        # Check if the function body has any range validation
        body_names = self._collect_body_names(self._current_func_body)
        body_text = " ".join(body_names).lower()

        # Look for range-checking patterns near the variable
        result_lower = result_var.lower()
        has_range_check = any(p in body_text for p in (
            "math.min", "math.max", "clamp",
            "min(", "max(", "isnan", "isfinite",
            "number.issafeinteger", "number.isfinite",
            "number.isnan", "isinteger",
        ))

        if has_range_check:
            return

        # Determine what kind of integer use this is
        context = "general"
        if result_lower in ("page", "offset", "skip", "limit", "take", "size",
                            "perpage", "per_page", "pagesize", "page_size"):
            context = "pagination"
        elif result_lower in ("index", "idx", "i", "pos", "position"):
            context = "array_index"
        elif result_lower in ("id", "userid", "user_id", "accountid",
                              "account_id", "orderid", "order_id"):
            context = "identifier"
        elif result_lower in ("amount", "quantity", "qty", "count", "price",
                              "total", "balance"):
            context = "numeric_value"

        context_detail = ""
        if context == "pagination":
            context_detail = (
                " For pagination parameters, an attacker can submit "
                "negative values (causing errors), extremely large values "
                "(causing resource exhaustion), or NaN (causing undefined "
                "behavior)."
            )
        elif context == "array_index":
            context_detail = (
                " For array indices, an out-of-bounds value can cause "
                "crashes, information disclosure, or unexpected behavior."
            )
        elif context == "identifier":
            context_detail = (
                " For identifiers, negative or zero values may bypass "
                "authorization checks or reference unintended records."
            )
        elif context == "numeric_value":
            context_detail = (
                " For numeric business values, negative or extremely large "
                "numbers can cause financial manipulation or integer overflow."
            )

        self.findings.append(InputValidationFinding(
            category=InputVulnCategory.INTEGER_BOUNDARY,
            description=(
                f"{callee_name}() converts user input '{user_var}' to a "
                f"number without min/max range validation. The result "
                f"'{result_var}' is used without bounds checking.{context_detail}"
            ),
            location=loc,
            function_name=self._current_func,
            details={
                "function": callee_name,
                "user_input": user_var,
                "result_variable": result_var,
                "usage_context": context,
            },
        ))

    # ------------------------------------------------------------------
    # Utility Methods
    # ------------------------------------------------------------------

    def _is_user_input_access(self, expr: Expr) -> bool:
        """Check if an expression is a direct user input field access."""
        if isinstance(expr, Identifier):
            return expr.name.lower() in USER_INPUT_SOURCES

        if isinstance(expr, FieldAccess):
            if expr.field_name.lower() in USER_INPUT_FIELD_PATTERNS:
                return True
            if isinstance(expr.obj, Identifier):
                if expr.obj.name.lower() in USER_INPUT_SOURCES:
                    return True
            return self._is_user_input_access(expr.obj)

        return False

    def _expr_uses_user_var(self, expr: Expr) -> bool:
        """Check whether an expression references any user-input variable."""
        if isinstance(expr, Identifier):
            return expr.name in self._user_vars

        if isinstance(expr, FieldAccess):
            if isinstance(expr.obj, Identifier):
                if expr.obj.name.lower() in USER_INPUT_SOURCES:
                    return True
                return expr.obj.name in self._user_vars
            if expr.field_name.lower() in USER_INPUT_FIELD_PATTERNS:
                return True
            return self._expr_uses_user_var(expr.obj)

        if isinstance(expr, BinaryOp):
            return (self._expr_uses_user_var(expr.left) or
                    self._expr_uses_user_var(expr.right))

        if isinstance(expr, FunctionCall):
            return any(self._expr_uses_user_var(a) for a in expr.args)

        if isinstance(expr, MethodCall):
            return (self._expr_uses_user_var(expr.obj) or
                    any(self._expr_uses_user_var(a) for a in expr.args))

        return False

    def _identify_user_var(self, expr: Expr) -> Optional[str]:
        """Find the specific user-input variable name within an expression."""
        if isinstance(expr, Identifier):
            if expr.name in self._user_vars or expr.name.lower() in USER_INPUT_SOURCES:
                return expr.name

        if isinstance(expr, FieldAccess):
            obj_name = _expr_name(expr)
            if obj_name:
                return obj_name
            return self._identify_user_var(expr.obj)

        if isinstance(expr, BinaryOp):
            left = self._identify_user_var(expr.left)
            if left:
                return left
            return self._identify_user_var(expr.right)

        if isinstance(expr, FunctionCall):
            for arg in expr.args:
                name = self._identify_user_var(arg)
                if name:
                    return name

        if isinstance(expr, MethodCall):
            obj_name = self._identify_user_var(expr.obj)
            if obj_name:
                return obj_name
            for arg in expr.args:
                name = self._identify_user_var(arg)
                if name:
                    return name

        return None

    def _get_leaf_field(self, expr: Expr) -> Optional[str]:
        """Get the terminal field name from a field access chain."""
        if isinstance(expr, FieldAccess):
            return expr.field_name
        if isinstance(expr, Identifier):
            return expr.name
        return None


# ---------------------------------------------------------------------------
# Module-Level Helpers
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
    if isinstance(expr, FunctionCall):
        return _expr_name(expr.callee)
    return ""


def _get_callable_name(expr: Expr) -> Optional[str]:
    """Extract the callable name from a function/method call expression."""
    if isinstance(expr, FunctionCall):
        if isinstance(expr.callee, Identifier):
            return expr.callee.name
        if isinstance(expr.callee, FieldAccess):
            obj_name = _expr_name(expr.callee.obj)
            if obj_name:
                return f"{obj_name}.{expr.callee.field_name}"
            return expr.callee.field_name
    elif isinstance(expr, MethodCall):
        obj_name = _expr_name(expr.obj)
        if obj_name:
            return f"{obj_name}.{expr.method_name}"
        return expr.method_name
    return None


def _get_call_args(expr: Expr) -> List[Expr]:
    """Extract arguments from a function/method call."""
    if isinstance(expr, (FunctionCall, MethodCall)):
        return expr.args
    return []


# ---------------------------------------------------------------------------
# Error Conversion
# ---------------------------------------------------------------------------

def _finding_to_error(finding: InputValidationFinding) -> AeonError:
    """Convert an InputValidationFinding into an AeonError."""
    cwe = CWE_MAP[finding.category]
    owasp = OWASP_MAP[finding.category]
    severity = finding.severity_override or SEVERITY_MAP[finding.category]
    remediation = REMEDIATION_MAP[finding.category]
    vuln_name = finding.category.value.replace("_", " ").title()

    return contract_error(
        precondition=(
            f"Input validation: {vuln_name} ({cwe}) -- "
            f"[{severity.upper()}] {finding.description}"
        ),
        failing_values={
            "engine": "Input Validation",
            "vulnerability": finding.category.value,
            "cwe": cwe,
            "owasp": owasp,
            "severity": severity,
            "remediation": remediation,
            **finding.details,
        },
        function_signature=finding.function_name,
        location=finding.location,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_input_validation(program: Program) -> list:
    """Run deep input validation analysis on an AEON program.

    Detects structural input validation vulnerabilities across ten categories:

    1.  Missing length limits (CWE-20)
        String inputs accepted without max length validation.
        Pattern: req.body.field used without .length check, .maxLength,
        max_length, truncate, or schema validation with max.

    2.  Type coercion bypass (CWE-843)
        Loose type comparison allowing type confusion.
        Pattern: == instead of === in security-sensitive comparisons.
        parseInt without radix parameter.

    3.  Unicode normalization attacks (CWE-176)
        String comparison without Unicode normalization.
        Pattern: username/email comparison or lookup without
        .normalize('NFC') or .normalize('NFKC').

    4.  Regex validation bypass (CWE-185)
        Anchored regex without ^ and $ (or \\A and \\z).
        Pattern: new RegExp(pattern) or /pattern/ used for validation
        without anchors.

    5.  Null byte injection (CWE-626)
        String operations that don't strip null bytes.
        Pattern: filename, path, or query operations with user input
        without null byte filtering.

    6.  HTTP parameter pollution (CWE-235)
        Accepting duplicate parameter names without handling.
        Pattern: req.query.param where param could appear multiple times.

    7.  Mass assignment via input (CWE-915)
        Object spread or direct assignment from user input without
        allowlisting.
        Pattern: Object.assign(model, req.body), {...req.body},
        Model.create(req.body), struct |> cast(params, fields).

    8.  JSON injection (CWE-94)
        Building JSON strings by concatenation with user input.
        Pattern: string concatenation containing "key": with user
        variable interpolation.

    9.  Email validation bypass (CWE-20)
        Email validation that accepts header injection characters.
        Pattern: email used in SMTP/sendmail context with only regex
        validation (no library validator).

    10. Integer boundary issues (CWE-190)
        User-supplied integers used without range checking.
        Pattern: parseInt(req.body.page) or Number(input) without
        min/max bounds.

    Frontend-aware: Functions containing React patterns (useState, onClick,
    etc.) have findings suppressed or severity lowered for checks that
    only matter server-side.

    Each finding includes CWE, OWASP category, severity, and remediation.

    Args:
        program: The parsed AEON Program AST.

    Returns:
        A list of AeonError instances, one per detected vulnerability.
    """
    try:
        analyzer = InputValidationAnalyzer()
        findings = analyzer.check_program(program)

        # Deduplicate: same category + function + detail key = one finding
        seen: Set[Tuple[str, str, str]] = set()
        errors: List[AeonError] = []

        for f in findings:
            detail_key = f.details.get("input_field",
                         f.details.get("user_input",
                         f.details.get("pattern",
                         f.details.get("parameter", ""))))
            key = (f.category.value, f.function_name, detail_key)
            if key in seen:
                continue
            seen.add(key)
            errors.append(_finding_to_error(f))

        return errors
    except Exception:
        # Engine-level safety net: never let the entire engine crash
        # the verification pipeline
        return []
