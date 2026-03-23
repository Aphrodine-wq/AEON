"""AEON Supply Chain Security Engine — Dependency & Code Provenance Analysis.

Implements supply chain attack surface detection based on:
  Ohm, M. et al. (2020) "Backstabber's Knife Collection: A Review of Open
  Source Software Supply Chain Attacks"
  DIMVA '20, https://doi.org/10.1007/978-3-030-52683-2_2

  Ladisa, P. et al. (2023) "A Taxonomy of Attacks on Open-Source Software
  Supply Chains"
  IEEE S&P '23, https://doi.org/10.1109/SP46215.2023.10179304

  Zahan, N. et al. (2022) "Weak Links in Authentication Chains: A Large-scale
  Analysis of Key Signing Vulnerabilities in Package Managers"
  USENIX Security '22

  Gu, T. et al. (2017) "BadNets: Identifying Vulnerabilities in the Machine
  Learning Model Supply Chain"
  NeurIPS ML & Security Workshop '17

Key Theory:

1. DYNAMIC DEPENDENCY LOADING (CWE-829):
   Importing modules via runtime-computed strings defeats static analysis
   and allows attackers to inject arbitrary code paths.
   Pattern: require(variable), importlib.import_module(user_input),
   __import__(expr), eval("require(...)")

2. INSECURE PACKAGE INSTALLATION (CWE-829):
   Installing packages at runtime via subprocess or os.system bypasses
   lockfile integrity and version pinning.
   Pattern: subprocess.call(["pip","install",...]), os.system("npm install")

3. TYPOSQUATTING (CWE-1357):
   Packages with names almost identical to popular libraries, differing
   by character transposition, omission, or addition. Ladisa et al. (2023)
   documented 17K+ typosquatting packages across PyPI and npm.

4. DEPENDENCY CONFUSION (CWE-427):
   Internal package names that collide with public registry names. An
   attacker publishes a higher-version public package that shadows the
   internal one. Birsan (2021) demonstrated this at Apple, Microsoft, PayPal.

5. UNSAFE DESERIALIZATION (CWE-502):
   Deserializing untrusted data with pickle, yaml.load (no SafeLoader),
   Marshal.load, ObjectInputStream, or PHP unserialize() grants full RCE
   if the data contains crafted class instantiation gadgets.

6. CODE EXECUTION FROM URLS (CWE-494):
   Fetching remote code and executing it (eval(fetch(url)), exec(requests.get().text),
   curl|bash) provides zero integrity verification and allows MITM injection.

7. POSTINSTALL SCRIPT RISKS (CWE-829):
   Network access or filesystem writes at module top level (outside function
   bodies) execute during import and can exfiltrate secrets or install backdoors.

8. MISSING SUBRESOURCE INTEGRITY (CWE-494):
   Loading scripts from CDNs or external URLs without integrity hashes
   allows CDN compromise to inject malicious code silently.

Detects patterns visible in source code AST — NOT lockfile scanning
(that is a separate tool). Focuses on risky dependency usage patterns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto
from difflib import SequenceMatcher

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, StringLiteral,
    BinaryOp, FunctionCall, FieldAccess, MethodCall,
    LetStmt, AssignStmt, IfStmt, ExprStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Severity Classification
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


# ---------------------------------------------------------------------------
# CWE References
# ---------------------------------------------------------------------------

CWE_829 = "CWE-829: Inclusion of Functionality from Untrusted Control Sphere"
CWE_494 = "CWE-494: Download of Code Without Integrity Check"
CWE_502 = "CWE-502: Deserialization of Untrusted Data"
CWE_427 = "CWE-427: Uncontrolled Search Path Element"
CWE_1357 = "CWE-1357: Reliance on Uncontrolled Component"


# ---------------------------------------------------------------------------
# Category Definitions
# ---------------------------------------------------------------------------

class FindingCategory(Enum):
    DYNAMIC_DEPENDENCY = "dynamic_dependency_loading"
    INSECURE_INSTALL = "insecure_package_installation"
    TYPOSQUATTING = "typosquatting_risk"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    REMOTE_CODE_EXEC = "code_execution_from_url"
    POSTINSTALL_RISK = "postinstall_script_risk"
    MISSING_INTEGRITY = "missing_subresource_integrity"


CATEGORY_CWE: Dict[FindingCategory, str] = {
    FindingCategory.DYNAMIC_DEPENDENCY: CWE_829,
    FindingCategory.INSECURE_INSTALL: CWE_829,
    FindingCategory.TYPOSQUATTING: CWE_1357,
    FindingCategory.DEPENDENCY_CONFUSION: CWE_427,
    FindingCategory.UNSAFE_DESERIALIZATION: CWE_502,
    FindingCategory.REMOTE_CODE_EXEC: CWE_494,
    FindingCategory.POSTINSTALL_RISK: CWE_829,
    FindingCategory.MISSING_INTEGRITY: CWE_494,
}

CATEGORY_SEVERITY: Dict[FindingCategory, Severity] = {
    FindingCategory.DYNAMIC_DEPENDENCY: Severity.HIGH,
    FindingCategory.INSECURE_INSTALL: Severity.HIGH,
    FindingCategory.TYPOSQUATTING: Severity.MEDIUM,
    FindingCategory.DEPENDENCY_CONFUSION: Severity.MEDIUM,
    FindingCategory.UNSAFE_DESERIALIZATION: Severity.CRITICAL,
    FindingCategory.REMOTE_CODE_EXEC: Severity.CRITICAL,
    FindingCategory.POSTINSTALL_RISK: Severity.HIGH,
    FindingCategory.MISSING_INTEGRITY: Severity.MEDIUM,
}


# ---------------------------------------------------------------------------
# Known Package Names (for typosquatting detection)
# ---------------------------------------------------------------------------

POPULAR_PACKAGES: Set[str] = {
    # Python
    "requests", "flask", "django", "numpy", "pandas", "scipy",
    "colorama", "setuptools", "pip", "boto3", "cryptography",
    "pyyaml", "pillow", "beautifulsoup4", "sqlalchemy", "celery",
    "paramiko", "pycryptodome", "jinja2", "pygments", "httpx",
    "aiohttp", "fastapi", "uvicorn", "gunicorn", "psycopg2",
    "pytest", "black", "mypy", "ruff", "twine", "wheel",
    # Node / npm
    "express", "react", "lodash", "axios", "moment", "chalk",
    "commander", "webpack", "babel", "eslint", "prettier",
    "typescript", "next", "vue", "angular", "jquery",
    "underscore", "async", "debug", "minimist", "yargs",
    "cross-env", "dotenv", "uuid", "colors", "node-fetch",
    "socket.io", "puppeteer", "nodemon", "mocha", "jest",
    # Ruby
    "rails", "sinatra", "nokogiri", "puma", "devise", "rspec",
    # Go
    "gin", "echo", "fiber", "cobra", "viper",
}

# Known typosquat mappings: misspelling -> real package
KNOWN_TYPOSQUATS: Dict[str, str] = {
    "requets": "requests",
    "reqeusts": "requests",
    "request": "requests",
    "requsts": "requests",
    "reequests": "requests",
    "colorsama": "colorama",
    "colorma": "colorama",
    "colourama": "colorama",
    "colrama": "colorama",
    "numppy": "numpy",
    "numpiy": "numpy",
    "pandsa": "pandas",
    "panadas": "pandas",
    "djnago": "django",
    "dajngo": "django",
    "flaask": "flask",
    "flaskk": "flask",
    "beauitfulsoup4": "beautifulsoup4",
    "beautifulsoup": "beautifulsoup4",
    "cyptography": "cryptography",
    "crytpography": "cryptography",
    "crpytography": "cryptography",
    "set-up-tools": "setuptools",
    "setuptool": "setuptools",
    "urllib": "urllib3",
    "python-dateutil": "python-dateutil",
    "jinja": "jinja2",
    "pyyml": "pyyaml",
    "pyyalm": "pyyaml",
    "expres": "express",
    "expresss": "express",
    "lodsah": "lodash",
    "lodahs": "lodash",
    "axois": "axios",
    "axio": "axios",
    "momnet": "moment",
    "monment": "moment",
    "chalke": "chalk",
    "chlak": "chalk",
    "crossenv": "cross-env",
    "cross_env": "cross-env",
    "coss-env": "cross-env",
    "node-fecth": "node-fetch",
    "nodefetch": "node-fetch",
    "socket-io": "socket.io",
    "soket.io": "socket.io",
    "eeslint": "eslint",
    "eslintt": "eslint",
    "typscript": "typescript",
    "tyepscript": "typescript",
    "wepack": "webpack",
    "webpck": "webpack",
}


# ---------------------------------------------------------------------------
# Dynamic Import Functions
# ---------------------------------------------------------------------------

DYNAMIC_IMPORT_FUNCTIONS: Set[str] = {
    "require", "__import__", "import_module",
    "importlib.import_module", "load_module", "reload",
    "imp.load_source", "imp.load_module",
}

# ---------------------------------------------------------------------------
# Code Execution Functions
# ---------------------------------------------------------------------------

EXEC_FUNCTIONS: Set[str] = {
    "eval", "exec", "execfile", "compile",
    "Function",  # new Function(code)
}

# ---------------------------------------------------------------------------
# HTTP Fetch Functions
# ---------------------------------------------------------------------------

HTTP_FETCH_FUNCTIONS: Set[str] = {
    "fetch", "get", "post", "put", "delete", "patch",
    "urlopen", "urlretrieve", "request",
}

HTTP_FETCH_METHODS: Set[str] = {
    "get", "post", "put", "delete", "patch", "fetch",
    "urlopen", "urlretrieve", "request", "download",
    "read", "text", "json", "content",
}

# ---------------------------------------------------------------------------
# Package Manager Commands
# ---------------------------------------------------------------------------

PACKAGE_MANAGER_COMMANDS: Set[str] = {
    "pip install", "pip3 install",
    "npm install", "npm i ",
    "yarn add", "pnpm add",
    "gem install", "cargo install",
    "go get", "go install",
    "composer require",
    "apt install", "apt-get install",
    "brew install",
}

# ---------------------------------------------------------------------------
# Unsafe Deserialization Functions
# ---------------------------------------------------------------------------

# (function_or_method_name, requires_safe_arg_to_be_ok)
UNSAFE_DESER_FUNCTIONS: Dict[str, Optional[str]] = {
    # Python pickle — always unsafe with untrusted data
    "pickle.loads": None,
    "pickle.load": None,
    "pickle.Unpickler": None,
    "cPickle.loads": None,
    "cPickle.load": None,
    "_pickle.loads": None,
    # Python yaml — safe only with SafeLoader
    "yaml.load": "Loader",
    "yaml.unsafe_load": None,
    "yaml.full_load": None,
    # Python shelve — uses pickle internally
    "shelve.open": None,
    # Python marshal
    "marshal.loads": None,
    "marshal.load": None,
    # Ruby
    "Marshal.load": None,
    "Marshal.restore": None,
    # PHP
    "unserialize": None,
    # Java
    "ObjectInputStream": None,
    "readObject": None,
    # .NET
    "BinaryFormatter.Deserialize": None,
    "XmlSerializer.Deserialize": None,
    # Node.js
    "node-serialize.unserialize": None,
    "serialize-javascript": None,
}

UNSAFE_DESER_METHODS: Set[str] = {
    "loads", "load", "Unpickler", "unsafe_load", "full_load",
    "unserialize", "readObject", "Deserialize", "restore",
}

# ---------------------------------------------------------------------------
# Network/Filesystem Operations (for postinstall detection)
# ---------------------------------------------------------------------------

NETWORK_FUNCTIONS: Set[str] = {
    "fetch", "urlopen", "urlretrieve", "request",
    "get", "post", "connect", "socket", "send", "recv",
    "http.get", "http.request", "https.get", "https.request",
    "XMLHttpRequest", "WebSocket",
}

NETWORK_METHODS: Set[str] = {
    "get", "post", "put", "delete", "patch", "fetch",
    "connect", "send", "recv", "request", "open",
    "download", "upload",
}

FILESYSTEM_WRITE_FUNCTIONS: Set[str] = {
    "writeFile", "writeFileSync", "appendFile", "appendFileSync",
    "write", "open",  # with write mode
    "mkdir", "mkdirSync", "rmdir", "unlink",
    "rename", "copyFile", "chmod", "chown",
}


# ---------------------------------------------------------------------------
# Supply Chain Analyzer
# ---------------------------------------------------------------------------

class SupplyChainAnalyzer:
    """Analyzes programs for supply chain attack surface patterns.

    Scans source-level AST for risky dependency patterns:
    dynamic imports, runtime installs, typosquatting indicators,
    unsafe deserialization, remote code execution, and more.
    """

    def __init__(self):
        self.errors: List[AeonError] = []
        self._in_function_body: bool = False

    def check_program(self, program: Program) -> List[AeonError]:
        """Run supply chain analysis on the entire program."""
        self.errors = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._in_function_body = True
                self._analyze_function(decl)
                self._in_function_body = False

        # Second pass: check top-level statements for postinstall risks
        # Top-level expressions outside function bodies are module init code
        self._check_toplevel_statements(program)

        return self.errors

    # ------------------------------------------------------------------
    # Function-level analysis
    # ------------------------------------------------------------------

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a function body for supply chain risks."""
        for stmt in func.body:
            self._analyze_statement(stmt, func)

    def _analyze_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Walk a statement tree, dispatching to category-specific checks."""
        loc = getattr(stmt, 'location', SourceLocation("<supply-chain>", 0, 0))

        if isinstance(stmt, LetStmt):
            if stmt.value:
                self._check_expr(stmt.value, func, loc)

        elif isinstance(stmt, AssignStmt):
            self._check_expr(stmt.value, func, loc)

        elif isinstance(stmt, ExprStmt):
            self._check_expr(stmt.expr, func, loc)

        elif isinstance(stmt, IfStmt):
            self._check_expr(stmt.condition, func, loc)
            for s in stmt.then_body:
                self._analyze_statement(s, func)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._analyze_statement(s, func)

    # ------------------------------------------------------------------
    # Expression dispatcher
    # ------------------------------------------------------------------

    def _check_expr(self, expr: Expr, func: PureFunc | TaskFunc,
                    loc: SourceLocation) -> None:
        """Run all supply chain checks against an expression."""
        self._check_dynamic_dependency(expr, func, loc)
        self._check_insecure_install(expr, func, loc)
        self._check_typosquatting(expr, func, loc)
        self._check_dependency_confusion(expr, func, loc)
        self._check_unsafe_deserialization(expr, func, loc)
        self._check_remote_code_exec(expr, func, loc)
        self._check_missing_integrity(expr, func, loc)

        # Recurse into subexpressions
        if isinstance(expr, FunctionCall):
            for arg in expr.args:
                self._check_expr(arg, func, loc)
        elif isinstance(expr, MethodCall):
            self._check_expr(expr.obj, func, loc)
            for arg in expr.args:
                self._check_expr(arg, func, loc)
        elif isinstance(expr, BinaryOp):
            self._check_expr(expr.left, func, loc)
            self._check_expr(expr.right, func, loc)
        elif isinstance(expr, FieldAccess):
            self._check_expr(expr.obj, func, loc)

    # ------------------------------------------------------------------
    # 1. Dynamic Dependency Loading (CWE-829)
    # ------------------------------------------------------------------

    def _check_dynamic_dependency(self, expr: Expr, func: PureFunc | TaskFunc,
                                  loc: SourceLocation) -> None:
        """Detect require(variable), importlib.import_module(var), __import__(var)."""
        callee_name = self._get_callee_name(expr)
        if not callee_name:
            return

        # Check if this is a dynamic import function
        is_dynamic_import = callee_name in DYNAMIC_IMPORT_FUNCTIONS

        # Also catch method-style: importlib.import_module(x)
        if not is_dynamic_import and isinstance(expr, MethodCall):
            qualified = f"{self._expr_str(expr.obj)}.{expr.method_name}"
            is_dynamic_import = qualified in DYNAMIC_IMPORT_FUNCTIONS

        if not is_dynamic_import:
            return

        # Only flag if the argument is NOT a string literal
        args = self._get_args(expr)
        if args and not isinstance(args[0], StringLiteral):
            self._emit(
                category=FindingCategory.DYNAMIC_DEPENDENCY,
                message=(
                    f"Dynamic dependency loading: '{callee_name}()' called with "
                    f"a non-literal argument — module resolution is attacker-controllable"
                ),
                func=func,
                loc=loc,
                details={
                    "function": callee_name,
                    "argument_type": type(args[0]).__name__,
                },
            )

        # Also catch eval("require(...)") or eval("import(...)") patterns
        if callee_name in EXEC_FUNCTIONS and args:
            if isinstance(args[0], StringLiteral):
                val = args[0].value
                if "require(" in val or "import(" in val or "__import__(" in val:
                    self._emit(
                        category=FindingCategory.DYNAMIC_DEPENDENCY,
                        message=(
                            f"Eval-based module loading: '{callee_name}(\"{val}\")' — "
                            f"string-evaluated imports bypass static analysis entirely"
                        ),
                        func=func,
                        loc=loc,
                        details={
                            "function": callee_name,
                            "eval_content": val,
                        },
                        severity_override=Severity.CRITICAL,
                    )

    # ------------------------------------------------------------------
    # 2. Insecure Package Installation (CWE-829)
    # ------------------------------------------------------------------

    def _check_insecure_install(self, expr: Expr, func: PureFunc | TaskFunc,
                                loc: SourceLocation) -> None:
        """Detect runtime subprocess/os.system calls that install packages."""
        # Check for subprocess.call(["pip", "install", ...]) pattern
        callee_name = self._get_callee_name(expr)
        if not callee_name:
            return

        # subprocess.call, subprocess.run, subprocess.Popen, os.system, os.popen
        shell_executors = {
            "call", "run", "Popen", "check_call", "check_output",
            "system", "popen", "exec", "execvp",
        }

        is_shell_exec = callee_name in shell_executors
        if not is_shell_exec and isinstance(expr, MethodCall):
            is_shell_exec = expr.method_name in shell_executors

        if not is_shell_exec:
            # Also check for eval/exec containing install commands
            if callee_name in EXEC_FUNCTIONS:
                args = self._get_args(expr)
                if args and isinstance(args[0], StringLiteral):
                    if self._contains_package_command(args[0].value):
                        self._emit(
                            category=FindingCategory.INSECURE_INSTALL,
                            message=(
                                f"Runtime package installation via {callee_name}(): "
                                f"'{args[0].value}' — bypasses lockfile integrity"
                            ),
                            func=func,
                            loc=loc,
                            details={
                                "function": callee_name,
                                "command": args[0].value,
                            },
                        )
            return

        # Check arguments for package manager commands
        args = self._get_args(expr)
        for arg in args:
            if isinstance(arg, StringLiteral):
                if self._contains_package_command(arg.value):
                    self._emit(
                        category=FindingCategory.INSECURE_INSTALL,
                        message=(
                            f"Runtime package installation: '{callee_name}()' executes "
                            f"'{arg.value}' — bypasses lockfile pinning and integrity checks"
                        ),
                        func=func,
                        loc=loc,
                        details={
                            "function": callee_name,
                            "command": arg.value,
                        },
                    )

    def _contains_package_command(self, text: str) -> bool:
        """Check if a string contains a package manager install command."""
        text_lower = text.lower()
        return any(cmd in text_lower for cmd in PACKAGE_MANAGER_COMMANDS)

    # ------------------------------------------------------------------
    # 3. Typosquatting Risk Indicators (CWE-1357)
    # ------------------------------------------------------------------

    def _check_typosquatting(self, expr: Expr, func: PureFunc | TaskFunc,
                             loc: SourceLocation) -> None:
        """Detect imports of packages with names suspiciously similar to popular ones."""
        # We look for StringLiteral arguments to require/import_module/__import__
        callee_name = self._get_callee_name(expr)
        if not callee_name:
            return

        import_functions = {"require", "import_module", "__import__",
                            "importlib.import_module"}
        is_import = callee_name in import_functions
        if not is_import and isinstance(expr, MethodCall):
            qualified = f"{self._expr_str(expr.obj)}.{expr.method_name}"
            is_import = qualified in import_functions

        if not is_import:
            return

        args = self._get_args(expr)
        if not args or not isinstance(args[0], StringLiteral):
            return

        package_name = args[0].value.strip()
        # Strip leading path/scope: @scope/package -> package, ./local -> skip
        if package_name.startswith(".") or package_name.startswith("/"):
            return  # Local imports are not typosquat risks
        if "/" in package_name:
            package_name = package_name.split("/")[-1]
        if package_name.startswith("@") and "/" in args[0].value:
            package_name = args[0].value.split("/")[1]

        # Skip exact matches — those are legitimate
        if package_name in POPULAR_PACKAGES:
            return

        # Check known typosquat mapping
        if package_name in KNOWN_TYPOSQUATS:
            real_pkg = KNOWN_TYPOSQUATS[package_name]
            self._emit(
                category=FindingCategory.TYPOSQUATTING,
                message=(
                    f"Potential typosquatting: '{package_name}' is a known typosquat "
                    f"of '{real_pkg}' — verify this is the intended package"
                ),
                func=func,
                loc=loc,
                details={
                    "suspect_package": package_name,
                    "intended_package": real_pkg,
                    "confidence": "high",
                },
            )
            return

        # Fuzzy match against popular packages
        best_match, best_ratio = self._best_fuzzy_match(package_name)
        if best_match and best_ratio >= 0.80 and best_ratio < 1.0:
            self._emit(
                category=FindingCategory.TYPOSQUATTING,
                message=(
                    f"Possible typosquatting: '{package_name}' is {best_ratio:.0%} similar "
                    f"to popular package '{best_match}' — verify this is intentional"
                ),
                func=func,
                loc=loc,
                details={
                    "suspect_package": package_name,
                    "similar_to": best_match,
                    "similarity": round(best_ratio, 3),
                    "confidence": "medium" if best_ratio < 0.90 else "high",
                },
            )

    def _best_fuzzy_match(self, name: str) -> Tuple[Optional[str], float]:
        """Find the most similar popular package name using SequenceMatcher."""
        best_match: Optional[str] = None
        best_ratio: float = 0.0
        name_lower = name.lower()
        for pkg in POPULAR_PACKAGES:
            ratio = SequenceMatcher(None, name_lower, pkg.lower()).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_match = pkg
        return best_match, best_ratio

    # ------------------------------------------------------------------
    # 4. Dependency Confusion (CWE-427)
    # ------------------------------------------------------------------

    def _check_dependency_confusion(self, expr: Expr, func: PureFunc | TaskFunc,
                                    loc: SourceLocation) -> None:
        """Detect --extra-index-url without --index-url restriction."""
        if not isinstance(expr, StringLiteral):
            return

        val = expr.value
        if "--extra-index-url" in val and "--index-url" not in val:
            self._emit(
                category=FindingCategory.DEPENDENCY_CONFUSION,
                message=(
                    f"Dependency confusion risk: '--extra-index-url' used without "
                    f"'--index-url' restriction — public registry packages could "
                    f"shadow internal ones"
                ),
                func=func,
                loc=loc,
                details={
                    "config_value": val,
                    "mitigation": "Always pair --extra-index-url with --index-url "
                                  "pointing to your private registry",
                },
            )

        # Also check for pip.conf / .npmrc patterns with extra index
        if "extra-index-url" in val and "index-url" not in val.replace(
                "extra-index-url", ""):
            # Already caught above, but handle alternate formats
            pass

    # ------------------------------------------------------------------
    # 5. Unsafe Deserialization (CWE-502)
    # ------------------------------------------------------------------

    def _check_unsafe_deserialization(self, expr: Expr, func: PureFunc | TaskFunc,
                                     loc: SourceLocation) -> None:
        """Detect pickle.loads, yaml.load without SafeLoader, Marshal.load, etc."""
        callee_name = self._get_callee_name(expr)
        if not callee_name:
            return

        # Build qualified name for method calls
        qualified_name = callee_name
        if isinstance(expr, MethodCall):
            obj_str = self._expr_str(expr.obj)
            qualified_name = f"{obj_str}.{expr.method_name}"

        # Check against known unsafe deserialization functions
        safe_arg_name: Optional[str] = None
        matched_func: Optional[str] = None

        for deser_func, required_safe_arg in UNSAFE_DESER_FUNCTIONS.items():
            if (qualified_name == deser_func or
                    callee_name == deser_func or
                    qualified_name.endswith(f".{deser_func.split('.')[-1]}")):
                matched_func = deser_func
                safe_arg_name = required_safe_arg
                break

        # Also check method names alone for common patterns
        if not matched_func and isinstance(expr, MethodCall):
            if expr.method_name in UNSAFE_DESER_METHODS:
                obj_str = self._expr_str(expr.obj)
                # Only flag if the object looks like a deserialization library
                deser_libs = {"pickle", "cPickle", "_pickle", "yaml", "marshal",
                              "shelve", "Marshal", "ObjectInputStream",
                              "BinaryFormatter", "XmlSerializer"}
                if obj_str in deser_libs:
                    matched_func = f"{obj_str}.{expr.method_name}"
                    # yaml.load needs SafeLoader
                    if obj_str == "yaml" and expr.method_name == "load":
                        safe_arg_name = "Loader"

        if not matched_func:
            return

        # If a safe argument is required, check if it's present
        if safe_arg_name:
            args = self._get_args(expr)
            has_safe_arg = False
            for arg in args:
                # Check for Loader=SafeLoader style (keyword args appear
                # as identifiers named SafeLoader, FullLoader, etc.)
                if isinstance(arg, Identifier):
                    if "safe" in arg.name.lower() or arg.name == "SafeLoader":
                        has_safe_arg = True
                        break
                # Check for yaml.SafeLoader field access
                if isinstance(arg, FieldAccess):
                    if "safe" in self._expr_str(arg).lower():
                        has_safe_arg = True
                        break
            if has_safe_arg:
                return  # Safe usage, no finding

        self._emit(
            category=FindingCategory.UNSAFE_DESERIALIZATION,
            message=(
                f"Unsafe deserialization: '{matched_func}' can execute arbitrary "
                f"code if the input data is attacker-controlled"
            ),
            func=func,
            loc=loc,
            details={
                "function": matched_func,
                "safe_alternative": self._safe_alternative(matched_func),
            },
            severity_override=Severity.CRITICAL,
        )

    def _safe_alternative(self, func_name: str) -> str:
        """Suggest a safe alternative for an unsafe deserialization function."""
        alternatives: Dict[str, str] = {
            "pickle.loads": "Use json.loads() or a schema-validated format instead",
            "pickle.load": "Use json.load() or a schema-validated format instead",
            "pickle.Unpickler": "Use json or msgpack with schema validation",
            "cPickle.loads": "Use json.loads() instead",
            "cPickle.load": "Use json.load() instead",
            "_pickle.loads": "Use json.loads() instead",
            "yaml.load": "Use yaml.safe_load() or yaml.load(data, Loader=SafeLoader)",
            "yaml.unsafe_load": "Use yaml.safe_load() instead",
            "yaml.full_load": "Use yaml.safe_load() instead",
            "shelve.open": "Use a JSON-based storage format",
            "marshal.loads": "Use json.loads() instead",
            "marshal.load": "Use json.load() instead",
            "Marshal.load": "Use JSON.parse() or a safe format",
            "Marshal.restore": "Use JSON.parse() or a safe format",
            "unserialize": "Use json_decode() instead in PHP",
            "ObjectInputStream": "Use JSON deserialization with type filtering",
            "readObject": "Add ObjectInputFilter or use JSON deserialization",
            "BinaryFormatter.Deserialize": "Use System.Text.Json or JsonSerializer",
            "XmlSerializer.Deserialize": "Use System.Text.Json with type validation",
        }
        return alternatives.get(func_name, "Use JSON or a schema-validated format")

    # ------------------------------------------------------------------
    # 6. Code Execution from URLs (CWE-494)
    # ------------------------------------------------------------------

    def _check_remote_code_exec(self, expr: Expr, func: PureFunc | TaskFunc,
                                loc: SourceLocation) -> None:
        """Detect eval(fetch(url)), exec(requests.get(url).text), etc."""
        callee_name = self._get_callee_name(expr)
        if not callee_name:
            return

        if callee_name not in EXEC_FUNCTIONS:
            return

        args = self._get_args(expr)
        for arg in args:
            # Check if the argument is a fetch/HTTP call (nested FunctionCall/MethodCall)
            if self._is_http_fetch(arg):
                fetch_desc = self._describe_fetch(arg)
                self._emit(
                    category=FindingCategory.REMOTE_CODE_EXEC,
                    message=(
                        f"Remote code execution: '{callee_name}()' executes code "
                        f"fetched from a URL via {fetch_desc} — provides zero "
                        f"integrity verification and enables MITM attacks"
                    ),
                    func=func,
                    loc=loc,
                    details={
                        "exec_function": callee_name,
                        "fetch_expression": fetch_desc,
                    },
                    severity_override=Severity.CRITICAL,
                )
                return

            # Check for string literals containing curl|bash patterns
            if isinstance(arg, StringLiteral):
                val = arg.value
                if self._is_curl_pipe_pattern(val):
                    self._emit(
                        category=FindingCategory.REMOTE_CODE_EXEC,
                        message=(
                            f"Remote code execution: '{callee_name}()' runs a "
                            f"curl-pipe-shell pattern — '{val}'"
                        ),
                        func=func,
                        loc=loc,
                        details={
                            "exec_function": callee_name,
                            "command": val,
                        },
                        severity_override=Severity.CRITICAL,
                    )
                    return

            # Also flag eval/exec with FieldAccess chains like requests.get(url).text
            if isinstance(arg, FieldAccess):
                if self._is_http_fetch(arg.obj):
                    self._emit(
                        category=FindingCategory.REMOTE_CODE_EXEC,
                        message=(
                            f"Remote code execution: '{callee_name}()' executes "
                            f"remote content accessed via '.{arg.field_name}' — "
                            f"downloaded code runs without integrity check"
                        ),
                        func=func,
                        loc=loc,
                        details={
                            "exec_function": callee_name,
                            "field_accessed": arg.field_name,
                        },
                        severity_override=Severity.CRITICAL,
                    )
                    return

    def _is_http_fetch(self, expr: Expr) -> bool:
        """Check if an expression represents an HTTP fetch operation."""
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return expr.callee.name in HTTP_FETCH_FUNCTIONS
        if isinstance(expr, MethodCall):
            return expr.method_name in HTTP_FETCH_METHODS
        if isinstance(expr, FieldAccess):
            return self._is_http_fetch(expr.obj)
        return False

    def _describe_fetch(self, expr: Expr) -> str:
        """Build a human-readable description of a fetch expression."""
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return f"{expr.callee.name}()"
        if isinstance(expr, MethodCall):
            return f"{self._expr_str(expr.obj)}.{expr.method_name}()"
        return "<fetch>"

    def _is_curl_pipe_pattern(self, text: str) -> bool:
        """Check if a string contains curl|bash or wget|sh patterns."""
        text_lower = text.lower()
        pipe_patterns = [
            ("curl", "|", "bash"), ("curl", "|", "sh"),
            ("curl", "|", "python"), ("curl", "|", "perl"),
            ("curl", "|", "ruby"), ("curl", "|", "node"),
            ("wget", "|", "bash"), ("wget", "|", "sh"),
            ("wget", "|", "python"),
            ("curl", "|", "sudo"),
            ("wget", "-O", "-", "|"),
        ]
        for parts in pipe_patterns:
            if all(p in text_lower for p in parts):
                return True
        return False

    # ------------------------------------------------------------------
    # 7. Postinstall Script Risks (CWE-829)
    # ------------------------------------------------------------------

    def _check_toplevel_statements(self, program: Program) -> None:
        """Check for network/filesystem operations at module top level.

        These execute during import and are a common postinstall attack vector.
        We look at the top-level declarations for any function that appears
        to be module-init code performing I/O.
        """
        # In the AEON AST, top-level code lives as declarations.
        # Functions named __init__, module_init, or with empty names are
        # treated as module init code. We also check for patterns in
        # function bodies where the function name suggests initialization.
        for decl in program.declarations:
            if not isinstance(decl, (PureFunc, TaskFunc)):
                continue

            is_init = self._is_init_function(decl.name)
            if not is_init:
                continue

            for stmt in decl.body:
                self._check_postinstall_statement(stmt, decl)

    def _is_init_function(self, name: str) -> bool:
        """Check if a function name suggests module initialization."""
        init_names = {
            "__init__", "init", "module_init", "setup", "initialize",
            "on_import", "register", "__post_init__",
            # Top-level / unnamed
            "", "<module>", "<top>",
        }
        return name.lower() in init_names

    def _check_postinstall_statement(self, stmt: Statement,
                                     func: PureFunc | TaskFunc) -> None:
        """Check if a statement in init code performs network/FS operations."""
        loc = getattr(stmt, 'location', SourceLocation("<supply-chain>", 0, 0))

        if isinstance(stmt, ExprStmt):
            self._check_postinstall_expr(stmt.expr, func, loc)
        elif isinstance(stmt, LetStmt) and stmt.value:
            self._check_postinstall_expr(stmt.value, func, loc)
        elif isinstance(stmt, AssignStmt):
            self._check_postinstall_expr(stmt.value, func, loc)
        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._check_postinstall_statement(s, func)
            if stmt.else_body:
                for s in stmt.else_body:
                    self._check_postinstall_statement(s, func)

    def _check_postinstall_expr(self, expr: Expr, func: PureFunc | TaskFunc,
                                loc: SourceLocation) -> None:
        """Flag network or filesystem operations in module init code."""
        callee_name = self._get_callee_name(expr)
        if not callee_name:
            return

        is_network = callee_name in NETWORK_FUNCTIONS
        is_fs_write = callee_name in FILESYSTEM_WRITE_FUNCTIONS

        if isinstance(expr, MethodCall):
            is_network = is_network or expr.method_name in NETWORK_METHODS
            is_fs_write = is_fs_write or expr.method_name in FILESYSTEM_WRITE_FUNCTIONS

        if is_network:
            self._emit(
                category=FindingCategory.POSTINSTALL_RISK,
                message=(
                    f"Network access during module initialization: '{callee_name}()' "
                    f"in '{func.name}' — code that runs on import can exfiltrate "
                    f"environment variables and secrets"
                ),
                func=func,
                loc=loc,
                details={
                    "function": callee_name,
                    "init_function": func.name,
                    "risk": "data_exfiltration",
                },
            )

        if is_fs_write:
            self._emit(
                category=FindingCategory.POSTINSTALL_RISK,
                message=(
                    f"Filesystem write during module initialization: '{callee_name}()' "
                    f"in '{func.name}' — postinstall writes can install backdoors "
                    f"or modify system configuration"
                ),
                func=func,
                loc=loc,
                details={
                    "function": callee_name,
                    "init_function": func.name,
                    "risk": "filesystem_tampering",
                },
            )

    # ------------------------------------------------------------------
    # 8. Missing Subresource Integrity (CWE-494)
    # ------------------------------------------------------------------

    def _check_missing_integrity(self, expr: Expr, func: PureFunc | TaskFunc,
                                 loc: SourceLocation) -> None:
        """Detect external script/resource URLs without integrity hashes."""
        if not isinstance(expr, StringLiteral):
            return

        val = expr.value.strip()

        # Only check URLs that load executable content
        is_script_url = (
            val.startswith("http://") or val.startswith("https://")
        ) and self._is_executable_resource_url(val)

        if not is_script_url:
            return

        # Check if there is a nearby integrity attribute
        # In the AST, we look for "integrity" or "sha256-" / "sha384-" / "sha512-"
        # in sibling expressions or the same statement context.
        # Since we cannot easily look at sibling HTML attributes in the AST,
        # we check if the URL string itself contains a hash or if the function
        # call includes an integrity parameter.
        has_integrity = self._check_integrity_context(expr, func, loc)

        if not has_integrity:
            self._emit(
                category=FindingCategory.MISSING_INTEGRITY,
                message=(
                    f"External resource loaded without integrity check: '{val}' — "
                    f"CDN compromise or MITM could inject malicious code"
                ),
                func=func,
                loc=loc,
                details={
                    "url": val,
                    "mitigation": "Add subresource integrity hash "
                                  "(integrity='sha384-...')",
                },
            )

    def _is_executable_resource_url(self, url: str) -> bool:
        """Check if a URL likely points to executable code."""
        url_lower = url.lower()
        executable_extensions = {".js", ".mjs", ".cjs", ".ts", ".wasm"}
        cdn_indicators = {
            "cdn.", "cdnjs.", "unpkg.com", "jsdelivr.net", "cloudflare.com",
            "googleapis.com", "bootstrapcdn.com", "ajax.googleapis.com",
            "stackpath.", "rawgit.", "raw.githubusercontent.com",
            "esm.sh", "skypack.dev", "deno.land",
        }

        has_exec_ext = any(url_lower.endswith(ext) or f"{ext}?" in url_lower
                          for ext in executable_extensions)
        is_cdn = any(indicator in url_lower for indicator in cdn_indicators)

        return has_exec_ext or is_cdn

    def _check_integrity_context(self, expr: Expr, func: PureFunc | TaskFunc,
                                 loc: SourceLocation) -> bool:
        """Check if there is an integrity hash near this URL reference.

        Scans sibling statements in the same function for 'integrity' or
        hash prefixes that indicate SRI is in use.
        """
        # Walk the function body looking for integrity indicators near the URL
        for stmt in func.body:
            if self._stmt_has_integrity_marker(stmt):
                return True
        return False

    def _stmt_has_integrity_marker(self, stmt: Statement) -> bool:
        """Check if a statement contains an integrity hash."""
        if isinstance(stmt, LetStmt) and stmt.value:
            return self._expr_has_integrity(stmt.value)
        if isinstance(stmt, AssignStmt):
            return self._expr_has_integrity(stmt.value)
        if isinstance(stmt, ExprStmt):
            return self._expr_has_integrity(stmt.expr)
        return False

    def _expr_has_integrity(self, expr: Expr) -> bool:
        """Check if an expression contains integrity hash markers."""
        if isinstance(expr, StringLiteral):
            val = expr.value.lower()
            return (
                "integrity" in val or
                val.startswith("sha256-") or
                val.startswith("sha384-") or
                val.startswith("sha512-")
            )
        if isinstance(expr, Identifier):
            return "integrity" in expr.name.lower()
        if isinstance(expr, FunctionCall):
            for arg in expr.args:
                if self._expr_has_integrity(arg):
                    return True
        if isinstance(expr, MethodCall):
            for arg in expr.args:
                if self._expr_has_integrity(arg):
                    return True
        return False

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    def _get_callee_name(self, expr: Expr) -> Optional[str]:
        """Extract the function or method name from a call expression."""
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return expr.callee.name
        if isinstance(expr, MethodCall):
            return expr.method_name
        return None

    def _get_args(self, expr: Expr) -> List[Expr]:
        """Get the argument list from a call expression."""
        if isinstance(expr, FunctionCall):
            return expr.args
        if isinstance(expr, MethodCall):
            return expr.args
        return []

    def _expr_str(self, expr: Expr) -> str:
        """Convert an expression to a human-readable string."""
        if isinstance(expr, Identifier):
            return expr.name
        if isinstance(expr, StringLiteral):
            return f'"{expr.value}"'
        if isinstance(expr, FieldAccess):
            return f"{self._expr_str(expr.obj)}.{expr.field_name}"
        if isinstance(expr, MethodCall):
            return f"{self._expr_str(expr.obj)}.{expr.method_name}()"
        if isinstance(expr, FunctionCall) and isinstance(expr.callee, Identifier):
            return f"{expr.callee.name}()"
        return "<expr>"

    def _emit(self, category: FindingCategory, message: str,
              func: PureFunc | TaskFunc, loc: SourceLocation,
              details: Optional[Dict] = None,
              severity_override: Optional[Severity] = None) -> None:
        """Emit a supply chain finding as an AeonError."""
        severity = severity_override or CATEGORY_SEVERITY[category]
        cwe = CATEGORY_CWE[category]

        finding_details = {
            "category": category.value,
            "severity": severity.value,
            "cwe": cwe,
            "engine": "Supply Chain Security",
        }
        if details:
            finding_details.update(details)

        self.errors.append(contract_error(
            precondition=f"Supply chain risk ({severity.value}): {message}",
            failing_values=finding_details,
            function_signature=func.name,
            location=loc,
        ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_supply_chain(program: Program) -> list:
    """Run supply chain security analysis on an AEON program.

    Detects source-level patterns that indicate supply chain risks:
    - Dynamic dependency loading (CWE-829)
    - Insecure runtime package installation (CWE-829)
    - Typosquatting risk indicators (CWE-1357)
    - Dependency confusion patterns (CWE-427)
    - Unsafe deserialization of external data (CWE-502)
    - Code execution from remote URLs (CWE-494)
    - Postinstall script risks (CWE-829)
    - Missing subresource integrity (CWE-494)

    Returns a list of AeonError findings with severity, CWE, and
    category metadata in each error's details dict.

    Note: This engine analyzes AST patterns in source code. It does NOT
    scan lockfiles or dependency manifests — that is a separate tool.
    """
    analyzer = SupplyChainAnalyzer()
    return analyzer.check_program(program)
