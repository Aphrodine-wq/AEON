"""AEON Advanced Injection Detection Engine — Beyond Standard Taint Analysis.

Catches injection attack vectors that the core taint analysis engine does not
cover. The taint engine handles SQL injection, XSS, command injection, path
traversal, SSRF, and deserialization at the source-sink-sanitizer level. This
engine performs deeper structural and pattern-based analysis for less common
but equally dangerous injection categories.

Based on:
  OWASP Testing Guide v4.2 — Injection Flaws
  https://owasp.org/www-project-web-security-testing-guide/

  Staicu & Pradel (2018) "Freezing the Web: A Study of ReDoS Vulnerabilities
  in JavaScript-based Web Servers"
  USENIX Security '18, https://www.usenix.org/conference/usenixsecurity18

  James Kettle (2015) "Server-Side Template Injection"
  PortSwigger Research, https://portswigger.net/research/server-side-template-injection

  Sullivan & Liu (2012) "Web Application Security: A Beginner's Guide"
  McGraw-Hill Education, ISBN 978-0071776165

Detects:
  - Server-Side Template Injection (SSTI) — CWE-94
  - HTTP Header Injection / Response Splitting — CWE-113
  - Log Injection / Log Forging — CWE-117
  - NoSQL Injection — CWE-943
  - LDAP Injection — CWE-90
  - XML External Entity (XXE) — CWE-611
  - ReDoS (Regular Expression Denial of Service) — CWE-1333
  - Expression Language Injection — CWE-94
  - Open Redirect — CWE-601
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
    LetStmt, AssignStmt, IfStmt, ExprStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Injection Categories
# ---------------------------------------------------------------------------

class InjectionCategory(Enum):
    SSTI = "server_side_template_injection"
    HEADER = "http_header_injection"
    LOG = "log_injection"
    NOSQL = "nosql_injection"
    LDAP = "ldap_injection"
    XXE = "xml_external_entity"
    REDOS = "regex_denial_of_service"
    EXPR_LANG = "expression_language_injection"
    OPEN_REDIRECT = "open_redirect"


# CWE mapping for each category
CWE_MAP: Dict[InjectionCategory, str] = {
    InjectionCategory.SSTI: "CWE-94",
    InjectionCategory.HEADER: "CWE-113",
    InjectionCategory.LOG: "CWE-117",
    InjectionCategory.NOSQL: "CWE-943",
    InjectionCategory.LDAP: "CWE-90",
    InjectionCategory.XXE: "CWE-611",
    InjectionCategory.REDOS: "CWE-1333",
    InjectionCategory.EXPR_LANG: "CWE-94",
    InjectionCategory.OPEN_REDIRECT: "CWE-601",
}

# OWASP category mapping
OWASP_MAP: Dict[InjectionCategory, str] = {
    InjectionCategory.SSTI: "A03:2021 Injection",
    InjectionCategory.HEADER: "A03:2021 Injection",
    InjectionCategory.LOG: "A09:2021 Security Logging and Monitoring Failures",
    InjectionCategory.NOSQL: "A03:2021 Injection",
    InjectionCategory.LDAP: "A03:2021 Injection",
    InjectionCategory.XXE: "A05:2021 Security Misconfiguration",
    InjectionCategory.REDOS: "A06:2021 Vulnerable and Outdated Components",
    InjectionCategory.EXPR_LANG: "A03:2021 Injection",
    InjectionCategory.OPEN_REDIRECT: "A01:2021 Broken Access Control",
}

# Severity per category
SEVERITY_MAP: Dict[InjectionCategory, str] = {
    InjectionCategory.SSTI: "critical",
    InjectionCategory.HEADER: "high",
    InjectionCategory.LOG: "medium",
    InjectionCategory.NOSQL: "high",
    InjectionCategory.LDAP: "high",
    InjectionCategory.XXE: "critical",
    InjectionCategory.REDOS: "high",
    InjectionCategory.EXPR_LANG: "critical",
    InjectionCategory.OPEN_REDIRECT: "medium",
}

# Remediation guidance per category
REMEDIATION_MAP: Dict[InjectionCategory, str] = {
    InjectionCategory.SSTI: (
        "Never pass user input directly to template engines. Use sandboxed "
        "template rendering, pre-compiled templates with variable substitution, "
        "or strict allowlists for template content."
    ),
    InjectionCategory.HEADER: (
        "Strip or reject CR (\\r) and LF (\\n) characters from all user input "
        "before inserting into HTTP headers. Use framework-provided header "
        "setters that enforce encoding."
    ),
    InjectionCategory.LOG: (
        "Sanitize user input before logging by stripping or encoding newlines, "
        "carriage returns, and ANSI escape sequences. Use structured logging "
        "formats (JSON) that inherently escape special characters."
    ),
    InjectionCategory.NOSQL: (
        "Never construct NoSQL queries by embedding raw user input into query "
        "objects. Use explicit field-value matching, validate input types, and "
        "reject query operators ($gt, $ne, $regex, etc.) from user input."
    ),
    InjectionCategory.LDAP: (
        "Use parameterized LDAP queries or escape special LDAP characters "
        "(*, (, ), \\, NUL) in user input. Use ldap3.utils.dn.escape_rdn or "
        "equivalent library escaping functions."
    ),
    InjectionCategory.XXE: (
        "Disable external entity processing and DTD loading in all XML parsers. "
        "Use defusedxml in Python, set XMLConstants.FEATURE_SECURE_PROCESSING "
        "in Java, or configure parser to disallow doctype declarations entirely."
    ),
    InjectionCategory.REDOS: (
        "Avoid nested quantifiers (e.g., (a+)+, (a*)*) and overlapping alternation "
        "with quantifiers. Use atomic groups or possessive quantifiers where supported. "
        "Set regex execution timeouts and consider using RE2 or similar linear-time engines."
    ),
    InjectionCategory.EXPR_LANG: (
        "Never pass user input to eval(), exec(), Function(), setTimeout/setInterval "
        "with string arguments, or expression language evaluators. Use AST-based "
        "evaluation with strict allowlists or sandboxed interpreters."
    ),
    InjectionCategory.OPEN_REDIRECT: (
        "Validate redirect URLs against a strict allowlist of trusted domains. "
        "Use relative paths instead of full URLs. Reject input containing protocol "
        "schemes (http://, //, javascript:) unless explicitly allowed."
    ),
}


# ---------------------------------------------------------------------------
# Pattern Specifications
# ---------------------------------------------------------------------------

# SSTI: Functions that compile or render templates from strings
SSTI_TEMPLATE_COMPILERS: Set[str] = {
    # Python / Jinja2
    "render_template_string", "Template", "from_string",
    # Jinja2 direct
    "jinja2.Template", "Environment",
    # Mako
    "mako.Template", "MakoTemplate",
    # Twig (PHP-like)
    "twig.render", "createTemplate",
    # Handlebars
    "Handlebars.compile", "handlebars.compile",
    # EJS
    "ejs.render", "ejs.compile",
    # Pug / Jade
    "pug.render", "pug.compile", "jade.render",
    # Mustache
    "Mustache.render",
    # Tornado
    "tornado.template.Template",
    # Django (unsafe usage)
    "django.template.Template",
    # Nunjucks
    "nunjucks.renderString",
    # Velocity
    "VelocityEngine.evaluate",
    # Freemarker
    "freemarker.Template",
}

# Normalized lowercase set for matching
_SSTI_LOWER: Set[str] = {s.lower() for s in SSTI_TEMPLATE_COMPILERS}

# Header injection: methods that set HTTP headers on a response
HEADER_SETTERS: Set[str] = {
    "setHeader", "set", "append", "writeHead",
    "addHeader", "add_header", "set_header",
    "response_header", "setResponseHeader",
    "header",
}

# Specific dangerous headers
DANGEROUS_HEADERS: Set[str] = {
    "location", "set-cookie", "content-type",
    "access-control-allow-origin", "x-forwarded-for",
    "content-disposition", "refresh",
}

# Log injection: logging functions
LOG_FUNCTIONS: Set[str] = {
    "log", "info", "warn", "warning", "error", "debug", "critical",
    "fatal", "trace", "notice",
    # Python
    "logger.info", "logger.warn", "logger.warning", "logger.error",
    "logger.debug", "logger.critical", "logger.fatal",
    "logging.info", "logging.warn", "logging.warning", "logging.error",
    "logging.debug", "logging.critical",
    # JavaScript / Node
    "console.log", "console.warn", "console.error", "console.info",
    "console.debug", "console.trace",
    # General
    "print", "println", "printf", "fprintf", "puts", "write",
    "syslog", "NSLog",
}

_LOG_LOWER: Set[str] = {s.lower() for s in LOG_FUNCTIONS}

# NoSQL: MongoDB-style query methods
NOSQL_QUERY_METHODS: Set[str] = {
    "find", "findOne", "find_one", "findMany", "find_many",
    "aggregate", "update", "updateOne", "update_one",
    "updateMany", "update_many", "deleteOne", "delete_one",
    "deleteMany", "delete_many", "replaceOne", "replace_one",
    "countDocuments", "count_documents", "distinct",
    "findOneAndUpdate", "find_one_and_update",
    "findOneAndDelete", "find_one_and_delete",
    "findOneAndReplace", "find_one_and_replace",
    "where",
}

_NOSQL_LOWER: Set[str] = {s.lower() for s in NOSQL_QUERY_METHODS}

# LDAP: LDAP search/query functions
LDAP_FUNCTIONS: Set[str] = {
    "search", "search_s", "search_st", "search_ext", "search_ext_s",
    "ldap_search", "ldap.search", "ldap_search_s",
    "ldap_search_ext", "ldap_search_ext_s",
    "ldap_bind", "ldap_bind_s",
    "modify", "modify_s", "add", "add_s",
    "compare", "compare_s",
}

_LDAP_LOWER: Set[str] = {s.lower() for s in LDAP_FUNCTIONS}

# LDAP filter patterns indicating string interpolation
LDAP_FILTER_PATTERNS: List[str] = [
    "(&(", "(|(", "(uid=", "(cn=", "(sAMAccountName=",
    "(mail=", "(ou=", "(dc=", "(objectClass=",
    "(memberOf=", "(distinguishedName=",
]

# XXE: Vulnerable XML parsers
XXE_VULNERABLE_PARSERS: Set[str] = {
    # Python stdlib (vulnerable by default)
    "xml.etree.ElementTree.parse", "ET.parse", "ElementTree.parse",
    "xml.sax.parse", "xml.sax.parseString",
    "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
    "xml.dom.pulldom.parse", "xml.dom.pulldom.parseString",
    "xml.etree.ElementTree.fromstring", "ET.fromstring",
    "ElementTree.fromstring",
    # lxml
    "lxml.etree.parse", "lxml.etree.fromstring",
    "lxml.etree.XML", "lxml.etree.iterparse",
    "etree.parse", "etree.fromstring", "etree.XML",
    # Java
    "DocumentBuilderFactory.newInstance",
    "SAXParserFactory.newInstance",
    "XMLReaderFactory.createXMLReader",
    "XMLReader", "SAXParser", "DocumentBuilder",
    "TransformerFactory.newInstance",
    "SchemaFactory.newInstance",
    "XMLInputFactory.newInstance",
    # .NET
    "XmlDocument", "XmlReader.Create",
    "XmlTextReader", "XDocument.Load",
    # PHP
    "simplexml_load_string", "simplexml_load_file",
    "DOMDocument.loadXML", "DOMDocument.load",
    # Ruby
    "Nokogiri::XML", "REXML::Document.new",
}

_XXE_LOWER: Set[str] = {s.lower() for s in XXE_VULNERABLE_PARSERS}

# Safe XML parser functions/patterns (defusedxml, configured parsers)
XXE_SAFE_PARSERS: Set[str] = {
    "defusedxml", "defused_xml",
    "setFeature", "set_feature",
    "XMLConstants.FEATURE_SECURE_PROCESSING",
    "resolve_entities", "no_network",
    "disallow-doctype-decl",
    "XMLParser", "iterparse",  # lxml XMLParser with resolve_entities=False
}

_XXE_SAFE_LOWER: Set[str] = {s.lower() for s in XXE_SAFE_PARSERS}

# Expression language injection: evaluation functions
EXPR_EVAL_FUNCTIONS: Set[str] = {
    "eval", "exec", "compile", "execfile",
    # JavaScript
    "Function", "setTimeout", "setInterval",
    # Spring EL
    "parseExpression", "evaluateExpression",
    "SpelExpressionParser", "StandardEvaluationContext",
    # OGNL
    "Ognl.getValue", "Ognl.setValue",
    "OgnlUtil.getValue", "OgnlUtil.setValue",
    # MVEL
    "MVEL.eval", "MVEL.compileExpression",
    # JEL / JEXL
    "JexlEngine.createExpression", "JexlExpression.evaluate",
    # Python
    "ast.literal_eval",  # safe, but flagged for review when user input
    "getattr", "setattr",  # dynamic attribute access
    # Ruby
    "instance_eval", "class_eval", "module_eval",
    "send", "public_send",
}

_EXPR_EVAL_LOWER: Set[str] = {s.lower() for s in EXPR_EVAL_FUNCTIONS}

# Open redirect: redirect functions
REDIRECT_FUNCTIONS: Set[str] = {
    "redirect", "redirect_to", "sendRedirect",
    "Response.redirect", "res.redirect", "response.redirect",
    "header", "writeHead",
    "location.assign", "location.replace", "location.href",
    "window.location", "navigate", "navigateTo",
    "router.push", "router.replace",
    "HttpResponseRedirect", "HttpResponse",
}

_REDIRECT_LOWER: Set[str] = {s.lower() for s in REDIRECT_FUNCTIONS}

# ReDoS: patterns for catastrophic backtracking detection
# These regex patterns match dangerous regex constructs within string values
_REDOS_DANGER_PATTERNS: List[re.Pattern] = [
    # Nested quantifiers: (a+)+, (a*)+, (a+)*, (a*)*
    re.compile(r'\([^)]*[+*]\)[+*]'),
    # Overlapping alternation with quantifier: (a|a)+, (a|ab)+
    re.compile(r'\(([^|)]+)\|(\1[^)]*|[^)]*\1)\)[+*]'),
    # Quantified group with repetition: (.+.+)+, (.*.*)+
    re.compile(r'\([^)]*[.\\w\\d\\s][+*][^)]*[.\\w\\d\\s][+*][^)]*\)[+*]'),
    # Star-of-star: a**  or a*+  or a++
    re.compile(r'[^\\][+*][+*]'),
    # Dot-star followed by specific then dot-star: .*a.*
    # Not always dangerous alone, but risky in combination with anchoring issues
]

# Regex compilation functions
REGEX_COMPILE_FUNCTIONS: Set[str] = {
    "compile", "match", "search", "findall", "finditer",
    "sub", "split", "fullmatch",
    # Python re module
    "re.compile", "re.match", "re.search", "re.findall",
    "re.finditer", "re.sub", "re.split", "re.fullmatch",
    # JavaScript
    "RegExp", "new RegExp",
    # Java
    "Pattern.compile", "Pattern.matches",
    # Ruby
    "Regexp.new", "Regexp.compile",
    # Go
    "regexp.Compile", "regexp.MustCompile",
    # .NET
    "Regex", "new Regex",
}

_REGEX_LOWER: Set[str] = {s.lower() for s in REGEX_COMPILE_FUNCTIONS}


# ---------------------------------------------------------------------------
# User Input Detection
# ---------------------------------------------------------------------------

# Variable name patterns that indicate user-derived input
_USER_INPUT_KEYWORDS: Set[str] = {
    "input", "request", "query", "param", "user", "data",
    "body", "form", "header", "cookie", "args", "payload",
    "content", "raw", "untrusted", "extern", "external",
    "search", "filter", "url", "uri", "path", "redirect",
    "target", "dest", "destination", "next", "return_url",
    "callback", "goto", "ref", "referer", "referrer",
    "template", "tpl", "name", "value", "field", "text",
    "message", "msg", "comment", "title", "description",
    "username", "email", "password",
}

# Type annotation patterns for user input
_USER_INPUT_TYPES: Set[str] = {
    "request", "httprequest", "formdata", "querystring",
    "params", "body", "httpservletrequest", "servletrequest",
    "context", "ctx",
}


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Internal representation of a detected vulnerability."""
    category: InjectionCategory
    source_var: str
    sink_name: str
    detail: str
    location: Optional[SourceLocation] = None
    func_name: str = ""


class AdvancedInjectionAnalyzer:
    """Detects advanced injection vulnerabilities through AST pattern matching.

    Goes deeper than source-sink taint tracking by analyzing:
    - Structural patterns (template compilation with user input)
    - Missing security configurations (XXE parser setup)
    - Regex complexity analysis (ReDoS)
    - Protocol-specific injection vectors (LDAP, NoSQL, CRLF)
    """

    def __init__(self):
        self.findings: List[Finding] = []
        self._user_vars: Set[str] = set()
        self._sanitized_vars: Set[str] = set()
        self._safe_xml_context: bool = False

    def check_program(self, program: Program) -> List[AeonError]:
        """Run advanced injection analysis on the entire program."""
        self.findings = []

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        return self._findings_to_errors()

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a single function for advanced injection patterns."""
        self._user_vars = set()
        self._sanitized_vars = set()
        self._safe_xml_context = False

        # Identify user-input parameters
        for param in func.params:
            if self._is_user_input_param(param):
                self._user_vars.add(param.name)

        # Walk the function body
        for stmt in func.body:
            self._analyze_statement(stmt, func)

    def _is_user_input_param(self, param) -> bool:
        """Determine if a parameter likely carries user input."""
        name_lower = param.name.lower()
        type_str = str(param.type_annotation).lower() if param.type_annotation else ""

        if any(kw in name_lower for kw in _USER_INPUT_KEYWORDS):
            return True
        if any(kw in type_str for kw in _USER_INPUT_TYPES):
            return True
        return False

    def _analyze_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Analyze a statement for injection patterns."""
        loc = getattr(stmt, 'location', None) or SourceLocation("<injection-adv>", 0, 0)

        if isinstance(stmt, LetStmt):
            if stmt.value:
                # Track taint propagation: if value derives from user var, new var is also user
                if self._expr_uses_user_var(stmt.value):
                    self._user_vars.add(stmt.name)
                # Check all injection patterns against this expression
                self._check_all_patterns(stmt.value, func, loc)

        elif isinstance(stmt, AssignStmt):
            if isinstance(stmt.target, Identifier):
                if self._expr_uses_user_var(stmt.value):
                    self._user_vars.add(stmt.target.name)
            self._check_all_patterns(stmt.value, func, loc)

        elif isinstance(stmt, ExprStmt):
            self._check_all_patterns(stmt.expr, func, loc)

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._analyze_statement(s, func)
            for s in stmt.else_body:
                self._analyze_statement(s, func)

    def _check_all_patterns(self, expr: Expr, func: PureFunc | TaskFunc,
                            loc: SourceLocation) -> None:
        """Run all injection checks against an expression."""
        self._check_ssti(expr, func, loc)
        self._check_header_injection(expr, func, loc)
        self._check_log_injection(expr, func, loc)
        self._check_nosql_injection(expr, func, loc)
        self._check_ldap_injection(expr, func, loc)
        self._check_xxe(expr, func, loc)
        self._check_redos(expr, func, loc)
        self._check_expr_lang_injection(expr, func, loc)
        self._check_open_redirect(expr, func, loc)

        # Recurse into sub-expressions
        self._recurse_expr(expr, func, loc)

    def _recurse_expr(self, expr: Expr, func: PureFunc | TaskFunc,
                      loc: SourceLocation) -> None:
        """Recurse into nested expressions for deeper analysis."""
        if isinstance(expr, BinaryOp):
            self._check_all_patterns(expr.left, func, loc)
            self._check_all_patterns(expr.right, func, loc)
        elif isinstance(expr, FunctionCall):
            for arg in expr.args:
                self._check_all_patterns(arg, func, loc)
        elif isinstance(expr, MethodCall):
            self._check_all_patterns(expr.obj, func, loc)
            for arg in expr.args:
                self._check_all_patterns(arg, func, loc)
        elif isinstance(expr, FieldAccess):
            self._check_all_patterns(expr.obj, func, loc)

    # ------------------------------------------------------------------
    # 1. Server-Side Template Injection (SSTI)
    # ------------------------------------------------------------------

    def _check_ssti(self, expr: Expr, func: PureFunc | TaskFunc,
                    loc: SourceLocation) -> None:
        """Detect user input passed to template compilation/rendering functions."""
        func_name = self._get_callable_name(expr)
        if not func_name:
            return

        func_lower = func_name.lower()

        # Check if the function is a template compiler/renderer
        is_template_func = any(t in func_lower for t in _SSTI_LOWER)

        if not is_template_func:
            return

        # Check if any argument contains user-derived data
        args = self._get_call_args(expr)
        for arg in args:
            if self._expr_uses_user_var(arg):
                user_var = self._identify_user_var(arg)
                self.findings.append(Finding(
                    category=InjectionCategory.SSTI,
                    source_var=user_var,
                    sink_name=func_name,
                    detail=(
                        f"User-controlled variable '{user_var}' is passed to "
                        f"template engine '{func_name}'. An attacker can inject "
                        f"template syntax to execute arbitrary code on the server."
                    ),
                    location=loc,
                    func_name=func.name,
                ))
                return  # One finding per call site

    # ------------------------------------------------------------------
    # 2. Header Injection / HTTP Response Splitting
    # ------------------------------------------------------------------

    def _check_header_injection(self, expr: Expr, func: PureFunc | TaskFunc,
                                loc: SourceLocation) -> None:
        """Detect user input in HTTP headers without CRLF sanitization."""
        if not isinstance(expr, MethodCall):
            return

        method_lower = expr.method_name.lower()
        is_header_setter = any(h.lower() == method_lower for h in HEADER_SETTERS)

        if not is_header_setter:
            return

        # Check if the header value argument contains user input
        # Typical pattern: response.setHeader("Location", userInput)
        # The value is usually the last argument
        for arg in expr.args:
            if self._expr_uses_user_var(arg):
                user_var = self._identify_user_var(arg)
                header_name = self._extract_header_name(expr)
                detail_suffix = ""
                if header_name and header_name.lower() in DANGEROUS_HEADERS:
                    if header_name.lower() == "location":
                        detail_suffix = (
                            " The Location header with user input enables "
                            "open redirect attacks."
                        )
                    elif header_name.lower() == "set-cookie":
                        detail_suffix = (
                            " User-controlled Set-Cookie values allow "
                            "session fixation and cookie injection."
                        )

                self.findings.append(Finding(
                    category=InjectionCategory.HEADER,
                    source_var=user_var,
                    sink_name=f"{expr.method_name}({header_name or 'header'})",
                    detail=(
                        f"User-controlled variable '{user_var}' is used in HTTP "
                        f"header value via '{expr.method_name}' without CRLF "
                        f"sanitization. An attacker can inject \\r\\n to split "
                        f"the response and control headers or body.{detail_suffix}"
                    ),
                    location=loc,
                    func_name=func.name,
                ))
                return

    def _extract_header_name(self, expr: MethodCall) -> Optional[str]:
        """Extract the header name from a setHeader-style call."""
        if expr.args and isinstance(expr.args[0], StringLiteral):
            return expr.args[0].value
        return None

    # ------------------------------------------------------------------
    # 3. Log Injection / Log Forging
    # ------------------------------------------------------------------

    def _check_log_injection(self, expr: Expr, func: PureFunc | TaskFunc,
                             loc: SourceLocation) -> None:
        """Detect user input passed directly to logging functions."""
        func_name = self._get_callable_name(expr)
        if not func_name:
            return

        func_lower = func_name.lower()

        # Check against log functions (exact match or suffix match)
        is_log_func = False
        for log_fn in _LOG_LOWER:
            # Match "logger.info" via full name, or "info" via method name
            if func_lower == log_fn or func_lower.endswith("." + log_fn):
                is_log_func = True
                break
            # Also match method calls like logger.info
            if isinstance(expr, MethodCall) and expr.method_name.lower() == log_fn:
                is_log_func = True
                break

        if not is_log_func:
            return

        # Check if any argument contains user-derived data
        args = self._get_call_args(expr)
        for arg in args:
            if self._expr_uses_user_var(arg):
                user_var = self._identify_user_var(arg)
                self.findings.append(Finding(
                    category=InjectionCategory.LOG,
                    source_var=user_var,
                    sink_name=func_name,
                    detail=(
                        f"User-controlled variable '{user_var}' is passed to "
                        f"logging function '{func_name}' without sanitization. "
                        f"An attacker can inject newlines to forge log entries, "
                        f"ANSI escape sequences to exploit log viewers, or "
                        f"format string specifiers to cause crashes."
                    ),
                    location=loc,
                    func_name=func.name,
                ))
                return

    # ------------------------------------------------------------------
    # 4. NoSQL Injection
    # ------------------------------------------------------------------

    def _check_nosql_injection(self, expr: Expr, func: PureFunc | TaskFunc,
                               loc: SourceLocation) -> None:
        """Detect user input in MongoDB-style NoSQL queries."""
        if not isinstance(expr, MethodCall):
            return

        method_lower = expr.method_name.lower()
        is_query_method = method_lower in _NOSQL_LOWER

        if not is_query_method:
            return

        # Check if arguments (query filters) contain user-derived data
        for arg in expr.args:
            if self._expr_uses_user_var(arg):
                user_var = self._identify_user_var(arg)
                self.findings.append(Finding(
                    category=InjectionCategory.NOSQL,
                    source_var=user_var,
                    sink_name=f"{expr.method_name}",
                    detail=(
                        f"User-controlled variable '{user_var}' is passed to "
                        f"NoSQL query method '{expr.method_name}'. An attacker "
                        f"can inject query operators like $gt, $ne, $regex to "
                        f"bypass authentication or extract data. Use explicit "
                        f"field-value matching and validate input types."
                    ),
                    location=loc,
                    func_name=func.name,
                ))
                return

    # ------------------------------------------------------------------
    # 5. LDAP Injection
    # ------------------------------------------------------------------

    def _check_ldap_injection(self, expr: Expr, func: PureFunc | TaskFunc,
                              loc: SourceLocation) -> None:
        """Detect user input in LDAP queries."""
        # Check 1: LDAP function calls with user input in filter argument
        func_name = self._get_callable_name(expr)
        if func_name and func_name.lower() in _LDAP_LOWER:
            args = self._get_call_args(expr)
            for arg in args:
                if self._expr_uses_user_var(arg):
                    user_var = self._identify_user_var(arg)
                    self.findings.append(Finding(
                        category=InjectionCategory.LDAP,
                        source_var=user_var,
                        sink_name=func_name,
                        detail=(
                            f"User-controlled variable '{user_var}' is passed to "
                            f"LDAP function '{func_name}'. An attacker can inject "
                            f"LDAP filter metacharacters (*, (, ), \\, NUL) to "
                            f"modify the query logic, bypass authentication, or "
                            f"enumerate directory entries."
                        ),
                        location=loc,
                        func_name=func.name,
                    ))
                    return

        # Check 2: String concatenation with LDAP filter patterns
        if isinstance(expr, BinaryOp) and expr.op in ("+", "++", "~", ".."):
            ldap_pattern_found = self._contains_ldap_pattern(expr)
            if ldap_pattern_found and self._expr_uses_user_var(expr):
                user_var = self._identify_user_var(expr)
                self.findings.append(Finding(
                    category=InjectionCategory.LDAP,
                    source_var=user_var,
                    sink_name="LDAP filter concatenation",
                    detail=(
                        f"User-controlled variable '{user_var}' is concatenated "
                        f"into an LDAP filter string. This allows an attacker to "
                        f"inject LDAP metacharacters and alter query semantics. "
                        f"Use parameterized LDAP queries or escape user input."
                    ),
                    location=loc,
                    func_name=func.name,
                ))

    def _contains_ldap_pattern(self, expr: Expr) -> bool:
        """Check if an expression contains LDAP filter string patterns."""
        if isinstance(expr, StringLiteral):
            val = expr.value
            return any(pat in val for pat in LDAP_FILTER_PATTERNS)
        if isinstance(expr, BinaryOp):
            return (self._contains_ldap_pattern(expr.left) or
                    self._contains_ldap_pattern(expr.right))
        return False

    # ------------------------------------------------------------------
    # 6. XML External Entity (XXE)
    # ------------------------------------------------------------------

    def _check_xxe(self, expr: Expr, func: PureFunc | TaskFunc,
                   loc: SourceLocation) -> None:
        """Detect XML parsing without disabled external entities."""
        func_name = self._get_callable_name(expr)
        if not func_name:
            return

        func_lower = func_name.lower()

        # Check for safe parser usage (defusedxml, etc.)
        if any(safe in func_lower for safe in _XXE_SAFE_LOWER):
            self._safe_xml_context = True
            return

        # Check if this is a known vulnerable XML parser
        is_vulnerable_parser = any(p in func_lower for p in _XXE_LOWER)

        if not is_vulnerable_parser:
            return

        # If we previously saw defusedxml or safe configuration in this
        # function, suppress the finding
        if self._safe_xml_context:
            return

        # Python's stdlib XML modules are vulnerable by default
        is_python_stdlib = any(
            mod in func_lower for mod in
            ("xml.etree", "xml.sax", "xml.dom.minidom", "xml.dom.pulldom",
             "elementtree", "et.parse", "et.fromstring")
        )

        detail_extra = ""
        if is_python_stdlib:
            detail_extra = (
                " Python's xml.etree, xml.sax, xml.dom.minidom, and "
                "xml.dom.pulldom are vulnerable to XXE by default. "
                "Use defusedxml as a drop-in replacement."
            )

        self.findings.append(Finding(
            category=InjectionCategory.XXE,
            source_var="xml_input",
            sink_name=func_name,
            detail=(
                f"XML parser '{func_name}' is used without explicitly disabling "
                f"external entity processing or DTD loading. An attacker can "
                f"supply a crafted XML document with a malicious DOCTYPE to read "
                f"local files, perform SSRF, or cause denial of service."
                f"{detail_extra}"
            ),
            location=loc,
            func_name=func.name,
        ))

    # ------------------------------------------------------------------
    # 7. ReDoS (Regular Expression Denial of Service)
    # ------------------------------------------------------------------

    def _check_redos(self, expr: Expr, func: PureFunc | TaskFunc,
                     loc: SourceLocation) -> None:
        """Detect regex patterns with catastrophic backtracking potential."""
        func_name = self._get_callable_name(expr)
        if not func_name:
            return

        func_lower = func_name.lower()

        # Check if this is a regex compilation/matching function
        is_regex_func = any(r in func_lower for r in _REGEX_LOWER)

        if not is_regex_func:
            return

        # Look for string literal arguments that contain dangerous patterns
        args = self._get_call_args(expr)
        for arg in args:
            if isinstance(arg, StringLiteral):
                pattern_str = arg.value
                danger = self._analyze_regex_danger(pattern_str)
                if danger:
                    self.findings.append(Finding(
                        category=InjectionCategory.REDOS,
                        source_var=f"regex:{pattern_str[:60]}",
                        sink_name=func_name,
                        detail=(
                            f"Regular expression '{pattern_str}' compiled by "
                            f"'{func_name}' contains a pattern vulnerable to "
                            f"catastrophic backtracking: {danger}. An attacker "
                            f"who controls the input string can cause exponential "
                            f"CPU consumption, leading to denial of service."
                        ),
                        location=loc,
                        func_name=func.name,
                    ))
                    return

    def _analyze_regex_danger(self, pattern: str) -> Optional[str]:
        """Analyze a regex pattern string for ReDoS vulnerabilities.

        Returns a human-readable description of the danger, or None if safe.
        """
        # Check for nested quantifiers: (a+)+, (a*)+, (a+)*, (a*)*
        if re.search(r'\([^)]*[+*]\)\s*[+*]', pattern):
            return "nested quantifiers (e.g., (x+)+ or (x*)*) cause exponential backtracking"

        # Check for overlapping alternation with quantifier
        # e.g., (a|a)+, (ab|ab)+
        if re.search(r'\(([^|)]+)\|\1[^)]*\)\s*[+*]', pattern):
            return "overlapping alternation with quantifier (e.g., (a|a)+) creates ambiguous paths"

        # Check for quantified groups containing multiple quantified elements
        # e.g., (a+b+)+, (.*.*)+
        if re.search(r'\([^)]*[+*][^)]*[+*][^)]*\)\s*[+*]', pattern):
            return "group with multiple quantified elements under a quantifier (e.g., (a+b+)+)"

        # Check for star-of-star or plus-of-plus without grouping
        # e.g., a** or a++
        if re.search(r'(?<!\\)[^\\(][*+]\s*[*+]', pattern):
            return "consecutive quantifiers (e.g., a** or a++) indicate backtracking risk"

        # Check for repetition of dot-star: (.*)+
        if re.search(r'\(\.\*\)\s*[+*]', pattern):
            return "quantified dot-star group (.*)+  matches everything with exponential paths"

        # Check for common dangerous patterns
        # (.+)+ or (.*)+ or (.+)* or (.*)*
        if re.search(r'\(\.[+*]\)\s*[+*]', pattern):
            return "quantified dot-quantifier group (e.g., (.+)+ or (.*)+)"

        # Check for \\s+ followed by \\s in a group with quantifier
        if re.search(r'\([^)]*\\s[+*][^)]*\\s[^)]*\)\s*[+*]', pattern):
            return "overlapping whitespace quantifiers in a repeated group"

        return None

    # ------------------------------------------------------------------
    # 8. Expression Language Injection
    # ------------------------------------------------------------------

    def _check_expr_lang_injection(self, expr: Expr, func: PureFunc | TaskFunc,
                                   loc: SourceLocation) -> None:
        """Detect user input in eval/exec/compile/Function calls."""
        func_name = self._get_callable_name(expr)
        if not func_name:
            return

        func_lower = func_name.lower()

        # Check against expression evaluation functions
        is_eval_func = func_lower in _EXPR_EVAL_LOWER

        if not is_eval_func:
            return

        # Special case: setTimeout/setInterval only dangerous with string arg
        if func_lower in ("settimeout", "setinterval"):
            args = self._get_call_args(expr)
            if not args:
                return
            first_arg = args[0]
            # If the first argument is not a string/user-var, it is a
            # callback function reference and is safe
            if not (isinstance(first_arg, StringLiteral) or
                    self._expr_uses_user_var(first_arg)):
                return

        # Check if any argument contains user-derived data
        args = self._get_call_args(expr)
        for arg in args:
            if self._expr_uses_user_var(arg):
                user_var = self._identify_user_var(arg)
                self.findings.append(Finding(
                    category=InjectionCategory.EXPR_LANG,
                    source_var=user_var,
                    sink_name=func_name,
                    detail=(
                        f"User-controlled variable '{user_var}' is passed to "
                        f"expression evaluator '{func_name}'. An attacker can "
                        f"inject arbitrary code for execution. This is equivalent "
                        f"to remote code execution (RCE) in most contexts."
                    ),
                    location=loc,
                    func_name=func.name,
                ))
                return

        # Also flag Spring EL / OGNL patterns in string literals
        for arg in args:
            if isinstance(arg, StringLiteral):
                val = arg.value
                # Spring EL: #{...}, ${...}
                if re.search(r'[#$]\{.*\}', val):
                    self.findings.append(Finding(
                        category=InjectionCategory.EXPR_LANG,
                        source_var=f"template_expr:{val[:40]}",
                        sink_name=func_name,
                        detail=(
                            f"Expression language syntax ('${{...}}' or '#{{...}}') "
                            f"found in argument to '{func_name}'. If any part of "
                            f"this expression is user-controlled, it enables "
                            f"arbitrary code execution via EL injection."
                        ),
                        location=loc,
                        func_name=func.name,
                    ))
                    return

    # ------------------------------------------------------------------
    # 9. Open Redirect
    # ------------------------------------------------------------------

    def _check_open_redirect(self, expr: Expr, func: PureFunc | TaskFunc,
                             loc: SourceLocation) -> None:
        """Detect user-controlled redirect URLs without domain validation."""
        func_name = self._get_callable_name(expr)
        if not func_name:
            return

        func_lower = func_name.lower()

        # Check if this is a redirect function
        is_redirect = any(r in func_lower for r in _REDIRECT_LOWER)

        if not is_redirect:
            return

        # Check if arguments contain user-derived data
        args = self._get_call_args(expr)
        for arg in args:
            if self._expr_uses_user_var(arg):
                user_var = self._identify_user_var(arg)
                self.findings.append(Finding(
                    category=InjectionCategory.OPEN_REDIRECT,
                    source_var=user_var,
                    sink_name=func_name,
                    detail=(
                        f"User-controlled variable '{user_var}' is used as the "
                        f"redirect target in '{func_name}' without domain "
                        f"validation. An attacker can redirect users to a "
                        f"malicious site for phishing or credential theft. "
                        f"Validate against an allowlist of trusted domains."
                    ),
                    location=loc,
                    func_name=func.name,
                ))
                return

    # ------------------------------------------------------------------
    # Utility Methods
    # ------------------------------------------------------------------

    def _get_callable_name(self, expr: Expr) -> Optional[str]:
        """Extract the callable name from a function/method call expression."""
        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                return expr.callee.name
            if isinstance(expr.callee, FieldAccess):
                # e.g., jinja2.Template -> "jinja2.Template"
                obj_name = self._expr_to_name(expr.callee.obj)
                if obj_name:
                    return f"{obj_name}.{expr.callee.field_name}"
                return expr.callee.field_name
        elif isinstance(expr, MethodCall):
            obj_name = self._expr_to_name(expr.obj)
            if obj_name:
                return f"{obj_name}.{expr.method_name}"
            return expr.method_name
        return None

    def _expr_to_name(self, expr: Expr) -> Optional[str]:
        """Convert an expression to a dotted name string, if possible."""
        if isinstance(expr, Identifier):
            return expr.name
        if isinstance(expr, FieldAccess):
            obj_name = self._expr_to_name(expr.obj)
            if obj_name:
                return f"{obj_name}.{expr.field_name}"
            return expr.field_name
        return None

    def _get_call_args(self, expr: Expr) -> List[Expr]:
        """Extract arguments from a function/method call."""
        if isinstance(expr, (FunctionCall, MethodCall)):
            return expr.args
        return []

    def _expr_uses_user_var(self, expr: Expr) -> bool:
        """Check whether an expression references any user-input variable."""
        if isinstance(expr, Identifier):
            return expr.name in self._user_vars

        if isinstance(expr, BinaryOp):
            return (self._expr_uses_user_var(expr.left) or
                    self._expr_uses_user_var(expr.right))

        if isinstance(expr, FunctionCall):
            return any(self._expr_uses_user_var(a) for a in expr.args)

        if isinstance(expr, MethodCall):
            return (self._expr_uses_user_var(expr.obj) or
                    any(self._expr_uses_user_var(a) for a in expr.args))

        if isinstance(expr, FieldAccess):
            return self._expr_uses_user_var(expr.obj)

        return False

    def _identify_user_var(self, expr: Expr) -> str:
        """Find the specific user-input variable name within an expression."""
        if isinstance(expr, Identifier) and expr.name in self._user_vars:
            return expr.name

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

        if isinstance(expr, FieldAccess):
            return self._identify_user_var(expr.obj)

        return "<user_input>"

    def _findings_to_errors(self) -> List[AeonError]:
        """Convert internal findings to AeonError objects."""
        errors: List[AeonError] = []
        # Deduplicate: same category + sink + function = one finding
        seen: Set[Tuple[str, str, str]] = set()

        for f in self.findings:
            key = (f.category.value, f.sink_name, f.func_name)
            if key in seen:
                continue
            seen.add(key)

            cwe = CWE_MAP[f.category]
            owasp = OWASP_MAP[f.category]
            severity = SEVERITY_MAP[f.category]
            remediation = REMEDIATION_MAP[f.category]
            vuln_name = f.category.value.replace("_", " ").title()

            errors.append(contract_error(
                precondition=(
                    f"Advanced injection: {vuln_name} — "
                    f"{f.detail}"
                ),
                failing_values={
                    "vulnerability": f.category.value,
                    "cwe": cwe,
                    "owasp": owasp,
                    "severity": severity,
                    "source": f.source_var,
                    "sink": f.sink_name,
                    "remediation": remediation,
                    "engine": "Injection Advanced",
                },
                function_signature=f.func_name,
                location=f.location,
            ))

        return errors


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_injection_advanced(program: Program) -> list:
    """Run advanced injection detection on an AEON program.

    Complements the core taint analysis engine by detecting structural
    and pattern-based injection vectors:

    - Server-Side Template Injection (SSTI) — CWE-94
    - HTTP Header Injection / Response Splitting — CWE-113
    - Log Injection / Log Forging — CWE-117
    - NoSQL Injection — CWE-943
    - LDAP Injection — CWE-90
    - XML External Entity (XXE) — CWE-611
    - ReDoS (Regex Denial of Service) — CWE-1333
    - Expression Language Injection — CWE-94
    - Open Redirect — CWE-601

    Each finding includes CWE, OWASP category, severity, and remediation.
    """
    analyzer = AdvancedInjectionAnalyzer()
    return analyzer.check_program(program)
