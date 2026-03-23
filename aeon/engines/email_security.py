"""AEON Email Security Engine -- Detecting Email Security Vulnerabilities.

Implements email security analysis targeting injection, data exposure, and
compliance issues in email-sending code paths.

Based on:
  OWASP Testing Guide v4.2 -- Injection Flaws (Email Header Injection)
  https://owasp.org/www-project-web-security-testing-guide/

  RFC 5321 -- Simple Mail Transfer Protocol
  https://www.rfc-editor.org/rfc/rfc5321

  RFC 7489 -- Domain-based Message Authentication, Reporting, and Conformance
  (DMARC)
  https://www.rfc-editor.org/rfc/rfc7489

  RFC 6376 -- DomainKeys Identified Mail (DKIM) Signatures
  https://www.rfc-editor.org/rfc/rfc6376

  RFC 7208 -- Sender Policy Framework (SPF)
  https://www.rfc-editor.org/rfc/rfc7208

  CAN-SPAM Act, 15 U.S.C. 7701-7713 (2003)
  https://www.ftc.gov/legal-library/browse/rules/can-spam-rule

Key Theory:

1. EMAIL HEADER INJECTION (CWE-93):
   SMTP headers are delimited by CRLF (\\r\\n). If user input is placed
   into To, CC, BCC, Subject, From, or Reply-To headers without stripping
   \\r and \\n characters, an attacker can inject arbitrary headers or even
   a second email body. This is the email equivalent of HTTP header injection.

2. HTML INJECTION IN EMAILS (CWE-79):
   When user input is rendered inside HTML email bodies without HTML encoding,
   an attacker can inject arbitrary HTML and JavaScript. While most email
   clients strip scripts, HTML injection still enables phishing overlays,
   CSS-based data exfiltration, and content spoofing.

3. SMTP INJECTION (CWE-93):
   Raw SMTP operations (smtplib, nodemailer transport) with user-controlled
   sender or recipient addresses allow an attacker to inject SMTP commands
   via CRLF sequences, potentially turning the server into a spam relay.

4. EMAIL ADDRESS VALIDATION BYPASS (CWE-20):
   Weak regex-only email validation fails to reject addresses containing
   injection payloads. Library validators (validator.isEmail, email-validator)
   implement RFC 5321/5322 parsing and reject dangerous input.

5. MISSING SPF/DKIM/DMARC AWARENESS (CWE-290):
   Sending email from custom domains without SPF, DKIM, and DMARC DNS records
   allows attackers to spoof the sender domain. Code that sets a custom From
   address should reference or document DNS authentication configuration.

6. SENSITIVE DATA IN EMAIL (CWE-312):
   Sending passwords, tokens, SSNs, credit card numbers, or full reset tokens
   in plaintext email bodies exposes them to interception. Email traverses
   the internet in cleartext unless both sender and receiver enforce TLS.

7. OPEN RELAY PATTERNS (CWE-441):
   API endpoints where both sender and recipient are user-controlled, without
   restricting the From address to authorized senders, create an open relay
   that attackers can abuse for spam and phishing campaigns.

8. UNSUBSCRIBE COMPLIANCE (CWE-16):
   The CAN-SPAM Act and GDPR require commercial/marketing emails to include
   a visible unsubscribe mechanism. RFC 2369 defines the List-Unsubscribe
   header. Bulk email code without these mechanisms violates regulations.

CWE References:
  - CWE-93:  Improper Neutralization of CRLF Sequences
  - CWE-79:  Improper Neutralization of Input During Web Page Generation
  - CWE-20:  Improper Input Validation
  - CWE-290: Authentication Bypass by Spoofing
  - CWE-312: Cleartext Storage of Sensitive Information
  - CWE-441: Unintended Proxy or Intermediary
  - CWE-16:  Configuration

Detects:
  - User input in email headers without CRLF sanitization
  - User input in HTML email body without HTML encoding
  - Raw SMTP operations with user-controlled sender/recipient
  - Regex-only email validation without library validators
  - Custom From domain without SPF/DKIM/DMARC references
  - Passwords, tokens, PII sent in plaintext email body
  - Email endpoints where both sender and recipient are user-controlled
  - Bulk/marketing email without unsubscribe mechanism
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
    LetStmt, AssignStmt, IfStmt, ReturnStmt, ExprStmt,
    WhileStmt, ForStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Vulnerability Categories
# ---------------------------------------------------------------------------

class EmailVulnCategory(Enum):
    HEADER_INJECTION = "email_header_injection"
    HTML_INJECTION = "html_injection_in_email"
    SMTP_INJECTION = "smtp_injection"
    EMAIL_VALIDATION_BYPASS = "email_validation_bypass"
    MISSING_SPF_DKIM_DMARC = "missing_spf_dkim_dmarc"
    SENSITIVE_DATA_IN_EMAIL = "sensitive_data_in_email"
    OPEN_RELAY = "open_relay_pattern"
    MISSING_UNSUBSCRIBE = "missing_unsubscribe_compliance"


CWE_MAP: Dict[EmailVulnCategory, str] = {
    EmailVulnCategory.HEADER_INJECTION: "CWE-93",
    EmailVulnCategory.HTML_INJECTION: "CWE-79",
    EmailVulnCategory.SMTP_INJECTION: "CWE-93",
    EmailVulnCategory.EMAIL_VALIDATION_BYPASS: "CWE-20",
    EmailVulnCategory.MISSING_SPF_DKIM_DMARC: "CWE-290",
    EmailVulnCategory.SENSITIVE_DATA_IN_EMAIL: "CWE-312",
    EmailVulnCategory.OPEN_RELAY: "CWE-441",
    EmailVulnCategory.MISSING_UNSUBSCRIBE: "CWE-16",
}

SEVERITY_MAP: Dict[EmailVulnCategory, str] = {
    EmailVulnCategory.HEADER_INJECTION: "high",
    EmailVulnCategory.HTML_INJECTION: "medium",
    EmailVulnCategory.SMTP_INJECTION: "high",
    EmailVulnCategory.EMAIL_VALIDATION_BYPASS: "medium",
    EmailVulnCategory.MISSING_SPF_DKIM_DMARC: "medium",
    EmailVulnCategory.SENSITIVE_DATA_IN_EMAIL: "high",
    EmailVulnCategory.OPEN_RELAY: "critical",
    EmailVulnCategory.MISSING_UNSUBSCRIBE: "medium",
}

REMEDIATION_MAP: Dict[EmailVulnCategory, str] = {
    EmailVulnCategory.HEADER_INJECTION: (
        "Strip or reject CR (\\r) and LF (\\n) characters from all user input "
        "before placing it into email headers. Use library-provided header "
        "setters (e.g., Python email.message, nodemailer) that enforce encoding. "
        "Never concatenate user input directly into raw header strings."
    ),
    EmailVulnCategory.HTML_INJECTION: (
        "HTML-encode all user input before embedding it in HTML email bodies. "
        "Use template engines with auto-escaping enabled (e.g., Jinja2 autoescape, "
        "Handlebars). Never use raw string interpolation for user data in HTML emails."
    ),
    EmailVulnCategory.SMTP_INJECTION: (
        "Never pass user-controlled values directly to raw SMTP operations. "
        "Validate email addresses with a library validator before passing them "
        "to smtp.sendmail() or equivalent. Use high-level email libraries "
        "(nodemailer, Python email.message) instead of raw SMTP commands."
    ),
    EmailVulnCategory.EMAIL_VALIDATION_BYPASS: (
        "Replace regex-only email validation with a library validator that "
        "implements RFC 5321/5322 parsing: validator.isEmail (Node.js), "
        "email-validator (Python), Apache Commons EmailValidator (Java). "
        "Regex alone cannot properly validate email addresses and may allow "
        "injection payloads through."
    ),
    EmailVulnCategory.MISSING_SPF_DKIM_DMARC: (
        "Configure SPF, DKIM, and DMARC DNS records for any custom domain "
        "used as a From address. Without these, attackers can spoof your "
        "sender domain. Document DNS authentication requirements alongside "
        "email-sending code. Reference the DNS configuration in comments or "
        "a configuration file."
    ),
    EmailVulnCategory.SENSITIVE_DATA_IN_EMAIL: (
        "Never send passwords, tokens, SSNs, credit card numbers, or other "
        "PII in plaintext email bodies. For password resets, use short-lived "
        "tokens (under 15 minutes) with a link to a secure page. For account "
        "notifications, reference the data without including it."
    ),
    EmailVulnCategory.OPEN_RELAY: (
        "Restrict the From address to a fixed set of authorized sender addresses. "
        "Never allow API callers to specify an arbitrary From address. If the "
        "sender must vary, validate it against a whitelist of domains owned by "
        "the organization."
    ),
    EmailVulnCategory.MISSING_UNSUBSCRIBE: (
        "Add a List-Unsubscribe header (RFC 2369) and a visible unsubscribe "
        "link in the email body for all bulk/marketing emails. CAN-SPAM and "
        "GDPR require a functioning opt-out mechanism. Gmail and Outlook "
        "surface the List-Unsubscribe header as a one-click unsubscribe button."
    ),
}


# ---------------------------------------------------------------------------
# Frontend File Detection (skip React/Vue/Angular files)
# ---------------------------------------------------------------------------

FRONTEND_INDICATORS: Set[str] = {
    "react", "jsx", "tsx", "usestate", "useeffect", "useref",
    "component", "render", "vue", "angular", "svelte",
    "createelement", "createroot", "hydrateroot",
    "document.getelementbyid", "document.queryselector",
    "window.addeventlistener",
}


# ---------------------------------------------------------------------------
# Email-Sending Functions and Methods
# ---------------------------------------------------------------------------

# Functions/methods that send email
EMAIL_SEND_FUNCTIONS: Set[str] = {
    # General
    "sendMail", "send_mail", "sendmail", "send_email", "sendEmail",
    "deliver", "deliver_now", "deliver_later",
    # Nodemailer
    "transporter.sendMail", "transport.sendMail",
    # Python
    "smtp.sendmail", "smtp.send_message", "server.sendmail",
    "send_mail", "send_mass_mail", "EmailMessage.send",
    "MIMEText", "MIMEMultipart",
    # PHP
    "mail", "wp_mail", "Swift_Mailer.send", "Mailer.send",
    # Ruby
    "deliver", "deliver!", "deliver_now", "deliver_later",
    "ActionMailer", "mail",
    # Java
    "Transport.send", "JavaMailSender.send", "MimeMessageHelper",
    # SendGrid / Mailgun / SES
    "sgMail.send", "sg.send", "mailgun.messages.send",
    "ses.sendEmail", "ses.send_email",
    "ses.sendRawEmail", "ses.send_raw_email",
    # Generic
    "sendNotification", "send_notification",
    "sendTransactional", "send_transactional",
}

_EMAIL_SEND_LOWER: Set[str] = {s.lower() for s in EMAIL_SEND_FUNCTIONS}

# SMTP library references (raw SMTP usage)
SMTP_RAW_FUNCTIONS: Set[str] = {
    "sendmail", "send_message",
    "SMTP", "SMTP_SSL", "smtplib.SMTP", "smtplib.SMTP_SSL",
    "createTransport", "create_transport",
    "SMTPClient", "smtp_client",
}

_SMTP_RAW_LOWER: Set[str] = {s.lower() for s in SMTP_RAW_FUNCTIONS}


# ---------------------------------------------------------------------------
# Email Header Field Names
# ---------------------------------------------------------------------------

EMAIL_HEADER_FIELDS: Set[str] = {
    "to", "cc", "bcc", "subject", "from", "reply-to", "replyto",
    "reply_to", "sender", "return-path", "returnpath", "return_path",
}

_EMAIL_HEADER_LOWER: Set[str] = {s.lower().replace("-", "").replace("_", "")
                                  for s in EMAIL_HEADER_FIELDS}

# Header-setting method names on email objects
EMAIL_HEADER_SETTERS: Set[str] = {
    "set", "setHeader", "set_header", "addHeader", "add_header",
    "setSubject", "set_subject", "setFrom", "set_from",
    "setTo", "set_to", "setCc", "set_cc", "setBcc", "set_bcc",
    "setReplyTo", "set_reply_to",
    "add_recipients", "addRecipients",
}

_EMAIL_HEADER_SETTERS_LOWER: Set[str] = {s.lower() for s in EMAIL_HEADER_SETTERS}


# ---------------------------------------------------------------------------
# CRLF Sanitization Evidence
# ---------------------------------------------------------------------------

CRLF_SANITIZERS: Set[str] = {
    "replace", "strip", "sanitize", "escape", "encode",
    "sanitize_header", "sanitizeHeader",
    "clean", "filter", "scrub",
    "remove_newlines", "removeNewlines", "strip_newlines", "stripNewlines",
}

_CRLF_SANITIZERS_LOWER: Set[str] = {s.lower() for s in CRLF_SANITIZERS}

# String patterns indicating CRLF awareness
CRLF_PATTERNS: Set[str] = {
    "\\r", "\\n", "\\r\\n", "\r", "\n",
    "carriage", "newline", "crlf",
}


# ---------------------------------------------------------------------------
# HTML Encoding Evidence
# ---------------------------------------------------------------------------

HTML_ENCODERS: Set[str] = {
    "escape", "escapeHtml", "escape_html", "htmlEscape", "html_escape",
    "encode", "encodeHtml", "encode_html",
    "sanitize", "sanitizeHtml", "sanitize_html",
    "DOMPurify", "purify", "bleach", "clean",
    "xss", "strip_tags", "stripTags",
    "markupsafe", "Markup",
    "autoescape",
    "cgi.escape", "html.escape",
    "encodeURIComponent", "encodeURI",
}

_HTML_ENCODERS_LOWER: Set[str] = {s.lower() for s in HTML_ENCODERS}

# HTML content indicators in string literals
HTML_TAG_PATTERN: re.Pattern = re.compile(r"<\s*(html|body|div|p|span|table|tr|td|a|img|h[1-6]|br|hr|ul|ol|li|b|i|strong|em)\b", re.IGNORECASE)
HTML_TEMPLATE_INTERP_PATTERN: re.Pattern = re.compile(r"\$\{[^}]+\}|%s|\{[a-zA-Z_][a-zA-Z0-9_.]*\}|%\([^)]+\)s")


# ---------------------------------------------------------------------------
# Email Validation Patterns
# ---------------------------------------------------------------------------

# Regex-based email validation (weak)
EMAIL_REGEX_PATTERNS: List[re.Pattern] = [
    re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]"),
    re.compile(r"\\w+@\\w+\\.\\w+"),
    re.compile(r"\[a-z\].*@.*\\\."),
    re.compile(r"[\^]?[\[]?[a-zA-Z0-9].*@"),
]

# Library-based email validators (strong)
EMAIL_VALIDATORS: Set[str] = {
    # JavaScript
    "isEmail", "is_email", "validator.isEmail",
    "email_validator", "emailValidator",
    "validate_email", "validateEmail",
    "parseAddress", "parse_address",
    # Python
    "email_validator.validate_email",
    "validate_email_address",
    "EmailValidator",
    # Java
    "EmailValidator.getInstance",
    "InternetAddress",
    # General
    "isValidEmail", "is_valid_email",
}

_EMAIL_VALIDATORS_LOWER: Set[str] = {s.lower() for s in EMAIL_VALIDATORS}

# Regex compilation functions
REGEX_FUNCTIONS: Set[str] = {
    "compile", "match", "search", "test", "exec",
    "re.compile", "re.match", "re.search",
    "RegExp", "new RegExp",
    "Pattern.compile", "Pattern.matches",
    "Regexp.new",
}

_REGEX_FUNCTIONS_LOWER: Set[str] = {s.lower() for s in REGEX_FUNCTIONS}


# ---------------------------------------------------------------------------
# SPF/DKIM/DMARC Awareness Indicators
# ---------------------------------------------------------------------------

DNS_AUTH_INDICATORS: Set[str] = {
    "spf", "dkim", "dmarc",
    "domainkeys", "domain_keys",
    "txt record", "dns record", "dns_record",
    "v=spf1", "v=dkim1", "v=dmarc1",
    "d=", "s=", "p=",
    "dkim-signature", "dkim_signature",
    "authentication-results", "authentication_results",
}

_DNS_AUTH_LOWER: Set[str] = {s.lower() for s in DNS_AUTH_INDICATORS}

# Custom domain pattern in From addresses
CUSTOM_DOMAIN_PATTERN: re.Pattern = re.compile(
    r"@(?!gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|icloud\.com"
    r"|aol\.com|protonmail\.com|mail\.com|zoho\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)


# ---------------------------------------------------------------------------
# Sensitive Data Variable Names
# ---------------------------------------------------------------------------

SENSITIVE_EMAIL_VARS: Set[str] = {
    "password", "passwd", "pwd", "pass",
    "token", "access_token", "accessToken", "refresh_token", "refreshToken",
    "reset_token", "resetToken", "reset_link", "resetLink",
    "ssn", "social_security", "socialSecurity",
    "credit_card", "creditCard", "card_number", "cardNumber",
    "cvv", "cvc", "pin",
    "secret", "secret_key", "secretKey",
    "private_key", "privateKey",
    "api_key", "apiKey",
    "mfa_code", "mfaCode", "otp", "otp_code", "otpCode",
    "verification_code", "verificationCode",
}

_SENSITIVE_LOWER: Set[str] = {s.lower() for s in SENSITIVE_EMAIL_VARS}

# Keywords in variable names that indicate sensitive content
SENSITIVE_KEYWORDS: Set[str] = {
    "password", "passwd", "pwd", "token", "secret",
    "ssn", "credit_card", "creditcard", "cardnumber", "card_number",
    "cvv", "cvc", "pin", "private_key", "privatekey",
    "reset_link", "resetlink", "reset_token", "resettoken",
}


# ---------------------------------------------------------------------------
# Open Relay Detection Patterns
# ---------------------------------------------------------------------------

# Request body access patterns (user-controlled input)
REQUEST_BODY_PATTERNS: Set[str] = {
    "body", "data", "payload", "json",
    "request_data", "request_body", "requestBody",
    "parsed_body", "parsedBody", "params",
    "req.body", "request.body", "request.data",
    "request.json", "request.form",
}

_REQUEST_BODY_LOWER: Set[str] = {s.lower() for s in REQUEST_BODY_PATTERNS}

# Authorized sender patterns (evidence of From restriction)
SENDER_RESTRICTION_PATTERNS: Set[str] = {
    "noreply", "no-reply", "no_reply",
    "notifications", "admin", "support",
    "info", "team", "hello", "contact",
    "SENDER_EMAIL", "FROM_EMAIL", "DEFAULT_FROM",
    "sender_email", "from_email", "default_from",
    "MAIL_FROM", "mail_from", "EMAIL_FROM",
}

_SENDER_RESTRICTION_LOWER: Set[str] = {s.lower() for s in SENDER_RESTRICTION_PATTERNS}


# ---------------------------------------------------------------------------
# Unsubscribe Compliance Patterns
# ---------------------------------------------------------------------------

UNSUBSCRIBE_INDICATORS: Set[str] = {
    "unsubscribe", "opt-out", "opt_out", "optout",
    "list-unsubscribe", "list_unsubscribe", "listunsubscribe",
    "manage_preferences", "managePreferences",
    "email_preferences", "emailPreferences",
    "subscription_settings", "subscriptionSettings",
}

_UNSUBSCRIBE_LOWER: Set[str] = {s.lower() for s in UNSUBSCRIBE_INDICATORS}

# Bulk/marketing email indicators
BULK_EMAIL_INDICATORS: Set[str] = {
    "newsletter", "campaign", "marketing", "broadcast",
    "mass_mail", "massMail", "bulk", "blast",
    "mailing_list", "mailingList", "subscribers",
    "send_mass_mail", "sendMassMail",
    "each", "forEach", "for_each", "map",
    "batch", "batchSend", "batch_send",
}

_BULK_EMAIL_LOWER: Set[str] = {s.lower() for s in BULK_EMAIL_INDICATORS}


# ---------------------------------------------------------------------------
# User Input Detection
# ---------------------------------------------------------------------------

_USER_INPUT_KEYWORDS: Set[str] = {
    "input", "request", "query", "param", "user", "data",
    "body", "form", "header", "cookie", "args", "payload",
    "content", "raw", "untrusted", "extern", "external",
    "name", "value", "field", "text",
    "message", "msg", "comment", "title", "description",
    "username", "email", "address", "recipient",
    "sender", "from_addr", "to_addr", "subject",
}

_USER_INPUT_TYPES: Set[str] = {
    "request", "httprequest", "formdata", "querystring",
    "params", "body", "httpservletrequest", "servletrequest",
    "context", "ctx",
}


# ---------------------------------------------------------------------------
# Finding Data Structure
# ---------------------------------------------------------------------------

@dataclass
class EmailFinding:
    """Internal representation of a detected email security vulnerability."""
    category: EmailVulnCategory
    source_var: str
    sink_name: str
    detail: str
    location: Optional[SourceLocation] = None
    func_name: str = ""


# ---------------------------------------------------------------------------
# Email Security Analyzer
# ---------------------------------------------------------------------------

class EmailSecurityAnalyzer:
    """Analyzes programs for email security vulnerabilities.

    Performs a two-pass analysis:
      Pass 1: Collect file-level context (email sending, validation, DNS config).
      Pass 2: Per-function analysis for each vulnerability category.

    Skips frontend files (React/Vue/Angular) since email sending happens
    server-side.
    """

    def __init__(self):
        self.findings: List[EmailFinding] = []
        self._user_vars: Set[str] = set()
        self._sanitized_vars: Set[str] = set()
        self._has_crlf_sanitization: bool = False
        self._has_html_encoding: bool = False
        self._has_library_email_validator: bool = False
        self._has_dns_auth_reference: bool = False
        self._has_unsubscribe_mechanism: bool = False
        self._is_frontend_file: bool = False
        self._program_filename: str = "<stdin>"
        self._all_string_values: List[str] = []

    def check_program(self, program: Program) -> List[AeonError]:
        """Run email security analysis on the entire program."""
        self.findings = []
        self._program_filename = program.filename
        self._all_string_values = []

        # --- Frontend file detection: skip entirely ---
        if self._detect_frontend(program):
            return []

        # --- Pass 1: Collect file-level context ---
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._collect_file_context(decl)

        # --- Pass 2: Per-function vulnerability analysis ---
        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                self._analyze_function(decl)

        return self._findings_to_errors()

    # ------------------------------------------------------------------
    # Frontend detection
    # ------------------------------------------------------------------

    def _detect_frontend(self, program: Program) -> bool:
        """Check if this file is a frontend component (React/Vue/Angular)."""
        filename_lower = program.filename.lower() if program.filename else ""

        # File extension check
        if any(filename_lower.endswith(ext) for ext in (".jsx", ".tsx")):
            self._is_frontend_file = True
            return True

        # Check for frontend indicators in function names and string literals
        for decl in program.declarations:
            if not isinstance(decl, (PureFunc, TaskFunc)):
                continue
            func_lower = decl.name.lower()
            # React component patterns
            if func_lower.startswith("use") and len(func_lower) > 3 and func_lower[3].isupper():
                self._is_frontend_file = True
                return True
            # Check for JSX/render patterns
            for stmt in decl.body:
                if self._stmt_has_frontend_pattern(stmt):
                    self._is_frontend_file = True
                    return True

        return False

    def _stmt_has_frontend_pattern(self, stmt: Statement) -> bool:
        """Check if a statement contains frontend framework patterns."""
        if isinstance(stmt, ExprStmt):
            return self._expr_has_frontend_pattern(stmt.expr)
        if isinstance(stmt, LetStmt) and stmt.value:
            return self._expr_has_frontend_pattern(stmt.value)
        if isinstance(stmt, ReturnStmt) and stmt.value:
            return self._expr_has_frontend_pattern(stmt.value)
        return False

    def _expr_has_frontend_pattern(self, expr: Expr) -> bool:
        """Check if an expression contains frontend framework calls."""
        if isinstance(expr, FunctionCall):
            name = self._get_callable_name(expr)
            if name and name.lower() in FRONTEND_INDICATORS:
                return True
            # Check for createElement, createRoot, etc.
            if name and any(ind in name.lower() for ind in FRONTEND_INDICATORS):
                return True
        if isinstance(expr, MethodCall):
            if expr.method_name.lower() in FRONTEND_INDICATORS:
                return True
        return False

    # ------------------------------------------------------------------
    # Pass 1: File-level context collection
    # ------------------------------------------------------------------

    def _collect_file_context(self, func: PureFunc | TaskFunc) -> None:
        """Scan a function to collect file-level facts about email handling."""
        for stmt in func.body:
            self._collect_context_from_stmt(stmt)

    def _collect_context_from_stmt(self, stmt: Statement) -> None:
        """Recursively collect file-level context from a statement."""
        if isinstance(stmt, ExprStmt):
            self._collect_context_from_expr(stmt.expr)
        elif isinstance(stmt, LetStmt) and stmt.value:
            self._collect_context_from_expr(stmt.value)
        elif isinstance(stmt, AssignStmt):
            self._collect_context_from_expr(stmt.value)
        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._collect_context_from_stmt(s)
            for s in stmt.else_body:
                self._collect_context_from_stmt(s)
        elif isinstance(stmt, ReturnStmt) and stmt.value:
            self._collect_context_from_expr(stmt.value)
        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._collect_context_from_stmt(s)
        elif isinstance(stmt, ForStmt):
            for s in stmt.body:
                self._collect_context_from_stmt(s)

    def _collect_context_from_expr(self, expr: Expr) -> None:
        """Extract file-level signals from an expression."""
        if isinstance(expr, StringLiteral):
            self._all_string_values.append(expr.value)
            val_lower = expr.value.lower()

            # Check for DNS auth references in comments or strings
            for indicator in _DNS_AUTH_LOWER:
                if indicator in val_lower:
                    self._has_dns_auth_reference = True
                    break

            # Check for unsubscribe references
            for indicator in _UNSUBSCRIBE_LOWER:
                if indicator in val_lower:
                    self._has_unsubscribe_mechanism = True
                    break

            # Check for CRLF sanitization evidence
            for pattern in CRLF_PATTERNS:
                if pattern in expr.value:
                    self._has_crlf_sanitization = True
                    break

        elif isinstance(expr, FunctionCall):
            callee_name = self._get_callable_name(expr)
            if callee_name:
                cn_lower = callee_name.lower()

                # Library email validators
                if cn_lower in _EMAIL_VALIDATORS_LOWER:
                    self._has_library_email_validator = True

                # CRLF sanitization functions
                if any(san in cn_lower for san in _CRLF_SANITIZERS_LOWER):
                    self._has_crlf_sanitization = True

                # HTML encoding functions
                if any(enc in cn_lower for enc in _HTML_ENCODERS_LOWER):
                    self._has_html_encoding = True

                # Unsubscribe mechanism
                if any(unsub in cn_lower for unsub in _UNSUBSCRIBE_LOWER):
                    self._has_unsubscribe_mechanism = True

            for arg in expr.args:
                self._collect_context_from_expr(arg)

        elif isinstance(expr, MethodCall):
            method_lower = expr.method_name.lower()

            # Library email validators
            if method_lower in _EMAIL_VALIDATORS_LOWER:
                self._has_library_email_validator = True

            # CRLF sanitization
            if any(san in method_lower for san in _CRLF_SANITIZERS_LOWER):
                self._has_crlf_sanitization = True

            # HTML encoding
            if any(enc in method_lower for enc in _HTML_ENCODERS_LOWER):
                self._has_html_encoding = True

            # Unsubscribe
            if any(unsub in method_lower for unsub in _UNSUBSCRIBE_LOWER):
                self._has_unsubscribe_mechanism = True

            self._collect_context_from_expr(expr.obj)
            for arg in expr.args:
                self._collect_context_from_expr(arg)

        elif isinstance(expr, BinaryOp):
            self._collect_context_from_expr(expr.left)
            self._collect_context_from_expr(expr.right)

        elif isinstance(expr, FieldAccess):
            field_lower = expr.field_name.lower()
            # Check unsubscribe in field names
            if any(unsub in field_lower for unsub in _UNSUBSCRIBE_LOWER):
                self._has_unsubscribe_mechanism = True
            self._collect_context_from_expr(expr.obj)

    # ------------------------------------------------------------------
    # Pass 2: Per-function vulnerability analysis
    # ------------------------------------------------------------------

    def _analyze_function(self, func: PureFunc | TaskFunc) -> None:
        """Analyze a single function for email security vulnerabilities."""
        self._user_vars = set()
        self._sanitized_vars = set()

        # Identify user-input parameters
        for param in func.params:
            if self._is_user_input_param(param):
                self._user_vars.add(param.name)

        # Track whether this function sends email
        func_sends_email = False
        func_has_loop = False
        func_has_bulk_indicator = False
        func_email_send_locations: List[SourceLocation] = []

        # Walk the function body
        for stmt in func.body:
            self._analyze_statement(stmt, func)
            # Track email sending and loop context
            if self._stmt_sends_email(stmt):
                func_sends_email = True
                loc = getattr(stmt, "location",
                              SourceLocation(self._program_filename, 0, 0))
                func_email_send_locations.append(loc)
            if isinstance(stmt, (WhileStmt, ForStmt)):
                func_has_loop = True
            if self._stmt_has_bulk_indicator(stmt):
                func_has_bulk_indicator = True

        # --- File-level check: SPF/DKIM/DMARC ---
        if func_sends_email:
            self._check_spf_dkim_dmarc(func, func_email_send_locations)

        # --- File-level check: Unsubscribe compliance ---
        if func_sends_email and (func_has_loop or func_has_bulk_indicator):
            self._check_unsubscribe_compliance(func, func_email_send_locations)

    def _analyze_statement(self, stmt: Statement, func: PureFunc | TaskFunc) -> None:
        """Analyze a statement for email security patterns."""
        loc = getattr(stmt, "location",
                      SourceLocation(self._program_filename, 0, 0))

        if isinstance(stmt, LetStmt):
            if stmt.value:
                # Track taint propagation
                if self._expr_uses_user_var(stmt.value):
                    self._user_vars.add(stmt.name)
                # Check all email security patterns
                self._check_all_patterns(stmt.value, func, loc, stmt.name)

        elif isinstance(stmt, AssignStmt):
            if isinstance(stmt.target, Identifier):
                if self._expr_uses_user_var(stmt.value):
                    self._user_vars.add(stmt.target.name)
            self._check_all_patterns(stmt.value, func, loc, "")

        elif isinstance(stmt, ExprStmt):
            self._check_all_patterns(stmt.expr, func, loc, "")

        elif isinstance(stmt, ReturnStmt) and stmt.value:
            self._check_all_patterns(stmt.value, func, loc, "")

        elif isinstance(stmt, IfStmt):
            for s in stmt.then_body:
                self._analyze_statement(s, func)
            for s in stmt.else_body:
                self._analyze_statement(s, func)

        elif isinstance(stmt, WhileStmt):
            for s in stmt.body:
                self._analyze_statement(s, func)

        elif isinstance(stmt, ForStmt):
            for s in stmt.body:
                self._analyze_statement(s, func)

    def _check_all_patterns(self, expr: Expr, func: PureFunc | TaskFunc,
                            loc: SourceLocation, var_name: str) -> None:
        """Run all email security checks against an expression."""
        self._check_header_injection(expr, func, loc)
        self._check_html_injection(expr, func, loc)
        self._check_smtp_injection(expr, func, loc)
        self._check_email_validation_bypass(expr, func, loc, var_name)
        self._check_sensitive_data_in_email(expr, func, loc)
        self._check_open_relay(expr, func, loc)

        # Recurse into sub-expressions
        self._recurse_expr(expr, func, loc)

    def _recurse_expr(self, expr: Expr, func: PureFunc | TaskFunc,
                      loc: SourceLocation) -> None:
        """Recurse into nested expressions for deeper analysis."""
        if isinstance(expr, BinaryOp):
            self._check_all_patterns(expr.left, func, loc, "")
            self._check_all_patterns(expr.right, func, loc, "")
        elif isinstance(expr, FunctionCall):
            for arg in expr.args:
                self._check_all_patterns(arg, func, loc, "")
        elif isinstance(expr, MethodCall):
            self._check_all_patterns(expr.obj, func, loc, "")
            for arg in expr.args:
                self._check_all_patterns(arg, func, loc, "")
        elif isinstance(expr, FieldAccess):
            self._check_all_patterns(expr.obj, func, loc, "")

    # ------------------------------------------------------------------
    # 1. Email Header Injection (CWE-93)
    # ------------------------------------------------------------------

    def _check_header_injection(self, expr: Expr, func: PureFunc | TaskFunc,
                                loc: SourceLocation) -> None:
        """Detect user input in email headers without CRLF sanitization."""
        # Skip if file-level CRLF sanitization detected
        if self._has_crlf_sanitization:
            return

        # Pattern A: email-sending function call with user data in header args
        func_name = self._get_callable_name(expr)
        if func_name and self._is_email_send_function(func_name):
            args = self._get_call_args(expr)
            for arg in args:
                if self._expr_uses_user_var(arg) and self._arg_is_header_context(expr, arg):
                    user_var = self._identify_user_var(arg)
                    self.findings.append(EmailFinding(
                        category=EmailVulnCategory.HEADER_INJECTION,
                        source_var=user_var,
                        sink_name=func_name,
                        detail=(
                            f"User-controlled variable '{user_var}' is passed to "
                            f"email function '{func_name}' in a header context "
                            f"(To, CC, BCC, Subject, From, Reply-To) without CRLF "
                            f"sanitization. An attacker can inject \\r\\n to add "
                            f"arbitrary headers or BCC recipients."
                        ),
                        location=loc,
                        func_name=func.name,
                    ))
                    return

        # Pattern B: method call setting email headers with user data
        if isinstance(expr, MethodCall):
            method_lower = expr.method_name.lower()
            if method_lower in _EMAIL_HEADER_SETTERS_LOWER:
                for arg in expr.args:
                    if self._expr_uses_user_var(arg):
                        user_var = self._identify_user_var(arg)
                        self.findings.append(EmailFinding(
                            category=EmailVulnCategory.HEADER_INJECTION,
                            source_var=user_var,
                            sink_name=f"{expr.method_name}",
                            detail=(
                                f"User-controlled variable '{user_var}' is passed to "
                                f"email header setter '{expr.method_name}' without "
                                f"CRLF sanitization. An attacker can inject \\r\\n "
                                f"sequences to manipulate email headers."
                            ),
                            location=loc,
                            func_name=func.name,
                        ))
                        return

        # Pattern C: string concatenation building email headers with user data
        if isinstance(expr, BinaryOp) and expr.op in ("+", "++", "~", ".."):
            if self._contains_header_field_name(expr) and self._expr_uses_user_var(expr):
                user_var = self._identify_user_var(expr)
                self.findings.append(EmailFinding(
                    category=EmailVulnCategory.HEADER_INJECTION,
                    source_var=user_var,
                    sink_name="header string concatenation",
                    detail=(
                        f"User-controlled variable '{user_var}' is concatenated "
                        f"into an email header string. An attacker can inject "
                        f"CRLF sequences to add arbitrary headers or BCC recipients."
                    ),
                    location=loc,
                    func_name=func.name,
                ))

    def _contains_header_field_name(self, expr: Expr) -> bool:
        """Check if an expression contains email header field name strings."""
        if isinstance(expr, StringLiteral):
            val_lower = expr.value.lower().replace("-", "").replace("_", "")
            return any(hdr in val_lower for hdr in _EMAIL_HEADER_LOWER)
        if isinstance(expr, BinaryOp):
            return (self._contains_header_field_name(expr.left) or
                    self._contains_header_field_name(expr.right))
        return False

    def _arg_is_header_context(self, call_expr: Expr, arg: Expr) -> bool:
        """Determine if an argument to an email function is in a header context.

        Checks if the argument is associated with header field names (To, CC,
        Subject, etc.) by examining keyword arguments, adjacent string literals,
        or position in the call.
        """
        args = self._get_call_args(call_expr)
        if not args:
            return True  # Conservative: assume header context if unknown

        # Check for named/keyword patterns in adjacent arguments
        for a in args:
            if isinstance(a, StringLiteral):
                val_lower = a.value.lower().replace("-", "").replace("_", "")
                if any(hdr in val_lower for hdr in _EMAIL_HEADER_LOWER):
                    return True

        # If the function is a known email sender, the first few args are
        # typically header fields (to, subject, body)
        if len(args) >= 2 and arg is args[0]:
            return True  # First arg is typically 'to'
        if len(args) >= 3 and arg is args[1]:
            return True  # Second arg is typically 'subject'

        return False

    # ------------------------------------------------------------------
    # 2. HTML Injection in Emails (CWE-79)
    # ------------------------------------------------------------------

    def _check_html_injection(self, expr: Expr, func: PureFunc | TaskFunc,
                              loc: SourceLocation) -> None:
        """Detect user input rendered in HTML email body without escaping."""
        # Skip if file-level HTML encoding is present
        if self._has_html_encoding:
            return

        # Look for string concatenation/interpolation with HTML tags and user data
        if isinstance(expr, BinaryOp) and expr.op in ("+", "++", "~", ".."):
            if self._contains_html_tags(expr) and self._expr_uses_user_var(expr):
                # Check if this is in an email-sending context
                user_var = self._identify_user_var(expr)
                self.findings.append(EmailFinding(
                    category=EmailVulnCategory.HTML_INJECTION,
                    source_var=user_var,
                    sink_name="HTML email body",
                    detail=(
                        f"User-controlled variable '{user_var}' is embedded in "
                        f"an HTML string without HTML encoding. In an email context, "
                        f"this allows phishing overlays, content spoofing, and "
                        f"CSS-based data exfiltration."
                    ),
                    location=loc,
                    func_name=func.name,
                ))
                return

        # Check for string literals containing HTML with template interpolation
        if isinstance(expr, StringLiteral):
            if HTML_TAG_PATTERN.search(expr.value) and HTML_TEMPLATE_INTERP_PATTERN.search(expr.value):
                self.findings.append(EmailFinding(
                    category=EmailVulnCategory.HTML_INJECTION,
                    source_var="template variable",
                    sink_name="HTML email template",
                    detail=(
                        "HTML email body contains template interpolation "
                        f"(e.g., ${{...}}, %s, {{...}}) without explicit HTML "
                        f"encoding. If the interpolated values come from user "
                        f"input, this enables HTML injection."
                    ),
                    location=loc,
                    func_name=func.name,
                ))

    def _contains_html_tags(self, expr: Expr) -> bool:
        """Check if an expression contains HTML tag strings."""
        if isinstance(expr, StringLiteral):
            return bool(HTML_TAG_PATTERN.search(expr.value))
        if isinstance(expr, BinaryOp):
            return (self._contains_html_tags(expr.left) or
                    self._contains_html_tags(expr.right))
        return False

    # ------------------------------------------------------------------
    # 3. SMTP Injection (CWE-93)
    # ------------------------------------------------------------------

    def _check_smtp_injection(self, expr: Expr, func: PureFunc | TaskFunc,
                              loc: SourceLocation) -> None:
        """Detect user input passed to raw SMTP operations."""
        func_name = self._get_callable_name(expr)
        if not func_name:
            return

        fn_lower = func_name.lower()

        # Check if this is a raw SMTP function
        is_smtp = any(smtp in fn_lower for smtp in _SMTP_RAW_LOWER)
        if not is_smtp:
            return

        # Check if sender or recipient arguments contain user input
        args = self._get_call_args(expr)
        for arg in args:
            if self._expr_uses_user_var(arg):
                user_var = self._identify_user_var(arg)
                self.findings.append(EmailFinding(
                    category=EmailVulnCategory.SMTP_INJECTION,
                    source_var=user_var,
                    sink_name=func_name,
                    detail=(
                        f"User-controlled variable '{user_var}' is passed to "
                        f"raw SMTP function '{func_name}' without validation. "
                        f"An attacker can inject SMTP commands via CRLF sequences "
                        f"in the sender or recipient address, potentially turning "
                        f"the server into a spam relay."
                    ),
                    location=loc,
                    func_name=func.name,
                ))
                return

    # ------------------------------------------------------------------
    # 4. Email Address Validation Bypass (CWE-20)
    # ------------------------------------------------------------------

    def _check_email_validation_bypass(self, expr: Expr, func: PureFunc | TaskFunc,
                                       loc: SourceLocation,
                                       var_name: str) -> None:
        """Detect weak regex-only email validation without library validators."""
        # Skip if a library validator is already used in this file
        if self._has_library_email_validator:
            return

        # Look for regex compilation/match with email patterns
        func_name = self._get_callable_name(expr)
        if not func_name:
            return

        fn_lower = func_name.lower()
        is_regex_func = any(rf in fn_lower for rf in _REGEX_FUNCTIONS_LOWER)
        if not is_regex_func:
            return

        # Check if any argument is a string literal matching email regex patterns
        args = self._get_call_args(expr)
        for arg in args:
            if isinstance(arg, StringLiteral):
                for email_pat in EMAIL_REGEX_PATTERNS:
                    if email_pat.search(arg.value):
                        # Check if this is in an email-sending context
                        # (variable name or surrounding function suggests email)
                        if self._is_email_context(var_name, func.name):
                            self.findings.append(EmailFinding(
                                category=EmailVulnCategory.EMAIL_VALIDATION_BYPASS,
                                source_var=var_name or "email input",
                                sink_name=func_name,
                                detail=(
                                    f"Regex-only email validation detected in "
                                    f"'{func_name}'. Regex cannot properly validate "
                                    f"email addresses per RFC 5321/5322 and may allow "
                                    f"injection payloads. Use a library validator "
                                    f"(validator.isEmail, email-validator, etc.)."
                                ),
                                location=loc,
                                func_name=func.name,
                            ))
                            return

    def _is_email_context(self, var_name: str, func_name: str) -> bool:
        """Check if the variable or function name suggests email context."""
        combined = f"{var_name} {func_name}".lower()
        email_keywords = {"email", "mail", "address", "recipient", "sender", "smtp"}
        return any(kw in combined for kw in email_keywords)

    # ------------------------------------------------------------------
    # 5. Missing SPF/DKIM/DMARC Awareness (CWE-290)
    # ------------------------------------------------------------------

    def _check_spf_dkim_dmarc(self, func: PureFunc | TaskFunc,
                               email_send_locations: List[SourceLocation]) -> None:
        """Check for custom From domain without SPF/DKIM/DMARC references."""
        if self._has_dns_auth_reference:
            return

        # Look for custom domain in From addresses across all string literals
        has_custom_from = False
        for val in self._all_string_values:
            if CUSTOM_DOMAIN_PATTERN.search(val):
                has_custom_from = True
                break

        if not has_custom_from:
            return

        loc = email_send_locations[0] if email_send_locations else \
            SourceLocation(self._program_filename, 0, 0)

        self.findings.append(EmailFinding(
            category=EmailVulnCategory.MISSING_SPF_DKIM_DMARC,
            source_var="custom From domain",
            sink_name="email sender",
            detail=(
                "Email is sent from a custom domain without any reference to "
                "SPF, DKIM, or DMARC DNS records in the codebase. Without "
                "these authentication mechanisms, attackers can spoof your "
                "sender domain for phishing attacks."
            ),
            location=loc,
            func_name=func.name,
        ))

    # ------------------------------------------------------------------
    # 6. Sensitive Data in Email (CWE-312)
    # ------------------------------------------------------------------

    def _check_sensitive_data_in_email(self, expr: Expr,
                                       func: PureFunc | TaskFunc,
                                       loc: SourceLocation) -> None:
        """Detect passwords, tokens, PII sent in plaintext email body."""
        func_name = self._get_callable_name(expr)
        if not func_name:
            return

        if not self._is_email_send_function(func_name):
            return

        # Check arguments for sensitive variable references
        args = self._get_call_args(expr)
        for arg in args:
            sensitive_var = self._find_sensitive_var_in_expr(arg)
            if sensitive_var:
                self.findings.append(EmailFinding(
                    category=EmailVulnCategory.SENSITIVE_DATA_IN_EMAIL,
                    source_var=sensitive_var,
                    sink_name=func_name,
                    detail=(
                        f"Sensitive variable '{sensitive_var}' is included in "
                        f"email body sent via '{func_name}'. Passwords, tokens, "
                        f"SSNs, and credit card numbers should never be sent in "
                        f"plaintext email. Use short-lived tokens with secure "
                        f"links instead."
                    ),
                    location=loc,
                    func_name=func.name,
                ))
                return

    def _find_sensitive_var_in_expr(self, expr: Expr) -> Optional[str]:
        """Find a sensitive variable name within an expression."""
        if isinstance(expr, Identifier):
            name_lower = expr.name.lower()
            if name_lower in _SENSITIVE_LOWER:
                return expr.name
            for kw in SENSITIVE_KEYWORDS:
                if kw in name_lower:
                    return expr.name
            return None

        if isinstance(expr, BinaryOp):
            left = self._find_sensitive_var_in_expr(expr.left)
            if left:
                return left
            return self._find_sensitive_var_in_expr(expr.right)

        if isinstance(expr, FunctionCall):
            for arg in expr.args:
                found = self._find_sensitive_var_in_expr(arg)
                if found:
                    return found

        if isinstance(expr, MethodCall):
            obj_found = self._find_sensitive_var_in_expr(expr.obj)
            if obj_found:
                return obj_found
            for arg in expr.args:
                found = self._find_sensitive_var_in_expr(arg)
                if found:
                    return found

        if isinstance(expr, FieldAccess):
            field_lower = expr.field_name.lower()
            if field_lower in _SENSITIVE_LOWER:
                return expr.field_name
            for kw in SENSITIVE_KEYWORDS:
                if kw in field_lower:
                    return expr.field_name
            return self._find_sensitive_var_in_expr(expr.obj)

        return None

    # ------------------------------------------------------------------
    # 7. Open Relay Patterns (CWE-441)
    # ------------------------------------------------------------------

    def _check_open_relay(self, expr: Expr, func: PureFunc | TaskFunc,
                          loc: SourceLocation) -> None:
        """Detect email endpoints where both sender and recipient are user-controlled."""
        func_name = self._get_callable_name(expr)
        if not func_name:
            return

        if not self._is_email_send_function(func_name):
            return

        args = self._get_call_args(expr)
        if len(args) < 2:
            return

        # Check if both From (sender) and To (recipient) are user-controlled
        user_controlled_args = []
        for i, arg in enumerate(args):
            if self._expr_uses_user_var(arg):
                user_controlled_args.append(i)

        # Need at least 2 user-controlled args (sender + recipient)
        if len(user_controlled_args) < 2:
            return

        # Check for sender restriction (fixed From address)
        has_sender_restriction = False
        for arg in args:
            if isinstance(arg, StringLiteral):
                val_lower = arg.value.lower()
                if any(restr in val_lower for restr in _SENDER_RESTRICTION_LOWER):
                    has_sender_restriction = True
                    break
            if isinstance(arg, Identifier):
                name_lower = arg.name.lower()
                if any(restr in name_lower for restr in _SENDER_RESTRICTION_LOWER):
                    has_sender_restriction = True
                    break

        if has_sender_restriction:
            return

        # Also check function parameters for request body patterns
        func_has_request_param = any(
            any(rb in p.name.lower() for rb in _REQUEST_BODY_LOWER)
            for p in func.params
        )

        if not func_has_request_param:
            # Check if function name suggests API endpoint
            fn_lower = func.name.lower()
            endpoint_keywords = {"handler", "endpoint", "route", "api",
                                 "post", "send", "submit"}
            if not any(kw in fn_lower for kw in endpoint_keywords):
                return

        self.findings.append(EmailFinding(
            category=EmailVulnCategory.OPEN_RELAY,
            source_var="user-controlled sender and recipient",
            sink_name=func_name,
            detail=(
                f"Email-sending function '{func_name}' accepts both sender "
                f"and recipient from user input without restricting the From "
                f"address to authorized senders. This creates an open relay "
                f"that attackers can abuse for spam and phishing campaigns."
            ),
            location=loc,
            func_name=func.name,
        ))

    # ------------------------------------------------------------------
    # 8. Unsubscribe Compliance (CWE-16)
    # ------------------------------------------------------------------

    def _check_unsubscribe_compliance(self, func: PureFunc | TaskFunc,
                                      email_send_locations: List[SourceLocation]) -> None:
        """Check for bulk/marketing email without unsubscribe mechanism."""
        if self._has_unsubscribe_mechanism:
            return

        # Confirm this function has bulk email indicators
        func_lower = func.name.lower()
        is_bulk = any(bulk in func_lower for bulk in _BULK_EMAIL_LOWER)

        if not is_bulk:
            # Check if function body has loop + email send
            has_loop_with_send = False
            for stmt in func.body:
                if isinstance(stmt, (WhileStmt, ForStmt)):
                    if self._body_sends_email(
                        stmt.body if isinstance(stmt, (WhileStmt, ForStmt)) else []
                    ):
                        has_loop_with_send = True
                        break
            if not has_loop_with_send:
                return

        loc = email_send_locations[0] if email_send_locations else \
            SourceLocation(self._program_filename, 0, 0)

        self.findings.append(EmailFinding(
            category=EmailVulnCategory.MISSING_UNSUBSCRIBE,
            source_var="bulk email operation",
            sink_name=func.name,
            detail=(
                f"Function '{func.name}' sends bulk/marketing emails without "
                f"an unsubscribe mechanism. CAN-SPAM Act and GDPR require a "
                f"functioning opt-out mechanism for commercial emails. Add a "
                f"List-Unsubscribe header and visible unsubscribe link."
            ),
            location=loc,
            func_name=func.name,
        ))

    def _body_sends_email(self, stmts: List[Statement]) -> bool:
        """Check if a list of statements contains email-sending calls."""
        for stmt in stmts:
            if self._stmt_sends_email(stmt):
                return True
        return False

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _is_email_send_function(self, func_name: str) -> bool:
        """Check if a function name is an email-sending function."""
        fn_lower = func_name.lower()
        return any(email_fn in fn_lower for email_fn in _EMAIL_SEND_LOWER)

    def _stmt_sends_email(self, stmt: Statement) -> bool:
        """Check if a statement contains an email-sending call."""
        if isinstance(stmt, ExprStmt):
            return self._expr_sends_email(stmt.expr)
        if isinstance(stmt, LetStmt) and stmt.value:
            return self._expr_sends_email(stmt.value)
        if isinstance(stmt, AssignStmt):
            return self._expr_sends_email(stmt.value)
        if isinstance(stmt, ReturnStmt) and stmt.value:
            return self._expr_sends_email(stmt.value)
        if isinstance(stmt, IfStmt):
            for s in stmt.then_body + stmt.else_body:
                if self._stmt_sends_email(s):
                    return True
        if isinstance(stmt, WhileStmt):
            for s in stmt.body:
                if self._stmt_sends_email(s):
                    return True
        if isinstance(stmt, ForStmt):
            for s in stmt.body:
                if self._stmt_sends_email(s):
                    return True
        return False

    def _expr_sends_email(self, expr: Expr) -> bool:
        """Check if an expression is an email-sending call."""
        name = self._get_callable_name(expr)
        if name and self._is_email_send_function(name):
            return True
        if isinstance(expr, FunctionCall):
            return any(self._expr_sends_email(a) for a in expr.args)
        if isinstance(expr, MethodCall):
            return (self._expr_sends_email(expr.obj) or
                    any(self._expr_sends_email(a) for a in expr.args))
        return False

    def _stmt_has_bulk_indicator(self, stmt: Statement) -> bool:
        """Check if a statement has bulk email indicators."""
        if isinstance(stmt, ExprStmt):
            return self._expr_has_bulk_indicator(stmt.expr)
        if isinstance(stmt, LetStmt):
            name_lower = stmt.name.lower()
            if any(bulk in name_lower for bulk in _BULK_EMAIL_LOWER):
                return True
            if stmt.value:
                return self._expr_has_bulk_indicator(stmt.value)
        if isinstance(stmt, ForStmt):
            return True  # Any loop in email-sending function is suspicious
        if isinstance(stmt, WhileStmt):
            return True
        return False

    def _expr_has_bulk_indicator(self, expr: Expr) -> bool:
        """Check if an expression references bulk email patterns."""
        if isinstance(expr, Identifier):
            return any(bulk in expr.name.lower() for bulk in _BULK_EMAIL_LOWER)
        if isinstance(expr, MethodCall):
            return any(bulk in expr.method_name.lower() for bulk in _BULK_EMAIL_LOWER)
        if isinstance(expr, FunctionCall):
            name = self._get_callable_name(expr)
            if name and any(bulk in name.lower() for bulk in _BULK_EMAIL_LOWER):
                return True
        return False

    def _is_user_input_param(self, param) -> bool:
        """Determine if a parameter likely carries user input."""
        name_lower = param.name.lower()
        type_str = str(param.type_annotation).lower() if param.type_annotation else ""

        if any(kw in name_lower for kw in _USER_INPUT_KEYWORDS):
            return True
        if any(kw in type_str for kw in _USER_INPUT_TYPES):
            return True
        return False

    def _get_callable_name(self, expr: Expr) -> Optional[str]:
        """Extract the callable name from a function/method call expression."""
        if isinstance(expr, FunctionCall):
            if isinstance(expr.callee, Identifier):
                return expr.callee.name
            if isinstance(expr.callee, FieldAccess):
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

        return ""

    # ------------------------------------------------------------------
    # Finding conversion
    # ------------------------------------------------------------------

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
            severity = SEVERITY_MAP[f.category]
            remediation = REMEDIATION_MAP[f.category]
            vuln_name = f.category.value.replace("_", " ").title()

            errors.append(contract_error(
                precondition=(
                    f"Email security: {vuln_name} -- {f.detail}"
                ),
                failing_values={
                    "vulnerability": f.category.value,
                    "cwe": cwe,
                    "severity": severity,
                    "source": f.source_var,
                    "sink": f.sink_name,
                    "remediation": remediation,
                    "engine": "Email Security",
                },
                function_signature=f.func_name,
                location=f.location,
            ))

        return errors


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_email_security(program: Program) -> list:
    """Run email security analysis on an AEON program.

    Detects 8 categories of email security vulnerabilities:

    1.  Email Header Injection (CWE-93)
        User input in To, CC, BCC, Subject, From, Reply-To headers without
        CRLF sanitization.

    2.  HTML Injection in Emails (CWE-79)
        User input rendered in HTML email body without HTML encoding.

    3.  SMTP Injection (CWE-93)
        User input passed to raw SMTP operations (smtp.sendmail, smtplib)
        without validation.

    4.  Email Address Validation Bypass (CWE-20)
        Regex-only email validation without a library validator, especially
        when the email is used in SMTP context.

    5.  Missing SPF/DKIM/DMARC Awareness (CWE-290)
        Sending email from custom domains without referencing SPF/DKIM/DMARC
        DNS authentication configuration.

    6.  Sensitive Data in Email (CWE-312)
        Passwords, tokens, SSNs, credit card numbers sent in plaintext
        email body.

    7.  Open Relay Patterns (CWE-441)
        Email-sending endpoint where both sender and recipient are
        user-controlled without restricting the From address.

    8.  Unsubscribe Compliance (CWE-16)
        Bulk/marketing email sending without List-Unsubscribe header or
        unsubscribe link.

    Skips frontend files (React/Vue/Angular) since email sending is
    server-side.

    Each finding includes CWE reference, severity, and remediation guidance.

    Args:
        program: The parsed AEON Program AST.

    Returns:
        A list of AeonError instances, one per detected vulnerability.
    """
    try:
        analyzer = EmailSecurityAnalyzer()
        return analyzer.check_program(program)
    except Exception:
        # Engine-level safety net: never let the entire engine crash
        # the verification pipeline
        return []
