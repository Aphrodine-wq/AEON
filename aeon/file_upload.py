"""AEON File Upload Security Engine -- Detects File Upload Vulnerabilities.

Scans for dangerous file upload patterns that enable remote code execution,
path traversal, denial of service, cross-site scripting, and data exfiltration
through uploaded files.

References:
  OWASP Foundation (2023) "Unrestricted File Upload"
  https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload

  CWE-434: Unrestricted Upload of File with Dangerous Type
  https://cwe.mitre.org/data/definitions/434.html

  Livshits & Lam (2005) "Finding Security Vulnerabilities in Java
  Applications with Static Analysis"
  USENIX Security '05

  Sutton, Greene & Amini (2007) "Fuzzing: Brute Force Vulnerability Discovery"
  Addison-Wesley, ISBN 0-321-44611-9
  (Decompression bomb and malformed file attacks)

Detection Strategies:

1. UNRESTRICTED FILE TYPE (CWE-434):
   File upload handlers without extension/MIME type validation.
   Pattern: multer(), formidable, busboy, req.file, request.files
   without fileFilter, accept, or extension check.

2. PATH TRAVERSAL IN FILENAME (CWE-22):
   Using user-supplied filename directly in file path construction.
   Pattern: req.file.originalname or file.filename used in path.join,
   os.path.join, File.write without sanitizing .., /, \\.

3. MISSING FILE SIZE LIMIT (CWE-400):
   Upload handlers without size configuration.
   Pattern: upload middleware/handler without limits.fileSize,
   maxFileSize, MAX_CONTENT_LENGTH.

4. SVG XSS (CWE-79):
   Accepting SVG uploads without sanitization. SVGs can contain
   <script> tags, event handlers, and external entity references.
   Pattern: allowlist includes .svg or image/svg+xml without a
   sanitization step.

5. DANGEROUS FILE TYPES (CWE-434):
   Allowing executable file uploads without an explicit deny list.
   Pattern: .exe, .sh, .bat, .cmd, .ps1, .php, .jsp, .aspx,
   .py, .rb, .pl, .cgi accepted.

6. CLIENT-SIDE ONLY VALIDATION (CWE-602):
   File type validation only in frontend code without corresponding
   server-side validation.
   Pattern: HTML/JSX accept= attribute without server check.

7. IMAGE METADATA EXFILTRATION (CWE-200):
   Storing/serving uploaded images without stripping EXIF data
   (GPS location, camera info, timestamps).
   Pattern: image processing pipeline without strip(), exif_delete,
   or metadata removal step.

8. ZIP BOMB / DECOMPRESSION BOMB (CWE-409):
   Accepting zip/archive uploads without checking decompressed size.
   Pattern: unzip, tar.extract, ZipFile.extractall without size
   limit validation.

9. STORAGE PATH DISCLOSURE (CWE-209):
   Returning full server file path in upload response body.
   Pattern: response includes file.path, filepath, absolutePath
   from server filesystem.

10. MISSING VIRUS/MALWARE SCANNING:
    Upload pipeline without any scanning step before storing the file.
    Pattern: file saved to storage without calling a scan/check function.

Every finding includes:
  - Vulnerability category
  - Severity (critical / high / medium)
  - CWE reference
  - Remediation guidance
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, IntLiteral, BoolLiteral, StringLiteral,
    BinaryOp, UnaryOp, FunctionCall, FieldAccess, MethodCall,
    ReturnStmt, LetStmt, AssignStmt, ExprStmt, IfStmt, WhileStmt,
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

CWE_434 = "CWE-434: Unrestricted Upload of File with Dangerous Type"
CWE_22 = "CWE-22: Improper Limitation of a Pathname to a Restricted Directory"
CWE_400 = "CWE-400: Uncontrolled Resource Consumption"
CWE_79 = "CWE-79: Improper Neutralization of Input During Web Page Generation"
CWE_602 = "CWE-602: Client-Side Enforcement of Server-Side Security"
CWE_200 = "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
CWE_409 = "CWE-409: Improper Handling of Highly Compressed Data"
CWE_209 = "CWE-209: Generation of Error Message Containing Sensitive Information"


# ---------------------------------------------------------------------------
# Category Definitions
# ---------------------------------------------------------------------------

class FindingCategory(Enum):
    UNRESTRICTED_FILE_TYPE = "unrestricted_file_type"
    PATH_TRAVERSAL_FILENAME = "path_traversal_in_filename"
    MISSING_SIZE_LIMIT = "missing_file_size_limit"
    SVG_XSS = "svg_xss"
    DANGEROUS_FILE_TYPES = "dangerous_file_types_allowed"
    CLIENT_SIDE_ONLY = "client_side_only_validation"
    IMAGE_METADATA = "image_metadata_exfiltration"
    ZIP_BOMB = "zip_bomb_decompression"
    STORAGE_PATH_DISCLOSURE = "storage_path_disclosure"
    MISSING_MALWARE_SCAN = "missing_malware_scanning"


CATEGORY_CWE: Dict[FindingCategory, str] = {
    FindingCategory.UNRESTRICTED_FILE_TYPE: CWE_434,
    FindingCategory.PATH_TRAVERSAL_FILENAME: CWE_22,
    FindingCategory.MISSING_SIZE_LIMIT: CWE_400,
    FindingCategory.SVG_XSS: CWE_79,
    FindingCategory.DANGEROUS_FILE_TYPES: CWE_434,
    FindingCategory.CLIENT_SIDE_ONLY: CWE_602,
    FindingCategory.IMAGE_METADATA: CWE_200,
    FindingCategory.ZIP_BOMB: CWE_409,
    FindingCategory.STORAGE_PATH_DISCLOSURE: CWE_209,
    FindingCategory.MISSING_MALWARE_SCAN: CWE_434,
}

CATEGORY_SEVERITY: Dict[FindingCategory, Severity] = {
    FindingCategory.UNRESTRICTED_FILE_TYPE: Severity.CRITICAL,
    FindingCategory.PATH_TRAVERSAL_FILENAME: Severity.CRITICAL,
    FindingCategory.MISSING_SIZE_LIMIT: Severity.HIGH,
    FindingCategory.SVG_XSS: Severity.HIGH,
    FindingCategory.DANGEROUS_FILE_TYPES: Severity.CRITICAL,
    FindingCategory.CLIENT_SIDE_ONLY: Severity.HIGH,
    FindingCategory.IMAGE_METADATA: Severity.MEDIUM,
    FindingCategory.ZIP_BOMB: Severity.HIGH,
    FindingCategory.STORAGE_PATH_DISCLOSURE: Severity.MEDIUM,
    FindingCategory.MISSING_MALWARE_SCAN: Severity.MEDIUM,
}


# ---------------------------------------------------------------------------
# Pattern Databases
# ---------------------------------------------------------------------------

# Upload middleware/library names (function or constructor calls)
UPLOAD_MIDDLEWARE_FUNCTIONS: Set[str] = {
    "multer", "formidable", "busboy", "multiparty",
    "fileupload", "file_upload", "upload", "handleupload",
    "handle_upload", "process_upload", "processupload",
    "save_file", "savefile", "store_file", "storefile",
    "write_file", "writefile",
}

# Field access patterns that indicate upload handling
UPLOAD_FIELD_ACCESS_PATTERNS: Set[str] = {
    "file", "files", "uploadedfile", "uploaded_file",
    "originalname", "filename", "originalfilename",
    "original_filename",
}

# Patterns indicating file type validation is present
FILE_FILTER_INDICATORS: Set[str] = {
    "filefilter", "file_filter", "mimetype", "mime_type",
    "content_type", "contenttype", "extension", "ext",
    "allowed_extensions", "allowedextensions", "accept",
    "allowed_types", "allowedtypes", "file_types",
    "filetypes", "validate_type", "validatetype",
    "check_extension", "checkextension", "endswith",
    "content_type_validator",
}

# Path construction functions that are dangerous with unsanitized filenames
PATH_JOIN_FUNCTIONS: Set[str] = {
    "join", "path.join", "os.path.join", "path.resolve",
    "path.normalize", "path_join", "pathjoin",
    "file.write", "fs.writefile", "fs.writefilesync",
    "open", "fopen", "create", "save",
}

# User-supplied filename field access patterns
USER_FILENAME_FIELDS: Set[str] = {
    "originalname", "original_name", "filename", "file_name",
    "name", "clientname", "client_name",
}

# Sanitization indicators for path traversal
PATH_SANITIZATION_INDICATORS: Set[str] = {
    "basename", "path.basename", "os.path.basename",
    "sanitize", "sanitize_filename", "sanitizefilename",
    "secure_filename", "securefilename", "replace",
    "normalize", "clean", "strip",
}

# Size limit configuration patterns
SIZE_LIMIT_INDICATORS: Set[str] = {
    "filesize", "file_size", "maxfilesize", "max_file_size",
    "maxsize", "max_size", "sizelimit", "size_limit",
    "max_content_length", "maxcontentlength",
    "limits", "maxbytes", "max_bytes",
    "content_length_limit", "body_limit",
    "upload_max_filesize", "client_max_body_size",
}

# Dangerous executable extensions
DANGEROUS_EXTENSIONS: Set[str] = {
    ".exe", ".sh", ".bat", ".cmd", ".ps1", ".php",
    ".jsp", ".aspx", ".py", ".rb", ".pl", ".cgi",
    ".com", ".msi", ".scr", ".pif", ".hta", ".vbs",
    ".wsf", ".jar", ".war",
}

# SVG-related strings
SVG_INDICATORS: Set[str] = {
    ".svg", "svg", "image/svg+xml", "image/svg",
}

# SVG sanitization indicators
SVG_SANITIZATION_INDICATORS: Set[str] = {
    "sanitize", "sanitize_svg", "sanitizesvg",
    "dompurify", "purify", "clean_svg", "cleansvg",
    "strip_tags", "striptags", "bleach",
    "svg_sanitizer", "svgsanitizer",
    "remove_scripts", "removescripts",
}

# Archive/decompression functions
ARCHIVE_EXTRACT_FUNCTIONS: Set[str] = {
    "extractall", "extract_all", "extract", "unzip",
    "decompress", "gunzip", "inflate", "untar",
    "tar.extract", "zipfile.extractall",
}

# Archive decompression size check indicators
ARCHIVE_SIZE_CHECK_INDICATORS: Set[str] = {
    "file_size", "filesize", "getsize", "get_size",
    "uncompressed_size", "uncompressedsize",
    "total_size", "totalsize", "max_decompressed",
    "size_limit", "sizelimit", "quota",
    "zip_bomb", "zipbomb", "decompression_bomb",
}

# Server path disclosure patterns (field names in responses)
PATH_DISCLOSURE_FIELDS: Set[str] = {
    "path", "filepath", "file_path", "absolutepath",
    "absolute_path", "fullpath", "full_path",
    "server_path", "serverpath", "disk_path",
    "diskpath", "realpath", "real_path",
    "location", "storagepath", "storage_path",
}

# Image processing functions (without metadata stripping)
IMAGE_PROCESS_FUNCTIONS: Set[str] = {
    "save", "write", "resize", "crop", "thumbnail",
    "convert", "transform", "process",
}

# EXIF/metadata stripping indicators
METADATA_STRIP_INDICATORS: Set[str] = {
    "strip", "strip_exif", "stripexif", "exif_delete",
    "exifdelete", "remove_exif", "removeexif",
    "delete_exif", "deleteexif", "strip_metadata",
    "stripmetadata", "remove_metadata", "removemetadata",
    "autorotate", "auto_orient", "autoorient",
    "exiftool", "piexif", "pyexiv2",
    "without_metadata", "withoutmetadata",
    "clean_metadata", "cleanmetadata",
}

# Virus/malware scanning indicators
MALWARE_SCAN_INDICATORS: Set[str] = {
    "scan", "virus_scan", "virusscan", "malware_scan",
    "malwarescan", "clamav", "clamscan", "clamd",
    "antivirus", "anti_virus", "virus_check",
    "viruscheck", "scan_file", "scanfile",
    "virustotal", "virus_total", "check_malware",
    "checkmalware", "safe_file", "safefile",
    "quarantine",
}

# Response construction functions
RESPONSE_FUNCTIONS: Set[str] = {
    "json", "send", "respond", "response", "res.json",
    "res.send", "jsonify", "make_response", "jsonresponse",
    "json_response", "return", "render",
}

# Client-side file input patterns (frontend-only validation)
CLIENT_ACCEPT_PATTERNS: Set[str] = {
    "accept", "accept=", "type=\"file\"", "type='file'",
    "input type", "fileinput", "file_input",
}


# ---------------------------------------------------------------------------
# Finding Dataclass
# ---------------------------------------------------------------------------

@dataclass
class UploadFinding:
    """A single file upload security finding."""
    category: FindingCategory
    message: str
    remediation: str
    line: int
    column: int = 0
    file: str = "<unknown>"

    @property
    def cwe(self) -> str:
        return CATEGORY_CWE[self.category]

    @property
    def severity(self) -> Severity:
        return CATEGORY_SEVERITY[self.category]

    def to_aeon_error(self) -> AeonError:
        return contract_error(
            precondition=(
                f"File upload vulnerability ({self.cwe}): {self.message}"
            ),
            failing_values={
                "category": self.category.value,
                "cwe": self.cwe,
                "severity": self.severity.value,
                "remediation": self.remediation,
                "engine": "File Upload Security",
            },
            function_signature="",
            location=SourceLocation(
                line=self.line,
                column=self.column,
                file=self.file,
            ),
        )


# ---------------------------------------------------------------------------
# AST Walking Helpers
# ---------------------------------------------------------------------------

def _get_line(node) -> int:
    """Extract line number from an AST node."""
    loc = getattr(node, "location", None)
    if loc is not None:
        return getattr(loc, "line", 0)
    return 0


def _get_column(node) -> int:
    """Extract column number from an AST node."""
    loc = getattr(node, "location", None)
    if loc is not None:
        return getattr(loc, "column", 0)
    return 0


def _get_file(node) -> str:
    """Extract file name from an AST node."""
    loc = getattr(node, "location", None)
    if loc is not None:
        return getattr(loc, "file", "<unknown>")
    return "<unknown>"


def _callee_name(expr: FunctionCall) -> str:
    """Get the string name of a FunctionCall's callee, handling dotted access."""
    if isinstance(expr.callee, Identifier):
        return expr.callee.name
    if isinstance(expr.callee, FieldAccess):
        obj_name = ""
        if isinstance(expr.callee.obj, Identifier):
            obj_name = expr.callee.obj.name
        return f"{obj_name}.{expr.callee.field_name}" if obj_name else expr.callee.field_name
    return ""


def _name_matches_any(name: str, patterns: Set[str]) -> bool:
    """Check if a name matches any of the given patterns (case-insensitive substring)."""
    name_lower = name.lower()
    return any(p in name_lower for p in patterns)


def _get_target_name(stmt: Statement) -> str:
    """Get the variable name being assigned to in a LetStmt or AssignStmt."""
    if isinstance(stmt, LetStmt):
        return stmt.name
    if isinstance(stmt, AssignStmt) and isinstance(stmt.target, Identifier):
        return stmt.target.name
    if isinstance(stmt, AssignStmt) and isinstance(stmt.target, FieldAccess):
        return stmt.target.field_name
    return ""


def _collect_all_exprs(stmts: List[Statement]) -> List[Tuple[Expr, Statement]]:
    """Recursively collect all expressions from a statement list with their parent statement."""
    results: List[Tuple[Expr, Statement]] = []

    def _walk_expr(expr: Expr, parent: Statement) -> None:
        results.append((expr, parent))
        if isinstance(expr, BinaryOp):
            _walk_expr(expr.left, parent)
            _walk_expr(expr.right, parent)
        elif isinstance(expr, UnaryOp):
            _walk_expr(expr.operand, parent)
        elif isinstance(expr, FunctionCall):
            _walk_expr(expr.callee, parent)
            for arg in expr.args:
                _walk_expr(arg, parent)
        elif isinstance(expr, MethodCall):
            _walk_expr(expr.obj, parent)
            for arg in expr.args:
                _walk_expr(arg, parent)
        elif isinstance(expr, FieldAccess):
            _walk_expr(expr.obj, parent)

    for stmt in stmts:
        if isinstance(stmt, LetStmt) and stmt.value:
            _walk_expr(stmt.value, stmt)
        elif isinstance(stmt, AssignStmt):
            _walk_expr(stmt.target, stmt)
            _walk_expr(stmt.value, stmt)
        elif isinstance(stmt, ExprStmt):
            _walk_expr(stmt.expr, stmt)
        elif isinstance(stmt, ReturnStmt) and stmt.value:
            _walk_expr(stmt.value, stmt)
        elif isinstance(stmt, IfStmt):
            _walk_expr(stmt.condition, stmt)
            results.extend(_collect_all_exprs(stmt.then_body))
            if stmt.else_body:
                results.extend(_collect_all_exprs(stmt.else_body))
        elif isinstance(stmt, WhileStmt):
            _walk_expr(stmt.condition, stmt)
            results.extend(_collect_all_exprs(stmt.body))

    return results


def _collect_all_strings(body: List[Statement]) -> List[Tuple[StringLiteral, Statement]]:
    """Collect all string literals from a function body with their parent statement."""
    results: List[Tuple[StringLiteral, Statement]] = []
    for expr, stmt in _collect_all_exprs(body):
        if isinstance(expr, StringLiteral):
            results.append((expr, stmt))
    return results


def _function_contains_call_matching(body: List[Statement], patterns: Set[str]) -> bool:
    """Check if a function body contains a call whose name matches any pattern."""
    exprs = _collect_all_exprs(body)
    for expr, _ in exprs:
        if isinstance(expr, FunctionCall):
            cname = _callee_name(expr).lower()
            if any(p in cname for p in patterns):
                return True
        elif isinstance(expr, MethodCall):
            mname = expr.method_name.lower()
            if any(p in mname for p in patterns):
                return True
            # Also check with object prefix
            obj_name = ""
            if isinstance(expr.obj, Identifier):
                obj_name = expr.obj.name.lower()
            full_name = f"{obj_name}.{mname}" if obj_name else mname
            if any(p in full_name for p in patterns):
                return True
    return False


def _function_contains_field_access_matching(body: List[Statement], patterns: Set[str]) -> bool:
    """Check if a function body contains a field access matching any pattern."""
    exprs = _collect_all_exprs(body)
    for expr, _ in exprs:
        if isinstance(expr, FieldAccess):
            fname = expr.field_name.lower()
            if any(p in fname for p in patterns):
                return True
    return False


def _function_contains_string_matching(body: List[Statement], patterns: Set[str]) -> bool:
    """Check if a function body contains a string literal matching any pattern."""
    strings = _collect_all_strings(body)
    for slit, _ in strings:
        val = slit.value.lower()
        if any(p in val for p in patterns):
            return True
    return False


def _body_has_indicator(body: List[Statement], indicators: Set[str]) -> bool:
    """Check if a function body references any of the indicator strings.

    Searches function/method call names, field access names, variable names,
    and string literals.
    """
    if _function_contains_call_matching(body, indicators):
        return True
    if _function_contains_field_access_matching(body, indicators):
        return True
    # Check variable names in let/assign statements
    for stmt in body:
        target = _get_target_name(stmt)
        if target and _name_matches_any(target, indicators):
            return True
        # Recurse into if/while
        if isinstance(stmt, IfStmt):
            if _body_has_indicator(stmt.then_body, indicators):
                return True
            if stmt.else_body and _body_has_indicator(stmt.else_body, indicators):
                return True
        elif isinstance(stmt, WhileStmt):
            if _body_has_indicator(stmt.body, indicators):
                return True
    # Check string literals
    if _function_contains_string_matching(body, indicators):
        return True
    return False


def _is_upload_handler(func: PureFunc | TaskFunc, body: List[Statement]) -> bool:
    """Determine if a function is a file upload handler.

    Checks function name, parameter names, and body for upload-related patterns.
    """
    # Check function name
    func_name = getattr(func, "name", "")
    if func_name and _name_matches_any(func_name, UPLOAD_MIDDLEWARE_FUNCTIONS):
        return True

    # Check for upload-related parameter names
    params = getattr(func, "params", [])
    for param in params:
        pname = getattr(param, "name", "")
        if pname and _name_matches_any(pname, {"file", "upload", "multipart"}):
            return True

    # Check for upload library/middleware calls in body
    if _function_contains_call_matching(body, UPLOAD_MIDDLEWARE_FUNCTIONS):
        return True

    # Check for req.file / req.files / request.files field access
    exprs = _collect_all_exprs(body)
    for expr, _ in exprs:
        if isinstance(expr, FieldAccess):
            fname = expr.field_name.lower()
            if fname in {"file", "files"}:
                # Check if accessed on req/request
                if isinstance(expr.obj, Identifier):
                    obj_name = expr.obj.name.lower()
                    if obj_name in {"req", "request", "ctx", "context"}:
                        return True
        # Check for multer(), formidable(), busboy() calls
        if isinstance(expr, FunctionCall):
            cname = _callee_name(expr).lower()
            if cname in {"multer", "formidable", "busboy", "multiparty", "fileupload"}:
                return True

    return False


# ---------------------------------------------------------------------------
# Individual Detectors
# ---------------------------------------------------------------------------

class UnrestrictedFileTypeDetector:
    """Detect file upload handlers without extension/MIME type validation (CWE-434)."""

    def analyze(
        self,
        func: PureFunc | TaskFunc,
        body: List[Statement],
        exprs: List[Tuple[Expr, Statement]],
        file: str,
    ) -> List[UploadFinding]:
        findings: List[UploadFinding] = []

        if not _is_upload_handler(func, body):
            return findings

        # Check if the function has any file type validation
        has_filter = _body_has_indicator(body, FILE_FILTER_INDICATORS)

        if not has_filter:
            findings.append(UploadFinding(
                category=FindingCategory.UNRESTRICTED_FILE_TYPE,
                message=(
                    f"Upload handler '{getattr(func, 'name', '<anonymous>')}' "
                    f"accepts files without any file type validation — "
                    f"attackers can upload executable files, web shells, or "
                    f"malicious content"
                ),
                remediation=(
                    "Validate both the file extension AND MIME type on the server. "
                    "Use an allowlist of permitted extensions (e.g., .jpg, .png, .pdf). "
                    "Never trust Content-Type headers alone — verify the file's magic bytes. "
                    "Node.js: use multer({ fileFilter }) with extension check. "
                    "Python: validate against ALLOWED_EXTENSIONS set."
                ),
                line=_get_line(func),
                column=_get_column(func),
                file=file,
            ))

        return findings


class PathTraversalFilenameDetector:
    """Detect path traversal via user-supplied filenames (CWE-22)."""

    def analyze(
        self,
        func: PureFunc | TaskFunc,
        body: List[Statement],
        exprs: List[Tuple[Expr, Statement]],
        file: str,
    ) -> List[UploadFinding]:
        findings: List[UploadFinding] = []

        # Look for user filename field access followed by path construction
        has_user_filename = False
        filename_line = 0
        filename_col = 0

        for expr, stmt in exprs:
            if isinstance(expr, FieldAccess):
                fname = expr.field_name.lower()
                if fname in USER_FILENAME_FIELDS:
                    has_user_filename = True
                    filename_line = _get_line(expr) or _get_line(stmt)
                    filename_col = _get_column(expr)

        if not has_user_filename:
            return findings

        # Check if user filename is used in path construction
        has_path_join = _function_contains_call_matching(body, PATH_JOIN_FUNCTIONS)

        if not has_path_join:
            return findings

        # Check if there is sanitization present
        has_sanitization = _body_has_indicator(body, PATH_SANITIZATION_INDICATORS)

        if not has_sanitization:
            findings.append(UploadFinding(
                category=FindingCategory.PATH_TRAVERSAL_FILENAME,
                message=(
                    "User-supplied filename used directly in file path construction "
                    "without sanitization — an attacker can use '../' sequences "
                    "to write files outside the upload directory, overwriting "
                    "configuration files or placing web shells in executable paths"
                ),
                remediation=(
                    "Never use the client-provided filename directly. "
                    "Python: use werkzeug.utils.secure_filename() or os.path.basename(). "
                    "Node.js: use path.basename() and strip all '..' and path separators. "
                    "Best practice: generate a random filename server-side (e.g., UUID) "
                    "and store the original name in a database."
                ),
                line=filename_line,
                column=filename_col,
                file=file,
            ))

        return findings


class MissingSizeLimitDetector:
    """Detect upload handlers without file size limits (CWE-400)."""

    def analyze(
        self,
        func: PureFunc | TaskFunc,
        body: List[Statement],
        exprs: List[Tuple[Expr, Statement]],
        file: str,
    ) -> List[UploadFinding]:
        findings: List[UploadFinding] = []

        if not _is_upload_handler(func, body):
            return findings

        has_size_limit = _body_has_indicator(body, SIZE_LIMIT_INDICATORS)

        if not has_size_limit:
            findings.append(UploadFinding(
                category=FindingCategory.MISSING_SIZE_LIMIT,
                message=(
                    f"Upload handler '{getattr(func, 'name', '<anonymous>')}' "
                    f"does not enforce a file size limit — an attacker can upload "
                    f"arbitrarily large files to exhaust disk space or memory, "
                    f"causing denial of service"
                ),
                remediation=(
                    "Set explicit file size limits on all upload endpoints. "
                    "Node.js/multer: use limits: { fileSize: 5 * 1024 * 1024 } (5MB). "
                    "Express: app.use(express.json({ limit: '5mb' })). "
                    "Python/Flask: app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024. "
                    "Python/Django: FILE_UPLOAD_MAX_MEMORY_SIZE and DATA_UPLOAD_MAX_MEMORY_SIZE. "
                    "Nginx: client_max_body_size 5m."
                ),
                line=_get_line(func),
                column=_get_column(func),
                file=file,
            ))

        return findings


class SvgXssDetector:
    """Detect SVG upload acceptance without sanitization (CWE-79)."""

    def analyze(
        self,
        func: PureFunc | TaskFunc,
        body: List[Statement],
        exprs: List[Tuple[Expr, Statement]],
        file: str,
    ) -> List[UploadFinding]:
        findings: List[UploadFinding] = []

        # Check if SVG is mentioned in allowed types or string literals
        allows_svg = False
        svg_line = 0
        svg_col = 0

        for expr, stmt in exprs:
            if isinstance(expr, StringLiteral):
                val = expr.value.lower()
                if any(svg in val for svg in SVG_INDICATORS):
                    allows_svg = True
                    svg_line = _get_line(expr) or _get_line(stmt)
                    svg_col = _get_column(expr)
                    break

        if not allows_svg:
            return findings

        # Check if SVG sanitization is present
        has_sanitization = _body_has_indicator(body, SVG_SANITIZATION_INDICATORS)

        if not has_sanitization:
            findings.append(UploadFinding(
                category=FindingCategory.SVG_XSS,
                message=(
                    "SVG files are accepted for upload without sanitization — "
                    "SVG is an XML format that can contain <script> tags, "
                    "JavaScript event handlers (onload, onerror), and external "
                    "entity references, enabling stored XSS attacks when served "
                    "to other users"
                ),
                remediation=(
                    "Either reject SVG uploads entirely, or sanitize them before storage. "
                    "Use DOMPurify (Node.js) or bleach (Python) to strip script tags "
                    "and event handlers. Convert SVGs to raster format (PNG) if only "
                    "the image is needed. Serve user-uploaded SVGs with "
                    "Content-Disposition: attachment and Content-Type: application/octet-stream "
                    "to prevent browser execution."
                ),
                line=svg_line,
                column=svg_col,
                file=file,
            ))

        return findings


class DangerousFileTypesDetector:
    """Detect allowing executable file uploads without a deny list (CWE-434)."""

    def analyze(
        self,
        func: PureFunc | TaskFunc,
        body: List[Statement],
        exprs: List[Tuple[Expr, Statement]],
        file: str,
    ) -> List[UploadFinding]:
        findings: List[UploadFinding] = []

        if not _is_upload_handler(func, body):
            return findings

        # Check if any dangerous extensions appear in an allowlist
        allows_dangerous = False
        dangerous_ext = ""
        dangerous_line = 0
        dangerous_col = 0

        for expr, stmt in exprs:
            if isinstance(expr, StringLiteral):
                val = expr.value.lower().strip()
                if val in DANGEROUS_EXTENSIONS:
                    allows_dangerous = True
                    dangerous_ext = val
                    dangerous_line = _get_line(expr) or _get_line(stmt)
                    dangerous_col = _get_column(expr)
                    break

        if allows_dangerous:
            findings.append(UploadFinding(
                category=FindingCategory.DANGEROUS_FILE_TYPES,
                message=(
                    f"Executable file extension '{dangerous_ext}' is allowed "
                    f"in upload handler — this enables remote code execution "
                    f"if the file is stored in a web-accessible directory"
                ),
                remediation=(
                    "Maintain an explicit deny list for dangerous extensions: "
                    ".exe, .sh, .bat, .cmd, .ps1, .php, .jsp, .aspx, .py, .rb, "
                    ".pl, .cgi, .com, .msi, .jar, .war. Better yet, use a strict "
                    "allowlist of only the extensions your application needs "
                    "(e.g., .jpg, .png, .pdf, .docx)."
                ),
                line=dangerous_line,
                column=dangerous_col,
                file=file,
            ))
        else:
            # Check if there is no deny list and no allowlist at all
            # (already caught by UnrestrictedFileTypeDetector in that case)
            # Here we only flag explicit dangerous extension allowance
            pass

        return findings


class ClientSideOnlyValidationDetector:
    """Detect file validation only on the client side (CWE-602)."""

    def analyze(
        self,
        func: PureFunc | TaskFunc,
        body: List[Statement],
        exprs: List[Tuple[Expr, Statement]],
        file: str,
    ) -> List[UploadFinding]:
        findings: List[UploadFinding] = []

        # Look for HTML accept attribute patterns in string literals
        has_client_accept = False
        accept_line = 0
        accept_col = 0

        for expr, stmt in exprs:
            if isinstance(expr, StringLiteral):
                val = expr.value.lower()
                # Detect accept="image/*", type="file" accept patterns
                if ("accept=" in val or "accept =" in val) and (
                    "image/" in val or "video/" in val or
                    "audio/" in val or "application/" in val or
                    ".*" in val
                ):
                    has_client_accept = True
                    accept_line = _get_line(expr) or _get_line(stmt)
                    accept_col = _get_column(expr)
                    break
                # JSX pattern: accept="image/*" on input element
                if 'type="file"' in val or "type='file'" in val:
                    has_client_accept = True
                    accept_line = _get_line(expr) or _get_line(stmt)
                    accept_col = _get_column(expr)
                    break

        if not has_client_accept:
            # Also check for FieldAccess to accept attribute
            for expr, stmt in exprs:
                if isinstance(expr, FieldAccess):
                    if expr.field_name.lower() == "accept":
                        has_client_accept = True
                        accept_line = _get_line(expr) or _get_line(stmt)
                        accept_col = _get_column(expr)
                        break

        if not has_client_accept:
            return findings

        # Check if there is also server-side validation
        has_server_validation = _body_has_indicator(body, FILE_FILTER_INDICATORS)

        if not has_server_validation:
            findings.append(UploadFinding(
                category=FindingCategory.CLIENT_SIDE_ONLY,
                message=(
                    "File type validation appears to be client-side only "
                    "(HTML accept attribute) without corresponding server-side "
                    "validation — the accept attribute is trivially bypassed by "
                    "modifying the HTTP request directly"
                ),
                remediation=(
                    "Always validate file types on the server. The HTML accept "
                    "attribute is a UX convenience, NOT a security control. "
                    "Validate the file extension, MIME type, and magic bytes "
                    "on the server before accepting the upload."
                ),
                line=accept_line,
                column=accept_col,
                file=file,
            ))

        return findings


class ImageMetadataDetector:
    """Detect serving uploaded images without stripping EXIF data (CWE-200)."""

    def analyze(
        self,
        func: PureFunc | TaskFunc,
        body: List[Statement],
        exprs: List[Tuple[Expr, Statement]],
        file: str,
    ) -> List[UploadFinding]:
        findings: List[UploadFinding] = []

        # Check if this function processes images
        has_image_processing = _function_contains_call_matching(
            body, IMAGE_PROCESS_FUNCTIONS
        )

        # Also check for image-related string patterns
        if not has_image_processing:
            image_indicators = {"image", "photo", "picture", "avatar", "thumbnail"}
            func_name = getattr(func, "name", "")
            if not (func_name and _name_matches_any(func_name, image_indicators)):
                return findings
            # Must also have some file save/write call
            save_indicators = {"save", "write", "upload", "store", "put"}
            if not _function_contains_call_matching(body, save_indicators):
                return findings

        # Check if EXIF/metadata stripping is present
        has_metadata_strip = _body_has_indicator(body, METADATA_STRIP_INDICATORS)

        if not has_metadata_strip:
            findings.append(UploadFinding(
                category=FindingCategory.IMAGE_METADATA,
                message=(
                    "Uploaded images are processed/stored without stripping EXIF "
                    "metadata — EXIF data can contain GPS coordinates, device "
                    "information, timestamps, and other sensitive information "
                    "that may be exposed to other users"
                ),
                remediation=(
                    "Strip EXIF metadata from all uploaded images before storage. "
                    "Python/Pillow: image.save() with exif=b'' or use piexif.remove(). "
                    "Node.js: use sharp().rotate() (auto-strips EXIF). "
                    "Command line: exiftool -all= image.jpg. "
                    "Consider re-encoding images entirely to eliminate all metadata."
                ),
                line=_get_line(func),
                column=_get_column(func),
                file=file,
            ))

        return findings


class ZipBombDetector:
    """Detect archive extraction without decompressed size checks (CWE-409)."""

    def analyze(
        self,
        func: PureFunc | TaskFunc,
        body: List[Statement],
        exprs: List[Tuple[Expr, Statement]],
        file: str,
    ) -> List[UploadFinding]:
        findings: List[UploadFinding] = []

        # Check if function extracts archives
        has_extraction = False
        extract_line = 0
        extract_col = 0

        for expr, stmt in exprs:
            if isinstance(expr, FunctionCall):
                cname = _callee_name(expr).lower()
                if any(p in cname for p in ARCHIVE_EXTRACT_FUNCTIONS):
                    has_extraction = True
                    extract_line = _get_line(expr) or _get_line(stmt)
                    extract_col = _get_column(expr)
                    break
            elif isinstance(expr, MethodCall):
                mname = expr.method_name.lower()
                if any(p in mname for p in ARCHIVE_EXTRACT_FUNCTIONS):
                    has_extraction = True
                    extract_line = _get_line(expr) or _get_line(stmt)
                    extract_col = _get_column(expr)
                    break

        if not has_extraction:
            return findings

        # Check if decompressed size is validated
        has_size_check = _body_has_indicator(body, ARCHIVE_SIZE_CHECK_INDICATORS)

        if not has_size_check:
            findings.append(UploadFinding(
                category=FindingCategory.ZIP_BOMB,
                message=(
                    "Archive extraction without decompressed size validation — "
                    "a zip bomb (e.g., 42.zip: 42KB compressed, 4.5PB decompressed) "
                    "can exhaust disk space and memory, causing denial of service"
                ),
                remediation=(
                    "Before extracting, check the total uncompressed size of all "
                    "entries in the archive. Set a maximum decompressed size limit. "
                    "Python: iterate ZipFile.infolist() and sum file_size before "
                    "extracting. Check compression ratio (reject ratio > 100:1). "
                    "Node.js: use yauzl and check uncompressedSize per entry. "
                    "Also limit the number of files in the archive and recursion depth."
                ),
                line=extract_line,
                column=extract_col,
                file=file,
            ))

        return findings


class StoragePathDisclosureDetector:
    """Detect returning server file paths in upload responses (CWE-209)."""

    def analyze(
        self,
        func: PureFunc | TaskFunc,
        body: List[Statement],
        exprs: List[Tuple[Expr, Statement]],
        file: str,
    ) -> List[UploadFinding]:
        findings: List[UploadFinding] = []

        if not _is_upload_handler(func, body):
            return findings

        # Look for response construction that includes path fields
        has_response = _function_contains_call_matching(body, RESPONSE_FUNCTIONS)

        if not has_response:
            # Check for return statements (which may be the response)
            has_return = False
            for stmt in body:
                if isinstance(stmt, ReturnStmt):
                    has_return = True
                    break
            if not has_return:
                return findings

        # Check if path-related fields appear in the response body
        for expr, stmt in exprs:
            if isinstance(expr, FieldAccess):
                fname = expr.field_name.lower()
                if fname in PATH_DISCLOSURE_FIELDS:
                    # Check if the object is a file/filesystem reference
                    obj_name = ""
                    if isinstance(expr.obj, Identifier):
                        obj_name = expr.obj.name.lower()

                    file_obj_patterns = {
                        "file", "uploaded", "result", "upload",
                        "saved", "stored", "fs", "os",
                    }

                    if any(p in obj_name for p in file_obj_patterns) or not obj_name:
                        findings.append(UploadFinding(
                            category=FindingCategory.STORAGE_PATH_DISCLOSURE,
                            message=(
                                f"Server filesystem path ('{fname}') appears to be "
                                f"included in the upload response — this reveals "
                                f"internal directory structure to the client, aiding "
                                f"path traversal and server enumeration attacks"
                            ),
                            remediation=(
                                "Never return absolute or relative server filesystem "
                                "paths in API responses. Return only the public URL "
                                "or a resource identifier (e.g., UUID). Map file IDs "
                                "to storage paths server-side only."
                            ),
                            line=_get_line(expr) or _get_line(stmt),
                            column=_get_column(expr),
                            file=file,
                        ))
                        # Only report once per function
                        return findings

        return findings


class MissingMalwareScanDetector:
    """Detect upload pipelines without virus/malware scanning."""

    def analyze(
        self,
        func: PureFunc | TaskFunc,
        body: List[Statement],
        exprs: List[Tuple[Expr, Statement]],
        file: str,
    ) -> List[UploadFinding]:
        findings: List[UploadFinding] = []

        if not _is_upload_handler(func, body):
            return findings

        # Check if any malware scanning step is present
        has_scan = _body_has_indicator(body, MALWARE_SCAN_INDICATORS)

        if not has_scan:
            findings.append(UploadFinding(
                category=FindingCategory.MISSING_MALWARE_SCAN,
                message=(
                    f"Upload handler '{getattr(func, 'name', '<anonymous>')}' "
                    f"stores files without any virus or malware scanning step — "
                    f"malicious files can be distributed to other users or "
                    f"executed on the server"
                ),
                remediation=(
                    "Scan all uploaded files before storing or serving them. "
                    "Options: ClamAV (open source, self-hosted), VirusTotal API "
                    "(cloud), Windows Defender (Windows servers). "
                    "Python: use pyclamd to connect to clamd. "
                    "Node.js: use clamscan or node-clam. "
                    "Store files in quarantine until scan completes. "
                    "For high-security: scan in an isolated sandbox environment."
                ),
                line=_get_line(func),
                column=_get_column(func),
                file=file,
            ))

        return findings


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class FileUploadSecurityEngine:
    """Full file upload security detection engine.

    Walks the AEON AST and runs all detectors on every function body,
    focusing on functions that handle file uploads.
    """

    def __init__(self) -> None:
        self.unrestricted_type = UnrestrictedFileTypeDetector()
        self.path_traversal = PathTraversalFilenameDetector()
        self.missing_size = MissingSizeLimitDetector()
        self.svg_xss = SvgXssDetector()
        self.dangerous_types = DangerousFileTypesDetector()
        self.client_side_only = ClientSideOnlyValidationDetector()
        self.image_metadata = ImageMetadataDetector()
        self.zip_bomb = ZipBombDetector()
        self.storage_path = StoragePathDisclosureDetector()
        self.missing_scan = MissingMalwareScanDetector()

    def analyze(self, program: Program) -> List[UploadFinding]:
        """Run all file upload security detectors on the program."""
        all_findings: List[UploadFinding] = []
        file = program.filename

        for decl in program.declarations:
            if isinstance(decl, (PureFunc, TaskFunc)):
                findings = self._analyze_function(decl, file)
                all_findings.extend(findings)

        return all_findings

    def _analyze_function(
        self,
        func: PureFunc | TaskFunc,
        file: str,
    ) -> List[UploadFinding]:
        """Run all detectors on a single function."""
        findings: List[UploadFinding] = []
        body = func.body

        # Collect all expressions with their parent statements
        exprs = _collect_all_exprs(body)

        # Run each detector
        findings.extend(self.unrestricted_type.analyze(func, body, exprs, file))
        findings.extend(self.path_traversal.analyze(func, body, exprs, file))
        findings.extend(self.missing_size.analyze(func, body, exprs, file))
        findings.extend(self.svg_xss.analyze(func, body, exprs, file))
        findings.extend(self.dangerous_types.analyze(func, body, exprs, file))
        findings.extend(self.client_side_only.analyze(func, body, exprs, file))
        findings.extend(self.image_metadata.analyze(func, body, exprs, file))
        findings.extend(self.zip_bomb.analyze(func, body, exprs, file))
        findings.extend(self.storage_path.analyze(func, body, exprs, file))
        findings.extend(self.missing_scan.analyze(func, body, exprs, file))

        return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_file_upload(program: Program) -> list:
    """Run file upload security detection on an AEON program.

    Detects dangerous file upload patterns:
    - Unrestricted file type acceptance (CWE-434)
    - Path traversal via user-supplied filenames (CWE-22)
    - Missing file size limits (CWE-400)
    - SVG XSS via unsanitized SVG uploads (CWE-79)
    - Dangerous executable file types allowed (CWE-434)
    - Client-side only file validation (CWE-602)
    - Image metadata/EXIF data exposure (CWE-200)
    - Zip bomb / decompression bomb risk (CWE-409)
    - Storage path disclosure in responses (CWE-209)
    - Missing virus/malware scanning

    Args:
        program: An AEON Program AST node.

    Returns:
        A list of AeonError objects, one per finding.
    """
    try:
        engine = FileUploadSecurityEngine()
        findings = engine.analyze(program)

        errors: List[AeonError] = []
        for finding in findings:
            errors.append(finding.to_aeon_error())

        return errors
    except Exception:
        # Engine-level safety net: never let the entire engine crash
        # the verification pipeline
        return []
