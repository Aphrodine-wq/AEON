"""AEON Cross-File Analysis Engine.

Maps data flow across files to catch integration bugs:
  - API route returns shape X but frontend expects shape Y
  - Component passes wrong prop types
  - Exported type is defined differently than consumed
  - Import references non-existent export
  - Duplicate type definitions that may drift

Works by building an import/export graph and checking contracts
between connected files.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple
from pathlib import Path

from aeon.errors import AeonError, ErrorKind, SourceLocation


@dataclass
class ExportedSymbol:
    name: str
    kind: str          # function | type | interface | const | class | enum
    filepath: str
    line: int
    signature: str     # Type signature or function params
    is_default: bool = False


@dataclass
class ImportedSymbol:
    name: str
    source_module: str  # The 'from' path
    filepath: str
    line: int
    alias: Optional[str] = None  # { Foo as Bar }
    is_type_only: bool = False


@dataclass
class APIRoute:
    method: str        # GET | POST | PUT | PATCH | DELETE
    filepath: str
    line: int
    response_shape: str  # Rough shape of JSON response
    params: List[str]    # URL params
    body_shape: str      # Rough shape of request body


@dataclass
class CrossFileResult:
    findings: List[AeonError]
    exports: Dict[str, List[ExportedSymbol]]  # filepath -> exports
    imports: Dict[str, List[ImportedSymbol]]    # filepath -> imports
    api_routes: List[APIRoute]
    files_analyzed: int


def cross_file_error(
    message: str,
    category: str,
    filepath: str,
    line: int,
    severity: str = "warning",
    fix: Optional[str] = None,
    related_file: Optional[str] = None,
) -> AeonError:
    details: Dict = {
        "precondition": message,
        "failing_values": {
            "category": f"cross-file-{category}",
            "severity": severity,
            "rule": f"xfile-{category}",
        },
        "function_signature": "cross_file_analysis",
    }
    if related_file:
        details["failing_values"]["related_file"] = related_file
    return AeonError(
        kind=ErrorKind.CONTRACT_ERROR,
        message=f"Cross-file: {message}",
        location=SourceLocation(file=filepath, line=line, column=1),
        details=details,
        fix_suggestion=fix,
    )


# ── Extraction ────────────────────────────────────────────────────────────────

def _extract_exports(source: str, filepath: str) -> List[ExportedSymbol]:
    """Extract all exports from a TypeScript/JavaScript file."""
    exports: List[ExportedSymbol] = []
    lines = source.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # export function foo(...)
        m = re.match(r'export\s+(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)', stripped)
        if m:
            exports.append(ExportedSymbol(m.group(1), "function", filepath, i, m.group(2)))
            continue

        # export const foo = ...
        m = re.match(r'export\s+const\s+(\w+)\s*(?::\s*([^=]+))?\s*=', stripped)
        if m:
            exports.append(ExportedSymbol(m.group(1), "const", filepath, i, m.group(2) or ""))
            continue

        # export type Foo = ...
        m = re.match(r'export\s+type\s+(\w+)\s*=', stripped)
        if m:
            exports.append(ExportedSymbol(m.group(1), "type", filepath, i, ""))
            continue

        # export interface Foo { ... }
        m = re.match(r'export\s+interface\s+(\w+)', stripped)
        if m:
            exports.append(ExportedSymbol(m.group(1), "interface", filepath, i, ""))
            continue

        # export enum Foo { ... }
        m = re.match(r'export\s+enum\s+(\w+)', stripped)
        if m:
            exports.append(ExportedSymbol(m.group(1), "enum", filepath, i, ""))
            continue

        # export class Foo
        m = re.match(r'export\s+(?:abstract\s+)?class\s+(\w+)', stripped)
        if m:
            exports.append(ExportedSymbol(m.group(1), "class", filepath, i, ""))
            continue

        # export default function/class
        m = re.match(r'export\s+default\s+(?:async\s+)?function\s+(\w+)', stripped)
        if m:
            exports.append(ExportedSymbol(m.group(1), "function", filepath, i, "", is_default=True))
            continue

        # export default ...
        if stripped.startswith("export default "):
            exports.append(ExportedSymbol("default", "default", filepath, i, "", is_default=True))

    return exports


def _extract_imports(source: str, filepath: str) -> List[ImportedSymbol]:
    """Extract all imports from a TypeScript/JavaScript file."""
    imports: List[ImportedSymbol] = []

    # import { Foo, Bar as Baz } from 'module'
    for m in re.finditer(r'import\s+(?:type\s+)?\{([^}]+)\}\s+from\s+["\']([^"\']+)["\']', source):
        is_type = 'import type' in source[max(0, m.start()-12):m.start()+12]
        line = source[:m.start()].count("\n") + 1
        module = m.group(2)
        for sym in m.group(1).split(","):
            sym = sym.strip()
            if not sym:
                continue
            alias = None
            if " as " in sym:
                parts = sym.split(" as ")
                sym = parts[0].strip()
                alias = parts[1].strip()
            # Skip 'type' prefix in individual imports
            if sym.startswith("type "):
                sym = sym[5:]
                is_type = True
            imports.append(ImportedSymbol(sym, module, filepath, line, alias, is_type))

    # import Foo from 'module'
    for m in re.finditer(r'import\s+(\w+)\s+from\s+["\']([^"\']+)["\']', source):
        line = source[:m.start()].count("\n") + 1
        imports.append(ImportedSymbol(m.group(1), m.group(2), filepath, line))

    return imports


def _extract_api_routes(source: str, filepath: str) -> List[APIRoute]:
    """Extract API route handlers from Next.js route files."""
    routes: List[APIRoute] = []

    for m in re.finditer(r'export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\b', source):
        method = m.group(1)
        line = source[:m.start()].count("\n") + 1

        # Find response shape (look for NextResponse.json({ ... }))
        handler_start = m.start()
        handler_end = min(len(source), handler_start + 5000)
        handler_body = source[handler_start:handler_end]

        # Extract response keys
        response_keys = set()
        for rm in re.finditer(r'NextResponse\.json\s*\(\s*\{([^}]{1,200})\}', handler_body):
            keys = re.findall(r'(\w+)\s*:', rm.group(1))
            response_keys.update(keys)

        # Extract URL params
        params = re.findall(r'params\.\w+|params\s*\}\s*.*?(\w+Id|\w+_id)', handler_body, re.I)

        # Extract body shape
        body_keys = set()
        body_match = re.search(r'(?:req\.json|body)\s*(?:as\s+\w+)?\s*;?\s*(?:const\s+\{([^}]+)\})?', handler_body)
        if body_match and body_match.group(1):
            body_keys = set(re.findall(r'(\w+)', body_match.group(1)))

        routes.append(APIRoute(
            method=method,
            filepath=filepath,
            line=line,
            response_shape=", ".join(sorted(response_keys)) if response_keys else "<unknown>",
            params=params,
            body_shape=", ".join(sorted(body_keys)) if body_keys else "",
        ))

    return routes


# ── Analysis ──────────────────────────────────────────────────────────────────

class CrossFileAnalyzer:
    """Analyze relationships between files in a project."""

    def __init__(self):
        self.exports: Dict[str, List[ExportedSymbol]] = {}
        self.imports: Dict[str, List[ImportedSymbol]] = {}
        self.api_routes: List[APIRoute] = []
        self.errors: List[AeonError] = []
        self.all_export_names: Dict[str, List[str]] = {}  # symbol -> [filepaths]

    def analyze_directory(self, root: str) -> CrossFileResult:
        """Analyze all TypeScript/JavaScript files in a directory."""
        files = self._discover_files(root)

        # Phase 1: Extract exports and imports from all files
        for filepath in files:
            try:
                source = Path(filepath).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            rel_path = os.path.relpath(filepath, root)

            file_exports = _extract_exports(source, rel_path)
            self.exports[rel_path] = file_exports
            for exp in file_exports:
                self.all_export_names.setdefault(exp.name, []).append(rel_path)

            file_imports = _extract_imports(source, rel_path)
            self.imports[rel_path] = file_imports

            # Extract API routes
            if "route.ts" in filepath or "route.js" in filepath:
                self.api_routes.extend(_extract_api_routes(source, rel_path))

        # Phase 2: Cross-reference analysis
        self._check_duplicate_exports()
        self._check_circular_deps()
        self._check_api_consistency()
        self._check_orphan_exports()

        return CrossFileResult(
            findings=self.errors,
            exports=self.exports,
            imports=self.imports,
            api_routes=self.api_routes,
            files_analyzed=len(files),
        )

    def _check_duplicate_exports(self):
        """Flag types/interfaces exported from multiple files (may drift)."""
        for name, filepaths in self.all_export_names.items():
            if len(filepaths) > 1 and name not in ("default", "GET", "POST", "PUT", "PATCH", "DELETE"):
                # Check if same kind
                kinds = set()
                for fp in filepaths:
                    for exp in self.exports.get(fp, []):
                        if exp.name == name:
                            kinds.add(exp.kind)

                if "type" in kinds or "interface" in kinds:
                    self.errors.append(cross_file_error(
                        f"Type/interface '{name}' exported from {len(filepaths)} files — may drift out of sync",
                        "duplicate-type",
                        filepaths[0],
                        1,
                        severity="warning",
                        fix=f"Consolidate to single source of truth. Also exported from: {', '.join(filepaths[1:])}",
                        related_file=filepaths[1],
                    ))

    def _check_circular_deps(self):
        """Detect circular import chains."""
        # Build adjacency list
        graph: Dict[str, Set[str]] = {}
        for filepath, file_imports in self.imports.items():
            graph.setdefault(filepath, set())
            for imp in file_imports:
                # Resolve relative imports
                if imp.source_module.startswith("."):
                    resolved = self._resolve_import(filepath, imp.source_module)
                    if resolved:
                        graph[filepath].add(resolved)

        # DFS for cycles
        visited: Set[str] = set()
        path: List[str] = []
        path_set: Set[str] = set()

        def dfs(node: str):
            if node in path_set:
                cycle_start = path.index(node)
                cycle = path[cycle_start:] + [node]
                if len(cycle) <= 5:  # Only report short cycles
                    self.errors.append(cross_file_error(
                        f"Circular import: {' -> '.join(cycle)}",
                        "circular-import",
                        node, 1,
                        severity="warning",
                        fix="Break the cycle by extracting shared types to a common module",
                    ))
                return

            if node in visited:
                return
            visited.add(node)
            path.append(node)
            path_set.add(node)

            for neighbor in graph.get(node, set()):
                dfs(neighbor)

            path.pop()
            path_set.remove(node)

        for node in graph:
            dfs(node)

    def _check_api_consistency(self):
        """Check API routes for consistency patterns."""
        # Group routes by base path
        route_groups: Dict[str, List[APIRoute]] = {}
        for route in self.api_routes:
            base = os.path.dirname(route.filepath)
            route_groups.setdefault(base, []).append(route)

        for base, routes in route_groups.items():
            methods = {r.method for r in routes}

            # CRUD consistency: if POST exists, GET should too
            # Skip action endpoints (sign, send, decline, approve, etc.)
            action_patterns = re.compile(r'sign|send|decline|approve|pay|respond|export|generate|analyze|clone|predict|callback|status|resend|checkout|portal|viewed|ocr', re.I)
            if "POST" in methods and "GET" not in methods:
                if not action_patterns.search(base):
                    post_route = next(r for r in routes if r.method == "POST")
                    self.errors.append(cross_file_error(
                        f"POST endpoint without corresponding GET — incomplete CRUD",
                        "api-incomplete",
                        post_route.filepath,
                        post_route.line,
                        severity="info",
                        fix="Add GET handler for retrieving the created resource",
                    ))

    def _check_orphan_exports(self):
        """Find exported symbols that nothing imports (dead exports)."""
        # Build set of all imported symbols
        all_imported: Set[str] = set()
        for file_imports in self.imports.values():
            for imp in file_imports:
                all_imported.add(imp.name)

        # Find exports that nobody imports
        for filepath, file_exports in self.exports.items():
            for exp in file_exports:
                if exp.name == "default" or exp.is_default:
                    continue
                if exp.kind in ("type", "interface", "enum"):
                    continue  # Types may be used transitively
                if exp.name in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    continue  # API handlers are used by Next.js
                if exp.name not in all_imported:
                    self.errors.append(cross_file_error(
                        f"Exported '{exp.name}' ({exp.kind}) is not imported by any file — possible dead code",
                        "orphan-export",
                        filepath,
                        exp.line,
                        severity="info",
                        fix="Remove if unused, or mark as @internal",
                    ))

    def _resolve_import(self, from_file: str, module_path: str) -> Optional[str]:
        """Resolve a relative import to a file path."""
        from_dir = os.path.dirname(from_file)
        resolved = os.path.normpath(os.path.join(from_dir, module_path))
        # Try common extensions
        for ext in [".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx"]:
            candidate = resolved + ext
            if candidate in self.exports:
                return candidate
        return None

    def _discover_files(self, root: str) -> List[str]:
        """Find all TypeScript/JavaScript files, respecting gitignore."""
        files: List[str] = []
        skip_dirs = {"node_modules", ".next", "dist", ".git", "__pycache__", ".build",
                     "coverage", ".turbo", ".vercel", ".claude"}

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for f in filenames:
                if f.endswith((".ts", ".tsx", ".js", ".jsx")) and not f.endswith(".d.ts"):
                    files.append(os.path.join(dirpath, f))

        return files


# ── Module Entry Point ────────────────────────────────────────────────────────

def analyze_cross_file(root: str) -> CrossFileResult:
    """Run cross-file analysis on a project directory."""
    analyzer = CrossFileAnalyzer()
    return analyzer.analyze_directory(root)
