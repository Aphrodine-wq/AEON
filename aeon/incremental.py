"""AEON Incremental Analysis — Smart Dependency-Aware Verification.

Tracks file dependencies and only reanalyzes changed code plus dependents.
Provides massive speedups for large codebases during iterative development.

Usage:
    from aeon.incremental import IncrementalAnalyzer
    analyzer = IncrementalAnalyzer()
    result = analyzer.analyze("src/", deep_verify=True)
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any

from aeon.scanner import ScanResult, discover_files
from aeon.language_adapter import verify_file, detect_language


@dataclass
class FileMetadata:
    """Metadata for a source file."""
    path: str
    mtime: float
    size: int
    hash: str
    language: str
    dependencies: Set[str] = field(default_factory=set)
    dependents: Set[str] = field(default_factory=set)


@dataclass
class DependencyGraph:
    """Dependency graph for source files."""
    files: Dict[str, FileMetadata] = field(default_factory=dict)
    reverse_deps: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    
    def add_file(self, metadata: FileMetadata) -> None:
        self.files[metadata.path] = metadata
        for dep in metadata.dependencies:
            self.reverse_deps[dep].add(metadata.path)
    
    def get_affected_files(self, changed_file: str) -> Set[str]:
        """Get all files that depend on the changed file."""
        affected = {changed_file}
        to_visit = list(self.reverse_deps.get(changed_file, set()))
        
        while to_visit:
            current = to_visit.pop()
            if current not in affected:
                affected.add(current)
                to_visit.extend(self.reverse_deps.get(current, set()))
        
        return affected


class IncrementalAnalyzer:
    """Incremental analysis engine with dependency tracking."""
    
    def __init__(self, cache_dir: str = ".aeon-cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.metadata_file = self.cache_dir / "metadata.json"
        self.dep_graph_file = self.cache_dir / "deps.json"
        
        self.dep_graph = DependencyGraph()
        self._load_cache()
    
    def _load_cache(self) -> None:
        """Load cached metadata and dependency graph."""
        try:
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    for path, meta in data.items():
                        self.dep_graph.files[path] = FileMetadata(**meta)
            
            if self.dep_graph_file.exists():
                with open(self.dep_graph_file, 'r') as f:
                    data = json.load(f)
                    for file_path, deps in data.items():
                        self.dep_graph.reverse_deps[file_path] = set(deps)
        except Exception:
            # Cache corruption - start fresh
            self.dep_graph = DependencyGraph()
    
    def _save_cache(self) -> None:
        """Save metadata and dependency graph to cache."""
        try:
            # Save file metadata
            metadata_data = {}
            for path, meta in self.dep_graph.files.items():
                metadata_data[path] = {
                    "path": meta.path,
                    "mtime": meta.mtime,
                    "size": meta.size,
                    "hash": meta.hash,
                    "language": meta.language,
                    "dependencies": list(meta.dependencies),
                    "dependents": list(meta.dependents),
                }
            
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata_data, f, indent=2)
            
            # Save reverse dependencies
            rev_deps_data = {
                path: list(deps) for path, deps in self.dep_graph.reverse_deps.items()
            }
            with open(self.dep_graph_file, 'w') as f:
                json.dump(rev_deps_data, f, indent=2)
        except Exception:
            # Failed to save cache - continue without it
            pass
    
    def _compute_file_hash(self, filepath: str) -> str:
        """Compute SHA-256 hash of file contents."""
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""
    
    def _extract_dependencies(self, filepath: str, language: str) -> Set[str]:
        """Extract import dependencies from a source file."""
        deps = set()
        
        try:
            if language == "python":
                deps.update(self._extract_python_deps(filepath))
            elif language in ["javascript", "typescript"]:
                deps.update(self._extract_js_deps(filepath))
            elif language == "java":
                deps.update(self._extract_java_deps(filepath))
            elif language == "go":
                deps.update(self._extract_go_deps(filepath))
            elif language == "rust":
                deps.update(self._extract_rust_deps(filepath))
            # Add more language extractors as needed
        except Exception:
            # Failed to extract deps - continue without them
            pass
        
        return deps
    
    def _extract_python_deps(self, filepath: str) -> Set[str]:
        """Extract Python import dependencies."""
        deps = set()
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=filepath)
            base_dir = os.path.dirname(os.path.abspath(filepath))
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        # Try to resolve relative imports
                        if alias.name.startswith('.'):
                            resolved = self._resolve_python_import(
                                alias.name, base_dir, filepath
                            )
                            if resolved:
                                deps.add(resolved)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        # Handle from X import Y
                        resolved = self._resolve_python_import(
                            node.module, base_dir, filepath
                        )
                        if resolved:
                            deps.add(resolved)
        except Exception:
            pass
        
        return deps
    
    def _resolve_python_import(self, module: str, base_dir: str, current_file: str) -> Optional[str]:
        """Resolve Python import to actual file path."""
        # Simple heuristic - look for .py files in the same directory and parent directories
        parts = module.lstrip('.').split('.')
        
        # Handle relative imports
        if module.startswith('.'):
            level = len(module) - len(module.lstrip('.'))
            target_dir = base_dir
            for _ in range(level - 1):
                target_dir = os.path.dirname(target_dir)
            parts = [p for p in parts if p]  # Remove empty strings from relative imports
        else:
            target_dir = base_dir
        
        # Try to find the module file
        current = target_dir
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                # Last part - could be a file
                candidates = [
                    os.path.join(current, f"{part}.py"),
                    os.path.join(current, part, "__init__.py")
                ]
                for candidate in candidates:
                    if os.path.exists(candidate) and candidate != current_file:
                        return os.path.abspath(candidate)
            else:
                # Intermediate part - must be a directory
                current = os.path.join(current, part)
                if not os.path.isdir(current):
                    return None
        
        return None
    
    def _extract_js_deps(self, filepath: str) -> Set[str]:
        """Extract JavaScript/TypeScript dependencies."""
        deps = set()
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            import re
            # Match import statements
            patterns = [
                r'import.*from\s+["\']([^"\']+)["\']',
                r'require\(["\']([^"\']+)["\']\)',
                r'import\s+["\']([^"\']+)["\']'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if not match.startswith('.') and not match.startswith('/'):
                        continue  # Skip node_modules imports
                    
                    # Resolve relative imports
                    if match.startswith('.'):
                        base_dir = os.path.dirname(filepath)
                        import_path = os.path.abspath(os.path.join(base_dir, match))
                        
                        # Try common extensions
                        for ext in ['.js', '.ts', '.jsx', '.tsx', '.json']:
                            candidate = import_path + ext
                            if os.path.exists(candidate):
                                deps.add(candidate)
                                break
        except Exception:
            pass
        
        return deps
    
    def _extract_java_deps(self, filepath: str) -> Set[str]:
        """Extract Java dependencies."""
        deps = set()
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            import re
            # Match import statements
            pattern = r'import\s+([^\s;]+);'
            matches = re.findall(pattern, content)
            
            base_dir = self._find_java_source_root(filepath)
            for match in matches:
                # Convert package name to file path
                if not match.startswith('java.') and not match.startswith('javax.'):
                    path_parts = match.split('.')
                    candidate = os.path.join(base_dir, *path_parts) + ".java"
                    if os.path.exists(candidate) and candidate != filepath:
                        deps.add(candidate)
        except Exception:
            pass
        
        return deps
    
    def _find_java_source_root(self, filepath: str) -> str:
        """Find Java source root (directory containing package structure)."""
        current = os.path.dirname(filepath)
        while current and current != '/':
            if any(f.endswith('.java') for f in os.listdir(current)):
                return current
            current = os.path.dirname(current)
        return os.path.dirname(filepath)
    
    def _extract_go_deps(self, filepath: str) -> Set[str]:
        """Extract Go dependencies."""
        deps = set()
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            import re
            # Match import statements
            pattern = r'"([^"]+)"'
            import_section = re.search(r'import\s*\((.*?)\)', content, re.DOTALL)
            
            if import_section:
                matches = re.findall(pattern, import_section.group(1))
            else:
                # Single import
                single_import = re.search(r'import\s+"([^"]+)"', content)
                if single_import:
                    matches = [single_import.group(1)]
                else:
                    matches = []
            
            base_dir = self._find_go_module_root(filepath)
            for match in matches:
                if match.startswith('.') or match.startswith('./'):
                    # Local import
                    import_path = os.path.join(base_dir, match.replace('./', ''))
                    candidate = os.path.join(import_path, filepath.split('/')[-1])
                    if os.path.exists(candidate) and candidate != filepath:
                        deps.add(candidate)
        except Exception:
            pass
        
        return deps
    
    def _find_go_module_root(self, filepath: str) -> str:
        """Find Go module root (directory with go.mod)."""
        current = os.path.dirname(filepath)
        while current and current != '/':
            if os.path.exists(os.path.join(current, 'go.mod')):
                return current
            current = os.path.dirname(current)
        return os.path.dirname(filepath)
    
    def _extract_rust_deps(self, filepath: str) -> Set[str]:
        """Extract Rust dependencies."""
        deps = set()
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            import re
            # Match use statements
            pattern = r'use\s+([^;]+);'
            matches = re.findall(pattern, content)
            
            base_dir = self._find_rust_root(filepath)
            for match in matches:
                if match.startswith('crate::') or match.startswith('super::') or match.startswith('self::'):
                    # Local module
                    module_path = match.replace('crate::', '').replace('super::', '').replace('self::', '')
                    parts = module_path.split('::')
                    
                    current = base_dir
                    for i, part in enumerate(parts):
                        if i == len(parts) - 1:
                            # Last part - could be a file
                            candidate = os.path.join(current, f"{part}.rs")
                            if os.path.exists(candidate) and candidate != filepath:
                                deps.add(candidate)
                        else:
                            current = os.path.join(current, part)
                            if not os.path.isdir(current):
                                break
        except Exception:
            pass
        
        return deps
    
    def _find_rust_root(self, filepath: str) -> str:
        """Find Rust crate root (directory with Cargo.toml)."""
        current = os.path.dirname(filepath)
        while current and current != '/':
            if os.path.exists(os.path.join(current, 'Cargo.toml')):
                return current
            current = os.path.dirname(current)
        return os.path.dirname(filepath)
    
    def _get_file_metadata(self, filepath: str) -> FileMetadata:
        """Get current metadata for a file."""
        stat = os.stat(filepath)
        return FileMetadata(
            path=filepath,
            mtime=stat.st_mtime,
            size=stat.st_size,
            hash=self._compute_file_hash(filepath),
            language=detect_language(filepath),
            dependencies=self._extract_dependencies(filepath, detect_language(filepath))
        )
    
    def _is_file_changed(self, filepath: str) -> bool:
        """Check if a file has changed since last analysis."""
        if filepath not in self.dep_graph.files:
            return True
        
        current_meta = self._get_file_metadata(filepath)
        cached_meta = self.dep_graph.files[filepath]
        
        return (
            current_meta.mtime != cached_meta.mtime or
            current_meta.size != cached_meta.size or
            current_meta.hash != cached_meta.hash
        )
    
    def analyze(self, root: str, deep_verify: bool = True,
                analyses: Optional[List[str]] = None,
                force: bool = False) -> ScanResult:
        """Perform incremental analysis of a directory."""
        start_time = time.time()
        root = os.path.abspath(root)
        
        # Discover all files
        all_files = discover_files(root)
        
        # Find changed files
        changed_files = set()
        if not force:
            for filepath in all_files:
                if self._is_file_changed(filepath):
                    changed_files.add(filepath)
        else:
            changed_files = set(all_files)
        
        # Find all affected files (changed + dependents)
        files_to_analyze = set()
        for changed_file in changed_files:
            files_to_analyze.update(self.dep_graph.get_affected_files(changed_file))
        
        # Update metadata for changed files
        for filepath in changed_files:
            meta = self._get_file_metadata(filepath)
            self.dep_graph.add_file(meta)
        
        # Perform analysis on affected files
        result = ScanResult(root=root, files_scanned=len(all_files))
        
        for filepath in files_to_analyze:
            if filepath not in all_files:
                continue  # File was deleted
            
            try:
                lang = detect_language(filepath)
                result.languages[lang] = result.languages.get(lang, 0) + 1
                
                vr = verify_file(filepath, deep_verify=deep_verify, analyses=analyses)
                
                file_entry = {
                    "file": os.path.relpath(filepath, root),
                    "language": lang,
                    "verified": vr.verified,
                    "errors": len(vr.errors),
                    "warnings": len(vr.warnings),
                    "functions": vr.functions_analyzed,
                    "classes": vr.classes_analyzed,
                    "summary": vr.summary,
                    "incremental": filepath in files_to_analyze,
                }
                if vr.errors:
                    file_entry["error_details"] = vr.errors
                if vr.warnings:
                    file_entry["warning_details"] = vr.warnings
                
                result.file_results.append(file_entry)
                
                if vr.verified:
                    result.files_verified += 1
                if vr.errors:
                    result.files_with_errors += 1
                    result.total_errors += len(vr.errors)
                if vr.warnings:
                    result.files_with_warnings += 1
                    result.total_warnings += len(vr.warnings)
                
                result.total_functions += vr.functions_analyzed
                result.total_classes += vr.classes_analyzed
                
            except Exception as e:
                result.file_results.append({
                    "file": os.path.relpath(filepath, root),
                    "error": str(e),
                    "verified": False,
                    "incremental": filepath in files_to_analyze,
                })
        
        # Save updated cache
        self._save_cache()
        
        # Calculate timing
        elapsed = (time.time() - start_time) * 1000
        result.duration_ms = round(elapsed, 1)
        
        # Build summary
        lang_list = ", ".join(f"{v} {k}" for k, v in sorted(result.languages.items()))
        incremental_info = f"{len(files_to_analyze)}/{len(all_files)} files analyzed"
        
        if result.total_errors == 0:
            result.summary = (
                f"\u2705 ALL VERIFIED: {result.files_scanned} files, "
                f"{result.total_functions} functions ({lang_list}) — "
                f"{result.duration_ms}ms [{incremental_info}]"
            )
        else:
            result.summary = (
                f"\u274c {result.total_errors} error(s) in {result.files_with_errors} of "
                f"{result.files_scanned} files ({lang_list}) — "
                f"{result.duration_ms}ms [{incremental_info}]"
            )
        
        return result
    
    def clear_cache(self) -> None:
        """Clear the incremental analysis cache."""
        try:
            if self.metadata_file.exists():
                self.metadata_file.unlink()
            if self.dep_graph_file.exists():
                self.dep_graph_file.unlink()
            self.dep_graph = DependencyGraph()
        except Exception:
            pass
    
    def get_dependency_graph(self) -> Dict[str, Any]:
        """Get the current dependency graph for debugging."""
        return {
            "files": {path: {
                "path": meta.path,
                "language": meta.language,
                "dependencies": list(meta.dependencies),
                "dependents": list(meta.dependents),
            } for path, meta in self.dep_graph.files.items()},
            "reverse_dependencies": {
                path: list(deps) for path, deps in self.dep_graph.reverse_deps.items()
            }
        }
