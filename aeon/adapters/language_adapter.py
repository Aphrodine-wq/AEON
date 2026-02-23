"""AEON Multi-Language Adapter Framework.

Provides a pluggable architecture for verifying code in any language
by translating it to AEON's internal AST and running the 10 formal
verification engines.

Supported languages:
  - Python (built-in ast module)
  - Java (javalang)
  - JavaScript / TypeScript (tree-sitter)

Usage:
    from aeon.language_adapter import verify
    result = verify(source_code, language="java")

    # Or auto-detect from file extension:
    result = verify_file("MyClass.java")
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple

from aeon.ast_nodes import Program
from aeon.errors import AeonError


# ---------------------------------------------------------------------------
# Verification Result (shared across all languages)
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    """Result of verifying source code in any language."""
    source_language: str = ""
    functions_analyzed: int = 0
    classes_analyzed: int = 0
    errors: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    translation_errors: List[str] = field(default_factory=list)
    verified: bool = False
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_language": self.source_language,
            "functions_analyzed": self.functions_analyzed,
            "classes_analyzed": self.classes_analyzed,
            "errors": self.errors,
            "warnings": self.warnings,
            "translation_errors": self.translation_errors,
            "verified": self.verified,
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Abstract Language Translator
# ---------------------------------------------------------------------------

class LanguageTranslator(ABC):
    """Base class for language-specific translators.

    Each translator converts source code in a given language into
    an AEON Program AST, which can then be verified by the 10
    formal analysis engines.
    """

    def __init__(self):
        self.errors: List[str] = []

    @property
    @abstractmethod
    def language_name(self) -> str:
        """Human-readable language name, e.g. 'Python', 'Java'."""
        ...

    @property
    @abstractmethod
    def file_extensions(self) -> List[str]:
        """File extensions this translator handles, e.g. ['.py']."""
        ...

    @property
    @abstractmethod
    def noise_patterns(self) -> List[str]:
        """Patterns in error messages to filter as translation noise."""
        ...

    @abstractmethod
    def translate(self, source: str) -> Program:
        """Translate source code string to AEON Program AST."""
        ...

    def reset(self) -> None:
        """Reset translator state between invocations."""
        self.errors = []


# ---------------------------------------------------------------------------
# Language Registry
# ---------------------------------------------------------------------------

_REGISTRY: Dict[str, type] = {}
_EXT_MAP: Dict[str, str] = {}


def register_language(language_id: str, translator_class: type,
                      extensions: Optional[List[str]] = None) -> None:
    """Register a language translator."""
    _REGISTRY[language_id] = translator_class
    if extensions:
        for ext in extensions:
            _EXT_MAP[ext] = language_id


def get_translator(language_id: str) -> LanguageTranslator:
    """Get a translator instance for a language."""
    cls = _REGISTRY.get(language_id)
    if cls is None:
        supported = ", ".join(sorted(_REGISTRY.keys()))
        raise ValueError(
            f"Unsupported language: '{language_id}'. "
            f"Supported: {supported}"
        )
    return cls()


def detect_language(filepath: str) -> str:
    """Detect language from file extension."""
    ext = os.path.splitext(filepath)[1].lower()
    lang = _EXT_MAP.get(ext)
    if lang is None:
        supported = ", ".join(f"{e} ({l})" for e, l in sorted(_EXT_MAP.items()))
        raise ValueError(
            f"Cannot detect language for extension '{ext}'. "
            f"Supported: {supported}"
        )
    return lang


def supported_languages() -> List[Dict[str, Any]]:
    """List all registered languages with their extensions."""
    result = []
    for lang_id, cls in sorted(_REGISTRY.items()):
        inst = cls()
        result.append({
            "id": lang_id,
            "name": inst.language_name,
            "extensions": inst.file_extensions,
        })
    return result


# ---------------------------------------------------------------------------
# Unified Verification API
# ---------------------------------------------------------------------------

def _categorize_errors(errors: List[AeonError], noise_patterns: List[str],
                       result: VerificationResult) -> None:
    """Categorize AEON errors into result.errors and result.warnings,
    filtering out translation noise."""
    for e in errors:
        d = e.to_dict()
        msg = str(d.get("message", "")).lower()
        details = str(d.get("details", "")).lower()
        combined = msg + " " + details

        # Skip translation noise
        if any(p in combined for p in noise_patterns):
            continue

        if e.kind.value == "ownership_error":
            result.errors.append(d)
        elif e.kind.value == "contract_error":
            if any(kw in combined for kw in (
                "division by zero", "divide by zero",
                "symbolic execution", "may not terminate",
                "size-change termination", "missing base case",
                "missing decreasing", "termination",
            )):
                result.errors.append(d)
            elif any(kw in combined for kw in (
                "information flow", "effect security",
            )):
                result.warnings.append(d)
            else:
                result.warnings.append(d)
        elif e.kind.value == "type_error":
            result.warnings.append(d)
        elif e.kind.value == "effect_error":
            result.warnings.append(d)
        else:
            result.warnings.append(d)


def verify(source: str, language: str, deep_verify: bool = True,
           analyses: Optional[List[str]] = None) -> VerificationResult:
    """Verify source code in any supported language.

    Args:
        source: Source code string
        language: Language identifier ('python', 'java', 'javascript', 'typescript', 'go')
        deep_verify: Enable all 10 analysis passes
        analyses: Specific analyses to run (overrides deep_verify)

    Returns:
        VerificationResult with errors, warnings, and summary
    """
    from aeon.pass1_prove import prove
    from aeon.ast_nodes import PureFunc, TaskFunc, DataDef

    translator = get_translator(language)
    result = VerificationResult(source_language=language)

    # Step 1: Translate to AEON AST
    translator.reset()
    program = translator.translate(source)

    if translator.errors:
        result.translation_errors = translator.errors
        result.summary = f"Translation failed: {len(translator.errors)} errors"
        return result

    # Step 2: Count what we're analyzing
    result.functions_analyzed = len([d for d in program.declarations
                                     if isinstance(d, (PureFunc, TaskFunc))])
    result.classes_analyzed = len([d for d in program.declarations
                                   if isinstance(d, DataDef)])

    if result.functions_analyzed == 0 and result.classes_analyzed == 0:
        result.summary = "No functions or classes found to analyze"
        result.verified = True
        return result

    # Step 3: Build kwargs for prove()
    kwargs: Dict[str, bool] = {}
    if analyses:
        analysis_map = {
            "refinement": "refinement_types",
            "abstract": "abstract_interpretation",
            "termination": "size_change",
            "hoare": "hoare_logic",
            "effects": "algebraic_effects",
            "category": "category_check",
            "security": "information_flow",
            "dependent": "dependent_types",
            "certified": "certified_compilation",
            "symbolic": "symbolic_exec",
            "separation": "separation_logic",
            "taint": "taint_analysis",
            "concurrency": "concurrency_check",
            "shape": "shape_analysis",
            "model": "model_checking",
            "gradual": "gradual_typing",
            "linear": "linear_resource",
            "probabilistic": "probabilistic",
            "relational": "relational_verify",
            "session": "session_types",
            "complexity": "complexity_analysis",
            "abstract_refinement": "abstract_refinement",
            "privacy": "differential_privacy",
            "typestate": "typestate",
            "interpolation": "interpolation",
        }
        for a in analyses:
            key = analysis_map.get(a)
            if key:
                kwargs[key] = True
    else:
        kwargs["deep_verify"] = deep_verify

    # Step 4: Run AEON verification
    errors = prove(program, **kwargs)

    # Step 5: Categorize results
    _categorize_errors(errors, translator.noise_patterns, result)

    result.verified = len(result.errors) == 0
    bug_count = len(result.errors)
    warn_count = len(result.warnings)

    lang_label = translator.language_name
    if result.verified:
        result.summary = (
            f"\u2705 VERIFIED ({lang_label}): {result.functions_analyzed} functions, "
            f"{result.classes_analyzed} classes \u2014 no bugs found"
            + (f" ({warn_count} warnings)" if warn_count else "")
        )
    else:
        result.summary = (
            f"\u274c {bug_count} bug(s) found in {result.functions_analyzed} "
            f"{lang_label} functions"
            + (f", {warn_count} warning(s)" if warn_count else "")
        )

    return result


def verify_file(filepath: str, deep_verify: bool = True,
                analyses: Optional[List[str]] = None) -> VerificationResult:
    """Verify a source file, auto-detecting the language from extension."""
    language = detect_language(filepath)
    with open(filepath, "r") as f:
        source = f.read()
    return verify(source, language, deep_verify=deep_verify, analyses=analyses)


# ---------------------------------------------------------------------------
# Auto-register built-in languages on import
# ---------------------------------------------------------------------------

def _register_builtins() -> None:
    """Register all built-in language adapters."""
    # Python (always available)
    try:
        from aeon.python_adapter import PythonTranslator
        register_language("python", PythonTranslator, [".py"])
    except ImportError:
        pass

    # Java (requires javalang)
    try:
        from aeon.java_adapter import JavaTranslator
        register_language("java", JavaTranslator, [".java"])
    except ImportError:
        pass

    # JavaScript / TypeScript (requires tree-sitter)
    try:
        from aeon.js_adapter import JSTranslator, TSTranslator
        register_language("javascript", JSTranslator, [".js", ".jsx", ".mjs"])
        register_language("typescript", TSTranslator, [".ts", ".tsx"])
    except ImportError:
        pass

    # Go
    try:
        from aeon.go_adapter import GoTranslator
        register_language("go", GoTranslator, [".go"])
    except ImportError:
        pass

    # Rust
    try:
        from aeon.rust_adapter import RustTranslator
        register_language("rust", RustTranslator, [".rs"])
    except ImportError:
        pass

    # C / C++
    try:
        from aeon.c_adapter import CTranslator, CppTranslator
        register_language("c", CTranslator, [".c", ".h"])
        register_language("cpp", CppTranslator, [".cpp", ".hpp", ".cc", ".cxx", ".hxx"])
    except ImportError:
        pass

    # Ruby
    try:
        from aeon.ruby_adapter import RubyTranslator
        register_language("ruby", RubyTranslator, [".rb"])
    except ImportError:
        pass

    # Swift
    try:
        from aeon.swift_adapter import SwiftTranslator
        register_language("swift", SwiftTranslator, [".swift"])
    except ImportError:
        pass

    # Kotlin
    try:
        from aeon.kotlin_adapter import KotlinTranslator
        register_language("kotlin", KotlinTranslator, [".kt", ".kts"])
    except ImportError:
        pass

    # PHP
    try:
        from aeon.php_adapter import PHPTranslator
        register_language("php", PHPTranslator, [".php"])
    except ImportError:
        pass

    # Scala
    try:
        from aeon.scala_adapter import ScalaTranslator
        register_language("scala", ScalaTranslator, [".scala"])
    except ImportError:
        pass

    # Dart
    try:
        from aeon.dart_adapter import DartTranslator
        register_language("dart", DartTranslator, [".dart"])
    except ImportError:
        pass

    # Lua
    try:
        from aeon.lua_adapter import LuaTranslator
        register_language("lua", LuaTranslator, [".lua"])
    except ImportError:
        pass

    # R
    try:
        from aeon.r_adapter import RTranslator
        register_language("r", RTranslator, [".R", ".r"])
    except ImportError:
        pass

    # Elixir
    try:
        from aeon.elixir_adapter import ElixirTranslator
        register_language("elixir", ElixirTranslator, [".ex", ".exs"])
    except ImportError:
        pass

    # Haskell
    try:
        from aeon.haskell_adapter import HaskellTranslator
        register_language("haskell", HaskellTranslator, [".hs", ".lhs"])
    except ImportError:
        pass

    # OCaml
    try:
        from aeon.ocaml_adapter import OCamlTranslator
        register_language("ocaml", OCamlTranslator, [".ml", ".mli"])
    except ImportError:
        pass

    # Zig
    try:
        from aeon.zig_adapter import ZigTranslator
        register_language("zig", ZigTranslator, [".zig"])
    except ImportError:
        pass

    # Julia
    try:
        from aeon.julia_adapter import JuliaTranslator
        register_language("julia", JuliaTranslator, [".jl"])
    except ImportError:
        pass


_register_builtins()
