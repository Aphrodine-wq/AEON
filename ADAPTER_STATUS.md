# AEON Language Adapter Status

> Generated for US-006 -- Documents which language adapters in `aeon/adapters/` are
> functional (Working), partially implemented (Partial), or stubs (Scaffolded).

## Summary

| # | Adapter File | Language(s) | Extensions | Status | Parser Strategy |
|---|-------------|-------------|------------|--------|-----------------|
| 1 | `python_adapter.py` | Python | `.py` | **Working** | Built-in `ast` module |
| 2 | `js_adapter.py` | JavaScript | `.js`, `.jsx`, `.mjs` | **Working** | Regex (tree-sitter optional) |
| 3 | `js_adapter.py` | TypeScript | `.ts`, `.tsx` | **Working** | Regex (tree-sitter optional) |
| 4 | `java_adapter.py` | Java | `.java` | **Working** | `javalang` library |
| 5 | `go_adapter.py` | Go | `.go` | **Working** | Regex |
| 6 | `rust_adapter.py` | Rust | `.rs` | **Working** | Regex |
| 7 | `c_adapter.py` | C | `.c`, `.h` | **Working** | Regex |
| 8 | `c_adapter.py` | C++ | `.cpp`, `.hpp`, `.cc`, `.cxx`, `.hxx` | **Working** | Regex |
| 9 | `ruby_adapter.py` | Ruby | `.rb` | **Working** | Regex |
| 10 | `swift_adapter.py` | Swift | `.swift` | **Working** | Regex |
| 11 | `kotlin_adapter.py` | Kotlin | `.kt`, `.kts` | **Working** | Regex |
| 12 | `scala_adapter.py` | Scala | `.scala` | **Working** | Regex |
| 13 | `php_adapter.py` | PHP | `.php` | **Working** | Regex |
| 14 | `dart_adapter.py` | Dart | `.dart` | **Working** | Regex |
| 15 | `elixir_adapter.py` | Elixir | `.ex`, `.exs` | **Working** | Regex |
| 16 | `haskell_adapter.py` | Haskell | `.hs`, `.lhs` | **Working** | Regex |
| 17 | `ocaml_adapter.py` | OCaml | `.ml`, `.mli` | **Working** | Regex |
| 18 | `lua_adapter.py` | Lua | `.lua` | **Working** | Regex |
| 19 | `r_adapter.py` | R | `.R`, `.r` | **Working** | Regex |
| 20 | `julia_adapter.py` | Julia | `.jl` | **Working** | Regex |
| 21 | `zig_adapter.py` | Zig | `.zig` | **Working** | Regex |

**Total: 20 adapter files, 21 language targets, 0 scaffolded, 0 partial.**

## Status Definitions

- **Working** -- Has real parsing logic (AST or regex-based), translates source into
  AEON `Program` AST nodes (`PureFunc`, `TaskFunc`, `DataDef`), maps types, detects
  side effects, infers effects, extracts contracts, and feeds into the AEON
  verification pipeline via `prove()`.
- **Partial** -- Has some translation logic but missing key features (e.g., no body
  translation, no type mapping, or no effect inference).
- **Scaffolded** -- Returns empty `Program(declarations=[])` or stub results without
  any real parsing.

## Detailed Notes

### Tier 1: Full AST Parsing (most robust)

**Python** (`python_adapter.py`) -- Uses Python's built-in `ast` module for proper AST
parsing. Translates functions, classes, statements, and expressions. Extracts contracts
from docstrings (`Requires:` / `Ensures:`). Detects side effects and infers effects
(Console, File, Database, Network). This is the most complete adapter.

**Java** (`java_adapter.py`) -- Uses the `javalang` third-party library for full Java
AST parsing. Handles classes, interfaces, constructors, methods, fields. Extracts
contracts from Javadoc (`@requires` / `@ensures`). Requires `pip install javalang`; if
missing, returns a clear error message rather than crashing.

### Tier 2: Regex + Optional Tree-Sitter

**JavaScript / TypeScript** (`js_adapter.py`) -- Two translator classes (`JSTranslator`,
`TSTranslator`) sharing a `_BaseJSTranslator`. Has an optional `tree-sitter` path but
fully functional with the regex fallback (`_RegexJSParser`). Parses functions (named,
arrow, class methods), classes, and translates body statements. Extracts JSDoc contracts.
Maps TS types to AEON types.

### Tier 3: Regex-Based (all fully functional)

All remaining adapters follow the same proven architecture:
1. A `_Regex<Lang>Parser` class that extracts functions, structs/classes, and enums
   from source via regex patterns.
2. A `<Lang>Translator` class that converts parsed info into AEON AST nodes.
3. Type mapping dictionaries (`_<LANG>_TYPE_MAP`) converting language types to AEON types.
4. Side-effect detection via known function/method sets.
5. Effect inference (Console, File, Network, Database, Sync, etc.).
6. Contract extraction from comments (`@requires` / `@ensures` or `Requires:` / `Ensures:`).

These adapters are: **Go**, **Rust**, **C**, **C++**, **Ruby**, **Swift**, **Kotlin**,
**Scala**, **PHP**, **Dart**, **Elixir**, **Haskell**, **OCaml**, **Lua**, **R**,
**Julia**, **Zig**.

### External Dependencies

| Adapter | Required Dependency | Fallback |
|---------|-------------------|----------|
| Python | None (stdlib `ast`) | N/A |
| Java | `javalang` | Error message, no crash |
| JS/TS | `tree-sitter-javascript`, `tree-sitter-typescript` | Regex fallback (fully functional) |
| All others | None | N/A |

## Test Command Examples

```bash
# Python (primary, always available)
aeon check examples/demo.py

# JavaScript
aeon check examples/demo.js

# TypeScript
aeon check examples/demo.ts

# Java (requires: pip install javalang)
aeon check examples/Demo.java

# Go
aeon check examples/demo.go

# Rust
aeon check examples/demo.rs

# C
aeon check examples/demo.c

# C++
aeon check examples/demo.cpp

# Ruby
aeon check examples/demo.rb

# Swift
aeon check examples/demo.swift

# Kotlin
aeon check examples/demo.kt

# Scala
aeon check examples/demo.scala

# PHP
aeon check examples/demo.php

# Dart
aeon check examples/demo.dart

# Elixir
aeon check examples/demo.ex

# Haskell
aeon check examples/demo.hs

# OCaml
aeon check examples/demo.ml

# Lua
aeon check examples/demo.lua

# R
aeon check examples/demo.R

# Julia
aeon check examples/demo.jl

# Zig
aeon check examples/demo.zig
```

## Architecture Note

All adapters share the same pipeline defined in `aeon/adapters/language_adapter.py`:

1. **Parse** -- Language-specific translator parses source into structured data.
2. **Translate** -- Structured data is converted to AEON AST (`Program` with
   `PureFunc`, `TaskFunc`, `DataDef` declarations).
3. **Verify** -- The unified `verify()` function passes the AST to `aeon.pass1_prove.prove()`
   which runs the formal verification engines.
4. **Categorize** -- Results are categorized into errors, warnings, and translation noise
   using language-specific noise patterns.

The `LanguageTranslator` base class and `_REGISTRY` / `_EXT_MAP` system in
`language_adapter.py` auto-registers all adapters at import time. Adding a new language
requires implementing `LanguageTranslator` and calling `register_language()`.
