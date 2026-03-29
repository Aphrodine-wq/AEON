# AEON Implementation Summary

## Overview

AEON is a research programming language with integrated formal verification, plus a multi-language code analysis tool with 73 engine files (71 analysis engines + quality filter + finding prioritizer) targeting 21 programming languages.

## Architecture

### AEON Language Compiler

Three-pass compiler: Prove (type check + verify) -> Flatten (AST to flat IR DAG) -> Emit (LLVM IR -> native binary via llvmlite).

14 compiler files in `aeon/compiler/`: ast_nodes, contracts, effects, errors, ir, lexer, memory, ownership, parser, pass1_prove, pass2_flatten, pass3_emit, termination, types.

### Multi-Language Code Scanner

Scans existing codebases in 21 language targets via 20 adapter files (19 language adapters + 1 registry) in `aeon/adapters/`. Quality filtering ON by default -- findings scored by confidence, deduplicated, false positives suppressed.

### Verification Engines

73 engine files in `aeon/engines/`, each based on peer-reviewed research:

- 14 core formal verification engines (Hoare logic, abstract interpretation, symbolic execution, separation logic, refinement types, taint analysis, etc.)
- 22 cybersecurity engines (OWASP Top 10, supply chain, JWT, container security, etc.)
- 35 additional analysis engines (domain-specific, type theory, concurrency, etc.)
- 2 infrastructure engines (finding_quality.py, prioritize.py)

### Dual File Structure

CRITICAL: Many engine files exist BOTH at `aeon/` root level AND inside `aeon/engines/`. The compiler uses the root copies. When fixing bugs, check BOTH locations.

## CLI

24 commands: compile, check, scan, watch, fix, review, explain, seal, verify-seal, harden, autopsy, ghost, formal-diff, synthesize, graveyard, mcp-safety, portfolio, health, init, test, ir, proof-trace, abstract-trace, profiles.

## Profiles

12 profiles (7 built-in + 5 stack-tuned):

Built-in: quick, daily, security, performance, construction, cybersecurity, safety.

Stack-tuned: nextjs, rust, elixir, python, portfolio.

## Performance Features

- Parallel verification engine with configurable workers
- Incremental analysis with smart dependency tracking
- SQLite-based persistent cache with semantic hash invalidation

## Integration

- VS Code extension: real-time diagnostics, CodeLens, hover info, code actions
- GitHub Actions CI/CD templates
- Web dashboard for team analytics
- SARIF output for GitHub Advanced Security
- FVaaS (Formal Verification as a Service) API

## AI Features

- Natural language to formal contract generation
- Automated test generation from verification gaps
- AI-powered code review and explanations

## Testing

346 tests across 15 test files in `tests/`.

## Package

- Name: aeon-lang
- Version: 0.5.0
- Entry point: `aeon = aeon.cli:main`
- Requires Python 3.10+
- Zero required runtime dependencies (all stdlib). Optional: z3-solver, llvmlite, javalang, flask, plotly, PyJWT.
- License: MIT
