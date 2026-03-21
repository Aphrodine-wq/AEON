# AEON — Developer Guide

## Quick Commands

```bash
# Run from venv
cd ~/Desktop/WORK/Projects/IN\ House/AEON
.venv/bin/python -m aeon.cli <command>

# Scan a project (most common usage)
.venv/bin/python -m aeon.cli scan /path/to/src --profile security --format json --parallel

# Quick check a file
.venv/bin/python -m aeon.cli check app.py

# Compile AEON source
.venv/bin/python -m aeon.cli compile examples/hello_world.aeon

# Auto-fix issues
.venv/bin/python -m aeon.cli fix src/

# Run tests
.venv/bin/python -m aeon.cli test --all
# or: pytest tests/ -v
```

## Architecture

```
aeon/
  cli.py              # 24+ commands (scan, check, compile, fix, review, seal, etc.)
  config.py           # .aeonrc.yml/json parsing
  profiles.py         # quick, daily, security, performance, construction, safety
  scanner.py          # Directory scanning
  parallel.py         # Parallel verification
  adapters/           # 14+ language adapters (Python, JS/TS, Java, Rust, Go, C, Swift, etc.)
  compiler/           # AEON language 3-pass compiler (prove → flatten → emit LLVM)
  engines/            # 50+ analysis engines (symbolic exec, Hoare logic, taint, etc.)
  enterprise/         # Dashboard, FVaaS API
```

## Key Engines

| Engine | File | LOC | Purpose |
|--------|------|-----|---------|
| Abstract interpretation | `abstract_interp.py` | 45K | Interval/sign/congruence domains |
| Refinement types | `refinement_types.py` | 39K | Predicates on types |
| Hoare logic | `hoare.py` | 32K | Contracts -> Z3 SMT |
| Symbolic execution | `symbolic_execution.py` | 27K | Path-sensitive analysis |
| Separation logic | `separation_logic.py` | 25K | Heap reasoning |
| UI/UX lint | `ui_ux_lint.py` | 54K | Accessibility, contrast, buttons |
| Money math | `money_math.py` | 20K | Financial precision |
| Construction domain | `construction_domain.py` | 18K | Construction-specific rules |
| Taint analysis | `taint_analysis.py` | — | Source/sink tracking |
| Information flow | `information_flow.py` | 25K | Noninterference |

## Profiles

- `quick` — symbolic exec + abstract interp + contracts (fast CI)
- `daily` — + taint, concurrency, Hoare logic (default)
- `security` — + info flow, separation logic, money_math (API/auth/payment code)
- `construction` — + numeric safety, framework rules
- `safety` — all 50+ engines (pre-release audit)

## Configuration

Projects configure AEON via `.aeonrc.yml` at their root. Key fields:

```yaml
profile: security
engines: {symbolic_exec: true, taint_analysis: true}
severity: warning
include: ["src/**/*.ts"]
exclude: ["node_modules/**", "**/*.test.ts"]
custom_taint_sources: ["searchParams", "request.body"]
custom_taint_sinks: ["supabase.from", "dangerouslySetInnerHTML"]
parallel: true
```

## Language Adapters

14+ adapters in `adapters/`. Each translates source language AST to AEON's internal representation. Python adapter is most mature. JS/TS, Java, Rust, Go are functional. Others are scaffolded.

## Dependencies

Zero required runtime deps (all stdlib). Optional:
- `z3-solver` — SMT solving (for symbolic exec, Hoare logic)
- `llvmlite` — LLVM code generation (for AEON compilation)
- `javalang` — Java parsing
- `flask` + `plotly` — Dashboard
- `pytest` + `hypothesis` — Testing

## Testing

```bash
pytest tests/ -v --tb=short
pytest tests/ -m "requires_z3"     # Only Z3-dependent tests
.venv/bin/python -m aeon.cli test --priority P0
```

Tests organized by module: `tests/compiler/`, `tests/hoare/`, `tests/ghost/`, `tests/seal/`, etc.
