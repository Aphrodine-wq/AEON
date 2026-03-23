# AEON — Developer Guide

## Quick Commands

```bash
# Run from venv (if not installed globally)
cd ~/Projects/aeon
.venv/bin/python -m aeon.cli <command>

# Or use the installed entrypoint after: pip install -e .
aeon <command>

# Scan a project (most common usage)
aeon scan /path/to/src --profile security --format json --parallel

# Quick check a file
aeon check app.py

# Compile AEON source
aeon compile examples/hello_world.aeon

# Auto-fix issues
aeon fix src/

# Run tests
aeon test --all
# or: pytest tests/ -v
```

## Architecture

```
aeon/
  cli.py              # 23 commands (scan, check, compile, fix, review, seal, etc.)
  config.py           # .aeonrc.yml/json parsing
  profiles.py         # quick, daily, security, performance, construction, cybersecurity, safety
  scanner.py          # Directory scanning
  parallel.py         # Parallel verification
  language_adapter.py # Top-level adapter registry (legacy, mirrors aeon/adapters/)
  adapters/           # 20 adapter files — 21 language targets
  compiler/           # AEON language 3-pass compiler (prove → flatten → emit LLVM)
  engines/            # 50 analysis engines (symbolic exec, Hoare logic, taint, etc.)
  enterprise/         # Baseline, config, parallel, SARIF, and scanner helpers
  ai/                 # AI integration and synthetic test helpers
```

## Key Engines

| Engine | File | Purpose |
|--------|------|---------|
| Abstract interpretation | `engines/abstract_interp.py` | Interval/sign/congruence domains |
| Refinement types | `engines/refinement_types.py` | Predicates on types |
| Hoare logic | `engines/hoare.py` | Contracts -> Z3 SMT |
| Symbolic execution | `engines/symbolic_execution.py` | Path-sensitive analysis |
| Separation logic | `engines/separation_logic.py` | Heap reasoning |
| UI/UX lint | `engines/ui_ux_lint.py` | Accessibility, contrast, buttons |
| Money math | `engines/money_math.py` | Financial precision |
| Construction domain | `engines/construction_domain.py` | Construction-specific rules |
| Taint analysis | `engines/taint_analysis.py` | Source/sink tracking |
| Information flow | `engines/information_flow.py` | Noninterference |
| Secret detection | `engines/secret_detection.py` | Hardcoded credentials, API keys (CWE-798) |
| Auth & access control | `engines/auth_access_control.py` | Broken auth, IDOR, CSRF (OWASP A01/A07) |
| Crypto misuse | `engines/crypto_misuse.py` | Weak algorithms, timing attacks (CWE-327/330) |
| Injection advanced | `engines/injection_advanced.py` | SSTI, ReDoS, XXE, log injection (CWE-94) |
| API security | `engines/api_security.py` | CORS, headers, mass assignment (OWASP API) |
| Supply chain | `engines/supply_chain.py` | Dynamic imports, unsafe deser (CWE-829) |
| Session & JWT | `engines/session_jwt.py` | JWT misconfig, cookie flags (CWE-347) |
| Container security | `engines/container_security.py` | Docker/K8s misconfig (CWE-250) |
| SSRF advanced | `engines/ssrf_advanced.py` | Cloud metadata, DNS rebinding (CWE-918) |
| Prototype pollution | `engines/prototype_pollution.py` | Deep merge, dynamic props (CWE-1321) |

60 engine files total in `aeon/engines/`.

## CLI Commands

| Command | Description |
|---------|-------------|
| `aeon compile <file.aeon>` | Compile AEON source to native binary |
| `aeon check <file>` | Type check + verify (auto-detects language) |
| `aeon scan <dir>` | Recursive directory scan |
| `aeon watch <dir>` | File watcher, re-verify on changes |
| `aeon fix <target>` | Auto-fix detected issues |
| `aeon review [file\|dir]` | AI-powered code review |
| `aeon explain <file>` | Plain-English bug explanations |
| `aeon seal <file>` | Generate proof-carrying seal |
| `aeon verify-seal <file>` | Verify existing seal |
| `aeon harden <target>` | Gradual hardening analysis |
| `aeon autopsy [file]` | Incident traces -> contracts |
| `aeon ghost <file>` | Ghost assertions (intent violations) |
| `aeon formal-diff [file_a] [file_b]` | Compare versions, invariant changes |
| `aeon synthesize --spec "..."` | Generate code from specs |
| `aeon graveyard` | Analyze famous historical bugs |
| `aeon mcp-safety` | Start MCP safety server |
| `aeon portfolio` | Portfolio scan across projects |
| `aeon init [dir]` | Project setup wizard |
| `aeon test` | Run test suite |
| `aeon ir <file.aeon>` | Emit flat IR as JSON |
| `aeon proof-trace <file.aeon>` | Show Hoare logic proof obligations |
| `aeon abstract-trace <file.aeon>` | Show abstract domain states |
| `aeon profiles` | List available profiles |

## Profiles

- `quick` — symbolic exec + abstract interp + contracts (fast CI)
- `daily` — + taint, concurrency, Hoare logic (default)
- `security` — + info flow, separation logic, money_math + 6 cybersecurity engines
- `performance` — + size-change, complexity, effects
- `construction` — + numeric safety, framework rules
- `cybersecurity` — full OWASP Top 10 + all 10 cybersecurity engines (pentest-grade)
- `safety` — all 60 engines (pre-release audit)

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

20 adapter files in `aeon/adapters/`, covering 21 language targets. Each translates source language AST to AEON's internal representation. Python adapter is most mature. JS/TS, Java, Rust, Go are functional. Others are regex-based and fully functional.

| Adapter File | Language(s) |
|---|---|
| `python_adapter.py` | Python |
| `js_adapter.py` | JavaScript, TypeScript |
| `java_adapter.py` | Java |
| `go_adapter.py` | Go |
| `rust_adapter.py` | Rust |
| `c_adapter.py` | C, C++ |
| `ruby_adapter.py` | Ruby |
| `swift_adapter.py` | Swift |
| `kotlin_adapter.py` | Kotlin |
| `scala_adapter.py` | Scala |
| `php_adapter.py` | PHP |
| `dart_adapter.py` | Dart |
| `elixir_adapter.py` | Elixir |
| `haskell_adapter.py` | Haskell |
| `ocaml_adapter.py` | OCaml |
| `lua_adapter.py` | Lua |
| `r_adapter.py` | R |
| `julia_adapter.py` | Julia |
| `zig_adapter.py` | Zig |
| `language_adapter.py` | Registry / base class |

## Dependencies

Zero required runtime deps (all stdlib). Optional:
- `z3-solver` — SMT solving (for symbolic exec, Hoare logic, contract verification)
- `llvmlite` — LLVM code generation (for AEON compilation to native binary)
- `javalang` — Java parsing
- `flask` + `plotly` — Dashboard
- `flask-limiter` + `PyJWT` — FVaaS API
- `pytest` + `hypothesis` — Testing

Install optional extras:

```bash
pip install -e ".[z3]"        # Z3 only
pip install -e ".[llvm]"      # llvmlite only
pip install -e ".[java]"      # javalang only
pip install -e ".[full]"      # Everything
pip install -e ".[dev]"       # Test dependencies
```

## Testing

```bash
pytest tests/ -v --tb=short
pytest tests/ -m "requires_z3"      # Only Z3-dependent tests
aeon test --priority P0
aeon test --category compiler
```

Tests are organized by module under `tests/`: `tests/compiler/`, `tests/hoare/`, `tests/ghost/`, `tests/seal/`, `tests/synthesizer/`, `tests/autopsy/`, `tests/formal_diff/`, `tests/graveyard/`, `tests/mcp_safety/`, `tests/perf/`, `tests/ai/`, `tests/properties/`.

## Package Metadata

- **Package name**: `aeon-lang`
- **Version**: `0.5.0`
- **Entry point**: `aeon = aeon.cli:main`
- **Requires Python**: 3.10+
