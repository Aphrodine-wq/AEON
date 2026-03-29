# AEON Security Documentation

AEON includes a dedicated cybersecurity engine suite for static analysis of security vulnerabilities. This document covers engine coverage, usage, profiles, baseline management, and CI/CD integration.

---

## Cybersecurity Engine Inventory

### Tier 1 — OWASP Top 10 Core

| Engine | Profile Key | CWE / OWASP Coverage |
|--------|-------------|----------------------|
| `secret_detection` | `secret_detection` | CWE-798 — Hard-coded credentials, API keys, tokens |
| `auth_access_control` | `auth_check` | CWE-862/863 (missing auth/authz), CWE-639 (IDOR), CWE-307 (brute force), CWE-352 (CSRF), CWE-613 (session expiry) — OWASP A01/A07 |
| `crypto_misuse` | `crypto_misuse` | CWE-327/328 (broken algorithms), CWE-916 (weak password hashing), CWE-330 (insufficient randomness) |
| `injection_advanced` | `injection_advanced` | CWE-94 (SSTI), CWE-113 (header injection), CWE-117 (log injection), CWE-943 (NoSQL), CWE-90 (LDAP), CWE-611 (XXE), CWE-1333 (ReDoS), CWE-601 (open redirect) |
| `api_security` | `api_security` | OWASP API Security Top 10 — CORS misconfig, missing security headers, mass assignment |
| `supply_chain` | `supply_chain` | CWE-829 (dynamic/untrusted imports), CWE-1357 (typosquatting), insecure package installation |
| `session_jwt` | `session_jwt` | CWE-347 (JWT alg:none / missing verification), CWE-346 (origin validation), CWE-614 (missing Secure flag), CWE-1004 (missing HttpOnly flag), CWE-613 (session expiry) |
| `container_security` | `container_security` | CWE-250/269 (root containers, excessive privileges), CWE-532 (secrets in env/logs), CWE-16 (Docker/K8s misconfig) |
| `ssrf_advanced` | `ssrf_advanced` | CWE-918 (SSRF) — cloud metadata endpoint access, DNS rebinding, CWE-441 (proxy/intermediary abuse) |
| `prototype_pollution` | `prototype_pollution` | CWE-1321 (deep merge/assign), CWE-915 (dynamic property modification), CWE-94 (code generation) |

### Tier 2 — Business Logic & Infrastructure

| Engine | Profile Key | CWE / OWASP Coverage |
|--------|-------------|----------------------|
| `business_logic` | `business_logic` | CWE-362 (race in financial ops), CWE-837 (double-spend), CWE-20 (negative amounts), CWE-472 (price manipulation), CWE-841 (workflow bypass), CWE-190 (integer overflow), CWE-770 (unbounded allocation) |
| `dependency_audit` | `dependency_audit` | CWE-1035 (known vulnerable components), CWE-1104 (unmaintained/EOL runtimes), CWE-829 (wildcard imports), CWE-1188 (insecure defaults), CWE-693 (missing security packages) — OWASP A06 |
| `race_condition_security` | `race_condition_security` | CWE-367 (TOCTOU in authorization/file ops), CWE-362 (concurrent payment/balance/session races) |
| `data_exposure` | `data_exposure` | OWASP A02 — sensitive data in logs, responses, error messages |
| `security_misconfig` | `security_misconfig` | OWASP A05 — debug modes, default credentials, permissive CORS |
| `oauth_oidc` | `oauth_oidc` | OAuth 2.0 / OIDC misconfigurations, token leakage, state parameter bypass |
| `file_upload` | `file_upload` | Unrestricted file upload, path traversal, MIME type bypass |
| `input_validation` | `input_validation` | Missing/insufficient validation at API boundaries |
| `email_security` | `email_security` | Email header injection, open relay patterns |
| `insecure_randomness` | `insecure_randomness` | CWE-330 — use of `Math.random()` / `random.random()` for security purposes |
| `cache_poisoning` | `cache_poisoning` | Web cache poisoning via unkeyed headers |
| `http_smuggling` | `http_smuggling` | HTTP request smuggling via ambiguous Transfer-Encoding / Content-Length |

---

## Usage

### Run a cybersecurity scan

```bash
# Full OWASP + all 22 cybersecurity engines (pentest-grade)
aeon scan /path/to/project --profile cybersecurity

# Tier 1 only — OWASP Top 10 core engines
aeon scan /path/to/project --profile security

# Single file
aeon check src/api/auth.py --profile cybersecurity

# JSON output for tooling integration
aeon scan /path/to/project --profile cybersecurity --format json

# SARIF output for GitHub Advanced Security / IDE integration
aeon scan /path/to/project --profile cybersecurity --format sarif

# Write results to file
aeon scan /path/to/project --profile cybersecurity --format sarif --output results.sarif
```

### Run specific engines

```bash
# Secret detection only
aeon check app.py --secret-detection

# JWT + session + auth
aeon check routes.py --auth-check --session-jwt

# Full cybersecurity suite on a directory
aeon scan src/ --profile cybersecurity --parallel
```

---

## Profiles

| Profile | Engines | Use Case |
|---------|---------|----------|
| `quick` | symbolic exec, abstract interp, contracts | Fast CI gate — seconds |
| `daily` | + taint, concurrency, Hoare logic | Default everyday check |
| `security` | + info flow, separation logic, money math, 6 cybersecurity engines | Security-focused PRs |
| `performance` | + size-change, complexity, termination | Performance regression CI |
| `construction` | + money math, numeric safety, domain rules | Financial / construction apps |
| `cybersecurity` | All 22 cybersecurity engines + core formal methods | Pentest-grade audit |
| `safety` | All 73 engine files (--deep-verify) | Pre-release / compliance audit |

The `cybersecurity` profile activates all 10 Tier 1 engines and all 12 Tier 2 engines simultaneously, producing pentest-grade coverage in a single pass.

---

## Baseline Management

Baseline management lets you track findings over time and suppress known/accepted issues so CI only alerts on regressions.

```bash
# Create a baseline from the current scan
aeon scan /path/to/project --profile cybersecurity --create-baseline --baseline .aeon-baseline.json

# Subsequent scans — only report NEW findings vs. the baseline
aeon scan /path/to/project --profile cybersecurity --baseline .aeon-baseline.json
```

Commit `.aeon-baseline.json` to your repository. Pull requests will only fail on net-new security findings introduced in that PR.

---

## Reporting and CI Integration

### SARIF (GitHub Advanced Security / VS Code)

```bash
aeon scan src/ --profile cybersecurity --format sarif --output aeon-results.sarif
```

Upload to GitHub Code Scanning:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: aeon-results.sarif
```

### JSON (custom tooling)

```bash
aeon scan src/ --profile cybersecurity --format json | jq '.file_results[] | select(.errors > 0)'
```

### GitHub Actions CI template

```yaml
name: AEON Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install aeon-lang
      - run: aeon scan src/ --profile cybersecurity --format sarif --output aeon.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: aeon.sarif
        if: always()
```

### Parallel scanning for large codebases

```bash
aeon scan /path/to/large/project --profile cybersecurity --parallel --workers 8
```

---

## Reporting Security Issues in AEON Itself

If you discover a security vulnerability in AEON, please open a GitHub issue with the label `security`. Do not include exploit code in public issues — a description of the class of vulnerability and affected component is sufficient.
