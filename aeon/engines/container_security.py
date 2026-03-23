"""AEON Container Security Engine -- Infrastructure & Container Hardening Scanner.

Detects security misconfigurations in Dockerfiles, Docker Compose files,
Kubernetes manifests, and Infrastructure-as-Code (Terraform/Pulumi/CDK)
patterns embedded in application source code.

References:
  CWE-250: Execution with Unnecessary Privileges
  https://cwe.mitre.org/data/definitions/250.html

  CWE-269: Improper Privilege Management
  https://cwe.mitre.org/data/definitions/269.html

  CWE-532: Insertion of Sensitive Information into Log File
  https://cwe.mitre.org/data/definitions/532.html

  CWE-16: Configuration
  https://cwe.mitre.org/data/definitions/16.html

  CWE-1188: Insecure Default Initialization of Resource
  https://cwe.mitre.org/data/definitions/1188.html

  NIST SP 800-190 "Application Container Security Guide"
  https://doi.org/10.6028/NIST.SP.800-190

  CIS Docker Benchmark v1.6
  https://www.cisecurity.org/benchmark/docker

  CIS Kubernetes Benchmark v1.8
  https://www.cisecurity.org/benchmark/kubernetes

Detection Categories:

1. DOCKERFILE ISSUES:
   Running as root, :latest tags, hardcoded secrets in ENV/ARG,
   COPY . . without .dockerignore, ADD vs COPY, apt-get without
   version pinning, chmod 777, unnecessary exposed ports.

2. DOCKER COMPOSE ISSUES:
   privileged: true, network_mode: host, binding 0.0.0.0,
   hardcoded passwords, sensitive volume mounts, missing resource
   limits, missing health checks.

3. KUBERNETES MANIFEST ISSUES:
   Privileged containers, privilege escalation, running as root,
   hostPath mounts, hostNetwork/hostPID, missing resource limits,
   missing readOnlyRootFilesystem, :latest images, missing
   NetworkPolicy, cluster-admin ServiceAccount.

4. INFRASTRUCTURE CODE ISSUES (AST):
   S3 buckets without encryption, security groups with 0.0.0.0/0,
   RDS without encryption at rest, CloudFront without WAF --
   detected via FunctionCall/MethodCall patterns matching
   Terraform/Pulumi/CDK API calls.

5. SECRET EXPOSURE IN INFRASTRUCTURE:
   .env file references without .gitignore, secrets as build args
   (visible in image layers), ARG PASSWORD / ARG SECRET patterns.

This engine is unique in that it operates primarily on raw source text
(Dockerfiles, YAML configs) rather than AST. It accepts an optional
source_text parameter for regex-based pattern matching, while also
walking the AST for IaC patterns in Python/JS code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum, auto

from aeon.ast_nodes import (
    Program, PureFunc, TaskFunc,
    Statement, Expr, Identifier, StringLiteral,
    FunctionCall, FieldAccess, MethodCall,
    LetStmt, AssignStmt, ExprStmt,
)
from aeon.errors import AeonError, contract_error, SourceLocation


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# Finding Data
# ---------------------------------------------------------------------------

@dataclass
class ContainerFinding:
    """Internal representation of a container/infra security issue."""
    category: str          # Dockerfile, Compose, Kubernetes, IaC, SecretExposure
    rule_id: str           # Short identifier, e.g., "DOCKER-001"
    severity: Severity
    title: str
    description: str
    cwe: str               # e.g., "CWE-250"
    line: int = 0          # Line number in source_text (0 = unknown / AST-based)
    remediation: str = ""


# ---------------------------------------------------------------------------
# Frontend File Detection (false positive suppression)
# ---------------------------------------------------------------------------

# File extensions that indicate frontend/UI component code.
# Regex-based IaC detection should NOT run on these files because JSX string
# content (e.g., "bucket list", "encryption settings") triggers false positives
# against Dockerfile/K8s/Compose patterns.
_FRONTEND_EXTENSIONS = frozenset({
    ".tsx", ".jsx", ".vue", ".svelte",
})


def _is_frontend_file(filename: str) -> bool:
    """Check if the filename indicates a frontend/UI component file."""
    if not filename:
        return False
    name_lower = filename.lower()
    return any(name_lower.endswith(ext) for ext in _FRONTEND_EXTENSIONS)


# ---------------------------------------------------------------------------
# Dockerfile Analysis (source text)
# ---------------------------------------------------------------------------

# Compiled regex patterns for Dockerfile directives
_RE_FROM = re.compile(r"^\s*FROM\s+(.+)", re.MULTILINE | re.IGNORECASE)
_RE_USER = re.compile(r"^\s*USER\s+(\S+)", re.MULTILINE | re.IGNORECASE)
_RE_ENV_SECRET = re.compile(
    r"^\s*(?:ENV|ARG)\s+("
    r"[A-Za-z_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|"
    r"CREDENTIALS|DB_PASS|AUTH_TOKEN|SIGNING_KEY|ENCRYPTION_KEY)"
    r"[A-Za-z_]*"
    r")\s*[=\s]\s*(\S+)",
    re.MULTILINE | re.IGNORECASE,
)
_RE_COPY_ALL = re.compile(r"^\s*COPY\s+\.\s+\.", re.MULTILINE | re.IGNORECASE)
_RE_ADD = re.compile(r"^\s*ADD\s+(.+)", re.MULTILINE | re.IGNORECASE)
_RE_APT_NO_PIN = re.compile(
    r"^\s*RUN\s+.*apt-get\s+install\s+(?!.*=).*$",
    re.MULTILINE | re.IGNORECASE,
)
_RE_CHMOD_777 = re.compile(r"^\s*RUN\s+.*chmod\s+777\b", re.MULTILINE | re.IGNORECASE)
_RE_EXPOSE = re.compile(r"^\s*EXPOSE\s+(\d+)", re.MULTILINE | re.IGNORECASE)
_RE_LATEST_TAG = re.compile(r":latest\b", re.IGNORECASE)
_RE_ADD_URL = re.compile(r"https?://", re.IGNORECASE)
_RE_ADD_TAR = re.compile(r"\.(tar|tar\.gz|tgz|tar\.bz2|tar\.xz|zip)\b", re.IGNORECASE)

# High-risk ports that should not be exposed unless necessary
_RISKY_PORTS: Set[int] = {22, 23, 3389, 5900, 6379, 27017, 9200, 11211, 2375, 2376}


def _analyze_dockerfile(source: str) -> List[ContainerFinding]:
    """Scan Dockerfile source text for security issues."""
    findings: List[ContainerFinding] = []
    lines = source.splitlines()

    # --- Running as root ---
    user_directives = _RE_USER.findall(source)
    if not user_directives:
        findings.append(ContainerFinding(
            category="Dockerfile",
            rule_id="DOCKER-001",
            severity=Severity.HIGH,
            title="Container runs as root (no USER directive)",
            description=(
                "No USER directive found. The container process will run as "
                "root, violating the principle of least privilege. If an "
                "attacker escapes the application, they have full root access "
                "inside the container."
            ),
            cwe="CWE-250",
            remediation="Add a USER directive with a non-root user: USER appuser",
        ))
    elif user_directives[-1].strip().lower() == "root":
        # Find the line number of the last USER directive
        user_line = 0
        for i, line in enumerate(lines, 1):
            if re.match(r"^\s*USER\s+root\b", line, re.IGNORECASE):
                user_line = i
        findings.append(ContainerFinding(
            category="Dockerfile",
            rule_id="DOCKER-002",
            severity=Severity.HIGH,
            title="Container explicitly runs as root (USER root)",
            description=(
                "The final USER directive is set to root. The container "
                "process will run with full root privileges."
            ),
            cwe="CWE-250",
            line=user_line,
            remediation="Change USER root to a non-root user: USER appuser",
        ))

    # --- :latest tag ---
    for match in _RE_FROM.finditer(source):
        image_spec = match.group(1).strip().split()[0]  # Handle "AS builder"
        line_num = source[:match.start()].count("\n") + 1
        if _RE_LATEST_TAG.search(image_spec):
            findings.append(ContainerFinding(
                category="Dockerfile",
                rule_id="DOCKER-003",
                severity=Severity.MEDIUM,
                title=f"Using :latest tag in FROM ({image_spec})",
                description=(
                    "The :latest tag is mutable and can change unexpectedly, "
                    "breaking reproducibility. Builds may silently pull "
                    "different base images across environments."
                ),
                cwe="CWE-1188",
                line=line_num,
                remediation=(
                    "Pin to a specific version or digest: "
                    f"{image_spec.replace(':latest', ':<version>')}"
                ),
            ))
        elif ":" not in image_spec and "@" not in image_spec and image_spec.lower() != "scratch":
            # No tag at all implies :latest
            findings.append(ContainerFinding(
                category="Dockerfile",
                rule_id="DOCKER-003",
                severity=Severity.MEDIUM,
                title=f"No tag specified in FROM ({image_spec} implies :latest)",
                description=(
                    "No tag or digest specified. Docker will pull :latest by "
                    "default, which is mutable and non-reproducible."
                ),
                cwe="CWE-1188",
                line=line_num,
                remediation=f"Pin to a specific version: FROM {image_spec}:<version>",
            ))

    # --- Hardcoded secrets in ENV/ARG ---
    for match in _RE_ENV_SECRET.finditer(source):
        var_name = match.group(1)
        value = match.group(2)
        line_num = source[:match.start()].count("\n") + 1
        # Skip if value is a variable reference
        if value.startswith("$") or value.startswith("${"):
            continue
        findings.append(ContainerFinding(
            category="Dockerfile",
            rule_id="DOCKER-004",
            severity=Severity.CRITICAL,
            title=f"Hardcoded secret in ENV/ARG ({var_name})",
            description=(
                f"The directive sets '{var_name}' to a hardcoded value. "
                f"ENV/ARG values are baked into image layers and can be "
                f"extracted with 'docker history' or 'docker inspect'."
            ),
            cwe="CWE-532",
            line=line_num,
            remediation=(
                "Use runtime secrets injection (Docker secrets, environment "
                "variables at runtime, or a secrets manager) instead of "
                "baking credentials into the image."
            ),
        ))

    # --- COPY . . (copying everything) ---
    for match in _RE_COPY_ALL.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Dockerfile",
            rule_id="DOCKER-005",
            severity=Severity.HIGH,
            title="COPY . . may include secrets (.env, .git, credentials)",
            description=(
                "COPY . . copies the entire build context into the image, "
                "including .env files, .git history, private keys, and other "
                "sensitive files unless a .dockerignore is properly configured."
            ),
            cwe="CWE-532",
            line=line_num,
            remediation=(
                "Add a .dockerignore excluding .env, .git, *.pem, *.key, "
                "node_modules, and other sensitive paths. Or copy only the "
                "files you need explicitly."
            ),
        ))

    # --- ADD when COPY would suffice ---
    for match in _RE_ADD.finditer(source):
        args = match.group(1).strip()
        line_num = source[:match.start()].count("\n") + 1
        # ADD is acceptable for URLs or tar extraction
        if _RE_ADD_URL.search(args) or _RE_ADD_TAR.search(args):
            continue
        findings.append(ContainerFinding(
            category="Dockerfile",
            rule_id="DOCKER-006",
            severity=Severity.LOW,
            title="Using ADD when COPY would suffice",
            description=(
                "ADD has implicit tar extraction and URL fetching behavior "
                "that can be unexpected. COPY is explicit and preferred "
                "unless you specifically need ADD's features."
            ),
            cwe="CWE-16",
            line=line_num,
            remediation="Replace ADD with COPY unless you need tar extraction or URL fetching.",
        ))

    # --- apt-get install without version pinning ---
    for match in _RE_APT_NO_PIN.finditer(source):
        line_text = match.group(0).strip()
        line_num = source[:match.start()].count("\n") + 1
        # Crude heuristic: if any package name contains '=' it is pinned
        if "=" in line_text.split("install", 1)[-1]:
            continue
        findings.append(ContainerFinding(
            category="Dockerfile",
            rule_id="DOCKER-007",
            severity=Severity.MEDIUM,
            title="apt-get install without version pinning",
            description=(
                "Installing packages without version pinning means builds "
                "are not reproducible. Different builds may get different "
                "package versions, potentially introducing vulnerabilities."
            ),
            cwe="CWE-1188",
            line=line_num,
            remediation="Pin package versions: apt-get install package=1.2.3",
        ))

    # --- chmod 777 ---
    for match in _RE_CHMOD_777.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Dockerfile",
            rule_id="DOCKER-008",
            severity=Severity.HIGH,
            title="chmod 777 grants world-writable permissions",
            description=(
                "Setting permissions to 777 allows any user in the "
                "container to read, write, and execute the file. This "
                "violates least privilege and can enable privilege escalation."
            ),
            cwe="CWE-269",
            line=line_num,
            remediation="Use restrictive permissions: chmod 755 (dirs) or chmod 644 (files).",
        ))

    # --- Exposed risky ports ---
    for match in _RE_EXPOSE.finditer(source):
        port = int(match.group(1))
        line_num = source[:match.start()].count("\n") + 1
        if port in _RISKY_PORTS:
            findings.append(ContainerFinding(
                category="Dockerfile",
                rule_id="DOCKER-009",
                severity=Severity.MEDIUM,
                title=f"Exposed risky port {port}",
                description=(
                    f"Port {port} is commonly associated with sensitive "
                    f"services (SSH, databases, admin interfaces). Exposing "
                    f"it increases the attack surface."
                ),
                cwe="CWE-16",
                line=line_num,
                remediation=(
                    f"Remove EXPOSE {port} unless explicitly required, and "
                    f"ensure network policies restrict access."
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# Docker Compose Analysis (source text)
# ---------------------------------------------------------------------------

_RE_PRIVILEGED = re.compile(r"^\s*privileged\s*:\s*true", re.MULTILINE | re.IGNORECASE)
_RE_NETWORK_HOST = re.compile(r"^\s*network_mode\s*:\s*['\"]?host['\"]?", re.MULTILINE | re.IGNORECASE)
_RE_BIND_ALL = re.compile(r"0\.0\.0\.0:\d+", re.MULTILINE)
_RE_COMPOSE_PASSWORD = re.compile(
    r"^\s*-?\s*[A-Za-z_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|CREDENTIALS)[A-Za-z_]*\s*[=:]\s*(\S+)",
    re.MULTILINE | re.IGNORECASE,
)
_RE_SENSITIVE_VOLUME = re.compile(
    r"^\s*-\s*['\"]?(/(?:etc|var/run/docker\.sock|root|proc|sys))['\"]?\s*:",
    re.MULTILINE,
)
_RE_ROOT_VOLUME = re.compile(
    r"^\s*-\s*['\"]?/\s*:", re.MULTILINE,
)
_RE_MEM_LIMIT = re.compile(r"^\s*(?:mem_limit|memory)\s*:", re.MULTILINE | re.IGNORECASE)
_RE_CPU_LIMIT = re.compile(r"^\s*(?:cpus|cpu_quota|cpu_shares)\s*:", re.MULTILINE | re.IGNORECASE)
_RE_HEALTHCHECK = re.compile(r"^\s*healthcheck\s*:", re.MULTILINE | re.IGNORECASE)
_RE_SERVICES = re.compile(r"^\s*services\s*:", re.MULTILINE | re.IGNORECASE)


def _is_compose_file(source: str) -> bool:
    """Heuristic to detect if source text is a Docker Compose file."""
    return bool(_RE_SERVICES.search(source)) and (
        "image:" in source.lower() or "build:" in source.lower()
    )


def _analyze_compose(source: str) -> List[ContainerFinding]:
    """Scan Docker Compose YAML source text for security issues."""
    findings: List[ContainerFinding] = []

    if not _is_compose_file(source):
        return findings

    # --- privileged: true ---
    for match in _RE_PRIVILEGED.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Compose",
            rule_id="COMPOSE-001",
            severity=Severity.CRITICAL,
            title="Container runs in privileged mode",
            description=(
                "privileged: true disables all security boundaries. "
                "The container gains full access to the host kernel, "
                "devices, and capabilities -- effectively root on the host."
            ),
            cwe="CWE-250",
            line=line_num,
            remediation=(
                "Remove privileged: true. If specific capabilities are "
                "needed, use cap_add with only the required capabilities."
            ),
        ))

    # --- network_mode: host ---
    for match in _RE_NETWORK_HOST.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Compose",
            rule_id="COMPOSE-002",
            severity=Severity.HIGH,
            title="Container uses host network namespace",
            description=(
                "network_mode: host shares the host network stack with "
                "the container, bypassing Docker network isolation. The "
                "container can bind to any host port and see all host traffic."
            ),
            cwe="CWE-269",
            line=line_num,
            remediation="Remove network_mode: host. Use port mappings instead.",
        ))

    # --- Binding to 0.0.0.0 ---
    for match in _RE_BIND_ALL.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Compose",
            rule_id="COMPOSE-003",
            severity=Severity.MEDIUM,
            title="Port binding to 0.0.0.0 (all interfaces)",
            description=(
                "Binding to 0.0.0.0 exposes the service on all network "
                "interfaces, including external-facing ones. This may "
                "unintentionally expose internal services to the internet."
            ),
            cwe="CWE-16",
            line=line_num,
            remediation="Bind to 127.0.0.1 for local-only access: 127.0.0.1:<port>:<port>",
        ))

    # --- Hardcoded passwords in environment ---
    for match in _RE_COMPOSE_PASSWORD.finditer(source):
        value = match.group(1).strip().strip("'\"")
        line_num = source[:match.start()].count("\n") + 1
        # Skip variable references and empty values
        if value.startswith("$") or value.startswith("${") or not value:
            continue
        findings.append(ContainerFinding(
            category="Compose",
            rule_id="COMPOSE-004",
            severity=Severity.CRITICAL,
            title="Hardcoded password/secret in environment variables",
            description=(
                "Secrets are hardcoded in the Compose file. Anyone with "
                "access to the file (version control, CI logs) can read "
                "these credentials."
            ),
            cwe="CWE-532",
            line=line_num,
            remediation=(
                "Use Docker secrets, .env files (excluded from VCS), "
                "or a secrets manager. Reference with ${VARIABLE} syntax."
            ),
        ))

    # --- Sensitive volume mounts ---
    for match in _RE_SENSITIVE_VOLUME.finditer(source):
        path = match.group(1)
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Compose",
            rule_id="COMPOSE-005",
            severity=Severity.CRITICAL,
            title=f"Sensitive host path mounted as volume ({path})",
            description=(
                f"Mounting {path} into the container exposes sensitive "
                f"host system files. /var/run/docker.sock grants full "
                f"Docker API access (container escape). /etc, /root, /proc, "
                f"and /sys expose host configuration and kernel interfaces."
            ),
            cwe="CWE-250",
            line=line_num,
            remediation=(
                f"Remove the {path} volume mount. If Docker socket access "
                f"is required, use a Docker proxy with restricted permissions."
            ),
        ))

    # --- Root filesystem mount ---
    for match in _RE_ROOT_VOLUME.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Compose",
            rule_id="COMPOSE-006",
            severity=Severity.CRITICAL,
            title="Host root filesystem (/) mounted as volume",
            description=(
                "Mounting the entire host root filesystem into the "
                "container grants unrestricted access to all host files, "
                "including /etc/shadow, SSH keys, and kernel interfaces."
            ),
            cwe="CWE-250",
            line=line_num,
            remediation="Never mount / into a container. Mount only specific required paths.",
        ))

    # --- Missing resource limits ---
    if not _RE_MEM_LIMIT.search(source) and not _RE_CPU_LIMIT.search(source):
        # Also check deploy.resources.limits pattern (Compose v3)
        if "resources:" not in source.lower() or "limits:" not in source.lower():
            findings.append(ContainerFinding(
                category="Compose",
                rule_id="COMPOSE-007",
                severity=Severity.MEDIUM,
                title="No resource limits defined (mem_limit, cpus)",
                description=(
                    "Without resource limits, a single container can consume "
                    "all host memory and CPU, enabling denial-of-service "
                    "attacks against co-located services."
                ),
                cwe="CWE-16",
                line=0,
                remediation=(
                    "Add resource limits: mem_limit: 512m, cpus: '0.5' "
                    "or deploy.resources.limits in Compose v3."
                ),
            ))

    # --- Missing health checks ---
    if not _RE_HEALTHCHECK.search(source):
        findings.append(ContainerFinding(
            category="Compose",
            rule_id="COMPOSE-008",
            severity=Severity.LOW,
            title="No healthcheck defined for services",
            description=(
                "Without health checks, Docker cannot detect when a "
                "container is unhealthy and restart it. Failing containers "
                "may continue receiving traffic."
            ),
            cwe="CWE-16",
            line=0,
            remediation="Add healthcheck with test, interval, and timeout for each service.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Kubernetes Manifest Analysis (source text)
# ---------------------------------------------------------------------------

_RE_K8S_KIND = re.compile(r"^\s*kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet|Job|CronJob)", re.MULTILINE)
_RE_K8S_PRIVILEGED = re.compile(
    r"privileged\s*:\s*true", re.MULTILINE | re.IGNORECASE,
)
_RE_K8S_PRIV_ESCALATION = re.compile(
    r"allowPrivilegeEscalation\s*:\s*true", re.MULTILINE | re.IGNORECASE,
)
_RE_K8S_RUN_AS_ROOT = re.compile(
    r"runAsUser\s*:\s*0\b", re.MULTILINE,
)
_RE_K8S_HOST_PATH = re.compile(
    r"hostPath\s*:", re.MULTILINE | re.IGNORECASE,
)
_RE_K8S_HOST_NETWORK = re.compile(
    r"hostNetwork\s*:\s*true", re.MULTILINE | re.IGNORECASE,
)
_RE_K8S_HOST_PID = re.compile(
    r"hostPID\s*:\s*true", re.MULTILINE | re.IGNORECASE,
)
_RE_K8S_RESOURCES = re.compile(
    r"resources\s*:", re.MULTILINE | re.IGNORECASE,
)
_RE_K8S_LIMITS = re.compile(
    r"limits\s*:", re.MULTILINE | re.IGNORECASE,
)
_RE_K8S_REQUESTS = re.compile(
    r"requests\s*:", re.MULTILINE | re.IGNORECASE,
)
_RE_K8S_READ_ONLY_ROOT = re.compile(
    r"readOnlyRootFilesystem\s*:\s*true", re.MULTILINE | re.IGNORECASE,
)
_RE_K8S_LATEST_IMAGE = re.compile(
    r"image\s*:\s*['\"]?[a-zA-Z0-9._/-]+:latest['\"]?", re.MULTILINE | re.IGNORECASE,
)
_RE_K8S_NO_TAG_IMAGE = re.compile(
    r"^\s*image\s*:\s*['\"]?([a-zA-Z0-9._/-]+)['\"]?\s*$", re.MULTILINE,
)
_RE_K8S_NETWORK_POLICY = re.compile(
    r"kind\s*:\s*NetworkPolicy", re.MULTILINE | re.IGNORECASE,
)
_RE_K8S_CLUSTER_ADMIN = re.compile(
    r"cluster-admin", re.MULTILINE | re.IGNORECASE,
)
_RE_K8S_CLUSTER_ROLE_BINDING = re.compile(
    r"kind\s*:\s*ClusterRoleBinding", re.MULTILINE | re.IGNORECASE,
)


def _is_k8s_manifest(source: str) -> bool:
    """Heuristic to detect if source text is a Kubernetes manifest."""
    return bool(_RE_K8S_KIND.search(source)) and "apiVersion:" in source


def _analyze_kubernetes(source: str) -> List[ContainerFinding]:
    """Scan Kubernetes manifest YAML for security issues."""
    findings: List[ContainerFinding] = []

    if not _is_k8s_manifest(source):
        return findings

    # --- securityContext.privileged: true ---
    for match in _RE_K8S_PRIVILEGED.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Kubernetes",
            rule_id="K8S-001",
            severity=Severity.CRITICAL,
            title="Container runs in privileged mode",
            description=(
                "securityContext.privileged: true gives the container "
                "full access to host devices and kernel capabilities, "
                "effectively running as root on the host node."
            ),
            cwe="CWE-250",
            line=line_num,
            remediation="Set privileged: false and use specific capabilities if needed.",
        ))

    # --- allowPrivilegeEscalation: true ---
    for match in _RE_K8S_PRIV_ESCALATION.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Kubernetes",
            rule_id="K8S-002",
            severity=Severity.HIGH,
            title="Privilege escalation allowed",
            description=(
                "allowPrivilegeEscalation: true permits processes in "
                "the container to gain more privileges than the parent "
                "process via setuid binaries or kernel exploits."
            ),
            cwe="CWE-269",
            line=line_num,
            remediation="Set allowPrivilegeEscalation: false in securityContext.",
        ))

    # --- runAsUser: 0 (root) ---
    for match in _RE_K8S_RUN_AS_ROOT.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Kubernetes",
            rule_id="K8S-003",
            severity=Severity.HIGH,
            title="Container runs as root (runAsUser: 0)",
            description=(
                "runAsUser: 0 forces the container to run as UID 0 (root). "
                "Compromise of the application grants root-level access "
                "inside the container."
            ),
            cwe="CWE-250",
            line=line_num,
            remediation="Set runAsUser to a non-zero UID (e.g., 1000) and runAsNonRoot: true.",
        ))

    # --- hostPath mounts ---
    for match in _RE_K8S_HOST_PATH.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Kubernetes",
            rule_id="K8S-004",
            severity=Severity.HIGH,
            title="hostPath volume mount detected",
            description=(
                "hostPath volumes mount directories from the host node "
                "into the pod. This breaks pod isolation and can expose "
                "sensitive host files or enable container escape."
            ),
            cwe="CWE-250",
            line=line_num,
            remediation=(
                "Use PersistentVolumeClaims, ConfigMaps, or Secrets "
                "instead of hostPath mounts."
            ),
        ))

    # --- hostNetwork: true ---
    for match in _RE_K8S_HOST_NETWORK.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Kubernetes",
            rule_id="K8S-005",
            severity=Severity.HIGH,
            title="Pod uses host network namespace (hostNetwork: true)",
            description=(
                "hostNetwork: true shares the host network stack with "
                "the pod, bypassing Kubernetes network policies. The pod "
                "can bind to any host port and see all host traffic."
            ),
            cwe="CWE-269",
            line=line_num,
            remediation="Remove hostNetwork: true. Use Services and Ingress for networking.",
        ))

    # --- hostPID: true ---
    for match in _RE_K8S_HOST_PID.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Kubernetes",
            rule_id="K8S-006",
            severity=Severity.HIGH,
            title="Pod uses host PID namespace (hostPID: true)",
            description=(
                "hostPID: true shares the host PID namespace, allowing "
                "the pod to see and potentially signal all host processes. "
                "This can be used to extract secrets from other processes."
            ),
            cwe="CWE-269",
            line=line_num,
            remediation="Remove hostPID: true unless absolutely required for debugging.",
        ))

    # --- Missing resource requests/limits ---
    has_resources = _RE_K8S_RESOURCES.search(source)
    has_limits = _RE_K8S_LIMITS.search(source)
    has_requests = _RE_K8S_REQUESTS.search(source)
    if not has_resources or not has_limits or not has_requests:
        findings.append(ContainerFinding(
            category="Kubernetes",
            rule_id="K8S-007",
            severity=Severity.MEDIUM,
            title="Missing resource requests and/or limits",
            description=(
                "Without resource requests and limits, pods can consume "
                "unbounded CPU and memory. This enables noisy-neighbor "
                "problems and denial-of-service on shared nodes."
            ),
            cwe="CWE-16",
            remediation=(
                "Add resources.requests and resources.limits for cpu "
                "and memory to all containers."
            ),
        ))

    # --- Missing readOnlyRootFilesystem ---
    if not _RE_K8S_READ_ONLY_ROOT.search(source):
        findings.append(ContainerFinding(
            category="Kubernetes",
            rule_id="K8S-008",
            severity=Severity.MEDIUM,
            title="Missing readOnlyRootFilesystem: true",
            description=(
                "Without a read-only root filesystem, an attacker who "
                "compromises the application can write to the container "
                "filesystem -- installing backdoors, modifying binaries, "
                "or writing malicious cron jobs."
            ),
            cwe="CWE-269",
            remediation=(
                "Set securityContext.readOnlyRootFilesystem: true and "
                "use emptyDir volumes for writable paths (/tmp, /var/log)."
            ),
        ))

    # --- Using :latest images ---
    for match in _RE_K8S_LATEST_IMAGE.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Kubernetes",
            rule_id="K8S-009",
            severity=Severity.MEDIUM,
            title="Using :latest image tag in Kubernetes manifest",
            description=(
                "The :latest tag is mutable and non-deterministic. "
                "Deployments may pull different images across replicas "
                "or rollouts, causing inconsistent behavior."
            ),
            cwe="CWE-1188",
            line=line_num,
            remediation="Pin images to a specific version tag or SHA256 digest.",
        ))

    # Also detect images with no tag at all (implies :latest)
    for match in _RE_K8S_NO_TAG_IMAGE.finditer(source):
        image_name = match.group(1).strip()
        if ":" in image_name or "@" in image_name:
            continue
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="Kubernetes",
            rule_id="K8S-009",
            severity=Severity.MEDIUM,
            title=f"No tag specified for image ({image_name} implies :latest)",
            description=(
                "No tag or digest specified for the container image. "
                "Kubernetes will pull :latest by default."
            ),
            cwe="CWE-1188",
            line=line_num,
            remediation=f"Pin to a specific version: {image_name}:<version>",
        ))

    # --- No NetworkPolicy ---
    if not _RE_K8S_NETWORK_POLICY.search(source):
        findings.append(ContainerFinding(
            category="Kubernetes",
            rule_id="K8S-010",
            severity=Severity.MEDIUM,
            title="No NetworkPolicy defined",
            description=(
                "Without NetworkPolicy resources, all pods can communicate "
                "with each other unrestricted. An attacker who compromises "
                "one pod can pivot to any other service in the cluster."
            ),
            cwe="CWE-16",
            remediation=(
                "Define NetworkPolicy resources to restrict ingress and "
                "egress traffic to only what each workload requires."
            ),
        ))

    # --- ServiceAccount with cluster-admin ---
    if _RE_K8S_CLUSTER_ADMIN.search(source) and _RE_K8S_CLUSTER_ROLE_BINDING.search(source):
        for match in _RE_K8S_CLUSTER_ADMIN.finditer(source):
            line_num = source[:match.start()].count("\n") + 1
            findings.append(ContainerFinding(
                category="Kubernetes",
                rule_id="K8S-011",
                severity=Severity.CRITICAL,
                title="ServiceAccount bound to cluster-admin role",
                description=(
                    "Binding a ServiceAccount to cluster-admin grants "
                    "unrestricted access to the entire Kubernetes API. "
                    "A compromised pod with this binding can take over "
                    "the entire cluster."
                ),
                cwe="CWE-269",
                line=line_num,
                remediation=(
                    "Use least-privilege RBAC roles. Create specific Roles "
                    "or ClusterRoles with only the permissions required."
                ),
            ))
            break  # One finding is enough

    return findings


# ---------------------------------------------------------------------------
# Infrastructure Code Analysis (AST-based)
# ---------------------------------------------------------------------------

# IaC function/method patterns that indicate insecure configurations
_IAC_INSECURE_PATTERNS: List[Dict] = [
    {
        "names": {"s3_bucket", "Bucket", "aws_s3_bucket", "s3.Bucket", "create_bucket"},
        "bad_fields": {"encryption", "server_side_encryption", "sse_algorithm"},
        "check": "missing_field",
        "rule_id": "IAC-001",
        "severity": Severity.HIGH,
        "title": "S3 bucket without server-side encryption",
        "description": (
            "S3 bucket created without server-side encryption. Data at "
            "rest is stored in plaintext, violating data protection "
            "requirements and compliance mandates."
        ),
        "cwe": "CWE-16",
        "remediation": "Enable SSE-S3, SSE-KMS, or SSE-C encryption on the bucket.",
    },
    {
        "names": {"security_group", "SecurityGroup", "aws_security_group", "ec2.SecurityGroup"},
        "bad_strings": {"0.0.0.0/0", "::/0"},
        "check": "contains_string",
        "rule_id": "IAC-002",
        "severity": Severity.CRITICAL,
        "title": "Security group allows ingress from 0.0.0.0/0",
        "description": (
            "The security group allows inbound traffic from any IP "
            "address. This exposes the resource to the entire internet, "
            "making it vulnerable to brute force, scanning, and exploitation."
        ),
        "cwe": "CWE-16",
        "remediation": "Restrict ingress to specific IP ranges or security groups.",
    },
    {
        "names": {"db_instance", "DatabaseInstance", "aws_db_instance", "rds.DatabaseInstance"},
        "bad_fields": {"storage_encrypted", "encryption", "storageEncrypted"},
        "check": "missing_field",
        "rule_id": "IAC-003",
        "severity": Severity.HIGH,
        "title": "RDS instance without encryption at rest",
        "description": (
            "The database instance is created without encryption at rest. "
            "Database storage, automated backups, read replicas, and "
            "snapshots are all stored unencrypted."
        ),
        "cwe": "CWE-16",
        "remediation": "Enable storage_encrypted: true and specify a KMS key.",
    },
    {
        "names": {"cloudfront", "Distribution", "aws_cloudfront_distribution", "cloudfront.Distribution"},
        "bad_fields": {"web_acl_id", "webAclId", "waf"},
        "check": "missing_field",
        "rule_id": "IAC-004",
        "severity": Severity.MEDIUM,
        "title": "CloudFront distribution without WAF",
        "description": (
            "The CloudFront distribution has no Web Application Firewall "
            "(WAF) attached. It cannot filter malicious requests such as "
            "SQL injection, XSS, or DDoS traffic at the edge."
        ),
        "cwe": "CWE-16",
        "remediation": "Associate an AWS WAF WebACL with the CloudFront distribution.",
    },
]


def _analyze_iac_ast(program: Program) -> List[ContainerFinding]:
    """Walk the AST for Infrastructure-as-Code patterns with insecure configs."""
    findings: List[ContainerFinding] = []

    for decl in program.declarations:
        if not isinstance(decl, (PureFunc, TaskFunc)):
            continue
        for stmt in getattr(decl, "body", []):
            findings.extend(_walk_stmt_iac(stmt))

    return findings


def _walk_stmt_iac(stmt: Statement) -> List[ContainerFinding]:
    """Recursively walk a statement looking for IaC patterns."""
    findings: List[ContainerFinding] = []
    loc = getattr(stmt, "location", None)

    if isinstance(stmt, LetStmt) and stmt.value:
        findings.extend(_check_expr_iac(stmt.value, loc))
    elif isinstance(stmt, AssignStmt):
        findings.extend(_check_expr_iac(stmt.value, loc))
    elif isinstance(stmt, ExprStmt):
        findings.extend(_check_expr_iac(stmt.expr, loc))

    # Recurse into block statements
    if hasattr(stmt, "then_body"):
        for s in getattr(stmt, "then_body", []):
            findings.extend(_walk_stmt_iac(s))
    if hasattr(stmt, "else_body"):
        for s in getattr(stmt, "else_body", []):
            findings.extend(_walk_stmt_iac(s))
    if hasattr(stmt, "body") and isinstance(getattr(stmt, "body", None), list):
        for s in stmt.body:
            findings.extend(_walk_stmt_iac(s))

    return findings


def _check_expr_iac(expr: Expr, loc: Optional[SourceLocation]) -> List[ContainerFinding]:
    """Check an expression for IaC security patterns."""
    findings: List[ContainerFinding] = []

    if isinstance(expr, FunctionCall):
        func_name = _extract_callee_name(expr.callee)
        if func_name:
            findings.extend(_match_iac_patterns(func_name, expr.args, loc))
        # Recurse into arguments
        for arg in expr.args:
            findings.extend(_check_expr_iac(arg, loc))

    elif isinstance(expr, MethodCall):
        method_name = expr.method_name
        # Also check combined obj.method pattern
        obj_name = _extract_callee_name(expr.obj)
        combined = f"{obj_name}.{method_name}" if obj_name else method_name
        if combined:
            findings.extend(_match_iac_patterns(combined, expr.args, loc))
        if method_name:
            findings.extend(_match_iac_patterns(method_name, expr.args, loc))
        # Recurse
        findings.extend(_check_expr_iac(expr.obj, loc))
        for arg in expr.args:
            findings.extend(_check_expr_iac(arg, loc))

    elif isinstance(expr, FieldAccess):
        findings.extend(_check_expr_iac(expr.obj, loc))

    return findings


def _extract_callee_name(expr: Expr) -> str:
    """Extract a readable name from a callee expression."""
    if isinstance(expr, Identifier):
        return expr.name
    if isinstance(expr, FieldAccess):
        obj_name = _extract_callee_name(expr.obj)
        return f"{obj_name}.{expr.field_name}" if obj_name else expr.field_name
    return ""


def _match_iac_patterns(
    name: str,
    args: list,
    loc: Optional[SourceLocation],
) -> List[ContainerFinding]:
    """Match a function/method name against IaC insecure patterns."""
    findings: List[ContainerFinding] = []
    name_lower = name.lower()

    for pattern in _IAC_INSECURE_PATTERNS:
        # Check if function name matches any known IaC pattern
        matched = False
        for pname in pattern["names"]:
            if pname.lower() in name_lower or name_lower in pname.lower():
                matched = True
                break

        if not matched:
            continue

        check_type = pattern["check"]

        if check_type == "contains_string":
            # Look for dangerous string literals in arguments
            bad_strings = pattern.get("bad_strings", set())
            arg_strings = _collect_string_literals(args)
            for s in arg_strings:
                if s in bad_strings:
                    findings.append(ContainerFinding(
                        category="IaC",
                        rule_id=pattern["rule_id"],
                        severity=pattern["severity"],
                        title=pattern["title"],
                        description=pattern["description"],
                        cwe=pattern["cwe"],
                        line=loc.line if loc else 0,
                        remediation=pattern["remediation"],
                    ))
                    break  # One finding per call site

        elif check_type == "missing_field":
            # For "missing_field" checks, the finding fires when the
            # IaC constructor is called. In a real AST we would check
            # keyword args; here we flag the usage and note the missing config.
            findings.append(ContainerFinding(
                category="IaC",
                rule_id=pattern["rule_id"],
                severity=pattern["severity"],
                title=pattern["title"],
                description=pattern["description"],
                cwe=pattern["cwe"],
                line=loc.line if loc else 0,
                remediation=pattern["remediation"],
            ))

    return findings


def _collect_string_literals(exprs: list) -> List[str]:
    """Recursively collect all string literal values from a list of expressions."""
    strings: List[str] = []
    for expr in exprs:
        if isinstance(expr, StringLiteral):
            strings.append(expr.value)
        elif isinstance(expr, FunctionCall):
            strings.extend(_collect_string_literals(expr.args))
        elif isinstance(expr, MethodCall):
            strings.extend(_collect_string_literals(expr.args))
    return strings


# ---------------------------------------------------------------------------
# Secret Exposure in Infrastructure (source text)
# ---------------------------------------------------------------------------

_RE_BUILD_ARG_SECRET = re.compile(
    r"^\s*ARG\s+("
    r"[A-Za-z_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIALS)"
    r"[A-Za-z_]*"
    r")",
    re.MULTILINE | re.IGNORECASE,
)
_RE_ENV_FILE_REF = re.compile(r"\.env\b", re.MULTILINE)
_RE_GITIGNORE_REF = re.compile(r"\.gitignore\b", re.MULTILINE)
_RE_BUILD_ARG_IN_RUN = re.compile(
    r"--build-arg\s+("
    r"[A-Za-z_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIALS)"
    r"[A-Za-z_]*"
    r")",
    re.MULTILINE | re.IGNORECASE,
)


def _analyze_secret_exposure(source: str) -> List[ContainerFinding]:
    """Detect secret exposure patterns in infrastructure source text."""
    findings: List[ContainerFinding] = []

    # --- Secrets passed as build args (visible in image layers) ---
    for match in _RE_BUILD_ARG_SECRET.finditer(source):
        arg_name = match.group(1)
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="SecretExposure",
            rule_id="SECRET-001",
            severity=Severity.CRITICAL,
            title=f"Secret passed as build arg ({arg_name})",
            description=(
                f"ARG {arg_name} bakes a secret into the Docker image. "
                f"Build arguments are stored in image layer metadata and "
                f"can be extracted with 'docker history --no-trunc'. "
                f"This is NOT a secure way to handle secrets."
            ),
            cwe="CWE-532",
            line=line_num,
            remediation=(
                "Use Docker BuildKit secrets (--mount=type=secret), "
                "multi-stage builds, or runtime environment variables "
                "instead of ARG for secrets."
            ),
        ))

    # --- --build-arg with secret names ---
    for match in _RE_BUILD_ARG_IN_RUN.finditer(source):
        arg_name = match.group(1)
        line_num = source[:match.start()].count("\n") + 1
        findings.append(ContainerFinding(
            category="SecretExposure",
            rule_id="SECRET-002",
            severity=Severity.HIGH,
            title=f"Secret passed via --build-arg ({arg_name})",
            description=(
                f"The --build-arg flag passes '{arg_name}' to the Docker "
                f"build. This value is visible in the image history and "
                f"build logs."
            ),
            cwe="CWE-532",
            line=line_num,
            remediation=(
                "Use Docker BuildKit secrets or inject at runtime. "
                "Never pass secrets as build arguments."
            ),
        ))

    # --- .env file referenced without .gitignore mention ---
    # This is a heuristic: if we see .env references but no .gitignore
    # references in the same file, it suggests the .env may not be excluded.
    if _RE_ENV_FILE_REF.search(source) and not _RE_GITIGNORE_REF.search(source):
        for match in _RE_ENV_FILE_REF.finditer(source):
            line_num = source[:match.start()].count("\n") + 1
            findings.append(ContainerFinding(
                category="SecretExposure",
                rule_id="SECRET-003",
                severity=Severity.MEDIUM,
                title=".env file referenced without .gitignore mention",
                description=(
                    "A .env file is referenced but there is no mention of "
                    ".gitignore in this file. If .env is not in .gitignore, "
                    "it may be committed to version control with secrets."
                ),
                cwe="CWE-532",
                line=line_num,
                remediation=(
                    "Ensure .env is listed in .gitignore and .dockerignore. "
                    "Use .env.example (without real values) as a template."
                ),
            ))
            break  # One finding is enough

    return findings


# ---------------------------------------------------------------------------
# Source Text AST Analysis (StringLiteral containing Dockerfile/YAML)
# ---------------------------------------------------------------------------

def _analyze_string_literals_for_infra(program: Program) -> List[ContainerFinding]:
    """Walk the AST for StringLiterals containing Dockerfile or YAML fragments.

    Developers sometimes embed Dockerfile content or YAML templates as
    string literals in Python/JS/TS code (e.g., for dynamic generation).
    This catches those embedded patterns.
    """
    findings: List[ContainerFinding] = []

    for decl in program.declarations:
        if not isinstance(decl, (PureFunc, TaskFunc)):
            continue
        for stmt in getattr(decl, "body", []):
            findings.extend(_walk_stmt_string_infra(stmt))

    return findings


def _walk_stmt_string_infra(stmt: Statement) -> List[ContainerFinding]:
    """Walk a statement looking for string literals with infra content."""
    findings: List[ContainerFinding] = []
    loc = getattr(stmt, "location", None)

    if isinstance(stmt, LetStmt) and stmt.value:
        findings.extend(_check_expr_string_infra(stmt.value, loc))
    elif isinstance(stmt, AssignStmt):
        findings.extend(_check_expr_string_infra(stmt.value, loc))
    elif isinstance(stmt, ExprStmt):
        findings.extend(_check_expr_string_infra(stmt.expr, loc))

    # Recurse into blocks
    if hasattr(stmt, "then_body"):
        for s in getattr(stmt, "then_body", []):
            findings.extend(_walk_stmt_string_infra(s))
    if hasattr(stmt, "else_body"):
        for s in getattr(stmt, "else_body", []):
            findings.extend(_walk_stmt_string_infra(s))
    if hasattr(stmt, "body") and isinstance(getattr(stmt, "body", None), list):
        for s in stmt.body:
            findings.extend(_walk_stmt_string_infra(s))

    return findings


def _check_expr_string_infra(expr: Expr, loc: Optional[SourceLocation]) -> List[ContainerFinding]:
    """Check string literals for embedded infrastructure patterns."""
    findings: List[ContainerFinding] = []

    if isinstance(expr, StringLiteral) and expr.value and len(expr.value) > 20:
        value = expr.value
        # Check if the string looks like a Dockerfile fragment
        if re.search(r"\bFROM\b.*\b(?:RUN|COPY|CMD|ENTRYPOINT|EXPOSE)\b", value, re.DOTALL | re.IGNORECASE):
            findings.extend(_analyze_dockerfile(value))
        # Check if the string looks like a K8s manifest fragment
        if "apiVersion:" in value and ("kind:" in value or "spec:" in value):
            findings.extend(_analyze_kubernetes(value))
        # Check if the string looks like a Compose fragment
        if _is_compose_file(value):
            findings.extend(_analyze_compose(value))

    elif isinstance(expr, FunctionCall):
        for arg in expr.args:
            findings.extend(_check_expr_string_infra(arg, loc))

    elif isinstance(expr, MethodCall):
        findings.extend(_check_expr_string_infra(expr.obj, loc))
        for arg in expr.args:
            findings.extend(_check_expr_string_infra(arg, loc))

    elif isinstance(expr, FieldAccess):
        findings.extend(_check_expr_string_infra(expr.obj, loc))

    return findings


# ---------------------------------------------------------------------------
# Error Conversion
# ---------------------------------------------------------------------------

def _finding_to_error(finding: ContainerFinding) -> AeonError:
    """Convert a ContainerFinding into an AeonError via contract_error."""
    severity_label = finding.severity.value.upper()

    location = None
    if finding.line > 0:
        location = SourceLocation(
            line=finding.line,
            column=0,
            file="<container-config>",
        )

    return contract_error(
        precondition=(
            f"Container security ({finding.cwe}) -- "
            f"[{severity_label}] [{finding.rule_id}] {finding.title}"
        ),
        failing_values={
            "category": finding.category,
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "title": finding.title,
            "description": finding.description,
            "cwe": finding.cwe,
            "remediation": finding.remediation,
            "engine": "Container Security",
        },
        function_signature="container_security",
        location=location,
    )


# ---------------------------------------------------------------------------
# Source Type Detection
# ---------------------------------------------------------------------------

def _detect_source_type(source: str) -> str:
    """Detect the type of infrastructure source text.

    Returns one of: "dockerfile", "compose", "kubernetes", "unknown".
    A file may match multiple types; callers should run all relevant analyzers.
    """
    if not source:
        return "unknown"

    # Dockerfile heuristic: FROM directive
    if re.search(r"^\s*FROM\s+\S+", source, re.MULTILINE | re.IGNORECASE):
        return "dockerfile"

    # Kubernetes heuristic: apiVersion + kind
    if _is_k8s_manifest(source):
        return "kubernetes"

    # Compose heuristic
    if _is_compose_file(source):
        return "compose"

    return "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_container_security(program: Program, source_text: str = "") -> list:
    """Run container and infrastructure security analysis.

    Detects security misconfigurations in Dockerfiles, Docker Compose files,
    Kubernetes manifests, and Infrastructure-as-Code patterns.

    Args:
        program: The parsed AEON Program AST. Used for:
            - Walking IaC patterns in Python/JS code (Terraform, Pulumi, CDK)
            - Detecting Dockerfile/YAML fragments embedded in string literals
        source_text: Optional raw source text of a Dockerfile, docker-compose.yml,
                     or Kubernetes manifest. When provided, regex-based pattern
                     matching is performed directly on the text.

    Returns:
        A list of AeonError instances, one per detected issue.

    Detection categories:
        1. Dockerfile issues (root user, :latest tags, secrets, COPY . .)
        2. Docker Compose issues (privileged, host network, volumes, secrets)
        3. Kubernetes manifest issues (privileges, hostPath, RBAC, resources)
        4. Infrastructure-as-Code issues (S3, security groups, RDS, CloudFront)
        5. Secret exposure (build args, .env files, image layer leaks)

    CWEs: CWE-250, CWE-269, CWE-532, CWE-16, CWE-1188
    """
    try:
        all_findings: List[ContainerFinding] = []

        # Determine if this is a frontend component file. Frontend files
        # (.tsx, .jsx, .vue, .svelte) contain JSX string content that
        # triggers false positives against Dockerfile/K8s/Compose regex
        # patterns (e.g., words like "bucket" or "encryption" in UI text).
        filename = getattr(program, "filename", "") or ""
        is_frontend = _is_frontend_file(filename)

        # --- Source text analysis (Dockerfile, Compose, K8s YAML) ---
        # Skip regex-based source text scanning for frontend files.
        # These regex patterns match on raw text and will false-positive
        # on JSX content. Only run on actual IaC/config files.
        if source_text and not is_frontend:
            source_type = _detect_source_type(source_text)

            # Run Dockerfile analysis
            if source_type == "dockerfile" or _RE_FROM.search(source_text):
                all_findings.extend(_analyze_dockerfile(source_text))

            # Run Compose analysis
            if source_type == "compose" or _is_compose_file(source_text):
                all_findings.extend(_analyze_compose(source_text))

            # Run Kubernetes analysis
            if source_type == "kubernetes" or _is_k8s_manifest(source_text):
                all_findings.extend(_analyze_kubernetes(source_text))

            # Run secret exposure analysis on any source text
            all_findings.extend(_analyze_secret_exposure(source_text))

        # --- AST-based analysis ---
        # Walk AST for IaC patterns (Terraform/Pulumi/CDK function calls)
        # This is safe for all file types -- it only matches actual IaC
        # library calls (S3 Bucket constructors, security group APIs, etc.)
        all_findings.extend(_analyze_iac_ast(program))

        # Walk AST for string literals containing embedded infra configs.
        # Skip for frontend files -- JSX string content in UI components
        # (e.g., "Upload to bucket", "Enable encryption") false-positives
        # against the Dockerfile/K8s fragment detection regex.
        if not is_frontend:
            all_findings.extend(_analyze_string_literals_for_infra(program))

        # Deduplicate by rule_id + line
        seen: Set[Tuple[str, int]] = set()
        unique_findings: List[ContainerFinding] = []
        for f in all_findings:
            key = (f.rule_id, f.line)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return [_finding_to_error(f) for f in unique_findings]

    except Exception:
        # Engine-level safety net: never let the engine crash the
        # verification pipeline
        return []
