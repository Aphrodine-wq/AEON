"""AEON CI Templates — GitHub Actions & Pre-Commit Integration.

Generates drop-in CI configuration for any project.
"""

from __future__ import annotations

from typing import Optional


def generate_github_workflow(profile: str = "daily",
                             project_name: str = "project",
                             scan_path: str = "src/") -> str:
    """Generate a GitHub Actions workflow for AEON verification."""
    return f'''name: AEON Verification

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main, master]

permissions:
  contents: read
  security-events: write  # For SARIF upload

jobs:
  verify:
    name: AEON Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install AEON
        run: pip install aeon-lang

      - name: Run AEON verification
        run: |
          aeon scan {scan_path} \\
            --profile {profile} \\
            --format sarif \\
            --output aeon-results.sarif \\
            --baseline .aeon-baseline.json || true

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: aeon-results.sarif
          category: aeon-{profile}

      - name: AEON Summary
        if: always()
        run: |
          aeon scan {scan_path} \\
            --profile {profile} \\
            --format summary \\
            --baseline .aeon-baseline.json || true
'''


def generate_precommit_hook(profile: str = "quick") -> str:
    """Generate a pre-commit hook configuration."""
    return f'''# AEON pre-commit hook
# Add to .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: aeon-check
        name: AEON Verification
        entry: aeon scan
        args: ["--profile", "{profile}", "--format", "summary"]
        language: system
        pass_filenames: false
        always_run: true
'''


def generate_precommit_script() -> str:
    """Generate a standalone pre-commit shell script."""
    return '''#!/bin/sh
# AEON pre-commit hook
# Install: cp this to .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

# Get list of staged files
STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(ts|tsx|js|jsx|py|rs|go|swift)$')

if [ -z "$STAGED" ]; then
    exit 0
fi

echo "Running AEON verification on staged files..."

ERRORS=0
for FILE in $STAGED; do
    RESULT=$(aeon check "$FILE" --profile quick --output-format json 2>/dev/null)
    if echo "$RESULT" | grep -q '"verified": false'; then
        echo "  FAIL: $FILE"
        ERRORS=$((ERRORS + 1))
    fi
done

if [ $ERRORS -gt 0 ]; then
    echo ""
    echo "$ERRORS file(s) have verification errors."
    echo "Run 'aeon check <file> --explain' for details."
    echo "To skip: git commit --no-verify"
    exit 1
fi

echo "All staged files verified."
exit 0
'''


def install_precommit_hook(project_dir: str) -> str:
    """Install the pre-commit hook in a project."""
    import os

    hook_dir = os.path.join(project_dir, ".git", "hooks")
    if not os.path.isdir(hook_dir):
        return f"No .git/hooks directory found at {project_dir}"

    hook_path = os.path.join(hook_dir, "pre-commit")
    script = generate_precommit_script()

    with open(hook_path, "w") as f:
        f.write(script)
    os.chmod(hook_path, 0o755)

    return f"Pre-commit hook installed at {hook_path}"
