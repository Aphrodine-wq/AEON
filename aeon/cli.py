"""AEON CLI — Command-line interface for the AEON compiler.

Commands:
  aeon compile <file.aeon>           — Run all 3 passes, produce binary
  aeon check <file>                  — Verify any file (auto-detects language)
  aeon fix <file>                    — Auto-fix detected issues
  aeon review <file>                 — AI-powered code review
  aeon explain <file>                — Plain-English bug explanations
  aeon scan <dir>                    — Scan entire directory
  aeon watch <dir>                   — Watch and re-verify on changes
  aeon init                          — Project setup wizard
  aeon ir <file.aeon>                — Emit flat IR (JSON)
  aeon test --all | --priority P0 | --category compiler
  aeon synthesize --spec "..."       — Generate provably correct code from specs
  aeon seal <file>                   — Generate proof-carrying seal
  aeon verify-seal <file>            — Verify an existing seal
  aeon harden <dir>                  — Gradually harden codebase with contracts
  aeon autopsy <file>                — Analyze incidents, generate contracts
  aeon formal-diff                   — Show invariant changes between versions
  aeon ghost <file>                  — Ghost-assertion shadowing (intent violations)
  aeon mcp-safety                    — Start MCP safety server for AI agents
  aeon graveyard                     — Analyze famous historical bugs
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from aeon import __version__
from aeon.parser import parse
from aeon.pass1_prove import prove
from aeon.pass2_flatten import flatten
from aeon.pass3_emit import emit, emit_and_compile, HAS_LLVMLITE
from aeon.errors import CompileError

# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

_MAX_SOURCE_SIZE = 10 * 1024 * 1024  # 10 MB


def _validate_source_file(path: str) -> str | None:
    """Return an error message if the file fails validation, else None.

    Checks:
    - File exists
    - File size within limit (DoS prevention)
    """
    if not os.path.isfile(path):
        return f"File not found: {path}"
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return f"Cannot stat file: {e}"
    if size > _MAX_SOURCE_SIZE:
        return f"File too large ({size // (1024 * 1024)}MB > 10MB limit): {path}"
    return None


def _validate_output_path(path: str) -> str | None:
    """Return an error message if the output path is unusable, else None.

    Checks:
    - Not an existing directory
    - Parent directory exists (or is creatable)
    """
    if not path:
        return None
    resolved = os.path.abspath(path)
    if os.path.isdir(resolved):
        return f"Output path is a directory: {resolved}"
    parent = os.path.dirname(resolved) or "."
    if not os.path.isdir(parent):
        return f"Output directory does not exist: {parent}"
    return None


def cmd_compile(args: argparse.Namespace) -> int:
    """Compile an AEON source file through all 3 passes."""
    source_path = args.file
    err = _validate_source_file(source_path)
    if err:
        print(json.dumps({"error": err}))
        return 1

    with open(source_path, "r") as f:
        source = f.read()

    # Parse
    try:
        program = parse(source, filename=source_path)
    except CompileError as e:
        print(e.to_json())
        return 1

    # Pass 1: Prove
    errors = prove(program, verify_contracts=args.verify, analyze_termination=args.termination, track_memory=args.memory,
                    refinement_types=args.refinement_types, abstract_interpretation=args.abstract_interp,
                    size_change=args.size_change, hoare_logic=args.hoare,
                    algebraic_effects=args.algebraic_effects, category_check=args.category,
                    information_flow=args.info_flow, dependent_types=args.dependent_types,
                    certified_compilation=args.certified, symbolic_exec=args.symbolic,
                    separation_logic=getattr(args, 'separation', False),
                    taint_analysis=getattr(args, 'taint', False),
                    concurrency_check=getattr(args, 'concurrency', False),
                    shape_analysis=getattr(args, 'shape', False),
                    model_checking=getattr(args, 'model', False),
                    gradual_typing=getattr(args, 'gradual', False),
                    linear_resource=getattr(args, 'linear', False),
                    probabilistic=getattr(args, 'probabilistic', False),
                    relational_verify=getattr(args, 'relational', False),
                    session_types=getattr(args, 'session', False),
                    complexity_analysis=getattr(args, 'complexity', False),
                    abstract_refinement=getattr(args, 'abstract_refinement', False),
                    differential_privacy=getattr(args, 'privacy', False),
                    typestate=getattr(args, 'typestate', False),
                    interpolation=getattr(args, 'interpolation', False),
                    # Cybersecurity engines
                    secret_detection=getattr(args, 'secret_detection', False),
                    auth_check=getattr(args, 'auth_check', False),
                    crypto_misuse=getattr(args, 'crypto_misuse', False),
                    injection_advanced=getattr(args, 'injection_advanced', False),
                    api_security=getattr(args, 'api_security', False),
                    supply_chain=getattr(args, 'supply_chain', False),
                    session_jwt=getattr(args, 'session_jwt', False),
                    container_security=getattr(args, 'container_security', False),
                    ssrf_advanced=getattr(args, 'ssrf_advanced', False),
                    prototype_pollution=getattr(args, 'prototype_pollution', False),
                    # Cybersecurity Tier 2
                    business_logic=getattr(args, 'business_logic', False),
                    data_exposure=getattr(args, 'data_exposure', False),
                    security_misconfig=getattr(args, 'security_misconfig', False),
                    oauth_oidc=getattr(args, 'oauth_oidc', False),
                    file_upload=getattr(args, 'file_upload', False),
                    input_validation=getattr(args, 'input_validation', False),
                    race_condition_security=getattr(args, 'race_condition_security', False),
                    dependency_audit=getattr(args, 'dependency_audit', False),
                    email_security=getattr(args, 'email_security', False),
                    insecure_randomness=getattr(args, 'insecure_randomness', False),
                    cache_poisoning=getattr(args, 'cache_poisoning', False),
                    http_smuggling=getattr(args, 'http_smuggling', False),
                    deep_verify=args.deep_verify)
    if errors:
        print(json.dumps([e.to_dict() for e in errors], indent=2))
        return 1

    # Pass 2: Flatten
    ir_module = flatten(program)

    # Pass 3: Emit
    if not HAS_LLVMLITE:
        print(json.dumps({"warning": "llvmlite not installed. Emitting IR JSON only."}))
        print(ir_module.to_json())
        return 0

    output = args.output or os.path.splitext(source_path)[0]

    try:
        llvm_ir_str = emit_and_compile(ir_module, output)
    except Exception as e:
        # Fall back to emitting LLVM IR text
        llvm_ir_str = emit(ir_module)
        ir_path = output + ".ll"
        with open(ir_path, "w") as f:
            f.write(llvm_ir_str)
        print(json.dumps({"status": "llvm_ir_emitted", "path": ir_path}))
        return 0

    # Link object file to binary
    obj_path = output + ".o"
    try:
        subprocess.run(
            ["cc", obj_path, "-o", output, "-lm"],
            check=True, capture_output=True,
        )
        os.remove(obj_path)
        print(json.dumps({"status": "compiled", "binary": output}))
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(json.dumps({"status": "object_emitted", "path": obj_path}))

    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Run Pass 1 only — fast type check. Auto-detects language from extension."""
    source_path = args.file
    err = _validate_source_file(source_path)
    if err:
        print(json.dumps({"error": err}))
        return 1

    ext = os.path.splitext(source_path)[1].lower()
    language = getattr(args, 'language', None)

    # Auto-detect language or use override
    if language:
        pass  # User specified explicitly
    elif ext in ('.py',):
        language = 'python'
    elif ext in ('.java',):
        language = 'java'
    elif ext in ('.js', '.jsx', '.mjs'):
        language = 'javascript'
    elif ext in ('.ts', '.tsx'):
        language = 'typescript'
    elif ext in ('.go',):
        language = 'go'
    elif ext in ('.rs',):
        language = 'rust'
    elif ext in ('.c', '.h'):
        language = 'c'
    elif ext in ('.cpp', '.hpp', '.cc', '.cxx', '.hxx'):
        language = 'cpp'
    elif ext in ('.rb',):
        language = 'ruby'
    elif ext in ('.swift',):
        language = 'swift'
    elif ext in ('.kt', '.kts'):
        language = 'kotlin'
    elif ext in ('.php',):
        language = 'php'
    elif ext in ('.scala',):
        language = 'scala'
    elif ext in ('.dart',):
        language = 'dart'
    elif ext in ('.lua',):
        language = 'lua'
    elif ext in ('.R', '.r'):
        language = 'r'
    elif ext in ('.ex', '.exs'):
        language = 'elixir'
    elif ext in ('.hs', '.lhs'):
        language = 'haskell'
    elif ext in ('.ml', '.mli'):
        language = 'ocaml'
    elif ext in ('.zig',):
        language = 'zig'
    elif ext in ('.jl',):
        language = 'julia'
    elif ext in ('.aeon',):
        language = 'aeon'
    else:
        language = 'aeon'  # Default to AEON

    with open(source_path, "r") as f:
        source = f.read()

    # For non-AEON languages, use the multi-language adapter
    if language != 'aeon':
        from aeon.language_adapter import verify as lang_verify
        from aeon.profiles import resolve_profile_to_prove_kwargs
        # Resolve profile to prove kwargs so cybersecurity engines get activated
        profile_name = getattr(args, 'profile', None)
        prove_kwargs = None
        if profile_name:
            prove_kwargs = resolve_profile_to_prove_kwargs(profile_name=profile_name, deep_verify=args.deep_verify)
        elif args.deep_verify:
            prove_kwargs = resolve_profile_to_prove_kwargs(deep_verify=True)
        result = lang_verify(source, language, deep_verify=args.deep_verify, prove_kwargs=prove_kwargs)
        result_dict = result.to_dict()
        fmt = getattr(args, 'output_format', 'pretty') or 'pretty'
        if getattr(args, 'explain', False):
            from aeon.explain import explain_all, format_explanations
            explanations = explain_all(result_dict)
            print(format_explanations(explanations, filepath=source_path))
        else:
            from aeon.formatters import format_result
            print(format_result(result_dict, fmt=fmt, filepath=source_path, source=source))
        return 0 if result.verified else 1

    # AEON language: use native parser + prove pipeline
    try:
        program = parse(source, filename=source_path)
    except CompileError as e:
        print(e.to_json())
        return 1

    errors = prove(program, verify_contracts=args.verify, analyze_termination=args.termination, track_memory=args.memory,
                    refinement_types=args.refinement_types, abstract_interpretation=args.abstract_interp,
                    size_change=args.size_change, hoare_logic=args.hoare,
                    algebraic_effects=args.algebraic_effects, category_check=args.category,
                    information_flow=args.info_flow, dependent_types=args.dependent_types,
                    certified_compilation=args.certified, symbolic_exec=args.symbolic,
                    separation_logic=getattr(args, 'separation', False),
                    taint_analysis=getattr(args, 'taint', False),
                    concurrency_check=getattr(args, 'concurrency', False),
                    shape_analysis=getattr(args, 'shape', False),
                    model_checking=getattr(args, 'model', False),
                    gradual_typing=getattr(args, 'gradual', False),
                    linear_resource=getattr(args, 'linear', False),
                    probabilistic=getattr(args, 'probabilistic', False),
                    relational_verify=getattr(args, 'relational', False),
                    session_types=getattr(args, 'session', False),
                    complexity_analysis=getattr(args, 'complexity', False),
                    abstract_refinement=getattr(args, 'abstract_refinement', False),
                    differential_privacy=getattr(args, 'privacy', False),
                    typestate=getattr(args, 'typestate', False),
                    interpolation=getattr(args, 'interpolation', False),
                    # Cybersecurity engines
                    secret_detection=getattr(args, 'secret_detection', False),
                    auth_check=getattr(args, 'auth_check', False),
                    crypto_misuse=getattr(args, 'crypto_misuse', False),
                    injection_advanced=getattr(args, 'injection_advanced', False),
                    api_security=getattr(args, 'api_security', False),
                    supply_chain=getattr(args, 'supply_chain', False),
                    session_jwt=getattr(args, 'session_jwt', False),
                    container_security=getattr(args, 'container_security', False),
                    ssrf_advanced=getattr(args, 'ssrf_advanced', False),
                    prototype_pollution=getattr(args, 'prototype_pollution', False),
                    # Cybersecurity Tier 2
                    business_logic=getattr(args, 'business_logic', False),
                    data_exposure=getattr(args, 'data_exposure', False),
                    security_misconfig=getattr(args, 'security_misconfig', False),
                    oauth_oidc=getattr(args, 'oauth_oidc', False),
                    file_upload=getattr(args, 'file_upload', False),
                    input_validation=getattr(args, 'input_validation', False),
                    race_condition_security=getattr(args, 'race_condition_security', False),
                    dependency_audit=getattr(args, 'dependency_audit', False),
                    email_security=getattr(args, 'email_security', False),
                    insecure_randomness=getattr(args, 'insecure_randomness', False),
                    cache_poisoning=getattr(args, 'cache_poisoning', False),
                    http_smuggling=getattr(args, 'http_smuggling', False),
                    deep_verify=args.deep_verify)

    # --proof-trace: emit Hoare proof obligations after normal check output
    if getattr(args, 'proof_trace', False) and language == 'aeon':
        from aeon.hoare import verify_contracts_hoare_with_trace
        _, trace = verify_contracts_hoare_with_trace(program)
        print(f"\n  AEON Proof Trace — {source_path}")
        print(f"  {'─' * 60}")
        print(trace.to_ascii_table())
        for ob in trace.obligations:
            print(ob.to_ascii())
            print()
        if getattr(args, 'emit_witnesses', False) and trace.witnesses():
            witnesses_path = source_path + ".witnesses.json"
            with open(witnesses_path, 'w') as wf:
                json.dump(trace.witnesses(), wf, indent=2)
            print(f"  Witnesses written to: {witnesses_path}")

    # Format output
    fmt = getattr(args, 'output_format', 'pretty') or 'pretty'
    if getattr(args, 'explain', False):
        from aeon.explain import explain_all, format_explanations
        error_list = [e.to_dict() for e in errors]
        result_dict = {"verified": len(errors) == 0, "errors": error_list, "warnings": []}
        explanations = explain_all(result_dict)
        print(format_explanations(explanations, filepath=source_path))
    elif fmt == 'json':
        if errors:
            print(json.dumps([e.to_dict() for e in errors], indent=2))
        else:
            print(json.dumps({"status": "ok", "file": source_path}))
    else:
        from aeon.formatters import format_result
        error_list = [e.to_dict() for e in errors]
        result_dict = {
            "verified": len(errors) == 0,
            "errors": error_list,
            "warnings": [],
            "summary": f"{'✅ VERIFIED' if not errors else f'❌ {len(errors)} bug(s) found'}",
        }
        print(format_result(result_dict, fmt=fmt, filepath=source_path, source=source))

    return 1 if errors else 0


def cmd_ir(args: argparse.Namespace) -> int:
    """Emit flat IR as JSON."""
    source_path = args.file
    if not os.path.exists(source_path):
        print(json.dumps({"error": f"File not found: {source_path}"}))
        return 1

    with open(source_path, "r") as f:
        source = f.read()

    try:
        program = parse(source, filename=source_path)
    except CompileError as e:
        print(e.to_json())
        return 1

    # Optionally check types first
    errors = prove(program, verify_contracts=False)
    if errors:
        print(json.dumps([e.to_dict() for e in errors], indent=2))
        return 1

    ir_module = flatten(program)
    print(ir_module.to_json())
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan and verify an entire directory recursively."""
    target = args.directory
    if not os.path.isdir(target):
        print(json.dumps({"error": f"Not a directory: {target}"}))
        return 1

    # Validate output path before doing any work
    output_path = getattr(args, 'output', '') or ''
    if output_path:
        out_err = _validate_output_path(output_path)
        if out_err:
            print(json.dumps({"error": out_err}))
            return 1

    from aeon.config import load_config
    config = load_config(start_dir=target)

    deep = args.deep_verify or config.deep_verify
    use_parallel = args.parallel or config.parallel
    workers = getattr(args, 'workers', 0) or config.parallel_workers

    # Resolve profile to prove kwargs for cybersecurity engine activation
    from aeon.profiles import resolve_profile_to_prove_kwargs
    profile_name = getattr(args, 'profile', None) or config.profile
    prove_kwargs = None
    if profile_name:
        prove_kwargs = resolve_profile_to_prove_kwargs(profile_name=profile_name, deep_verify=deep)
    elif deep:
        prove_kwargs = resolve_profile_to_prove_kwargs(deep_verify=True)

    if use_parallel:
        from aeon.parallel import parallel_scan
        result = parallel_scan(target, deep_verify=deep, workers=workers)
    else:
        from aeon.scanner import scan_directory
        result = scan_directory(target, deep_verify=deep, prove_kwargs=prove_kwargs)

    # Cross-file analysis (runs on the whole directory, not per-file)
    try:
        from aeon.engines.cross_file import analyze_cross_file
        xfile_result = analyze_cross_file(target)
        if xfile_result.findings:
            # Add cross-file findings to a special file result entry
            xfile_entry = {
                "file": "<cross-file-analysis>",
                "language": "typescript",
                "verified": len([f for f in xfile_result.findings
                                 if f.details.get("failing_values", {}).get("severity") == "error"]) == 0,
                "errors": len([f for f in xfile_result.findings
                               if f.details.get("failing_values", {}).get("severity") == "error"]),
                "warnings": len([f for f in xfile_result.findings
                                 if f.details.get("failing_values", {}).get("severity") != "error"]),
                "functions": 0, "classes": 0,
                "summary": f"Cross-file analysis: {len(xfile_result.findings)} findings across {xfile_result.files_analyzed} files",
                "error_details": [f.to_dict() for f in xfile_result.findings
                                  if f.details.get("failing_values", {}).get("severity") == "error"],
                "warning_details": [f.to_dict() for f in xfile_result.findings
                                    if f.details.get("failing_values", {}).get("severity") != "error"],
            }
            result.file_results.append(xfile_entry)
            result.total_errors += xfile_entry["errors"]
            result.total_warnings += xfile_entry["warnings"]
    except Exception as e:
        pass  # Cross-file analysis is optional

    # AI intent analysis (if API key available and --ai flag set)
    if getattr(args, 'ai_intent', False):
        try:
            from aeon.engines.ai_intent import AIIntentEngine, is_available
            if is_available():
                ai_engine = AIIntentEngine(max_functions=10)
                # Analyze the most critical files
                critical_patterns = ['route.ts', 'api/', 'calculations/', 'engine/']
                for fr in result.file_results[:50]:
                    filepath = fr.get("file", "")
                    if any(p in filepath for p in critical_patterns):
                        full_path = os.path.join(target, filepath)
                        if os.path.isfile(full_path):
                            ai_errors = ai_engine.analyze_file(full_path)
                            for err in ai_errors:
                                fr.setdefault("warning_details", []).append(err.to_dict())
                                fr["warnings"] = fr.get("warnings", 0) + 1
                                result.total_warnings += 1
        except Exception:
            pass  # AI analysis is optional

    # Quality filtering (confidence scoring, dedup, noise suppression) — ON by default
    if not getattr(args, 'raw', False):
        from aeon.scanner import apply_quality_filter
        min_conf = getattr(args, 'min_confidence', 0.3)
        result = apply_quality_filter(result, min_confidence=min_conf)

    # Baseline filtering
    baseline_path = getattr(args, 'baseline', '') or config.baseline
    if baseline_path and os.path.isfile(baseline_path) and not getattr(args, 'create_baseline', False):
        from aeon.baseline import load_baseline, filter_by_baseline
        baseline = load_baseline(baseline_path)
        result = filter_by_baseline(result, baseline)

    # Create baseline if requested
    if getattr(args, 'create_baseline', False) and baseline_path:
        from aeon.baseline import create_baseline, save_baseline
        bl = create_baseline(result)
        save_baseline(bl, baseline_path)
        print(f"Baseline saved: {baseline_path} ({len(bl.entries)} entries)")
        return 0

    # Output format
    fmt = getattr(args, 'format', 'pretty') or config.format
    output_path = getattr(args, 'output', '') or ''

    import io
    output_buf = io.StringIO() if output_path else None
    _print = (lambda *a, **kw: print(*a, file=output_buf, **kw)) if output_buf else print

    if fmt == 'sarif':
        from aeon.sarif import to_sarif
        _print(to_sarif(result))
    elif fmt == 'json':
        _print(json.dumps(result.to_dict(), indent=2))
    elif fmt == 'markdown':
        from aeon.formatters import format_markdown_scan
        _print(format_markdown_scan(result))
    elif fmt == 'pretty':
        from aeon.formatters import format_pretty_scan
        _print(format_pretty_scan(result))
    else:
        _print(result.summary)
        for fr in result.file_results:
            status = "\u2705" if fr.get('verified', False) else "\u274c"
            errors = fr.get('errors', 0)
            warnings = fr.get('warnings', 0)
            detail = ""
            if errors:
                detail += f" {errors} error(s)"
            if warnings:
                detail += f" {warnings} warning(s)"
            _print(f"  {status} {fr.get('file', '?')}{detail}")

    if output_buf and output_path:
        with open(output_path, 'w') as f:
            f.write(output_buf.getvalue())
        print(f"Results written to: {output_path}")

    return 0 if result.total_errors == 0 else 1


def cmd_watch(args: argparse.Namespace) -> int:
    """Watch a directory and re-verify on file changes."""
    target = args.directory
    if not os.path.isdir(target):
        print(json.dumps({"error": f"Not a directory: {target}"}))
        return 1

    from aeon.scanner import scan_directory, discover_files
    import time

    print(f"\u2693 Watching {target} for changes... (Ctrl+C to stop)")

    # Initial scan
    result = scan_directory(target, deep_verify=args.deep_verify)
    print(result.summary)

    # Track file modification times
    mtimes: dict = {}
    files = discover_files(target)
    for f in files:
        try:
            mtimes[f] = os.path.getmtime(f)
        except OSError:
            pass

    try:
        while True:
            time.sleep(1.0)  # Poll every second
            changed = []
            current_files = discover_files(target)

            for f in current_files:
                try:
                    mtime = os.path.getmtime(f)
                    if f not in mtimes or mtimes[f] != mtime:
                        changed.append(f)
                        mtimes[f] = mtime
                except OSError:
                    pass

            if changed:
                print(f"\n\u2699 {len(changed)} file(s) changed, re-verifying...")
                result = scan_directory(target, deep_verify=args.deep_verify)
                print(result.summary)

    except KeyboardInterrupt:
        print("\nWatch stopped.")
        return 0


def cmd_test(args: argparse.Namespace) -> int:
    """Run the AEON test suite."""
    import subprocess

    test_dir = Path(__file__).parent.parent / "tests"

    pytest_args = ["python3", "-m", "pytest", str(test_dir), "-v", "--tb=short"]

    if args.priority:
        pytest_args.extend(["-k", f"priority_{args.priority.lower()}"])
    if args.category:
        pytest_args.extend(["-k", args.category])

    result = subprocess.run(pytest_args)
    return result.returncode


def cmd_fix(args: argparse.Namespace) -> int:
    """Auto-fix detected issues in source files."""
    target = args.target
    dry_run = getattr(args, 'dry_run', False)
    fix_type = getattr(args, 'type', None)
    min_confidence = getattr(args, 'min_confidence', 0.5)
    deep_verify = getattr(args, 'deep_verify', True)

    from aeon.autofix import fix_file, fix_directory, format_fix_result, format_fix_diff

    if os.path.isfile(target):
        result = fix_file(
            target, dry_run=dry_run, fix_type=fix_type,
            min_confidence=min_confidence, deep_verify=deep_verify,
        )
        if dry_run:
            print(format_fix_diff(result))
        print(format_fix_result(result, verbose=True))
        return 0 if not result.fixes_applied or result.error_count_after == 0 else 1

    elif os.path.isdir(target):
        results = fix_directory(
            target, dry_run=dry_run, fix_type=fix_type,
            min_confidence=min_confidence, deep_verify=deep_verify,
        )
        total_applied = 0
        for result in results:
            if result.fixes_applied or result.fixes_skipped:
                print(format_fix_result(result, verbose=True))
                total_applied += len(result.fixes_applied)
        if total_applied == 0:
            print("✅ No issues to fix.")
        else:
            print(f"\n⚡ {total_applied} fix(es) applied across {len(results)} file(s).")
        return 0

    else:
        print(json.dumps({"error": f"Not found: {target}"}))
        return 1


def cmd_review(args: argparse.Namespace) -> int:
    """AI-powered code review."""
    from aeon.review import ReviewEngine, format_review_pretty, format_review_markdown

    engine = ReviewEngine(deep_verify=getattr(args, 'deep_verify', True))
    fmt = getattr(args, 'format', 'pretty') or 'pretty'

    diff_ref = getattr(args, 'diff', None)
    if diff_ref:
        report = engine.review_diff(diff_ref, cwd=".")
    elif hasattr(args, 'target') and args.target:
        target = args.target
        if os.path.isfile(target):
            report = engine.review_file(target)
        elif os.path.isdir(target):
            report = engine.review_directory(target)
        else:
            print(json.dumps({"error": f"Not found: {target}"}))
            return 1
    else:
        print("Usage: aeon review <file|dir> or aeon review --diff HEAD~1")
        return 1

    if fmt == 'markdown':
        print(format_review_markdown(report))
    elif fmt == 'json':
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_review_pretty(report))

    return 0 if report.error_count == 0 else 1


def cmd_explain(args: argparse.Namespace) -> int:
    """Plain-English bug explanations."""
    source_path = args.file
    if not os.path.isfile(source_path):
        print(json.dumps({"error": f"File not found: {source_path}"}))
        return 1

    with open(source_path, "r") as f:
        source = f.read()

    from aeon.autofix import _run_verification
    from aeon.explain import explain_all, format_explanations

    ext = os.path.splitext(source_path)[1].lower()
    lang_map = {
        ".py": "python", ".java": "java", ".js": "javascript", ".jsx": "javascript",
        ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".rs": "rust",
        ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".rb": "ruby",
        ".swift": "swift", ".kt": "kotlin", ".php": "php", ".scala": "scala",
        ".dart": "dart", ".aeon": "aeon",
    }
    language = lang_map.get(ext, "python")
    deep = getattr(args, 'deep_verify', True)

    errors = _run_verification(source, language, source_path, deep)
    result_dict = {"verified": len(errors) == 0, "errors": errors, "warnings": []}

    explanations = explain_all(result_dict)
    print(format_explanations(explanations, filepath=source_path))

    return 0 if not errors else 1


def cmd_init(args: argparse.Namespace) -> int:
    """Project setup wizard."""
    from aeon.init_cmd import run_init

    directory = getattr(args, 'directory', '.')
    profile = getattr(args, 'profile', None)
    generate_ci = getattr(args, 'ci', False)

    result = run_init(
        directory=directory,
        profile=profile,
        generate_ci=generate_ci,
    )
    return 0


def cmd_abstract_trace(args: argparse.Namespace) -> int:
    """Emit per-statement abstract domain states for teaching / inspection.

    Runs the AbstractDomainInspector on an AEON source file and prints
    a step-by-step table of how the abstract state evolves through each
    statement — the fixpoint computation made visible.
    """
    source_path = args.file
    if not os.path.exists(source_path):
        print(json.dumps({"error": f"File not found: {source_path}"}))
        return 1

    with open(source_path, "r") as f:
        source = f.read()

    try:
        program = parse(source, filename=source_path)
    except CompileError as e:
        print(e.to_json())
        return 1

    from aeon.abstract_interp import inspect_abstract_domains
    trace = inspect_abstract_domains(program)

    fmt = getattr(args, 'format', 'pretty') or 'pretty'

    if fmt == 'json':
        print(json.dumps(trace, indent=2))
        return 0

    # ASCII table output
    print(f"\n  AEON Abstract Domain Inspector — {source_path}")
    print(f"  {'─' * 60}")
    for func_name, steps in trace.items():
        print(f"\n  Function: {func_name}")
        print(f"  {'─' * 55}")
        for step in steps:
            point = step.get('point', '')
            stmt = step.get('stmt', '')
            note = step.get('note', '')
            state_after = step.get('state_after') or step.get('state', {})

            print(f"\n  [{point}] {stmt}")
            if note and note != 'no change':
                print(f"    Change : {note}")
            if state_after and not state_after.get('_bottom'):
                for var, info in sorted(state_after.items()):
                    iv = info.get('interval', '')
                    sg = info.get('sign', '')
                    cg = info.get('congruence', '')
                    parts = []
                    if iv:
                        parts.append(f"interval={iv}")
                    if sg:
                        parts.append(f"sign={sg}")
                    if cg:
                        parts.append(f"congruence={cg}")
                    print(f"    {var:15s}: {', '.join(parts)}")
            elif state_after.get('_bottom'):
                print("    (unreachable — bottom state)")
        print()
    return 0


def cmd_proof_trace(args: argparse.Namespace) -> int:
    """Run Hoare-logic verification and emit full proof trace.

    For each function with contracts, shows:
      - The verification condition (VC) generated
      - The SMTLIB2 query sent to Z3
      - The solver result (UNSAT = proved, SAT = counterexample)
      - The proof rule applied
    """
    source_path = args.file
    if not os.path.exists(source_path):
        print(json.dumps({"error": f"File not found: {source_path}"}))
        return 1

    with open(source_path, "r") as f:
        source = f.read()

    try:
        program = parse(source, filename=source_path)
    except CompileError as e:
        print(e.to_json())
        return 1

    from aeon.hoare import verify_contracts_hoare_with_trace
    errors, trace = verify_contracts_hoare_with_trace(program)

    fmt = getattr(args, 'format', 'pretty') or 'pretty'

    if fmt == 'json':
        print(trace.to_json())
        return 1 if errors else 0

    if fmt == 'smtlib2':
        print(trace.to_smtlib2_bundle())
        return 1 if errors else 0

    if fmt == 'latex':
        from aeon.latex_report import generate_latex_report
        from aeon.abstract_interp import inspect_abstract_domains
        abstract_trace = {}
        try:
            abstract_trace = inspect_abstract_domains(program)
        except Exception:
            pass
        print(generate_latex_report(
            source_file=source_path,
            proof_trace=trace,
            abstract_trace=abstract_trace,
        ))
        return 1 if errors else 0

    # Pretty output
    print(f"\n  AEON Proof Trace — {source_path}")
    print(f"  {'─' * 60}")
    print(trace.to_ascii_table())
    for ob in trace.obligations:
        print(ob.to_ascii())
        print()

    if getattr(args, 'emit_witnesses', False) and trace.witnesses():
        witnesses_path = source_path + ".witnesses.json"
        with open(witnesses_path, 'w') as wf:
            json.dump(trace.witnesses(), wf, indent=2)
        print(f"  Witnesses written to: {witnesses_path}")

    return 1 if errors else 0


def cmd_synthesize(args: argparse.Namespace) -> int:
    """Synthesize provably correct code from specifications."""
    from aeon.synthesizer import CodeSynthesizer, format_synthesis_result

    synth = CodeSynthesizer(target_language=getattr(args, 'language', 'python'))

    if getattr(args, 'list_templates', False):
        templates = synth.list_templates()
        print(f"\n  AEON Synthesis Templates ({len(templates)} available)\n")
        for t in templates:
            print(f"  {t['name']:20s} {t['description']}")
            if t['requires']:
                print(f"  {'':20s} Requires: {', '.join(t['requires'])}")
            if t['ensures']:
                print(f"  {'':20s} Ensures: {', '.join(t['ensures'])}")
            print(f"  {'':20s} Languages: {', '.join(t['languages'])}")
            print()
        return 0

    if getattr(args, 'spec', None):
        result = synth.synthesize_from_spec(args.spec)
    elif getattr(args, 'file', None):
        source = Path(args.file).read_text()
        result = synth.synthesize_from_aeon(source)
    else:
        print("Error: provide --spec or an .aeon spec file")
        return 1

    print(format_synthesis_result(result, verbose=getattr(args, 'verbose', False)))
    return 0


def cmd_seal(args: argparse.Namespace) -> int:
    """Generate a proof-carrying seal for verified code."""
    from aeon.seal import AeonSealer

    sealer = AeonSealer()
    filepath = args.file

    if not os.path.exists(filepath):
        print(json.dumps({"error": f"File not found: {filepath}"}))
        return 1

    # Run verification first to get results
    vr = {}
    try:
        from aeon.adapters.language_adapter import verify, detect_language
        lang = detect_language(filepath)
        if lang:
            result = verify(Path(filepath).read_text(), lang)
            vr = {
                "language": lang,
                "errors_found": len(result.errors) if hasattr(result, 'errors') else 0,
                "contracts_verified": getattr(result, 'contracts_verified', 0),
                "properties_proven": getattr(result, 'properties_proven', []),
                "engines": getattr(result, 'engines_used', []),
            }
    except Exception:
        pass

    seal_result = sealer.seal(filepath, vr)
    print(sealer.export_certificate(seal_result.certificate, fmt="text"))
    print(f"\nSeal written to: {seal_result.seal_file}")
    print(f"Badge: {seal_result.badge_markdown}")

    if getattr(args, 'embed', False):
        sealer.embed_seal(filepath, seal_result)
        print(f"Seal embedded in {filepath}")

    return 0


def cmd_verify_seal(args: argparse.Namespace) -> int:
    """Verify an existing proof seal."""
    from aeon.seal import AeonSealer

    sealer = AeonSealer()
    filepath = args.file
    seal_path = getattr(args, 'seal_file', None)

    if not os.path.exists(filepath):
        print(json.dumps({"error": f"File not found: {filepath}"}))
        return 1

    valid = sealer.verify_seal(filepath, seal_path)
    if valid:
        print(f"VERIFIED: Seal for {filepath} is valid.")
        return 0
    else:
        print(f"FAILED: Seal for {filepath} is invalid or missing.")
        return 1


def cmd_harden(args: argparse.Namespace) -> int:
    """Analyze and harden a codebase with contracts."""
    from aeon.harden import CodeHardener

    hardener = CodeHardener()
    target = args.target

    if not os.path.exists(target):
        print(json.dumps({"error": f"Path not found: {target}"}))
        return 1

    # Single function mode
    if getattr(args, 'function', None):
        result = hardener.harden_function(target, args.function)
        print(f"Hardening: {result.target.name} (risk: {result.target.risk_score:.2f})")
        if result.contracts_added:
            print("\nSuggested contracts:")
            for c in result.contracts_added:
                print(f"  + {c}")
        if result.source_patch:
            print(f"\n{result.source_patch}")
        return 0

    plan = hardener.analyze(target)

    if getattr(args, 'report', False):
        print(hardener.generate_report(plan))
        return 0

    # Summary view
    print(f"\n  AEON Hardening Analysis")
    print(f"  {'=' * 50}")
    print(f"  Total functions:    {plan.total_functions}")
    print(f"  Already verified:   {plan.already_verified}")
    print()
    for phase in ["critical", "high", "medium", "low"]:
        count = len(plan.phases.get(phase, []))
        cov = plan.coverage_by_phase.get(phase, 0)
        print(f"  {phase.upper():10s}  {count:4d} functions  ({cov:.1f}% cumulative coverage)")
    print()

    # Show top targets
    if plan.targets:
        print(f"  Top Risk Targets:")
        for t in plan.targets[:10]:
            print(f"    {t.risk_score:.2f}  {t.name:30s}  {t.file}")
            for rf in t.risk_factors[:2]:
                print(f"          {rf}")
    print()
    return 0


def cmd_autopsy(args: argparse.Namespace) -> int:
    """Analyze incidents and generate protective contracts."""
    from aeon.autopsy import IncidentAutopsy

    autopsy = IncidentAutopsy()

    if getattr(args, 'stdin', False):
        import sys as _sys
        text = _sys.stdin.read()
        incidents = autopsy.parse_log(text)
        incident = incidents[0] if incidents else autopsy.parse_stacktrace(text)
    elif getattr(args, 'file', None):
        if not os.path.exists(args.file):
            print(json.dumps({"error": f"File not found: {args.file}"}))
            return 1
        result = autopsy.autopsy_from_file(args.file, getattr(args, 'source_root', None))
        output = getattr(args, 'output', 'report')
        if output == 'contracts':
            for gc in result.generated_contracts:
                print(f"{gc.target_function}: {gc.contract}")
                print(f"  Reason: {gc.reason}")
            return 0
        elif output == 'tests':
            for gt in result.generated_tests:
                print(f"# {gt.test_name}")
                print(gt.test_code)
            return 0
        else:
            print(autopsy.format_report(result))
            return 0
    else:
        print("Error: provide a file or --stdin")
        return 1

    source_root = getattr(args, 'source_root', None)
    result = autopsy.analyze(incident, source_root)
    print(autopsy.format_report(result))
    return 0


def cmd_formal_diff(args: argparse.Namespace) -> int:
    """Show formal invariant changes between code versions."""
    from aeon.formal_diff import FormalDiffer

    differ = FormalDiffer()
    fmt = getattr(args, 'format', 'pretty')

    # Two files mode
    if getattr(args, 'file_a', None) and getattr(args, 'file_b', None):
        a_path, b_path = Path(args.file_a), Path(args.file_b)
        if not a_path.exists() or not b_path.exists():
            print("Error: one or both files not found")
            return 1
        ext = a_path.suffix.lower()
        from aeon.formal_diff import EXT_TO_LANG
        lang = EXT_TO_LANG.get(ext, "python")
        result = differ.diff_files(
            a_path.read_text(), b_path.read_text(), lang, str(a_path),
        )
        print(differ.format_diff(result, fmt))
        return 0

    # Branch mode
    if getattr(args, 'branch', None):
        result = differ.diff_branch(args.branch)
        print(differ.format_diff(result, fmt))
        return 0

    # Git commit mode
    commit_a = getattr(args, 'commit_a', None)
    commit_b = getattr(args, 'commit_b', None)
    if commit_a and commit_b:
        result = differ.diff_git(commit_a, commit_b)
        print(differ.format_diff(result, fmt))
        return 0

    # Default: staged changes
    result = differ.diff_staged()
    print(differ.format_diff(result, fmt))
    return 0


def cmd_ghost(args: argparse.Namespace) -> int:
    """Ghost-Assertion Shadowing — AI-inferred intent contracts."""
    from aeon.ghost import GhostAnalyzer

    analyzer = GhostAnalyzer()
    filepath = args.file

    if not os.path.exists(filepath):
        print(json.dumps({"error": f"File not found: {filepath}"}))
        return 1

    result = analyzer.analyze_file(filepath)
    fmt = getattr(args, 'format', 'pretty')

    if fmt == 'json':
        print(json.dumps([a.to_dict() for a in result], indent=2))
    else:
        if not result:
            print(f"No ghost assertions detected in {filepath}")
            return 0
        print(f"\n  Ghost Assertions — {filepath}")
        print(f"  {'=' * 50}")
        for ghost in result:
            status = "INTENT MATCH" if ghost.matches_code else "INTENT VIOLATION"
            print(f"\n  [{status}] {ghost.function}:{ghost.line}")
            print(f"  Ghost contract: {ghost.assertion}")
            print(f"  Confidence: {ghost.confidence:.0%}")
            if ghost.explanation:
                print(f"  {ghost.explanation}")
    return 0


def cmd_mcp_safety(args: argparse.Namespace) -> int:
    """Start AEON MCP safety server for AI agent verification."""
    from aeon.mcp_safety import AeonMCPServer

    server = AeonMCPServer()
    port = getattr(args, 'port', 8001)
    print(f"Starting AEON MCP Safety Server on port {port}...")
    print(f"AI agents can connect to verify tool calls before execution.")
    server.serve(port=port)
    return 0


def cmd_graveyard(args: argparse.Namespace) -> int:
    """Run AEON against famous historical bugs."""
    from aeon.graveyard import BugGraveyard

    graveyard = BugGraveyard()
    fmt = getattr(args, 'format', 'pretty')

    if getattr(args, 'bug', None):
        result = graveyard.analyze_bug(args.bug)
        print(graveyard.format_result(result, fmt))
    else:
        results = graveyard.analyze_all()
        print(graveyard.format_all(results, fmt))
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    """List available analysis profiles."""
    from aeon.profiles import list_profiles
    from aeon.formatters import bold, dim, cyan

    print(f"\n {bold('AEON Analysis Profiles')}")
    print(f" {dim('─' * 45)}")
    for p in list_profiles():
        print(f"   {cyan(p.name):20s} {p.description}")
    print(f"\n   Usage: aeon check app.py --profile <name>\n")
    return 0


def cmd_portfolio(args: argparse.Namespace) -> int:
    """Scan all projects in the portfolio."""
    from aeon.portfolio import (
        load_portfolio, scan_portfolio,
        format_portfolio_pretty, format_portfolio_summary,
    )

    config_path = getattr(args, 'config', None)
    project_filter = getattr(args, 'project', None)
    fmt = getattr(args, 'format', 'pretty')

    config = load_portfolio(config_path)
    if not config.projects:
        print("No projects found. Create ~/.aeon-portfolio.yml with your projects.")
        print("See: aeon portfolio --help")
        return 1

    if project_filter:
        aliases = [p.alias for p in config.projects]
        if project_filter.lower() not in [a.lower() for a in aliases]:
            print(f"Unknown project '{project_filter}'. Available: {', '.join(aliases)}")
            return 1

    quality = not getattr(args, 'raw', False)
    min_conf = getattr(args, 'min_confidence', 0.3)
    result = scan_portfolio(config, project_filter=project_filter,
                            quality_filter=quality, min_confidence=min_conf)

    if fmt == 'json':
        print(json.dumps(result.to_dict(), indent=2))
    elif fmt == 'summary':
        print(format_portfolio_summary(result))
    else:
        print(format_portfolio_pretty(result))

    return 0 if result.total_errors == 0 else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aeon",
        description="AEON — AI-Native Programming Language & Compiler",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # compile
    p_compile = subparsers.add_parser("compile", help="Compile AEON source to binary")
    p_compile.add_argument("file", help="AEON source file (.aeon)")
    p_compile.add_argument("-o", "--output", help="Output binary path")
    p_compile.add_argument("--verify", action="store_true", help="Enable Z3 contract verification")
    p_compile.add_argument("--termination", action="store_true", help="Enable P2 termination analysis")
    p_compile.add_argument("--memory", action="store_true", help="Enable P2 memory tracking")
    p_compile.add_argument("--deep-verify", action="store_true", dest="deep_verify", help="Enable ALL advanced analysis passes")
    p_compile.add_argument("--refinement-types", action="store_true", dest="refinement_types", help="Liquid type inference (Rondon et al. 2008)")
    p_compile.add_argument("--abstract-interp", action="store_true", dest="abstract_interp", help="Abstract interpretation (Cousot & Cousot 1977)")
    p_compile.add_argument("--size-change", action="store_true", dest="size_change", help="Size-change termination (Lee et al. 2001)")
    p_compile.add_argument("--hoare", action="store_true", help="Hoare logic / wp-calculus (Dijkstra 1975)")
    p_compile.add_argument("--algebraic-effects", action="store_true", dest="algebraic_effects", help="Algebraic effects with row polymorphism")
    p_compile.add_argument("--category", action="store_true", help="Category-theoretic semantics verification")
    p_compile.add_argument("--info-flow", action="store_true", dest="info_flow", help="Information flow / noninterference (Volpano et al. 1996)")
    p_compile.add_argument("--dependent-types", action="store_true", dest="dependent_types", help="Dependent types / Curry-Howard (Martin-Löf 1984)")
    p_compile.add_argument("--certified", action="store_true", help="Certified compilation (CompCert-style)")
    p_compile.add_argument("--symbolic", action="store_true", help="Symbolic execution (King 1976)")
    p_compile.add_argument("--separation-logic", action="store_true", dest="separation_logic", help="Separation logic / heap safety (Reynolds 2002)")
    p_compile.add_argument("--taint", action="store_true", help="Taint analysis / injection detection (Schwartz 2010)")
    p_compile.add_argument("--concurrency", action="store_true", help="Concurrency verification / race detection (Owicki & Gries 1976)")
    p_compile.add_argument("--shape", action="store_true", help="Shape analysis for linked structures (Sagiv et al. 2002)")
    p_compile.add_argument("--model-check", action="store_true", dest="model_check", help="Bounded model checking (Clarke et al. 1986)")
    # Cybersecurity engines
    p_compile.add_argument("--secret-detection", action="store_true", dest="secret_detection", help="Hardcoded secret/credential detection (CWE-798)")
    p_compile.add_argument("--auth-check", action="store_true", dest="auth_check", help="Auth & access control analysis (OWASP A01/A07)")
    p_compile.add_argument("--crypto-misuse", action="store_true", dest="crypto_misuse", help="Cryptographic misuse detection (CWE-327/330)")
    p_compile.add_argument("--injection-advanced", action="store_true", dest="injection_advanced", help="Advanced injection: SSTI, ReDoS, XXE, log/header injection")
    p_compile.add_argument("--api-security", action="store_true", dest="api_security", help="API security: CORS, headers, mass assignment, rate limiting")
    p_compile.add_argument("--supply-chain", action="store_true", dest="supply_chain", help="Supply chain: dynamic imports, unsafe deser, dependency confusion")
    p_compile.add_argument("--session-jwt", action="store_true", dest="session_jwt", help="Session & JWT: alg:none, cookie flags, session fixation")
    p_compile.add_argument("--container-security", action="store_true", dest="container_security", help="Container/IaC: Dockerfile, K8s, privilege escalation")
    p_compile.add_argument("--ssrf-advanced", action="store_true", dest="ssrf_advanced", help="Advanced SSRF: cloud metadata, DNS rebinding, protocol smuggling")
    p_compile.add_argument("--prototype-pollution", action="store_true", dest="prototype_pollution", help="Prototype pollution: deep merge, dynamic property assignment")
    p_compile.add_argument("--business-logic", action="store_true", dest="business_logic", help="Business logic: race conditions, double-spend, price manipulation")
    p_compile.add_argument("--data-exposure", action="store_true", dest="data_exposure", help="Data exposure: PII in logs, sensitive data in responses")
    p_compile.add_argument("--security-misconfig", action="store_true", dest="security_misconfig", help="Security misconfig: debug mode, default creds")
    p_compile.add_argument("--oauth-oidc", action="store_true", dest="oauth_oidc", help="OAuth/OIDC: missing PKCE, state param, token leakage")
    p_compile.add_argument("--file-upload", action="store_true", dest="file_upload", help="File upload: unrestricted types, path traversal")
    p_compile.add_argument("--input-validation", action="store_true", dest="input_validation", help="Input validation: length limits, type coercion, Unicode")
    p_compile.add_argument("--race-condition-security", action="store_true", dest="race_condition_security", help="Race conditions: TOCTOU, double-submit")
    p_compile.add_argument("--dependency-audit", action="store_true", dest="dependency_audit", help="Dependency audit: vulnerable patterns, deprecated APIs")
    p_compile.add_argument("--email-security", action="store_true", dest="email_security", help="Email: header injection, SMTP injection")
    p_compile.add_argument("--insecure-randomness", action="store_true", dest="insecure_randomness", help="Insecure randomness: UUID v1, weak seeds")
    p_compile.add_argument("--cache-poisoning", action="store_true", dest="cache_poisoning", help="Cache poisoning: unkeyed headers, cache deception")
    p_compile.add_argument("--http-smuggling", action="store_true", dest="http_smuggling", help="HTTP smuggling: CL/TE, raw HTTP, proxy risks")
    p_compile.set_defaults(func=cmd_compile)

    # check
    p_check = subparsers.add_parser("check", help="Verify source file (auto-detects language from extension)")
    p_check.add_argument("file", help="Source file (.aeon, .py, .java, .js, .ts, .go, .rs, .c, .cpp, .rb, .swift, .kt, .php, .scala, .dart)")
    p_check.add_argument("--language", choices=["aeon", "python", "java", "javascript", "typescript", "go", "rust", "c", "cpp", "ruby", "swift", "kotlin", "php", "scala", "dart"],
                         help="Override auto-detected language")
    p_check.add_argument("--profile", choices=["quick", "daily", "security", "performance", "construction", "cybersecurity", "safety"],
                         help="Analysis profile (quick|daily|security|performance|safety)")
    p_check.add_argument("--output-format", dest="output_format", choices=["pretty", "summary", "annotate", "markdown", "json"],
                         default="pretty", help="Output format (default: pretty)")
    p_check.add_argument("--explain", action="store_true", help="Show plain-English explanations for each issue")
    p_check.add_argument("--verify", action="store_true", help="Enable Z3 contract verification")
    p_check.add_argument("--termination", action="store_true", help="Enable P2 termination analysis")
    p_check.add_argument("--memory", action="store_true", help="Enable P2 memory tracking")
    p_check.add_argument("--deep-verify", action="store_true", dest="deep_verify", help="Enable ALL advanced analysis passes")
    p_check.add_argument("--refinement-types", action="store_true", dest="refinement_types", help="Liquid type inference")
    p_check.add_argument("--abstract-interp", action="store_true", dest="abstract_interp", help="Abstract interpretation")
    p_check.add_argument("--size-change", action="store_true", dest="size_change", help="Size-change termination")
    p_check.add_argument("--hoare", action="store_true", help="Hoare logic verification")
    p_check.add_argument("--algebraic-effects", action="store_true", dest="algebraic_effects", help="Algebraic effect analysis")
    p_check.add_argument("--category", action="store_true", help="Category semantics check")
    p_check.add_argument("--info-flow", action="store_true", dest="info_flow", help="Information flow analysis")
    p_check.add_argument("--dependent-types", action="store_true", dest="dependent_types", help="Dependent types / Curry-Howard")
    p_check.add_argument("--certified", action="store_true", help="Certified compilation checks")
    p_check.add_argument("--symbolic", action="store_true", help="Symbolic execution")
    p_check.add_argument("--separation-logic", action="store_true", dest="separation_logic", help="Separation logic / heap safety")
    p_check.add_argument("--taint", action="store_true", help="Taint analysis / injection detection")
    p_check.add_argument("--concurrency", action="store_true", help="Concurrency / race detection")
    p_check.add_argument("--shape", action="store_true", help="Shape analysis for linked structures")
    p_check.add_argument("--model-check", action="store_true", dest="model_check", help="Bounded model checking")
    # Cybersecurity engines
    p_check.add_argument("--secret-detection", action="store_true", dest="secret_detection", help="Hardcoded secret/credential detection (CWE-798)")
    p_check.add_argument("--auth-check", action="store_true", dest="auth_check", help="Auth & access control (OWASP A01/A07)")
    p_check.add_argument("--crypto-misuse", action="store_true", dest="crypto_misuse", help="Cryptographic misuse (CWE-327/330)")
    p_check.add_argument("--injection-advanced", action="store_true", dest="injection_advanced", help="Advanced injection: SSTI, ReDoS, XXE")
    p_check.add_argument("--api-security", action="store_true", dest="api_security", help="API security: CORS, headers, mass assignment")
    p_check.add_argument("--supply-chain", action="store_true", dest="supply_chain", help="Supply chain: dynamic imports, unsafe deser")
    p_check.add_argument("--session-jwt", action="store_true", dest="session_jwt", help="Session & JWT security")
    p_check.add_argument("--container-security", action="store_true", dest="container_security", help="Container/IaC security")
    p_check.add_argument("--ssrf-advanced", action="store_true", dest="ssrf_advanced", help="Advanced SSRF analysis")
    p_check.add_argument("--prototype-pollution", action="store_true", dest="prototype_pollution", help="Prototype pollution detection")
    p_check.add_argument("--business-logic", action="store_true", dest="business_logic", help="Business logic security")
    p_check.add_argument("--data-exposure", action="store_true", dest="data_exposure", help="Data exposure & privacy")
    p_check.add_argument("--security-misconfig", action="store_true", dest="security_misconfig", help="Security misconfiguration")
    p_check.add_argument("--oauth-oidc", action="store_true", dest="oauth_oidc", help="OAuth/OIDC security")
    p_check.add_argument("--file-upload", action="store_true", dest="file_upload", help="File upload security")
    p_check.add_argument("--input-validation", action="store_true", dest="input_validation", help="Input validation deep")
    p_check.add_argument("--race-condition-security", action="store_true", dest="race_condition_security", help="Race condition security")
    p_check.add_argument("--dependency-audit", action="store_true", dest="dependency_audit", help="Dependency audit")
    p_check.add_argument("--email-security", action="store_true", dest="email_security", help="Email security")
    p_check.add_argument("--insecure-randomness", action="store_true", dest="insecure_randomness", help="Insecure randomness deep")
    p_check.add_argument("--cache-poisoning", action="store_true", dest="cache_poisoning", help="Web cache poisoning")
    p_check.add_argument("--http-smuggling", action="store_true", dest="http_smuggling", help="HTTP request smuggling")
    p_check.add_argument("--proof-trace", action="store_true", dest="proof_trace",
                         help="Emit proof obligations table (Hoare VCs, solver results)")
    p_check.add_argument("--emit-witnesses", action="store_true", dest="emit_witnesses",
                         help="Write counterexample witnesses to <file>.witnesses.json")
    p_check.set_defaults(func=cmd_check)

    # fix
    p_fix = subparsers.add_parser("fix", help="Auto-fix detected issues in source files")
    p_fix.add_argument("target", help="File or directory to fix")
    p_fix.add_argument("--dry-run", action="store_true", dest="dry_run", help="Show proposed fixes without applying")
    p_fix.add_argument("--type", choices=["security", "correctness", "safety", "style"],
                       help="Only fix issues of this category")
    p_fix.add_argument("--min-confidence", type=float, default=0.5, dest="min_confidence",
                       help="Minimum confidence threshold (0.0-1.0, default: 0.5)")
    p_fix.add_argument("--deep-verify", action="store_true", dest="deep_verify", help="Enable ALL analysis engines")
    p_fix.set_defaults(func=cmd_fix)

    # review
    p_review = subparsers.add_parser("review", help="AI-powered code review")
    p_review.add_argument("target", nargs="?", default=None, help="File or directory to review")
    p_review.add_argument("--diff", default=None, help="Git diff ref to review (e.g. HEAD~1)")
    p_review.add_argument("--format", choices=["pretty", "markdown", "json"], default="pretty",
                          help="Output format (default: pretty)")
    p_review.add_argument("--deep-verify", action="store_true", dest="deep_verify", help="Enable ALL analysis engines")
    p_review.set_defaults(func=cmd_review)

    # explain
    p_explain = subparsers.add_parser("explain", help="Plain-English bug explanations with fix suggestions")
    p_explain.add_argument("file", help="Source file to explain issues for")
    p_explain.add_argument("--deep-verify", action="store_true", dest="deep_verify", help="Enable ALL analysis engines")
    p_explain.set_defaults(func=cmd_explain)

    # init
    p_init = subparsers.add_parser("init", help="Project setup wizard — create .aeonrc.yml and configure AEON")
    p_init.add_argument("directory", nargs="?", default=".", help="Project directory (default: current)")
    p_init.add_argument("--profile", choices=["quick", "daily", "security", "performance", "construction", "cybersecurity", "safety"],
                        help="Set analysis profile")
    p_init.add_argument("--ci", action="store_true", help="Generate GitHub Actions workflow")
    p_init.set_defaults(func=cmd_init)

    # abstract-trace
    p_abstract_trace = subparsers.add_parser(
        "abstract-trace",
        help="Emit per-statement abstract domain states (interval/sign/congruence) for teaching",
    )
    p_abstract_trace.add_argument("file", help="AEON source file (.aeon)")
    p_abstract_trace.add_argument(
        "--format", choices=["pretty", "json"], default="pretty",
        help="Output format (default: pretty ASCII table)",
    )
    p_abstract_trace.set_defaults(func=cmd_abstract_trace)

    # proof-trace
    p_proof_trace = subparsers.add_parser(
        "proof-trace",
        help="Emit Hoare-logic proof obligations with VC formulas and Z3 results",
    )
    p_proof_trace.add_argument("file", help="AEON source file (.aeon)")
    p_proof_trace.add_argument(
        "--format", choices=["pretty", "json", "smtlib2", "latex"], default="pretty",
        help="Output format (default: pretty)",
    )
    p_proof_trace.add_argument(
        "--emit-witnesses", action="store_true", dest="emit_witnesses",
        help="Write counterexample witnesses to <file>.witnesses.json",
    )
    p_proof_trace.set_defaults(func=cmd_proof_trace)

    # profiles
    p_profiles = subparsers.add_parser("profiles", help="List available analysis profiles")
    p_profiles.set_defaults(func=cmd_profiles)

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan and verify an entire directory")
    p_scan.add_argument("directory", help="Directory to scan recursively")
    p_scan.add_argument("--deep-verify", action="store_true", dest="deep_verify", help="Enable ALL analysis engines")
    p_scan.add_argument("--parallel", action="store_true", help="Use multiprocess parallel scanning")
    p_scan.add_argument("--workers", type=int, default=0, help="Number of parallel workers (0=auto)")
    p_scan.add_argument("--profile", choices=["quick", "daily", "security", "performance", "construction", "cybersecurity", "safety"],
                        help="Analysis profile (quick|daily|security|performance|safety|ui)")
    p_scan.add_argument("--ui-lint", action="store_true", dest="ui_lint",
                        help="Enable UI/UX lint engine (design, a11y, UX anti-patterns)")
    p_scan.add_argument("--ai", action="store_true", dest="ai_intent",
                        help="Enable AI intent analysis (requires ANTHROPIC_API_KEY)")
    p_scan.add_argument("--no-cross-file", action="store_true", dest="no_cross_file",
                        help="Disable cross-file analysis")
    p_scan.add_argument("--analyses", nargs="+", help="Specific analyses to run (e.g. taint info-flow concurrency complexity termination memory)")
    p_scan.add_argument("--format", choices=["text", "json", "sarif", "markdown", "pretty"], default="pretty", help="Output format")
    p_scan.add_argument("--output", "-o", default="", help="Output file path (default: stdout)")
    p_scan.add_argument("--baseline", default="", help="Baseline file for diff mode")
    p_scan.add_argument("--create-baseline", action="store_true", dest="create_baseline", help="Create a baseline from current results")
    p_scan.add_argument("--raw", action="store_true", help="Disable smart filtering — show all raw findings without confidence scoring or dedup")
    p_scan.add_argument("--min-confidence", type=float, default=0.3, dest="min_confidence", help="Min confidence threshold (0.0-1.0, default: 0.3)")
    p_scan.add_argument("--top", type=int, default=0, help="Only show top N findings by impact score")
    p_scan.set_defaults(func=cmd_scan)

    # watch
    p_watch = subparsers.add_parser("watch", help="Watch directory and re-verify on changes")
    p_watch.add_argument("directory", help="Directory to watch")
    p_watch.add_argument("--deep-verify", action="store_true", dest="deep_verify", help="Enable ALL analysis engines")
    p_watch.set_defaults(func=cmd_watch)

    # ir
    p_ir = subparsers.add_parser("ir", help="Emit flat IR as JSON")
    p_ir.add_argument("file", help="AEON source file (.aeon)")
    p_ir.set_defaults(func=cmd_ir)

    # test
    p_test = subparsers.add_parser("test", help="Run test suite")
    p_test.add_argument("--all", action="store_true", help="Run all tests")
    p_test.add_argument("--priority", choices=["P0", "P1", "P2"], help="Filter by priority")
    p_test.add_argument("--category", choices=["compiler", "perf", "ai"], help="Filter by category")
    p_test.set_defaults(func=cmd_test)

    # synthesize
    p_synth = subparsers.add_parser("synthesize", help="Generate provably correct code from specifications")
    p_synth.add_argument("file", nargs="?", help="AEON spec file (.aeon)")
    p_synth.add_argument("--spec", "-s", help="Natural language specification")
    p_synth.add_argument("--language", "-l", default="python", help="Target language (default: python)")
    p_synth.add_argument("--verbose", "-v", action="store_true", help="Show alternative implementations")
    p_synth.add_argument("--list-templates", action="store_true", dest="list_templates", help="List available synthesis templates")
    p_synth.set_defaults(func=cmd_synthesize)

    # seal
    p_seal = subparsers.add_parser("seal", help="Generate proof-carrying seal for verified code")
    p_seal.add_argument("file", help="Source file to seal")
    p_seal.add_argument("--embed", action="store_true", help="Embed seal comment in source file")
    p_seal.set_defaults(func=cmd_seal)

    # verify-seal
    p_vseal = subparsers.add_parser("verify-seal", help="Verify an existing proof seal")
    p_vseal.add_argument("file", help="Source file to verify seal for")
    p_vseal.add_argument("--seal-file", dest="seal_file", help="Path to .aeon-seal file (auto-detected by default)")
    p_vseal.set_defaults(func=cmd_verify_seal)

    # harden
    p_harden = subparsers.add_parser("harden", help="Gradually harden codebase with verified contracts")
    p_harden.add_argument("target", help="File or directory to harden")
    p_harden.add_argument("--function", "-f", help="Harden a specific function")
    p_harden.add_argument("--phase", choices=["critical", "high", "medium", "low"], help="Apply specific phase")
    p_harden.add_argument("--report", action="store_true", help="Generate markdown report")
    p_harden.add_argument("--apply", action="store_true", help="Apply hardening (add contracts)")
    p_harden.add_argument("--dry-run", action="store_true", dest="dry_run", help="Show changes without applying")
    p_harden.set_defaults(func=cmd_harden)

    # autopsy
    p_autopsy = subparsers.add_parser("autopsy", help="Analyze incidents and generate protective contracts")
    p_autopsy.add_argument("file", nargs="?", help="Log or stack trace file")
    p_autopsy.add_argument("--stdin", action="store_true", help="Read from stdin")
    p_autopsy.add_argument("--source-root", dest="source_root", help="Source root for tracing to code")
    p_autopsy.add_argument("--output", choices=["report", "contracts", "tests"], default="report",
                           help="Output type (default: report)")
    p_autopsy.add_argument("--apply", action="store_true", help="Apply contracts to source files")
    p_autopsy.set_defaults(func=cmd_autopsy)

    # formal-diff
    p_fdiff = subparsers.add_parser("formal-diff", help="Show invariant changes between code versions")
    p_fdiff.add_argument("file_a", nargs="?", help="First file or git commit")
    p_fdiff.add_argument("file_b", nargs="?", help="Second file or git commit")
    p_fdiff.add_argument("--branch", "-b", help="Diff against branch (default: main)")
    p_fdiff.add_argument("--format", choices=["pretty", "json", "markdown"], default="pretty",
                         help="Output format (default: pretty)")
    p_fdiff.set_defaults(func=cmd_formal_diff)

    # ghost
    p_ghost = subparsers.add_parser("ghost", help="Ghost-Assertion Shadowing — detect intent violations")
    p_ghost.add_argument("file", help="Source file to analyze")
    p_ghost.add_argument("--format", choices=["pretty", "json"], default="pretty", help="Output format")
    p_ghost.set_defaults(func=cmd_ghost)

    # mcp-safety
    p_mcp = subparsers.add_parser("mcp-safety", help="Start AEON MCP safety server for AI agent verification")
    p_mcp.add_argument("--port", type=int, default=8001, help="Server port (default: 8001)")
    p_mcp.set_defaults(func=cmd_mcp_safety)

    # graveyard
    p_grave = subparsers.add_parser("graveyard", help="Analyze famous historical bugs with AEON")
    p_grave.add_argument("--bug", help="Specific bug to analyze (e.g. heartbleed, log4shell)")
    p_grave.add_argument("--format", choices=["pretty", "json", "markdown"], default="pretty",
                         help="Output format")
    p_grave.set_defaults(func=cmd_graveyard)

    # portfolio
    p_portfolio = subparsers.add_parser("portfolio", help="Scan all projects defined in ~/.aeon-portfolio.yml")
    p_portfolio.add_argument("--project", "-p", help="Only scan this project alias")
    p_portfolio.add_argument("--format", choices=["pretty", "summary", "json"], default="pretty",
                             help="Output format (default: pretty)")
    p_portfolio.add_argument("--config", help="Path to portfolio config file")
    p_portfolio.add_argument("--raw", action="store_true", help="Disable smart filtering — show all raw findings")
    p_portfolio.add_argument("--min-confidence", type=float, default=0.3, dest="min_confidence", help="Min confidence (0.0-1.0)")
    p_portfolio.set_defaults(func=cmd_portfolio)

    # self-heal health report
    p_health = subparsers.add_parser("health", help="Show self-healing telemetry and engine crash trends")
    p_health.set_defaults(func=lambda args: (print(__import__('aeon.self_heal', fromlist=['get_health_report']).get_health_report()), 0)[1])

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
