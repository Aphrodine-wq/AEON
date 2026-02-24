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


def cmd_compile(args: argparse.Namespace) -> int:
    """Compile an AEON source file through all 3 passes."""
    source_path = args.file
    if not os.path.exists(source_path):
        print(json.dumps({"error": f"File not found: {source_path}"}))
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
    if not os.path.exists(source_path):
        print(json.dumps({"error": f"File not found: {source_path}"}))
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
        result = lang_verify(source, language, deep_verify=args.deep_verify)
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

    from aeon.config import load_config
    config = load_config(start_dir=target)

    deep = args.deep_verify or config.deep_verify
    use_parallel = args.parallel or config.parallel
    workers = getattr(args, 'workers', 0) or config.parallel_workers

    if use_parallel:
        from aeon.parallel import parallel_scan
        result = parallel_scan(target, deep_verify=deep, workers=workers)
    else:
        from aeon.scanner import scan_directory
        result = scan_directory(target, deep_verify=deep)

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
    p_compile.set_defaults(func=cmd_compile)

    # check
    p_check = subparsers.add_parser("check", help="Verify source file (auto-detects language from extension)")
    p_check.add_argument("file", help="Source file (.aeon, .py, .java, .js, .ts, .go, .rs, .c, .cpp, .rb, .swift, .kt, .php, .scala, .dart)")
    p_check.add_argument("--language", choices=["aeon", "python", "java", "javascript", "typescript", "go", "rust", "c", "cpp", "ruby", "swift", "kotlin", "php", "scala", "dart"],
                         help="Override auto-detected language")
    p_check.add_argument("--profile", choices=["quick", "daily", "security", "performance", "safety"],
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
    p_init.add_argument("--profile", choices=["quick", "daily", "security", "performance", "safety"],
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
    p_scan.add_argument("--profile", choices=["quick", "daily", "security", "performance", "safety"],
                        help="Analysis profile (quick|daily|security|performance|safety)")
    p_scan.add_argument("--analyses", nargs="+", help="Specific analyses to run (e.g. taint info-flow concurrency complexity termination memory)")
    p_scan.add_argument("--format", choices=["text", "json", "sarif", "markdown", "pretty"], default="pretty", help="Output format")
    p_scan.add_argument("--output", "-o", default="", help="Output file path (default: stdout)")
    p_scan.add_argument("--baseline", default="", help="Baseline file for diff mode")
    p_scan.add_argument("--create-baseline", action="store_true", dest="create_baseline", help="Create a baseline from current results")
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

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
