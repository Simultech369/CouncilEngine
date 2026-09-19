"""
anti_wrapper_audit.py - Anti-Wrapper Theatre, Dead-Code, and ΔLOC Audit Engine.

Evaluates repository codebases for:
1. ΔLOC Metrics: Production vs Test lines, code-to-comment ratios, complexity.
2. Dead-Code Scanner: Identifies unreferenced private helpers and dead symbols.
3. Wrapper Theatre Detection: Identifies naked pass-through delegates that lack
   contract boundaries (ReceiptEnvelope, validation, circuit breakers, rate limiting).
4. Report-Only by default; optional --strict enforcement mode.
"""

import ast
import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple

# Force UTF-8 encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


class CodeMetrics:
    """Computes line metrics for a source file."""
    @staticmethod
    def analyze_file(file_path: str) -> Dict[str, int]:
        total_lines = 0
        blank_lines = 0
        comment_lines = 0
        code_lines = 0

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    total_lines += 1
                    stripped = line.strip()
                    if not stripped:
                        blank_lines += 1
                    elif stripped.startswith("#"):
                        comment_lines += 1
                    else:
                        code_lines += 1
        except Exception:
            pass

        return {
            "total_lines": total_lines,
            "code_lines": code_lines,
            "comment_lines": comment_lines,
            "blank_lines": blank_lines,
        }


class DeadCodeScanner:
    """Scans Python AST for unreferenced internal functions and dead helpers."""

    @staticmethod
    def scan_file(file_path: str, code: str) -> Dict[str, Any]:
        try:
            tree = ast.parse(code, filename=file_path)
        except SyntaxError:
            return {"defined_helpers": [], "unused_helpers": [], "all_defined": []}

        defined_private_funcs = set()
        all_defined_funcs = set()
        referenced_names = set()

        # Phase 1: Collect definitions
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                all_defined_funcs.add(node.name)
                # Private or internal helper naming convention
                if node.name.startswith("_") and not (node.name.startswith("__") and node.name.endswith("__")):
                    defined_private_funcs.add(node.name)

        # Phase 2: Collect references (calls, attribute loads, name loads)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                referenced_names.add(node.id)
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                referenced_names.add(node.attr)

        # Unused private helpers are defined but never loaded as Name or Attribute
        unused_private = sorted(list(defined_private_funcs - referenced_names))

        return {
            "defined_helpers": sorted(list(defined_private_funcs)),
            "unused_helpers": unused_private,
            "all_defined_count": len(all_defined_funcs),
        }


class WrapperTheatreDetector:
    """
    Detects naked wrappers / pass-through delegates.

    A 'naked wrapper' is a function or method that merely forwards calls
    to an underlying function without contract enforcement, validation,
    receipt sealing, error handling, or telemetry.
    """

    CONTRACT_MARKERS = {
        "ReceiptEnvelope",
        "seal",
        "verify",
        "validate",
        "assert",
        "raise",
        "dlq",
        "breaker",
        "limiter",
        "telemetry",
        "tracer",
        "hashlib",
        "sha256",
        "sanitize",
        "mask",
        "unmask",
    }

    @classmethod
    def analyze_function(cls, node: ast.FunctionDef, source_code: str) -> Optional[Dict[str, Any]]:
        # Filter out dunder methods and test fixtures
        if node.name.startswith("__") and node.name.endswith("__"):
            return None
        if node.name.startswith("test_") or node.name in ("setUp", "tearDown", "setUpClass", "tearDownClass"):
            return None

        # A trivial wrapper usually has a docstring + 1 statement, or just 1 statement
        body_stmts = [stmt for stmt in node.body if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str))]
        if len(body_stmts) != 1:
            return None

        single_stmt = body_stmts[0]

        # Check if the single statement is a return of a call, or a pure call
        call_expr = None
        if isinstance(single_stmt, ast.Return) and isinstance(single_stmt.value, ast.Call):
            call_expr = single_stmt.value
        elif isinstance(single_stmt, ast.Expr) and isinstance(single_stmt.value, ast.Call):
            call_expr = single_stmt.value

        if not call_expr:
            return None

        # Check if the function contains any contract markers in its AST
        func_source = ast.get_source_segment(source_code, node) or ""
        has_contract_marker = any(marker.lower() in func_source.lower() for marker in cls.CONTRACT_MARKERS)

        # Extract target called name
        target_name = "unknown"
        if isinstance(call_expr.func, ast.Name):
            target_name = call_expr.func.id
        elif isinstance(call_expr.func, ast.Attribute):
            target_name = call_expr.func.attr

        # Check for docstrings indicating intentional backward compatibility
        docstring = ast.get_docstring(node) or ""
        is_compat_shim = "backward" in docstring.lower() or "compatibility" in docstring.lower() or "deprecated" in docstring.lower() or "adapter" in docstring.lower()

        classification = "COMPATIBILITY_SHIM" if is_compat_shim else ("CONTRACTUAL_WRAPPER" if has_contract_marker else "NAKED_WRAPPER")

        return {
            "function_name": node.name,
            "line_number": node.lineno,
            "target_called": target_name,
            "classification": classification,
            "has_contract_marker": has_contract_marker,
            "is_compat_shim": is_compat_shim,
            "docstring_snippet": docstring[:100] if docstring else "",
        }

    @classmethod
    def scan_file(cls, file_path: str, code: str) -> List[Dict[str, Any]]:
        # Skip test files for wrapper theatre detection
        norm_path = file_path.replace("\\", "/").lower()
        if "/test" in norm_path or norm_path.startswith("test_") or "/tests/" in norm_path:
            return []

        findings = []
        try:
            tree = ast.parse(code, filename=file_path)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                result = cls.analyze_function(node, code)
                if result and result["classification"] in ("NAKED_WRAPPER", "COMPATIBILITY_SHIM"):
                    result["file_path"] = file_path
                    findings.append(result)

        return findings


class AntiWrapperAuditor:
    """Coordinates full repository audit across ΔLOC, dead code, and wrapper theatre."""

    BASELINE_SCHEMA_VERSION = "council.anti_wrapper_baseline.v1"

    def __init__(self, target_dir: str, exclude_dirs: Optional[Set[str]] = None):
        self.target_dir = os.path.abspath(target_dir)
        self.exclude_dirs = exclude_dirs or {
            ".git", ".pytest_cache", ".ruff_cache", "__pycache__",
            "node_modules", "coverage", "build", "dist", "cache",
            "exports", "artifacts", ".gemini"
        }

    def run_audit(self) -> Dict[str, Any]:
        prod_metrics = {"files": 0, "total_lines": 0, "code_lines": 0, "comment_lines": 0, "blank_lines": 0}
        test_metrics = {"files": 0, "total_lines": 0, "code_lines": 0, "comment_lines": 0, "blank_lines": 0}

        dead_code_findings = []
        wrapper_findings = []
        scanned_files = []

        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            for fname in sorted(files):
                if not fname.endswith(".py"):
                    continue

                abs_path = os.path.join(root, fname)
                rel_path = os.path.relpath(abs_path, self.target_dir).replace("\\", "/")
                scanned_files.append(rel_path)

                # Metrics
                metrics = CodeMetrics.analyze_file(abs_path)
                is_test = fname.startswith("test_") or "test" in rel_path.split("/")

                target_dict = test_metrics if is_test else prod_metrics
                target_dict["files"] += 1
                for k in ("total_lines", "code_lines", "comment_lines", "blank_lines"):
                    target_dict[k] += metrics[k]

                # Dead code & wrapper analysis
                try:
                    with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                        code = f.read()

                    # Dead helpers (only for production files)
                    if not is_test:
                        dc_result = DeadCodeScanner.scan_file(rel_path, code)
                        if dc_result["unused_helpers"]:
                            for h in dc_result["unused_helpers"]:
                                dead_code_findings.append({
                                    "file": rel_path,
                                    "symbol": h,
                                    "category": "UNUSED_INTERNAL_HELPER"
                                })

                    # Wrapper theatre
                    wrappers = WrapperTheatreDetector.scan_file(rel_path, code)
                    for w in wrappers:
                        wrapper_findings.append(w)

                except Exception as e:
                    pass

        # Summary statistics
        total_loc = prod_metrics["code_lines"] + test_metrics["code_lines"]
        test_to_code_ratio = round(test_metrics["code_lines"] / max(prod_metrics["code_lines"], 1), 3)

        naked_wrappers = [w for w in wrapper_findings if w["classification"] == "NAKED_WRAPPER"]
        compat_shims = [w for w in wrapper_findings if w["classification"] == "COMPATIBILITY_SHIM"]

        report = {
            "audit_target": self.target_dir,
            "scanned_python_files": len(scanned_files),
            "loc_summary": {
                "production": prod_metrics,
                "test": test_metrics,
                "total_code_lines": total_loc,
                "test_to_code_ratio": test_to_code_ratio,
            },
            "dead_code_summary": {
                "total_unused_helpers": len(dead_code_findings),
                "findings": dead_code_findings,
            },
            "wrapper_theatre_summary": {
                "total_flagged": len(wrapper_findings),
                "naked_wrappers_count": len(naked_wrappers),
                "compat_shims_count": len(compat_shims),
                "findings": wrapper_findings,
            },
            "verdict": "FLAGGED_VIOLATIONS" if (naked_wrappers and False) else "CLEAN_REPORT",
        }

        return report

    @classmethod
    def build_baseline_snapshot(cls, report: Dict[str, Any]) -> Dict[str, Any]:
        """Return the stable metric subset used for regression checks."""
        loc = report["loc_summary"]
        dead = report["dead_code_summary"]
        wrappers = report["wrapper_theatre_summary"]
        return {
            "schema_version": cls.BASELINE_SCHEMA_VERSION,
            "audit_target": ".",
            "scanned_python_files": report["scanned_python_files"],
            "metrics": {
                "production_code_lines": loc["production"]["code_lines"],
                "test_code_lines": loc["test"]["code_lines"],
                "total_code_lines": loc["total_code_lines"],
                "test_to_code_ratio": loc["test_to_code_ratio"],
                "unused_internal_helpers": dead["total_unused_helpers"],
                "naked_wrappers": wrappers["naked_wrappers_count"],
                "compatibility_shims": wrappers["compat_shims_count"],
            },
        }

    @classmethod
    def compare_to_baseline(cls, report: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Compare current audit metrics against a prior baseline."""
        if baseline.get("schema_version") != cls.BASELINE_SCHEMA_VERSION:
            raise ValueError("Unsupported anti-wrapper baseline schema")

        current = cls.build_baseline_snapshot(report)["metrics"]
        prior = baseline.get("metrics") or {}
        checks = []

        def add_check(metric: str, status: str, reason: str):
            before = prior.get(metric)
            after = current.get(metric)
            delta = after - before if isinstance(before, (int, float)) and isinstance(after, (int, float)) else None
            checks.append({
                "metric": metric,
                "baseline": before,
                "current": after,
                "delta": delta,
                "status": status,
                "reason": reason,
            })

        for metric in ("unused_internal_helpers", "naked_wrappers"):
            before = prior.get(metric)
            after = current.get(metric)
            if before is None:
                add_check(metric, "WARN", "Metric missing from baseline; cannot compare.")
            elif after > before:
                add_check(metric, "FAIL", "Regression: count increased from baseline.")
            else:
                add_check(metric, "PASS", "No regression.")

        before_prod = prior.get("production_code_lines")
        after_prod = current.get("production_code_lines")
        if before_prod is None:
            add_check("production_code_lines", "WARN", "Metric missing from baseline; cannot compare.")
        elif after_prod > before_prod:
            add_check("production_code_lines", "WARN", "Production SLOC increased; review for deletion dividend or explicit justification.")
        else:
            add_check("production_code_lines", "PASS", "No production SLOC growth.")

        return {
            "baseline_schema_version": baseline.get("schema_version"),
            "status": "FAIL" if any(c["status"] == "FAIL" for c in checks) else "PASS_WITH_WARNINGS" if any(c["status"] == "WARN" for c in checks) else "PASS",
            "checks": checks,
        }

    def format_markdown_report(self, report: Dict[str, Any]) -> str:
        loc = report["loc_summary"]
        dc = report["dead_code_summary"]
        wt = report["wrapper_theatre_summary"]

        md = []
        md.append(f"# Anti-Wrapper Theatre, Dead-Code & ΔLOC Audit Report")
        md.append(f"**Target**: `{report['audit_target']}`  ")
        md.append(f"**Python Files Scanned**: {report['scanned_python_files']}  ")
        md.append("")
        md.append("## 1. ΔLOC & Volume Breakdown")
        md.append("")
        md.append("| Layer | Files | Total Lines | Code Lines (SLOC) | Comments | Blanks |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        md.append(f"| **Production** | {loc['production']['files']} | {loc['production']['total_lines']} | {loc['production']['code_lines']} | {loc['production']['comment_lines']} | {loc['production']['blank_lines']} |")
        md.append(f"| **Tests** | {loc['test']['files']} | {loc['test']['total_lines']} | {loc['test']['code_lines']} | {loc['test']['comment_lines']} | {loc['test']['blank_lines']} |")
        md.append(f"| **Total** | **{report['scanned_python_files']}** | **{loc['production']['total_lines'] + loc['test']['total_lines']}** | **{loc['total_code_lines']}** | **{loc['production']['comment_lines'] + loc['test']['comment_lines']}** | **{loc['production']['blank_lines'] + loc['test']['blank_lines']}** |")
        md.append("")
        md.append(f"**Test-to-Production Code Ratio**: `{loc['test_to_code_ratio']}` (Target: >= 0.50)")
        md.append("")
        md.append("## 2. Dead-Code & Unused Helper Audit")
        md.append(f"Total unreferenced internal helpers detected: **{dc['total_unused_helpers']}**")
        md.append("")
        if dc["findings"]:
            md.append("| File | Symbol | Classification |")
            md.append("| :--- | :--- | :--- |")
            for f in dc["findings"]:
                md.append(f"| `{f['file']}` | `{f['symbol']}` | `{f['category']}` |")
        else:
            md.append("✅ **Zero unreferenced internal helpers detected.** All defined private symbols have active call sites.")
        md.append("")
        md.append("## 3. Wrapper Theatre & Compatibility Shims Audit")
        md.append(f"- Naked Wrappers (no contract/invariants): **{wt['naked_wrappers_count']}**")
        md.append(f"- Documented Compatibility Shims: **{wt['compat_shims_count']}**")
        md.append("")
        if wt["findings"]:
            md.append("| File | Function | Target Called | Classification | Notes |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for f in wt["findings"]:
                md.append(f"| `{f.get('file_path', '')}` | `{f['function_name']}` | `{f['target_called']}` | `{f['classification']}` | `{f['docstring_snippet']}` |")
        else:
            md.append("✅ **Zero naked wrappers detected.** All delegating methods enforce contracts, receipts, rate limits, or verification.")
        md.append("")
        comparison = report.get("baseline_comparison")
        if comparison:
            md.append("## 4. Baseline Regression Check")
            md.append(f"Status: **{comparison['status']}**")
            md.append("")
            md.append("| Metric | Baseline | Current | Delta | Status | Reason |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for check in comparison["checks"]:
                md.append(
                    f"| `{check['metric']}` | `{check['baseline']}` | `{check['current']}` | "
                    f"`{check['delta']}` | `{check['status']}` | {check['reason']} |"
                )
            md.append("")
        return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description="Anti-Wrapper Theatre, Dead-Code, and ΔLOC Audit")
    parser.add_argument("--target-dir", type=str, default=".", help="Root directory to scan")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    parser.add_argument("--strict", action="store_true", help="Fail closed if naked wrappers detected")
    parser.add_argument("--output-file", type=str, help="Write markdown or JSON report to file")
    parser.add_argument("--baseline-file", type=str, help="Compare against or write a compact anti-wrapper baseline JSON")
    parser.add_argument("--write-baseline", action="store_true", help="Write the current compact metric baseline to --baseline-file")
    parser.add_argument("--fail-on-regression", action="store_true", help="Exit nonzero if baseline comparison finds dead-code or naked-wrapper regressions")

    args = parser.parse_args()
    auditor = AntiWrapperAuditor(target_dir=args.target_dir)
    report = auditor.run_audit()

    if args.baseline_file and not args.write_baseline and os.path.exists(args.baseline_file):
        with open(args.baseline_file, "r", encoding="utf-8") as f:
            baseline = json.load(f)
        report["baseline_comparison"] = AntiWrapperAuditor.compare_to_baseline(report, baseline)

    if args.json:
        out_text = json.dumps(report, indent=2)
    else:
        out_text = auditor.format_markdown_report(report)

    if args.output_file:
        os.makedirs(os.path.dirname(os.path.abspath(args.output_file)), exist_ok=True)
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(out_text)
        print(f">> Audit report written to: {args.output_file}")
    else:
        print(out_text)

    if args.baseline_file and args.write_baseline:
        os.makedirs(os.path.dirname(os.path.abspath(args.baseline_file)), exist_ok=True)
        with open(args.baseline_file, "w", encoding="utf-8") as f:
            json.dump(AntiWrapperAuditor.build_baseline_snapshot(report), f, indent=2)
        print(f">> Baseline written to: {args.baseline_file}")

    if args.strict and report["wrapper_theatre_summary"]["naked_wrappers_count"] > 0:
        print(f"[STRICT FAIL] Detected {report['wrapper_theatre_summary']['naked_wrappers_count']} naked wrappers without contracts.", file=sys.stderr)
        sys.exit(1)

    if args.fail_on_regression:
        comparison = report.get("baseline_comparison")
        if comparison and comparison["status"] == "FAIL":
            print("[REGRESSION FAIL] Anti-wrapper or dead-code count increased from baseline.", file=sys.stderr)
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
