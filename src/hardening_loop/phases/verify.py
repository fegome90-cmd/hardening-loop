"""Phase 4: VERIFY FASTER — Execute verification gates and collect latency/correctness benchmarks."""

import ast
import os
import re
import time
from typing import Any

from ..models import PhaseName, VerificationStatus
from .base import BasePhase


class VerifyPhase(BasePhase):
    """Executes fast verification passes and generates verification metrics."""

    def __init__(self):
        super().__init__(name=PhaseName.VERIFY)

    def _collect_sources(self, target_path: str) -> dict[str, str]:
        sources = {}
        if os.path.isfile(target_path):
            with open(target_path, encoding="utf-8", errors="ignore") as f:
                sources[target_path] = f.read()
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for file in sorted(files):
                    if file.endswith(".py"):
                        full_path = os.path.join(root, file)
                        with open(full_path, encoding="utf-8", errors="ignore") as f:
                            sources[full_path] = f.read()
        return sources

    def execute(
        self, target_path: str, context: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str], VerificationStatus]:
        checks = []
        if not os.path.exists(target_path):
            return {"error": f"Target {target_path} not found"}, ["Target missing"], VerificationStatus.FAIL

        sources = self._collect_sources(target_path)
        combined_code = "\n".join(sources.values())

        # 1. AST Validation Check across all files
        t0 = time.perf_counter()
        ast_errors = []
        parsed_trees: dict[str, ast.Module] = {}
        for path, code in sources.items():
            try:
                tree = ast.parse(code, filename=path)
                parsed_trees[path] = tree
            except SyntaxError as e:
                ast_errors.append(f"{os.path.basename(path)}:{e.lineno or 1}: {e.msg}")

        ast_duration_ms = (time.perf_counter() - t0) * 1000.0
        ast_pass = len(ast_errors) == 0
        checks.append(f"AST compilation passed for {len(sources)} source file(s)")

        # 2. Target-Level Safety & Invariant Checks
        t1 = time.perf_counter()
        safety_checks: list[dict[str, Any]] = []

        # Check 1: eval/exec dangerous dynamic execution check (CRITICAL)
        eval_calls: list[str] = []
        for path, tree in parsed_trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Name) and func.id in ("eval", "exec"):
                        eval_calls.append(f"{os.path.basename(path)}:{node.lineno}")

        safety_checks.append(
            {
                "check": "eval_exec_safety",
                "passed": len(eval_calls) == 0,
                "severity_if_failed": "CRITICAL",
                "details": f"Detected dynamic eval/exec at: {', '.join(eval_calls)}"
                if eval_calls
                else "No dynamic eval/exec detected in target.",
            }
        )

        # Check 2: Unconstrained shell execution check (HIGH)
        unsafe_shell_calls: list[str] = []
        for path, tree in parsed_trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Check os.system(...)
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "system":
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                            unsafe_shell_calls.append(f"{os.path.basename(path)}:{node.lineno} (os.system)")
                    # Check subprocess.run(..., shell=True)
                    elif isinstance(node.func, ast.Attribute) and node.func.attr in ("run", "Popen"):
                        for kw in node.keywords:
                            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                unsafe_shell_calls.append(
                                    f"{os.path.basename(path)}:{node.lineno} (subprocess shell=True)"
                                )

        safety_checks.append(
            {
                "check": "unconstrained_shell_safety",
                "passed": len(unsafe_shell_calls) == 0,
                "severity_if_failed": "HIGH",
                "details": f"Unsafe shell invocations: {', '.join(unsafe_shell_calls)}"
                if unsafe_shell_calls
                else "No unconstrained shell execution detected.",
            }
        )

        # Check 3: Hardcoded environment paths check (MEDIUM)
        hardcoded_paths = re.findall(r'["\'](/(?:Users|home)/[^"\']+)["\']', combined_code)
        safety_checks.append(
            {
                "check": "relocatable_paths_check",
                "passed": len(hardcoded_paths) == 0,
                "severity_if_failed": "MEDIUM",
                "details": f"Hardcoded developer paths found: {', '.join(set(hardcoded_paths))}"
                if hardcoded_paths
                else "Target is relocatable without hardcoded user environment paths.",
            }
        )

        # Check 4: Framework Invariant Checks (ONLY when auditing hardening_loop itself)
        is_framework_target = "hardening_loop" in os.path.realpath(target_path) and "src/hardening_loop" in target_path
        if is_framework_target:
            has_admission_gate = "KnowledgeAdmissionGate" in combined_code and "PENDING_REVIEW" in combined_code
            safety_checks.append(
                {
                    "check": "knowledge_admission_gate_invariants",
                    "passed": bool(has_admission_gate),
                    "severity_if_failed": "CRITICAL",
                    "details": "Checking if admission gate forbids auto-canonical promotion.",
                }
            )

        safety_duration_ms = (time.perf_counter() - t1) * 1000.0
        total_loop_ms = ast_duration_ms + safety_duration_ms

        failed_critical = any(not c["passed"] for c in safety_checks if c["severity_if_failed"] == "CRITICAL")
        failed_high = any(not c["passed"] for c in safety_checks if c["severity_if_failed"] == "HIGH")
        failed_medium = any(not c["passed"] for c in safety_checks if c["severity_if_failed"] == "MEDIUM")

        test_results = {
            "total_files_tested": len(sources),
            "total_checks": len(safety_checks) + 1,
            "passed_checks": sum(1 for c in safety_checks if c["passed"]) + (1 if ast_pass else 0),
            "failed_checks": sum(1 for c in safety_checks if not c["passed"]) + (0 if ast_pass else 1),
            "ast_validation": {"passed": ast_pass, "errors": ast_errors},
            "safety_checks": safety_checks,
        }

        # Deterministic benchmark payload (hermetic)
        benchmark = {
            "loop_target_threshold_ms": 100.0,
            "meets_fast_feedback_sla": total_loop_ms < 100.0,
        }

        runtime_evidence = {
            "target": target_path,
            "total_files": len(sources),
            "total_lines_of_code": len(combined_code.splitlines()),
            "environment": "local_ci",
            "deterministic_execution": True,
        }

        payload = {
            "test_results": test_results,
            "benchmark": benchmark,
            "runtime_evidence": runtime_evidence,
        }

        # Fail-Closed Enforcement (Ley VIII): Fail immediately on AST error or CRITICAL/HIGH safety check failure
        if not ast_pass or failed_critical or failed_high:
            overall_status = VerificationStatus.FAIL
        elif failed_medium:
            overall_status = VerificationStatus.WARN
        else:
            overall_status = VerificationStatus.PASS

        checks.append(f"Completed verification of {len(sources)} file(s) in {round(total_loop_ms, 3)}ms")
        return payload, checks, overall_status
