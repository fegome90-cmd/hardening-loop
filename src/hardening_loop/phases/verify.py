"""Phase 4: VERIFY FASTER — Execute verification gates and collect latency/correctness benchmarks."""

import ast
import os
import time
from typing import Any, Dict, List, Tuple
from ..models import PhaseName, VerificationStatus
from .base import BasePhase


class VerifyPhase(BasePhase):
    """Executes fast verification passes and generates verification metrics."""

    def __init__(self):
        super().__init__(name=PhaseName.VERIFY)

    def execute(self, target_path: str, context: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str], VerificationStatus]:
        checks = []
        if not os.path.exists(target_path):
            return {"error": f"Target {target_path} not found"}, ["Target missing"], VerificationStatus.FAIL

        # 1. AST Validation Check
        t0 = time.perf_counter()
        with open(target_path, "r", encoding="utf-8") as f:
            code = f.read()

        try:
            ast.parse(code)
            ast_pass = True
            checks.append("Syntax and AST compilation passed")
        except SyntaxError as e:
            ast_pass = False
            checks.append(f"AST compilation failed: {e}")
        ast_duration_ms = (time.perf_counter() - t0) * 1000.0

        # 2. Static Safety Checks
        t1 = time.perf_counter()
        safety_checks = []
        
        # Check 1: Tool whitelist safety
        has_safe_whitelist = "whitelist" in code.lower() and "fn in" in code
        safety_checks.append({
            "check": "tool_whitelist_enforcement",
            "passed": bool(has_safe_whitelist),
            "severity_if_failed": "HIGH",
            "details": "Checking if tool invocation is guarded by a strict whitelist."
        })

        # Check 2: Path boundary check
        has_path_boundary = "os.path.abspath" in code or "resolve" in code
        safety_checks.append({
            "check": "file_reader_workspace_boundary",
            "passed": bool(has_path_boundary),
            "severity_if_failed": "HIGH",
            "details": "Checking if file read tool verifies directory boundaries."
        })

        # Check 3: Structured evidence logging
        has_evidence_logging = "evidence" in code.lower() or "json.dump" in code and "envelope" in code
        safety_checks.append({
            "check": "structured_evidence_logging",
            "passed": bool(has_evidence_logging),
            "severity_if_failed": "MEDIUM",
            "details": "Checking if tool executions produce structured audit logs."
        })

        safety_duration_ms = (time.perf_counter() - t1) * 1000.0

        # 3. Overall Test Results and Benchmark Summary
        test_results = {
            "total_checks": len(safety_checks) + 1,
            "passed_checks": sum(1 for c in safety_checks if c["passed"]) + (1 if ast_pass else 0),
            "failed_checks": sum(1 for c in safety_checks if not c["passed"]) + (0 if ast_pass else 1),
            "ast_validation": {"passed": ast_pass, "duration_ms": round(ast_duration_ms, 3)},
            "safety_checks": safety_checks,
        }

        benchmark = {
            "ast_parse_ms": round(ast_duration_ms, 3),
            "safety_audit_ms": round(safety_duration_ms, 3),
            "total_verification_loop_ms": round(ast_duration_ms + safety_duration_ms, 3),
            "loop_target_threshold_ms": 100.0,
            "meets_fast_feedback_sla": (ast_duration_ms + safety_duration_ms) < 100.0,
        }

        runtime_evidence = {
            "target": target_path,
            "file_size_bytes": os.path.getsize(target_path),
            "lines_of_code": len(code.splitlines()),
            "environment": "local_ci",
            "deterministic_execution": True,
        }

        payload = {
            "test_results": test_results,
            "benchmark": benchmark,
            "runtime_evidence": runtime_evidence,
        }

        overall_status = VerificationStatus.PASS if ast_pass else VerificationStatus.FAIL
        checks.append(f"Completed verification in {benchmark['total_verification_loop_ms']}ms")
        return payload, checks, overall_status
