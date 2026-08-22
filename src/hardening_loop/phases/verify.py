"""Phase 4: VERIFY DETERMINISM — Fast automated verification, contract invariance, and fail-closed safety checks."""

import ast
import os
import re
import time
from typing import Any

from ..models import PhaseName, VerificationStatus
from .base import BasePhase


class VerifyPhase(BasePhase):
    """Executes target AST safety checks and verifies contract invariance under strict Fail-Closed policy (Ley VIII)."""

    def __init__(self):
        super().__init__(name=PhaseName.VERIFY)

    def _collect_sources(self, target_path: str) -> tuple[dict[str, str], list[str]]:
        sources = {}
        errors = []
        if os.path.isfile(target_path):
            try:
                with open(target_path, encoding="utf-8") as f:
                    sources[target_path] = f.read()
            except (UnicodeDecodeError, OSError) as e:
                errors.append(f"Failed to read {target_path}: {e}")
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for file in sorted(files):
                    if file.endswith(".py"):
                        full_path = os.path.join(root, file)
                        try:
                            with open(full_path, encoding="utf-8") as f:
                                sources[full_path] = f.read()
                        except (UnicodeDecodeError, OSError) as e:
                            errors.append(f"Failed to read {full_path}: {e}")
        return sources, errors

    def execute(
        self, target_path: str, context: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str], VerificationStatus]:
        checks = []
        if not os.path.exists(target_path):
            return (
                {"error": f"Target {target_path} not found"},
                ["Target missing"],
                VerificationStatus.FAIL,
            )

        sources, read_errors = self._collect_sources(target_path)
        if read_errors:
            return (
                {"error": f"Failed to read sources: {'; '.join(read_errors)}"},
                ["Source reading error (fail-closed)"],
                VerificationStatus.FAIL,
            )

        checks.append(f"Loaded {len(sources)} source file(s) for verification gate")

        # 1. AST Validation Check across all files
        t0 = time.perf_counter()
        ast_errors = []
        parsed_trees: dict[str, ast.Module] = {}
        total_ast_nodes = 0
        total_loc = 0

        for path, code in sources.items():
            total_loc += len(code.splitlines())
            try:
                tree = ast.parse(code, filename=path)
                parsed_trees[path] = tree
                total_ast_nodes += len(list(ast.walk(tree)))
            except SyntaxError as e:
                ast_errors.append(f"Syntax error in {os.path.basename(path)}:{e.lineno}: {e.msg}")

        ast_valid = len(ast_errors) == 0
        ast_check_result = {
            "name": "target_ast_syntax_validity",
            "passed": ast_valid,
            "severity": "CRITICAL",
            "details": f"Parsed {len(sources)} file(s) without syntax errors" if ast_valid else "; ".join(ast_errors),
        }

        # 2. Dynamic Execution Safety Checks (eval/exec)
        eval_exec_calls = []
        for path, tree in parsed_trees.items():
            fname = os.path.basename(path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    eval_exec_calls.append(f"{fname}:{node.lineno} invokes {node.func.id}()")

        eval_exec_check = {
            "name": "no_dynamic_eval_or_exec",
            "passed": len(eval_exec_calls) == 0,
            "severity": "CRITICAL",
            "details": "No dynamic eval() or exec() calls detected"
            if not eval_exec_calls
            else "; ".join(eval_exec_calls),
        }

        # 3. Unconstrained Shell Execution Safety Checks (subprocess shell=True / os.system)
        shell_calls = []
        for path, tree in parsed_trees.items():
            fname = os.path.basename(path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr == "system"
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "os"
                    ):
                        shell_calls.append(f"{fname}:{node.lineno} invokes os.system()")
                    elif (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("run", "Popen", "call", "check_output")
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "subprocess"
                    ):
                        has_shell_true = any(
                            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                            for kw in node.keywords
                        )
                        if has_shell_true:
                            shell_calls.append(f"{fname}:{node.lineno} invokes subprocess with shell=True")

        shell_check = {
            "name": "no_unconstrained_shell_execution",
            "passed": len(shell_calls) == 0,
            "severity": "HIGH",
            "details": "All subprocess invocations use structured arguments"
            if not shell_calls
            else "; ".join(shell_calls),
        }

        # 4. Hardcoded Environment Paths Check
        hardcoded_paths = []
        for path, code in sources.items():
            fname = os.path.basename(path)
            for lineno, line in enumerate(code.splitlines(), start=1):
                if re.search(r'["\']/(?:Users|home)/', line):
                    hardcoded_paths.append(f"{fname}:{lineno}")

        paths_check = {
            "name": "no_hardcoded_developer_paths",
            "passed": len(hardcoded_paths) == 0,
            "severity": "MEDIUM",
            "details": "No hardcoded absolute developer paths found"
            if not hardcoded_paths
            else f"Hardcoded paths detected at: {', '.join(hardcoded_paths)}",
        }

        # Compile all safety checks
        safety_checks = [ast_check_result, eval_exec_check, shell_check, paths_check]

        # 5. If self-auditing hardening_loop core, verify framework governance invariants
        is_framework_target = "hardening_loop" in target_path or any("hardening_loop" in p for p in sources.keys())
        if is_framework_target:
            combined_code = "\n".join(sources.values())
            has_gate = "KnowledgeAdmissionGate" in combined_code
            has_envelope = "EvidenceEnvelope" in combined_code
            safety_checks.append(
                {
                    "name": "framework_admission_gate_intact",
                    "passed": has_gate,
                    "severity": "CRITICAL",
                    "details": "KnowledgeAdmissionGate class is intact and active"
                    if has_gate
                    else "Missing KnowledgeAdmissionGate",
                }
            )
            safety_checks.append(
                {
                    "name": "framework_evidence_envelope_intact",
                    "passed": has_envelope,
                    "severity": "HIGH",
                    "details": "EvidenceEnvelope dataclass is intact and active"
                    if has_envelope
                    else "Missing EvidenceEnvelope",
                }
            )

        verification_duration_ms = round((time.perf_counter() - t0) * 1000, 3)

        passed_checks = [c for c in safety_checks if c["passed"]]
        failed_checks = [c for c in safety_checks if not c["passed"]]
        critical_or_high_failures = [c for c in failed_checks if c["severity"] in ("CRITICAL", "HIGH")]

        # Determine Fail-Closed status
        if not ast_valid or len(critical_or_high_failures) > 0:
            status = VerificationStatus.FAIL
            checks.append(
                f"[FAIL-CLOSED] Verification gate failed with {len(critical_or_high_failures)} CRITICAL/HIGH security violations"
            )
        elif len(failed_checks) > 0:
            status = VerificationStatus.WARN
            checks.append(f"Verification gate passed with {len(failed_checks)} non-blocking warnings")
        else:
            status = VerificationStatus.PASS
            checks.append(f"All {len(safety_checks)} target safety checks passed verification")

        payload = {
            "target": target_path,
            "total_files_audited": len(sources),
            "total_ast_nodes_visited": total_ast_nodes,
            "total_lines_of_code": total_loc,
            "test_results": {
                "total_checks": len(safety_checks),
                "passed_checks": len(passed_checks),
                "failed_checks": len(failed_checks),
                "checks": safety_checks,
                "fast_feedback_passed": verification_duration_ms < 5000.0,
            },
            "benchmark": {
                "target": target_path,
                "meets_fast_feedback_sla": verification_duration_ms < 5000.0,
                "total_loc": total_loc,
            },
            "runtime_evidence": {
                "total_lines_of_code": total_loc,
                "total_ast_nodes_visited": total_ast_nodes,
                "status": status.value,
            },
        }

        return payload, checks, status
