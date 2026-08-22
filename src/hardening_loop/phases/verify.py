"""Phase 4: VERIFY DETERMINISM — Fast automated verification, contract invariance, and fail-closed safety checks."""

import ast
import os
import re
import time
from typing import Any

from ..models import PhaseName, VerificationStatus
from .base import BasePhase, find_subprocess_calls, is_internal_framework_target


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
            for root, dirs, files in os.walk(target_path):
                dirs.sort()
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
        parsed_trees: dict[str, ast.Module] = {}
        total_ast_nodes = 0
        total_loc = 0

        files_audited = 0
        for path, code in sources.items():
            files_audited += 1
            file_loc = len(code.splitlines())
            total_loc += file_loc
            try:
                tree = ast.parse(code, filename=path)
                parsed_trees[path] = tree
                total_ast_nodes += len(list(ast.walk(tree)))
            except SyntaxError as e:
                err_msg = f"Syntax error in {os.path.basename(path)}:{e.lineno}: {e.msg}"
                verification_duration_ms = round((time.perf_counter() - t0) * 1000, 3)
                meets_sla = verification_duration_ms < 5000.0
                return (
                    {
                        "target": target_path,
                        "error": err_msg,
                        "file": path,
                        "line": e.lineno,
                        "message": e.msg,
                        "total_files_audited": files_audited,
                        "total_ast_nodes_visited": total_ast_nodes,
                        "total_lines_of_code": total_loc,
                        "test_results": {
                            "total_checks": 1,
                            "passed_checks": 0,
                            "failed_checks": 1,
                            "checks": [
                                {
                                    "name": "target_ast_syntax_validity",
                                    "passed": False,
                                    "severity": "CRITICAL",
                                    "category": "security_safety_check",
                                    "details": err_msg,
                                }
                            ],
                            "fast_feedback_passed": meets_sla,
                        },
                        "benchmark": {
                            "target": target_path,
                            "meets_fast_feedback_sla": meets_sla,
                            "total_loc": total_loc,
                        },
                        "runtime_evidence": {
                            "total_lines_of_code": total_loc,
                            "total_ast_nodes_visited": total_ast_nodes,
                            "status": VerificationStatus.FAIL.value,
                        },
                    },
                    [
                        f"[FAIL-CLOSED] Verification gate aborted immediately on syntax corruption in {os.path.basename(path)}:{e.lineno} ({e.msg})"
                    ],
                    VerificationStatus.FAIL,
                )

        ast_check_result = {
            "name": "target_ast_syntax_validity",
            "passed": True,
            "severity": "CRITICAL",
            "category": "security_safety_check",
            "details": f"Parsed {len(sources)} file(s) without syntax errors",
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
            "category": "security_safety_check",
            "details": "No dynamic eval() or exec() calls detected"
            if not eval_exec_calls
            else "; ".join(eval_exec_calls),
        }

        # 3. Unconstrained Shell Execution Safety Checks with import alias support
        shell_calls = []
        for path, tree in parsed_trees.items():
            fname = os.path.basename(path)
            # Check os.system calls
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "system"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                ):
                    shell_calls.append(f"{fname}:{node.lineno} invokes os.system()")

            # Check subprocess calls via aliases
            subp_calls = find_subprocess_calls(tree)
            for node, has_shell_true in subp_calls:
                if has_shell_true:
                    shell_calls.append(f"{fname}:{node.lineno} invokes subprocess with shell=True")

        shell_check = {
            "name": "no_unconstrained_shell_execution",
            "passed": len(shell_calls) == 0,
            "severity": "HIGH",
            "category": "security_safety_check",
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
            "category": "portability_warning",
            "details": "No hardcoded absolute developer paths found"
            if not hardcoded_paths
            else f"Hardcoded paths detected at: {', '.join(hardcoded_paths)}",
        }

        # Compile all verification checks (security safety checks + portability quality checks)
        verification_checks = [ast_check_result, eval_exec_check, shell_check, paths_check]

        # 5. If self-auditing hardening_loop core, verify framework governance invariants
        if is_internal_framework_target(target_path):
            combined_code = "\n".join(sources.values())
            has_gate = "KnowledgeAdmissionGate" in combined_code
            has_envelope = "EvidenceEnvelope" in combined_code
            verification_checks.append(
                {
                    "name": "framework_admission_gate_intact",
                    "passed": has_gate,
                    "severity": "CRITICAL",
                    "category": "security_safety_check",
                    "details": "KnowledgeAdmissionGate class is intact and active"
                    if has_gate
                    else "Missing KnowledgeAdmissionGate",
                }
            )
            verification_checks.append(
                {
                    "name": "framework_evidence_envelope_intact",
                    "passed": has_envelope,
                    "severity": "HIGH",
                    "category": "security_safety_check",
                    "details": "EvidenceEnvelope dataclass is intact and active"
                    if has_envelope
                    else "Missing EvidenceEnvelope",
                }
            )

        verification_duration_ms = round((time.perf_counter() - t0) * 1000, 3)

        passed_checks = [c for c in verification_checks if c["passed"]]
        failed_checks = [c for c in verification_checks if not c["passed"]]
        security_failures = [c for c in failed_checks if c.get("category") != "portability_warning"]

        # Determine Fail-Closed status
        if security_failures:
            status = VerificationStatus.FAIL
            checks.append(
                f"[FAIL-CLOSED] Verification gate failed with {len(security_failures)} security violation(s)"
            )
        elif failed_checks:
            status = VerificationStatus.WARN
            checks.append(
                f"Verification gate passed with {len(failed_checks)} non-blocking portability/quality warning(s)"
            )
        else:
            status = VerificationStatus.PASS
            checks.append(f"All {len(verification_checks)} target verification checks passed")

        payload = {
            "target": target_path,
            "total_files_audited": len(sources),
            "total_ast_nodes_visited": total_ast_nodes,
            "total_lines_of_code": total_loc,
            "test_results": {
                "total_checks": len(verification_checks),
                "passed_checks": len(passed_checks),
                "failed_checks": len(failed_checks),
                "checks": verification_checks,
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
