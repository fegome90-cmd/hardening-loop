"""Phase 2: DELETE HARNESS — Identify unnecessary complexity and dead harnesses with exact attribution."""

import ast
import difflib
import os
import re
from typing import Any

from ..models import PhaseName, VerificationStatus, compute_target_hash
from .base import BasePhase


class DeletePhase(BasePhase):
    """Pinpoints unnecessary harnesses, dead branches, and unsafe capabilities with exact attribution."""

    def __init__(self):
        super().__init__(name=PhaseName.DELETE)

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
            return {"error": f"Target {target_path} not found"}, ["Target missing"], VerificationStatus.FAIL

        sources, read_errors = self._collect_sources(target_path)
        if read_errors:
            return (
                {"error": f"Failed to read sources: {'; '.join(read_errors)}"},
                ["Source reading error (fail-closed)"],
                VerificationStatus.FAIL,
            )

        deletion_candidates: list[dict[str, Any]] = []
        total_ast_nodes = 0
        checks.append(f"Scanned {len(sources)} source file(s) for deletion candidates and over-privileged harnesses")

        is_framework_target = "hardening_loop" in target_path or any("hardening_loop" in p for p in sources.keys())

        for path, code in sources.items():
            fname = os.path.basename(path)
            try:
                tree = ast.parse(code, filename=path)
                total_ast_nodes += len(list(ast.walk(tree)))
            except SyntaxError as e:
                return (
                    {"error": f"Syntax error in {path}:{e.lineno}: {e.msg}"},
                    [f"AST parse failed in {fname}"],
                    VerificationStatus.FAIL,
                )

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # 1. os.system call
                    if (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr == "system"
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "os"
                    ):
                        deletion_candidates.append(
                            {
                                "candidate_id": f"DEL-{len(deletion_candidates) + 1:03d}",
                                "target": "os_system_invocation",
                                "location": f"{fname}:{node.lineno}",
                                "rationale": "Direct invocation of os.system executes unconstrained shell commands.",
                                "action": "REPLACE_WITH_STRUCTURED_SUBPROCESS",
                                "severity": "HIGH",
                            }
                        )

                    # 2. subprocess with shell=True or direct /bin/zsh /bin/bash shell wrapper
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
                        is_shell_binary = False
                        if node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                            for elt in node.args[0].elts:
                                if isinstance(elt, ast.Constant) and str(elt.value) in (
                                    "/bin/zsh",
                                    "/bin/bash",
                                    "bash",
                                    "zsh",
                                ):
                                    is_shell_binary = True

                        if has_shell_true or is_shell_binary:
                            deletion_candidates.append(
                                {
                                    "candidate_id": f"DEL-{len(deletion_candidates) + 1:03d}",
                                    "target": "unconstrained_shell_harness",
                                    "location": f"{fname}:{node.lineno}",
                                    "rationale": "Direct invocation of shell binary or shell=True allows unconstrained command injection.",
                                    "action": "REPLACE_WITH_STRUCTURED_RUNNER",
                                    "severity": "HIGH",
                                }
                            )

                    # 3. Dynamic eval / exec
                    elif isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                        deletion_candidates.append(
                            {
                                "candidate_id": f"DEL-{len(deletion_candidates) + 1:03d}",
                                "target": f"dynamic_{node.func.id}_call",
                                "location": f"{fname}:{node.lineno}",
                                "rationale": f"Dynamic execution via {node.func.id}() bypasses static analysis and introduces vulnerabilities.",
                                "action": "DELETE_OR_REFACTOR_STATICALLY",
                                "severity": "CRITICAL",
                            }
                        )

                # 4. Auto-promotion bypass functions (only for framework targets)
                elif is_framework_target and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name in ("auto_promote", "skip_review", "bypass_gate"):
                        deletion_candidates.append(
                            {
                                "candidate_id": f"DEL-{len(deletion_candidates) + 1:03d}",
                                "target": f"bypass_method_{node.name}",
                                "location": f"{fname}:{node.lineno}",
                                "rationale": "Knowledge Admission Gate prohibits auto-promotion to canonical without reviewer identity.",
                                "action": "DELETE_BYPASS_METHOD",
                                "severity": "CRITICAL",
                            }
                        )

            # 5. Check for hardcoded workspace/developer paths
            for lineno, line in enumerate(code.splitlines(), start=1):
                if re.search(r'["\']/(?:Users|home)/', line):
                    deletion_candidates.append(
                        {
                            "candidate_id": f"DEL-{len(deletion_candidates) + 1:03d}",
                            "target": "hardcoded_path_string",
                            "location": f"{fname}:{lineno}",
                            "rationale": "Hardcoded developer absolute path makes script brittle and non-relocatable.",
                            "action": "DELETE_AND_PARAMETERIZE",
                            "severity": "MEDIUM",
                        }
                    )

        # Generate sample diff for target
        target_file = target_path if os.path.isfile(target_path) else next(iter(sources.keys()), target_path)
        original_sample = sources.get(target_file, "")
        diff = "".join(
            difflib.unified_diff(
                original_sample.splitlines(keepends=True),
                original_sample.splitlines(keepends=True),
                fromfile=f"a/{os.path.basename(target_file)}",
                tofile=f"b/{os.path.basename(target_file)}",
            )
        )

        payload = {
            "target": target_path,
            "total_files_scanned": len(sources),
            "total_ast_nodes_visited": total_ast_nodes,
            "deletion_candidates": deletion_candidates,
            "deletion_candidates_count": len(deletion_candidates),
            "diff_patch": diff,
            "rollback_reference": {
                "original_target_hash": compute_target_hash(target_path),
                "target_path": target_path,
            },
        }

        checks.append(f"Identified {len(deletion_candidates)} deletion candidates with exact location attribution")
        checks.append("Generated deterministic rollback reference")
        status = VerificationStatus.PASS
        return payload, checks, status
