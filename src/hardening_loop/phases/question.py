"""Phase 1: QUESTION REQUIREMENTS — Challenge and classify requirements to eliminate unjustified assumptions."""

import ast
import os
import re
from typing import Any

from ..models import PhaseName, RequirementType, VerificationStatus
from .base import BasePhase, find_subprocess_calls


class QuestionPhase(BasePhase):
    """Audits, challenges, and classifies requirements from target source code."""

    def __init__(self):
        super().__init__(name=PhaseName.QUESTION)

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

    @staticmethod
    def _build_scope_map(tree: ast.AST) -> dict[ast.AST, str]:
        """Builds a map from each AST node to its innermost enclosing function/class scope."""
        scope_map: dict[ast.AST, str] = {}

        def _traverse(node: ast.AST, current_scope: str) -> None:
            scope_map[node] = current_scope
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _traverse(child, child.name)
                elif isinstance(child, ast.ClassDef):
                    _traverse(child, child.name)
                else:
                    _traverse(child, current_scope)

        _traverse(tree, "module")
        return scope_map

    def execute(
        self, target_path: str, context: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str], VerificationStatus]:
        checks = []
        if not os.path.exists(target_path):
            return (
                {"error": f"Target path {target_path} does not exist"},
                ["Target existence check failed"],
                VerificationStatus.FAIL,
            )

        sources, read_errors = self._collect_sources(target_path)
        if read_errors:
            return (
                {"error": f"Failed to read sources: {'; '.join(read_errors)}"},
                ["Source reading error (fail-closed)"],
                VerificationStatus.FAIL,
            )

        requirements: list[dict[str, Any]] = []
        total_ast_nodes = 0
        checks.append(f"Parsed {len(sources)} source file(s) for requirements extraction")

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

            scope_map = self._build_scope_map(tree)

            # 1. Audit explicit requirements (docstrings)
            docstring = ast.get_docstring(tree)
            if docstring:
                requirements.append(
                    {
                        "id": f"REQ-EXP-{len(requirements) + 1:03d}",
                        "type": RequirementType.EXPLICIT.value,
                        "statement": f"Module docstring declaration in {fname}",
                        "source": f"{fname}:1",
                        "justification_valid": True,
                        "notes": docstring.split("\n")[0],
                    }
                )

            # 2. Audit Subprocess Execution Security Constraints with alias resolution
            subp_calls = find_subprocess_calls(tree)
            for node, has_shell_true in subp_calls:
                scope = scope_map.get(node, "module")
                requirements.append(
                    {
                        "id": f"REQ-SEC-{len(requirements) + 1:03d}",
                        "type": RequirementType.SECURITY_CONSTRAINT.value,
                        "statement": "Subprocess execution must enforce command whitelisting and avoid unconstrained shell injection.",
                        "source": f"{fname}:{node.lineno} ({scope})",
                        "justification_valid": not has_shell_true,
                        "audit_finding": "Invokes shell=True without command whitelist"
                        if has_shell_true
                        else "Subprocess call uses structured argument list",
                    }
                )

            # 3. Audit File System Boundary Access
            for n in ast.walk(tree):
                if isinstance(n, ast.Call):
                    if isinstance(n.func, ast.Name) and n.func.id == "open":
                        scope = scope_map.get(n, "module")
                        requirements.append(
                            {
                                "id": f"REQ-SEC-{len(requirements) + 1:03d}",
                                "type": RequirementType.SECURITY_CONSTRAINT.value,
                                "statement": "File reading should be confined to authorized workspace boundaries.",
                                "source": f"{fname}:{n.lineno} ({scope})",
                                "justification_valid": True,
                                "audit_finding": "Standard open() invocation audited",
                            }
                        )

            # 4. Challenge Historical / Hardcoded Paths
            for lineno, line in enumerate(code.splitlines(), start=1):
                match = re.search(r'["\'](/(?:Users|home)/[^"\']+)["\']', line)
                if match:
                    requirements.append(
                        {
                            "id": f"REQ-HIST-{len(requirements) + 1:03d}",
                            "type": RequirementType.HISTORICAL.value,
                            "statement": f"Hardcoded developer environment path: {match.group(1)}",
                            "source": f"{fname}:{lineno}",
                            "justification_valid": False,
                            "challenge": "Environment paths must be injected via CLI arguments, environment variables, or workspace config.",
                        }
                    )

        # Baseline fallback if no code structures found
        if not requirements:
            requirements.append(
                {
                    "id": "REQ-INF-001",
                    "type": RequirementType.INFERRED.value,
                    "statement": "Target execution must comply with Python runtime standard contracts",
                    "source": os.path.basename(target_path),
                    "justification_valid": True,
                }
            )

        challenged_count = sum(1 for r in requirements if not r.get("justification_valid", True))
        checks.append(f"Classified {len(requirements)} requirements ({challenged_count} challenged)")

        payload = {
            "target": target_path,
            "total_files_audited": len(sources),
            "total_ast_nodes_visited": total_ast_nodes,
            "total_requirements_audited": len(requirements),
            "challenged_assumptions_count": challenged_count,
            "requirements": requirements,
        }

        status = VerificationStatus.PASS
        return payload, checks, status
