"""Phase 1: QUESTION REQUIREMENTS — Challenge and classify requirements to eliminate unjustified assumptions."""

import ast
import os
import re
from typing import Any

from ..models import PhaseName, RequirementType, VerificationStatus
from .base import BasePhase


class QuestionPhase(BasePhase):
    """Audits, challenges, and classifies requirements from target source code."""

    def __init__(self):
        super().__init__(name=PhaseName.QUESTION)

    def _collect_sources(self, target_path: str) -> dict[str, str]:
        sources = {}
        if os.path.isfile(target_path):
            with open(target_path, encoding="utf-8", errors="replace") as f:
                sources[target_path] = f.read()
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for file in sorted(files):
                    if file.endswith(".py"):
                        full_path = os.path.join(root, file)
                        with open(full_path, encoding="utf-8", errors="replace") as f:
                            sources[full_path] = f.read()
        return sources

    @staticmethod
    def _get_enclosing_scope(tree: ast.AST, target_node: ast.AST) -> str:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if child is target_node:
                        return node.name
        return "module"

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

        sources = self._collect_sources(target_path)
        requirements: list[dict[str, Any]] = []
        total_ast_nodes = 0
        checks.append(f"Parsed {len(sources)} source file(s) for requirements extraction")

        for path, code in sources.items():
            fname = os.path.basename(path)
            try:
                tree = ast.parse(code, filename=path)
                total_ast_nodes += len(list(ast.walk(tree)))
            except SyntaxError:
                continue

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

            # 2. Audit Subprocess Execution Security Constraints
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("run", "Popen", "check_output", "call")
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "subprocess"
                    ):
                        scope = self._get_enclosing_scope(tree, node)
                        has_shell_true = any(
                            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                            for kw in node.keywords
                        )
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
                    elif isinstance(node.func, ast.Name) and node.func.id == "open":
                        scope = self._get_enclosing_scope(tree, node)
                        requirements.append(
                            {
                                "id": f"REQ-SEC-{len(requirements) + 1:03d}",
                                "type": RequirementType.SECURITY_CONSTRAINT.value,
                                "statement": "File reading should be confined to authorized workspace boundaries.",
                                "source": f"{fname}:{node.lineno} ({scope})",
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
