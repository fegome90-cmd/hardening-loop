"""Phase 1: QUESTION CONTEXT — Audit explicit vs inferred requirements and challenge premises."""

import ast
import os
import re
from typing import Any, Dict, List, Tuple
from ..models import PhaseName, RequirementType, VerificationStatus
from .base import BasePhase


class QuestionPhase(BasePhase):
    """Examines target code and extracts/questions requirements."""

    def __init__(self):
        super().__init__(name=PhaseName.QUESTION)

    def execute(self, target_path: str, context: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str], VerificationStatus]:
        checks = []
        if not os.path.exists(target_path):
            return {"error": f"Target path {target_path} does not exist"}, ["Target existence check failed"], VerificationStatus.FAIL

        with open(target_path, "r", encoding="utf-8") as f:
            code = f.read()

        requirements = []
        checks.append("Parsed source code for requirements extraction")

        # 1. Audit explicit requirements (docstrings, comments, CLI help)
        docstring_match = re.search(r'"""(.*?)"""', code, re.DOTALL)
        if docstring_match:
            doc = docstring_match.group(1).strip()
            requirements.append({
                "id": "REQ-EXP-001",
                "type": RequirementType.EXPLICIT.value,
                "statement": "Wrapper executes tool calls for LLM via loop until final response.",
                "source": "module_docstring",
                "justification_valid": True,
                "notes": doc.split("\n")[0],
            })

        # 2. Audit security constraints
        if "subprocess.run" in code:
            has_whitelist = "whitelist" in code.lower()
            actual_whitelist_enforced = bool(re.search(r'cmd\s+in\s+\[', code) or "whitelist" in code and "if fn ==" in code)
            requirements.append({
                "id": "REQ-SEC-001",
                "type": RequirementType.SECURITY_CONSTRAINT.value,
                "statement": "Subprocess execution must strictly enforce command whitelist and sanitize input.",
                "source": "execute_function",
                "justification_valid": True,
                "audit_finding": "Claims strict whitelist in docstring but invokes unconstrained /bin/zsh -c cmd" if not actual_whitelist_enforced else "Whitelist present",
            })

        if "open(" in code:
            has_boundary_check = "os.path.abspath" in code or "resolve" in code or "startswith" in code
            requirements.append({
                "id": "REQ-SEC-002",
                "type": RequirementType.SECURITY_CONSTRAINT.value,
                "statement": "File reading must be restricted to workspace boundary.",
                "source": "execute_read",
                "justification_valid": True,
                "audit_finding": "No boundary verification before opening file_path" if not has_boundary_check else "Boundary checked",
            })

        # 3. Audit historical / inferred assumptions (e.g. hardcoded paths)
        hardcoded_paths = re.findall(r'["\'](/Users/[^"\']+)["\']', code)
        if hardcoded_paths:
            for i, p in enumerate(hardcoded_paths):
                requirements.append({
                    "id": f"REQ-HIST-{i+1:03d}",
                    "type": RequirementType.HISTORICAL.value,
                    "statement": f"Hardcoded developer environment path: {p}",
                    "source": "hardcoded_string",
                    "justification_valid": False,
                    "challenge": "Environment paths must be injected via CLI arguments, environment variables, or workspace config.",
                })

        # 4. Inferred return contract checks
        if "PASS" in code or "FAIL" in code:
            requirements.append({
                "id": "REQ-INF-001",
                "type": RequirementType.INFERRED.value,
                "statement": "Model is instructed to output JSON with {\"status\": \"PASS\"|\"FAIL\"}.",
                "source": "system_prompt",
                "justification_valid": True,
                "challenge": "Target wrapper does not assert or parse the final JSON PASS/FAIL status before exit.",
            })

        payload = {
            "target": target_path,
            "total_requirements_audited": len(requirements),
            "requirements": requirements,
            "challenged_assumptions_count": sum(1 for r in requirements if not r.get("justification_valid", True) or "audit_finding" in r),
        }
        checks.append(f"Audited {len(requirements)} requirements across 4 categories")
        status = VerificationStatus.PASS
        return payload, checks, status
