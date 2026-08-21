"""Phase 1: QUESTION CONTEXT — Audit explicit vs inferred requirements and challenge premises."""

import os
import re
from typing import Any

from ..models import PhaseName, RequirementType, VerificationStatus
from .base import BasePhase


class QuestionPhase(BasePhase):
    """Examines target code and extracts/questions requirements."""

    def __init__(self):
        super().__init__(name=PhaseName.QUESTION)

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
            return (
                {"error": f"Target path {target_path} does not exist"},
                ["Target existence check failed"],
                VerificationStatus.FAIL,
            )

        sources = self._collect_sources(target_path)
        combined_code = "\n".join(sources.values())
        requirements: list[dict[str, Any]] = []
        checks.append(f"Parsed {len(sources)} source file(s) for requirements extraction")

        # 1. Audit explicit requirements (docstrings)
        for path, code in sources.items():
            docstring_match = re.search(r'"""(.*?)"""', code, re.DOTALL)
            if docstring_match:
                doc = docstring_match.group(1).strip()
                requirements.append(
                    {
                        "id": f"REQ-EXP-{len(requirements) + 1:03d}",
                        "type": RequirementType.EXPLICIT.value,
                        "statement": f"Module docstring declaration in {os.path.basename(path)}",
                        "source": os.path.basename(path),
                        "justification_valid": True,
                        "notes": doc.split("\n")[0],
                    }
                )

        # 2. Audit security & provenance constraints
        if "subprocess.run" in combined_code or "subprocess.Popen" in combined_code:
            actual_whitelist_enforced = bool(
                re.search(r"cmd\s+in\s+\[", combined_code)
                or "ALLOWED_PROGRAMS" in combined_code
                or "ALLOWED_FUNCTIONS" in combined_code
            )
            requirements.append(
                {
                    "id": f"REQ-SEC-{len(requirements) + 1:03d}",
                    "type": RequirementType.SECURITY_CONSTRAINT.value,
                    "statement": "Subprocess execution must strictly enforce command whitelist and sanitize input.",
                    "source": "execute_function",
                    "justification_valid": True,
                    "audit_finding": "Claims whitelist but invokes unconstrained shell"
                    if not actual_whitelist_enforced
                    else "Strict whitelist enforced",
                }
            )

        if "open(" in combined_code:
            has_boundary_check = (
                "validate_rel_path" in combined_code
                or "relative_to" in combined_code
                or "os.path.realpath" in combined_code
            )
            requirements.append(
                {
                    "id": f"REQ-SEC-{len(requirements) + 1:03d}",
                    "type": RequirementType.SECURITY_CONSTRAINT.value,
                    "statement": "File reading must be restricted to workspace boundary.",
                    "source": "file_reader",
                    "justification_valid": True,
                    "audit_finding": "No boundary verification before opening file_path"
                    if not has_boundary_check
                    else "Boundary verification present",
                }
            )

        # 3. Audit provenance requirements
        has_provenance = "method_version" in combined_code and "environment_hash" in combined_code
        requirements.append(
            {
                "id": f"REQ-SEC-{len(requirements) + 1:03d}",
                "type": RequirementType.SECURITY_CONSTRAINT.value,
                "statement": "All evidence envelopes must declare method version and host environment hash.",
                "source": "evidence_provenance",
                "justification_valid": True,
                "audit_finding": "Provenace metadata present in envelopes"
                if has_provenance
                else "Missing explicit method_version/environment_hash tracking",
            }
        )

        # 4. Audit historical / hardcoded paths
        hardcoded_paths = re.findall(r'["\'](/Users/[^"\']+)["\']', combined_code)
        if hardcoded_paths:
            for i, p in enumerate(set(hardcoded_paths)):
                requirements.append(
                    {
                        "id": f"REQ-HIST-{i + 1:03d}",
                        "type": RequirementType.HISTORICAL.value,
                        "statement": f"Hardcoded developer environment path: {p}",
                        "source": "hardcoded_string",
                        "justification_valid": False,
                        "challenge": "Environment paths must be injected via CLI arguments, environment variables, or workspace config.",
                    }
                )

        payload = {
            "target": target_path,
            "total_files_audited": len(sources),
            "total_requirements_audited": len(requirements),
            "requirements": requirements,
            "challenged_assumptions_count": sum(
                [
                    1
                    for r in requirements
                    if not bool(r.get("justification_valid", True)) or "Missing" in str(r.get("audit_finding", ""))
                ]
            ),
        }
        checks.append(f"Audited {len(requirements)} requirements across {len(sources)} file(s)")
        status = VerificationStatus.PASS
        return payload, checks, status
