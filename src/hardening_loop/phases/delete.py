"""Phase 2: DELETE HARNESS — Identify unnecessary complexity, excessive capabilities, and dead harnesses."""

import difflib
import os
import re
from typing import Any, Dict, List, Tuple
from ..models import PhaseName, VerificationStatus, sha256_text
from .base import BasePhase


class DeletePhase(BasePhase):
    """Pinpoints unnecessary harnesses, dead branches, and unsafe capabilities."""

    def __init__(self):
        super().__init__(name=PhaseName.DELETE)

    def execute(self, target_path: str, context: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str], VerificationStatus]:
        checks = []
        if not os.path.exists(target_path):
            return {"error": f"Target {target_path} not found"}, ["Target missing"], VerificationStatus.FAIL

        with open(target_path, "r", encoding="utf-8") as f:
            original_code = f.read()

        deletion_candidates = []
        checks.append("Scanned target for deletion candidates and over-privileged harnesses")

        # 1. Check for unconstrained shell execution harness
        if "subprocess.run" in original_code and ("/bin/zsh" in original_code or "/bin/bash" in original_code or "shell=True" in original_code):
            deletion_candidates.append({
                "candidate_id": "DEL-001",
                "target": "unconstrained_shell_harness",
                "rationale": "Direct invocation of shell binary executes arbitrary shell scripts without token or executable whitelist.",
                "action": "REPLACE_WITH_STRUCTURED_RUNNER",
                "severity": "HIGH",
            })

        # 2. Check for hardcoded workspace path
        if re.search(r'cwd\s*=\s*["\']/Users/', original_code) or "/Users/" in original_code:
            deletion_candidates.append({
                "candidate_id": "DEL-002",
                "target": "hardcoded_cwd_string",
                "rationale": "Hardcoded developer absolute cwd makes script brittle and non-relocatable.",
                "action": "DELETE_AND_PARAMETERIZE",
                "severity": "MEDIUM",
            })

        # 3. Check for unsandboxed file reader harness
        if "open(" in original_code and ("validate_rel_path" not in original_code and "resolve" not in original_code):
            deletion_candidates.append({
                "candidate_id": "DEL-003",
                "target": "unsandboxed_open_call",
                "rationale": "Arbitrary file reading allows potential directory traversal beyond repo bounds.",
                "action": "REPLACE_WITH_SANDBOXED_RESOLVER",
                "severity": "HIGH",
            })

        # 4. Check for lack of structured evidence envelope logging
        if "evidence_id" not in original_code and "EvidenceEnvelope" not in original_code:
            deletion_candidates.append({
                "candidate_id": "DEL-004",
                "target": "unstructured_stderr_logging",
                "rationale": "Direct print statements to sys.stderr lack deterministic evidence logging and hashing.",
                "action": "REPLACE_WITH_EVIDENCE_ENVELOPE",
                "severity": "MEDIUM",
            })

        # Generate proposed hardened code simulation for patch generation
        hardened_lines = []
        for line in original_code.splitlines(keepends=True):
            if 'cwd="/Users/felipe_gonzalez/Developer/examen_grado"' in line:
                hardened_lines.append('                cwd=params.get("cwd", os.getcwd()),\n')
            else:
                hardened_lines.append(line)
        hardened_code = "".join(hardened_lines)

        diff = "".join(
            difflib.unified_diff(
                original_code.splitlines(keepends=True),
                hardened_code.splitlines(keepends=True),
                fromfile=f"a/{os.path.basename(target_path)}",
                tofile=f"b/{os.path.basename(target_path)}",
            )
        )

        payload = {
            "target": target_path,
            "deletion_candidates": deletion_candidates,
            "deletion_candidates_count": len(deletion_candidates),
            "diff_patch": diff,
            "rollback_reference": {
                "original_sha256": sha256_text(original_code),
                "proposed_sha256": sha256_text(hardened_code),
                "target_path": target_path,
            },
        }

        checks.append(f"Identified {len(deletion_candidates)} deletion candidates")
        checks.append("Generated deterministic unified diff and rollback reference")
        status = VerificationStatus.PASS
        return payload, checks, status
