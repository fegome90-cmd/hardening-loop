"""Phase 2: DELETE HARNESS — Identify unnecessary complexity, excessive capabilities, and dead harnesses."""

import difflib
import os
import re
from typing import Any

from ..models import PhaseName, VerificationStatus, compute_target_hash
from .base import BasePhase


class DeletePhase(BasePhase):
    """Pinpoints unnecessary harnesses, dead branches, and unsafe capabilities."""

    def __init__(self):
        super().__init__(name=PhaseName.DELETE)

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
        deletion_candidates = []
        checks.append(f"Scanned {len(sources)} source file(s) for deletion candidates and over-privileged harnesses")

        # 1. Check for unconstrained shell execution harness
        if "subprocess.run" in combined_code and (
            "/bin/zsh" in combined_code or "/bin/bash" in combined_code or "shell=True" in combined_code
        ):
            deletion_candidates.append(
                {
                    "candidate_id": "DEL-001",
                    "target": "unconstrained_shell_harness",
                    "rationale": "Direct invocation of shell binary executes arbitrary shell scripts without token or executable whitelist.",
                    "action": "REPLACE_WITH_STRUCTURED_RUNNER",
                    "severity": "HIGH",
                }
            )

        # 2. Check for hardcoded workspace path
        if re.search(r'cwd\s*=\s*["\']/Users/', combined_code) or "/Users/" in combined_code:
            deletion_candidates.append(
                {
                    "candidate_id": "DEL-002",
                    "target": "hardcoded_cwd_string",
                    "rationale": "Hardcoded developer absolute cwd makes script brittle and non-relocatable.",
                    "action": "DELETE_AND_PARAMETERIZE",
                    "severity": "MEDIUM",
                }
            )

        # 3. Check for unsandboxed file reader harness
        if "open(" in combined_code and (
            "validate_rel_path" not in combined_code
            and "resolve" not in combined_code
            and "os.walk" not in combined_code
        ):
            deletion_candidates.append(
                {
                    "candidate_id": "DEL-003",
                    "target": "unsandboxed_open_call",
                    "rationale": "Arbitrary file reading allows potential directory traversal beyond repo bounds.",
                    "action": "REPLACE_WITH_SANDBOXED_RESOLVER",
                    "severity": "HIGH",
                }
            )

        # 4. Check for lack of structured evidence envelope logging
        if "evidence_id" not in combined_code and "EvidenceEnvelope" not in combined_code:
            deletion_candidates.append(
                {
                    "candidate_id": "DEL-004",
                    "target": "unstructured_stderr_logging",
                    "rationale": "Direct print statements to sys.stderr lack deterministic evidence logging and hashing.",
                    "action": "REPLACE_WITH_EVIDENCE_ENVELOPE",
                    "severity": "MEDIUM",
                }
            )

        # 5. Check for accidental auto-promotion bypass
        if "auto_promote" in combined_code or "skip_review" in combined_code:
            deletion_candidates.append(
                {
                    "candidate_id": "DEL-005",
                    "target": "auto_promotion_bypass",
                    "rationale": "Knowledge Admission Gate prohibits auto-promotion to canonical without reviewer identity.",
                    "action": "DELETE_BYPASS_METHOD",
                    "severity": "CRITICAL",
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
            "deletion_candidates": deletion_candidates,
            "deletion_candidates_count": len(deletion_candidates),
            "diff_patch": diff,
            "rollback_reference": {
                "original_target_hash": compute_target_hash(target_path),
                "target_path": target_path,
            },
        }

        checks.append(f"Identified {len(deletion_candidates)} deletion candidates")
        checks.append("Generated deterministic rollback reference")
        status = VerificationStatus.PASS
        return payload, checks, status
