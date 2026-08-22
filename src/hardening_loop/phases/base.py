"""Base phase interface with cryptographic envelope creation and schema validation."""

import abc
import ast
import os
import time
from typing import Any

from ..models import (
    CanonicalEvidence,
    EvidenceEnvelope,
    PhaseName,
    RuntimeReceipt,
    VerificationStatus,
    compute_canonical_directory_digest,
    compute_execution_context_hash,
    sha256_dict,
    utc_now_iso,
)
from ..schema_validator import SchemaValidator


def is_internal_framework_target(target_path: str) -> bool:
    """Accurately checks if target_path is the internal hardening_loop framework module.

    Fails closed: path resolution errors propagate directly rather than silently returning False.
    """
    pkg_dir = os.path.realpath(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    target_real = os.path.realpath(target_path)
    return target_real == pkg_dir or target_real.startswith(pkg_dir + os.sep)


def find_subprocess_calls(tree: ast.AST) -> list[tuple[ast.Call, bool]]:
    """Finds all subprocess invocations in an AST tree, tracking module and function import aliases.

    Covers:
      - subprocess.run(..., shell=True)
      - import subprocess as sp; sp.run(..., shell=True)
      - from subprocess import run; run(..., shell=True)
      - from subprocess import check_call as cc; cc(..., shell=True)
      - Ignores arbitrary user objects like runner.run(...)

    Returns:
        List of (call_node, has_shell_true)
    """
    module_aliases = {"subprocess"}
    func_aliases: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess":
                    module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "subprocess":
                for alias in node.names:
                    if alias.name in ("run", "Popen", "call", "check_output", "check_call"):
                        func_aliases.add(alias.asname or alias.name)

    calls: list[tuple[ast.Call, bool]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            is_subp = False
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in module_aliases
                and node.func.attr in ("run", "Popen", "call", "check_output", "check_call")
            ):
                is_subp = True
            elif isinstance(node.func, ast.Name) and node.func.id in func_aliases:
                is_subp = True

            if is_subp:
                has_shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                calls.append((node, has_shell_true))
    return calls


class BasePhase(abc.ABC):
    """Abstract base class for hardening loop phases."""

    def __init__(
        self,
        name: PhaseName,
        version: str = "0.1.0-beta",
        method_version: str = "v0.3",
        schema_version: str = "v0.1-beta",
    ):
        self.name = name
        self.version = version
        self.method_version = method_version
        self.schema_version = schema_version

    def compute_input_hash(self, target_path: str, context: dict[str, Any]) -> str:
        target_content_hash = compute_canonical_directory_digest(target_path)
        context_payload = {
            "target_path": target_path,
            "target_content_hash": target_content_hash,
            "context": context,
        }
        return sha256_dict(context_payload)

    @abc.abstractmethod
    def execute(
        self, target_path: str, context: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str], VerificationStatus]:
        """Executes phase logic.

        Returns:
            Tuple of (payload, verification_checks, status)
        """
        pass

    def run(self, target_path: str, context: dict[str, Any], output_dir: str) -> EvidenceEnvelope:
        t0 = time.perf_counter()
        input_hash = self.compute_input_hash(target_path, context)

        payload, checks, status = self.execute(target_path, context)
        duration_ms = (time.perf_counter() - t0) * 1000.0

        output_hash = sha256_dict(payload)
        evidence_id = f"evi-{output_hash[:12]}"
        exec_ctx_hash = compute_execution_context_hash(schema_version=self.schema_version)

        canonical = CanonicalEvidence(
            evidence_id=evidence_id,
            phase=self.name,
            input_hash=input_hash,
            output_hash=output_hash,
            method_version=self.method_version,
            schema_version=self.schema_version,
            execution_context_hash=exec_ctx_hash,
            artifact_payload=payload,
        )

        runtime = RuntimeReceipt(
            producer=f"hardening-loop:{self.name.value}:{self.version}",
            timestamp=utc_now_iso(),
            duration_ms=duration_ms,
            checks=checks,
            status=status,
            error=None if status == VerificationStatus.PASS else "One or more checks failed or raised warnings.",
        )

        envelope = EvidenceEnvelope(canonical=canonical, runtime=runtime)

        # Fail-closed Schema Validation
        SchemaValidator.validate_or_raise("evidence_envelope", envelope.to_dict())

        return envelope
