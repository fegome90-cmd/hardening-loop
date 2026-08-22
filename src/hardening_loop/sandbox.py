"""Workspace boundary sandboxing and path traversal prevention (Constitución Ley VIII)."""

from __future__ import annotations

import os


class PathSandboxError(Exception):
    """Raised when a file path or directory escapes the authorized workspace boundary."""

    def __init__(self, message: str, path: str | None = None, workspace_root: str | None = None):
        self.path = path
        self.workspace_root = workspace_root
        super().__init__(message)


def assert_within_workspace(
    path: str,
    workspace_root: str | None = None,
    allow_unconfined: bool = False,
) -> str:
    """Validates that a path resides strictly within the authorized workspace boundary.

    Applies realpath canonicalization to resolve directory traversal and symlinks.
    Fails closed by default against the resolved workspace/repository root.

    Args:
        path: Path to target file or directory.
        workspace_root: Explicit authorized root directory. Defaults to os.getcwd().
        allow_unconfined: If True, explicitly bypasses the workspace boundary check.

    Returns:
        Canonical realpath of the validated path.

    Raises:
        PathSandboxError: If the resolved path escapes the authorized workspace root.
    """
    target_real = os.path.realpath(path)
    if allow_unconfined:
        return target_real

    effective_root = os.path.realpath(workspace_root) if workspace_root is not None else os.path.realpath(os.getcwd())
    root_prefix = effective_root if effective_root.endswith(os.sep) else effective_root + os.sep

    if target_real != effective_root and not target_real.startswith(root_prefix):
        raise PathSandboxError(
            f"[FAIL-CLOSED] Path '{path}' (resolved: '{target_real}') escapes workspace boundary '{effective_root}'.",
            path=path,
            workspace_root=effective_root,
        )
    return target_real
