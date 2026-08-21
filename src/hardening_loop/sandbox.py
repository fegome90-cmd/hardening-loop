"""Workspace boundary sandboxing and path traversal prevention (Constitución Ley VIII)."""

from __future__ import annotations

import os


class PathSandboxError(Exception):
    """Raised when a file path or directory escapes the authorized workspace boundary."""

    def __init__(self, message: str, path: str | None = None, workspace_root: str | None = None):
        self.path = path
        self.workspace_root = workspace_root
        super().__init__(message)


def assert_within_workspace(path: str, workspace_root: str | None = None) -> str:
    """Validates that a path resides strictly within the authorized workspace boundary.

    Applies realpath canonicalization to resolve directory traversal and symlinks.
    Fails closed if the path escapes the workspace root when workspace_root is specified.

    Args:
        path: Path to target file or directory.
        workspace_root: Authorized root directory (if None, boundary check is bypassed).

    Returns:
        Canonical realpath of the validated path.

    Raises:
        PathSandboxError: If the resolved path escapes the specified workspace root.
    """
    target_real = os.path.realpath(path)
    if workspace_root is None:
        return target_real

    ws_root = os.path.realpath(workspace_root)
    ws_root_prefix = ws_root if ws_root.endswith(os.sep) else ws_root + os.sep

    # A target is within workspace if it equals ws_root or starts with ws_root_prefix
    if target_real != ws_root and not target_real.startswith(ws_root_prefix):
        raise PathSandboxError(
            f"[FAIL-CLOSED] Path '{path}' (resolved: '{target_real}') escapes workspace boundary '{ws_root}'.",
            path=path,
            workspace_root=ws_root,
        )

    return target_real
