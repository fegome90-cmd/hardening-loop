"""Workspace boundary sandboxing and path traversal prevention (Constitución Ley VIII)."""

from __future__ import annotations

import os
import tempfile


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
    Fails closed by default against the current workspace and system temp directory.

    Args:
        path: Path to target file or directory.
        workspace_root: Explicit authorized root directory. If specified, path must be strictly inside.
        allow_unconfined: If True, explicitly bypasses the workspace boundary check.

    Returns:
        Canonical realpath of the validated path.

    Raises:
        PathSandboxError: If the resolved path escapes the authorized workspace root.
    """
    target_real = os.path.realpath(path)
    if allow_unconfined:
        return target_real

    # 1. Explicit workspace_root provided: strictly enforce boundary
    if workspace_root is not None:
        ws_root = os.path.realpath(workspace_root)
        ws_prefix = ws_root if ws_root.endswith(os.sep) else ws_root + os.sep
        if target_real != ws_root and not target_real.startswith(ws_prefix):
            raise PathSandboxError(
                f"[FAIL-CLOSED] Path '{path}' (resolved: '{target_real}') escapes workspace boundary '{ws_root}'.",
                path=path,
                workspace_root=ws_root,
            )
        return target_real

    # 2. Default fail-closed mode: path must be within current working directory OR system temp dir
    cwd_root = os.path.realpath(os.getcwd())
    cwd_prefix = cwd_root if cwd_root.endswith(os.sep) else cwd_root + os.sep

    temp_root = os.path.realpath(tempfile.gettempdir())
    temp_prefix = temp_root if temp_root.endswith(os.sep) else temp_root + os.sep

    # Check against cwd
    if target_real == cwd_root or target_real.startswith(cwd_prefix):
        return target_real

    # Check against system tempdir
    if target_real == temp_root or target_real.startswith(temp_prefix):
        return target_real

    # On macOS, /tmp and /var are symlinks to /private/tmp and /private/var
    for extra_temp in ("/tmp", "/var/tmp", "/private/tmp", "/private/var"):
        if os.path.exists(extra_temp):
            real_extra = os.path.realpath(extra_temp)
            extra_prefix = real_extra if real_extra.endswith(os.sep) else real_extra + os.sep
            if target_real == real_extra or target_real.startswith(extra_prefix):
                return target_real

    raise PathSandboxError(
        f"[FAIL-CLOSED] Path '{path}' (resolved: '{target_real}') escapes default workspace boundary '{cwd_root}'.",
        path=path,
        workspace_root=cwd_root,
    )
