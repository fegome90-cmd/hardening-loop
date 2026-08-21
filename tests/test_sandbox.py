"""Tests for workspace boundary sandboxing and path traversal prevention (Ley VIII)."""

import os
import tempfile

import pytest

from hardening_loop.sandbox import PathSandboxError, assert_within_workspace


def test_path_within_workspace_passes():
    with tempfile.TemporaryDirectory() as ws:
        target = os.path.join(ws, "src", "module.py")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as f:
            f.write("# code")

        canonical = assert_within_workspace(target, workspace_root=ws)
        assert canonical == os.path.realpath(target)


def test_path_traversal_escaping_workspace_fails_closed():
    with tempfile.TemporaryDirectory() as ws:
        # Path attempting to escape via ..
        escaping_path = os.path.join(ws, "..", "outside.py")
        with pytest.raises(PathSandboxError, match="escapes workspace boundary"):
            assert_within_workspace(escaping_path, workspace_root=ws)


def test_absolute_path_outside_workspace_fails_closed():
    with tempfile.TemporaryDirectory() as ws1, tempfile.TemporaryDirectory() as ws2:
        file_in_ws2 = os.path.join(ws2, "secret.py")
        with open(file_in_ws2, "w") as f:
            f.write("# secret")

        with pytest.raises(PathSandboxError, match="escapes workspace boundary"):
            assert_within_workspace(file_in_ws2, workspace_root=ws1)


def test_symlink_escaping_workspace_fails_closed():
    with tempfile.TemporaryDirectory() as ws, tempfile.TemporaryDirectory() as ext:
        outside_file = os.path.join(ext, "target.txt")
        with open(outside_file, "w") as f:
            f.write("outside")

        symlink_path = os.path.join(ws, "link_to_outside.txt")
        os.symlink(outside_file, symlink_path)

        with pytest.raises(PathSandboxError, match="escapes workspace boundary"):
            assert_within_workspace(symlink_path, workspace_root=ws)
