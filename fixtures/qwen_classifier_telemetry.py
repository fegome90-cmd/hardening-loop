#!/usr/bin/env python3
"""Classifier decision telemetry for wiki_classifier (Palanca E).

Emits ``qwen-classifier-decision/v1`` events to a JSONL ledger so the
Avoided Load Ratio is measured instead of assumed.

Guarantees (judgement-day rounds 1-2, 2026-08-21):
- Fail-closed: ANY invalid ledger line (malformed JSON, wrong shape,
  non-hex sha, blank) aborts the run. No silent skips.
- Idempotent under concurrency: dedup check + append run inside an
  exclusive ``fcntl.flock``; readers take the same lock.
- Honest metric: ``DETERMINISTIC_FIX`` keeps its own decision class; the
  ratio never counts fixes as discards.
- Stable identity: dedup key is ``document_sha`` alone.
- Atomic observation: the document is hashed before and after
  classification; any concurrent modification aborts the event.

Known residuals (accepted, operator-only tool):
- Prompt/ledger paths are caller-supplied: no confinement, symlinks
  followed. Same trust level as the rest of scripts/.
- Shadow audit / ``false_discard_rate`` (wiki spec P0) NOT implemented;
  quote the ratio as provisional until it lands.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "qwen-classifier-decision/v1"
LEDGER_PATH = Path(__file__).resolve().parent / "classifier_decisions.jsonl"
CHARS_PER_TOKEN = 4
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
VALID_DECISIONS = ("DISCARD_DETERMINISTIC", "FIX_DETERMINISTIC", "DISPATCH_TO_QWEN")
RAW_TO_DECISION = {
    "DETERMINISTIC_TRASH": "DISCARD_DETERMINISTIC",
    "DETERMINISTIC_FIX": "FIX_DETERMINISTIC",
    "NEEDS_QWEN": "DISPATCH_TO_QWEN",
}


def _document_sha(text: str) -> str:
    """Return the sha256 hex digest of the document text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _estimated_input_tokens(text: str) -> int:
    """Estimate input tokens at 4 chars per token, minimum 1."""
    return max(1, len(text) // CHARS_PER_TOKEN)


def build_decision_event(prompt_path: str) -> dict:
    """Classify one prompt file and build its telemetry event dict.

    The file is hashed before and after classification; if the content
    changed underneath us the event is rejected instead of logged with a
    hash that identifies different text than the decision.
    """
    path = Path(prompt_path)
    text_before = path.read_text(encoding="utf-8")
    document_sha = _document_sha(text_before)
    from wiki_classifier import classify_prompt

    raw_decision = classify_prompt(str(path))
    text_after = path.read_text(encoding="utf-8")
    if _document_sha(text_after) != document_sha:
        raise RuntimeError(
            f"{path}: file modified during classification; event rejected"
        )
    decision = RAW_TO_DECISION.get(raw_decision)
    if decision is None:
        raise ValueError(f"unknown raw decision: {raw_decision!r}")
    return {
        "schema_version": SCHEMA_VERSION,
        "ts": datetime.now(timezone.utc).isoformat(),
        "document_sha": document_sha,
        "path": str(path),
        "rule_id": "heuristic_v1",
        "decision": decision,
        "raw_decision": raw_decision,
        "estimated_input_tokens": _estimated_input_tokens(text_after),
    }


def _parse_ledger_line(line: str, ledger: Path, lineno: int) -> str:
    """Validate one ledger line and return its document sha. Fail-closed."""
    try:
        event = json.loads(line)
    except ValueError as exc:
        raise ValueError(f"{ledger}:{lineno}: malformed ledger line: {exc}") from exc
    if not isinstance(event, dict):
        raise ValueError(f"{ledger}:{lineno}: event must be a dict")
    document_sha = event.get("document_sha")
    if not isinstance(document_sha, str) or not SHA256_HEX.fullmatch(document_sha):
        raise ValueError(f"{ledger}:{lineno}: invalid document_sha")
    return document_sha


def load_seen_keys(ledger: Path) -> set[str]:
    """Return the document shas already present in the ledger.

    Fail-closed: ANY invalid line - malformed JSON, wrong shape, bad sha,
    blank - raises ``ValueError`` with path and line number.
    """
    seen: set[str] = set()
    if not ledger.exists():
        return seen
    for lineno, line in enumerate(
        ledger.read_text(encoding="utf-8").splitlines(), start=1
    ):
        seen.add(_parse_ledger_line(line, ledger, lineno))
    return seen


def log_decision(prompt_path: str, ledger: Path = LEDGER_PATH) -> dict | None:
    """Build the event for ``prompt_path`` and append it to ``ledger``.

    The dedup check and the append both run inside an exclusive flock on
    ``<ledger>.lock``, so concurrent callers cannot duplicate events.
    Returns None when the document sha is already logged; otherwise the
    appended event.
    """
    event = build_decision_event(prompt_path)
    lock_path = ledger.with_name(ledger.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        try:
            if event["document_sha"] in load_seen_keys(ledger):
                return None
            with ledger.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, sort_keys=True) + "\n")
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)
    return event


def _validate_event(event: object, source: str) -> dict:
    """Validate one ledger event for metric aggregation. Fail-closed."""
    if not isinstance(event, dict):
        raise ValueError(f"{source}: event must be a dict")
    decision = event.get("decision")
    if decision not in VALID_DECISIONS:
        raise ValueError(f"{source}: invalid decision {decision!r}")
    tokens = event.get("estimated_input_tokens")
    if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 1:
        raise ValueError(f"{source}: invalid estimated_input_tokens {tokens!r}")
    return event


def read_events(ledger: Path) -> list[dict]:
    """Read every ledger event under the exclusive lock. Fail-closed."""
    lock_path = ledger.with_name(ledger.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        try:
            if not ledger.exists():
                return []
            events: list[dict] = []
            for lineno, line in enumerate(
                ledger.read_text(encoding="utf-8").splitlines(), start=1
            ):
                try:
                    event = json.loads(line)
                except ValueError as exc:
                    raise ValueError(
                        f"{ledger}:{lineno}: malformed ledger line: {exc}"
                    ) from exc
                if not isinstance(event, dict):
                    raise ValueError(f"{ledger}:{lineno}: event must be a dict")
                document_sha = event.get("document_sha")
                if not isinstance(document_sha, str) or not SHA256_HEX.fullmatch(
                    document_sha
                ):
                    raise ValueError(f"{ledger}:{lineno}: invalid document_sha")
                events.append(event)
            return events
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)


def avoided_load_ratio(events: list[dict]) -> float | None:
    """Return the Qwen-load-avoided ratio: non-dispatch tokens / total.

    Counts ``DISCARD_DETERMINISTIC`` and ``FIX_DETERMINISTIC`` as avoided
    Qwen load; only ``DISPATCH_TO_QWEN`` events count as load served.
    Raises ``ValueError`` on any invalid event (no silent coercion).
    """
    if not events:
        return None
    validated = [_validate_event(e, f"events[{i}]") for i, e in enumerate(events)]
    total = sum(e["estimated_input_tokens"] for e in validated)
    if total == 0:
        return None
    avoided = sum(
        e["estimated_input_tokens"]
        for e in validated
        if e["decision"] != "DISPATCH_TO_QWEN"
    )
    return avoided / total


def main(argv: list[str] | None = None) -> int:
    """CLI: scan prompts into the ledger and optionally print the ratio."""
    parser = argparse.ArgumentParser(
        description="Log wiki_classifier decisions (Palanca E telemetry)"
    )
    parser.add_argument(
        "--scan", required=True, help="Prompt file or directory of .md prompts"
    )
    parser.add_argument(
        "--summary", action="store_true", help="Print Avoided Load Ratio after scanning"
    )
    args = parser.parse_args(argv)
    root = Path(args.scan)
    paths = sorted(root.rglob("*.md")) if root.is_dir() else [root]
    logged = 0
    for prompt_path in paths:
        if log_decision(str(prompt_path)) is not None:
            logged += 1
    if args.summary:
        events = [e for e in read_events(LEDGER_PATH)]
        ratio = avoided_load_ratio(events)
        print(f"events={len(events)} logged_now={logged} avoided_load_ratio={ratio}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
