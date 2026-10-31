"""Pre-publish gate: nothing private leaves in this public repository.

Checks every file git would publish for secrets, private infrastructure details and personal data,
and, when given the private NCA catalogue directory, for any 8-word run of NCA control text.

    uv run python scripts/public_check.py
    uv run python scripts/public_check.py --nca-dir <private catalogue dir>   # where it exists
    uv run python scripts/public_check.py --secret-dir <dir of key files>     # compared, never printed

Exit status 0 means clean. Findings name the file and the rule, never the matched value.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

RULES: dict[str, re.Pattern[str]] = {
    "private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "github token": re.compile(r"\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}"),
    "openai-style key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    "aws access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "hugging face token": re.compile(r"\bhf_[A-Za-z0-9]{30,}"),
    "tailnet address": re.compile(r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b"),
    "server home path": re.compile(r"/home/ubuntu\b"),
    "windows user path": re.compile(r"C:[\\/]+Users[\\/]+Maste|/c/Users/Maste", re.IGNORECASE),
    "tailnet name": re.compile(r"\b[\w-]+\.ts\.net\b"),
    "email address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "bearer token literal": re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}"),
}
# Email addresses and domains that are fine to publish: generic placeholders only.
ALLOWED_EMAILS: set[str] = set()
ALLOWED_EMAIL_DOMAINS = ("example.com", "example.org", "example.test", "wahat-alramal.test")
# The first address of the shared range, used as a generic test vector.
ALLOWED_ADDRESSES = {"100.64.0.1"}
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".woff2", ".mp4", ".ico")
NGRAM = 8
MAX_KEY_FILE_BYTES = 64_000
MIN_SECRET_LINE = 16


def published_files() -> list[Path]:
    """Tracked plus untracked-but-not-ignored files: what a push or an `add -A` would publish."""
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [ROOT / line for line in sorted(set(out.splitlines())) if line]


def _text(path: Path) -> str | None:
    if path.suffix.lower() in SKIP_SUFFIXES or not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def rule_findings(files: Iterable[Path]) -> Iterator[str]:
    for path in files:
        text = _text(path)
        if text is None:
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel == "scripts/public_check.py":
            continue  # holds the patterns themselves
        for name, pattern in RULES.items():
            for match in pattern.finditer(text):
                value = match.group(0).lower()
                if name == "email address" and (
                    value in ALLOWED_EMAILS or value.endswith(ALLOWED_EMAIL_DOMAINS)
                ):
                    continue
                if name == "tailnet address" and value in ALLOWED_ADDRESSES:
                    continue
                yield f"{rel}: {name}"
                break


def secret_findings(files: Iterable[Path], secret_dir: Path) -> Iterator[str]:
    """Every non-trivial line of every file in ``secret_dir`` must appear in no published file."""
    secrets: list[str] = []
    for key_file in secret_dir.rglob("*"):
        if key_file.is_file() and key_file.stat().st_size < MAX_KEY_FILE_BYTES:
            content = key_file.read_text(encoding="utf-8", errors="ignore")
            secrets += [line.strip() for line in content.splitlines() if len(line.strip()) >= MIN_SECRET_LINE]
    for path in files:
        text = _text(path)
        if text is not None and any(secret in text for secret in secrets):
            yield f"{path.relative_to(ROOT).as_posix()}: contains a line from a key file"


def _words(text: str) -> list[str]:
    return re.findall(r"[\w؀-ۿ]+", text.lower())


# Fields of the private catalogue that carry NCA wording: statement prose, clause text, and the titles
# of controls (group titles are domain names; catalogue metadata titles are ours). Ids, props, our own
# detection and remediation notes and metadata also appear, legitimately, in the public copy.
NCA_TEXT_KEYS = frozenset({"prose", "clause_en", "clause_ar"})
CONTROL_ID = re.compile(r"^(ecc|ncnicc)-\d")
# Catalogue parts the toolkit authors wrote themselves (not NCA wording).
OWN_PARTS = frozenset({"remediation"})


def _strings(node: object, key: str | None = None) -> Iterator[str]:
    if isinstance(node, str):
        if key in NCA_TEXT_KEYS:
            yield node
    elif isinstance(node, dict):
        if node.get("name") in OWN_PARTS:
            return
        node_id = node.get("id")
        is_control = isinstance(node_id, str) and CONTROL_ID.match(node_id) is not None
        for child_key, value in node.items():
            if child_key == "title" and is_control and isinstance(value, str):
                yield value
            else:
                yield from _strings(value, child_key)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value, key)


def nca_findings(files: Iterable[Path], nca_dir: Path) -> Iterator[str]:
    """Any 8-word run shared with the private NCA catalogue text is a leak."""
    grams: set[tuple[str, ...]] = set()
    for source in nca_dir.rglob("*.json"):
        for string in _strings(json.loads(source.read_text(encoding="utf-8"))):
            words = _words(string)
            grams.update(tuple(words[i : i + NGRAM]) for i in range(len(words) - NGRAM + 1))
    for path in files:
        text = _text(path)
        if text is None:
            continue
        words = _words(text)
        if any(tuple(words[i : i + NGRAM]) in grams for i in range(len(words) - NGRAM + 1)):
            yield f"{path.relative_to(ROOT).as_posix()}: shares an {NGRAM}-word run with NCA text"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pre-publish gate for this public repository.")
    parser.add_argument("--nca-dir", type=Path, help="private catalogue directory (JSON with NCA text)")
    parser.add_argument("--secret-dir", type=Path, help="directory of key files to compare against")
    args = parser.parse_args(argv)
    files = published_files()
    findings = list(rule_findings(files))
    if args.secret_dir:
        findings += secret_findings(files, args.secret_dir)
    if args.nca_dir:
        findings += nca_findings(files, args.nca_dir)
    for finding in findings:
        print(finding)
    print(f"public_check: {len(files)} files, {len(findings)} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
