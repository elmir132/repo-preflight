#!/usr/bin/env python3
"""preflight: look through a git repository for secrets, personal data and odd commit dates
before you publish it.

It never prints a full secret: findings show only the first characters and the length.
It only reads your repository; the one thing it can write is a pre-push hook, and only when
you ask for it with --install-hook.
"""
import argparse
import json
import math
import os
import re
import stat
import subprocess
import sys
import time
from collections import defaultdict

__version__ = "0.1.0"

LEVELS = {"info": 0, "warn": 1, "error": 2}
MAX_TEXT_BYTES = 2 * 1024 * 1024
BIG_FILE_BYTES = 5 * 1024 * 1024
IGNORE_MARK = "preflight: ignore"

SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b")),
    ("OpenAI-style API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Honcho API key", re.compile(r"\bhch-v\d+-[A-Za-z0-9]{40,}\b")),
]
ASSIGNMENT = re.compile(
    r"""(?ix)\b([A-Za-z0-9_.-]*(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)[A-Za-z0-9_.-]*)
        \s*[:=]\s*["']([^"'\s]{16,})["']""")
PLACEHOLDER = re.compile(r"(?i)(your|example|sample|placeholder|changeme|dummy|xxxx|\*\*\*|<|>|\$\{|%\(|redacted|todo)")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")
SAFE_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "localhost", "users.noreply.github.com", "noreply.github.com")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
PHONE = re.compile(r"(?<![\w.])(?:\+\d{1,3}[ -]?)?(?:\(\d{3}\)[ -]?|\d{3}[ -])\d{3}[ -]\d{4}(?![\w])")
INTL_PHONE = re.compile(r"(?<![\w.])\+\d{1,3}(?:[ -]?\d){9,12}(?![\w])")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b")
CARD = re.compile(r"(?<![\w.\-])(?:\d[ -]?){12,18}\d(?![\w\-]|\.?\d)")

RISKY_NAMES = [
    (".env", "error", "an environment file with real values is tracked"),
    ("*.pem", "error", "a PEM file (often a private key) is tracked"),
    ("*.key", "error", "a key file is tracked"),
    ("*.p12", "error", "a certificate bundle with a private key is tracked"),
    ("*.pfx", "error", "a certificate bundle with a private key is tracked"),
    ("id_rsa*", "error", "an SSH private key is tracked"),
    ("id_ed25519*", "error", "an SSH private key is tracked"),
    ("*.sqlite", "warn", "a database file is tracked; it may hold personal data"),
    ("*.sqlite3", "warn", "a database file is tracked; it may hold personal data"),
    ("*.db", "warn", "a database file is tracked; it may hold personal data"),
    ("*.pkl", "warn", "a pickle file is tracked; loading an unknown pickle can run code"),
    ("*.pickle", "warn", "a pickle file is tracked; loading an unknown pickle can run code"),
    (".DS_Store", "info", "a macOS folder file is tracked"),
]
TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")


class PreflightError(Exception):
    pass


def git(root, *args, check=True):
    result = subprocess.run(["git", "-C", root] + list(args), capture_output=True)
    if check and result.returncode != 0:
        raise PreflightError(result.stderr.decode("utf-8", "replace").strip() or "git failed")
    return result.stdout


def mask(value):
    value = str(value)
    return f"{value[:4]}… ({len(value)} characters)" if len(value) > 8 else "*" * len(value)


def mask_email(address):
    local, _, domain = address.partition("@")
    return f"{local[:1]}***@{domain}"


def entropy(text):
    counts = {c: text.count(c) for c in set(text)}
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def luhn_ok(digits):
    total = 0
    for index, ch in enumerate(reversed(digits)):
        n = int(ch)
        if index % 2:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
    return total % 10 == 0


def card_shape_ok(digits):
    """Real card numbers start with a known prefix and have a known length. This keeps
    timestamps, ids and long decimals that happen to pass the checksum from being reported."""
    n = len(digits)
    if digits[0] == "4":
        return n in (13, 16, 19)
    if digits[:2] in ("34", "37"):
        return n == 15
    if 51 <= int(digits[:2]) <= 55 or 2221 <= int(digits[:4]) <= 2720:
        return n == 16
    if digits[:4] == "6011" or digits[:2] == "65":
        return n in (16, 19)
    return False


def iban_ok(text):
    compact = text.replace(" ", "")
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    number = "".join(str(int(c, 36)) for c in rearranged)
    return int(number) % 97 == 1


def finding(level, check, message, path=None, line=None, detail=None, commit=None):
    item = {"level": level, "check": check, "message": message}
    for key, value in (("path", path), ("line", line), ("detail", detail), ("commit", commit)):
        if value is not None:
            item[key] = value
    return item


def scan_line(text, pii=True):
    """Yield (check, message, masked detail) for everything suspicious on one line."""
    if IGNORE_MARK in text:
        return
    for name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            yield "secret", f"matches the pattern of: {name}", mask(match.group(0))
    for match in ASSIGNMENT.finditer(text):
        value = match.group(2)
        if not PLACEHOLDER.search(value) and entropy(value) >= 3.5:
            yield "secret", f"a value that looks like a real secret is assigned to '{match.group(1)}'", mask(value)
    if not pii:
        return
    for match in EMAIL.finditer(text):
        domain = match.group(1).lower()
        if not any(domain == safe or domain.endswith("." + safe) for safe in SAFE_EMAIL_DOMAINS):
            yield "personal-data", "an email address", mask_email(match.group(0))
    for match in MAC.finditer(text):
        raw = re.sub(r"[:-]", "", match.group(0)).lower()
        if len(set(raw)) > 2:
            yield "personal-data", "a MAC address (a device identifier)", match.group(0)[:8] + ":**:**:**"
    spans = []
    for pattern in (PHONE, INTL_PHONE):  # a number both patterns match is reported once
        for match in pattern.finditer(text):
            if not any(match.start() < end and start < match.end() for start, end in spans):
                spans.append((match.start(), match.end()))
                yield "personal-data", "a phone number", match.group(0)[:4] + "…"
    for match in IBAN.finditer(text):
        if iban_ok(match.group(0)):
            yield "personal-data", "a valid IBAN (bank account number)", match.group(0)[:4] + "… (" + str(len(match.group(0).replace(" ", ""))) + " characters)"
    for match in CARD.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and card_shape_ok(digits) and luhn_ok(digits) and len(set(digits)) > 1:
            yield "personal-data", "a number that passes the credit card checksum", digits[:4] + "… (" + str(len(digits)) + " digits)"


def is_text(data):
    return b"\x00" not in data[:8192]


def file_findings(root, paths, pii=True, ignore=()):
    findings = []
    for path in paths:
        if any(match_glob(path, pattern) for pattern in ignore):
            continue
        base = os.path.basename(path)
        for pattern, level, message in RISKY_NAMES:
            if match_glob(base, pattern) and not base.endswith(TEMPLATE_SUFFIXES):
                findings.append(finding(level, "risky-file", message, path=path))
        if base.startswith(".env.") and not base.endswith(TEMPLATE_SUFFIXES):
            findings.append(finding("error", "risky-file", "an environment file with real values is tracked", path=path))
        full = os.path.join(root, path)
        try:
            size = os.path.getsize(full)
        except OSError:
            continue
        if size > BIG_FILE_BYTES:
            findings.append(finding("warn", "large-file", f"file is {size / 1024 / 1024:.1f} MB", path=path))
        if size > MAX_TEXT_BYTES:
            continue
        try:
            with open(full, "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        if not is_text(data):
            continue
        for number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            for check, message, detail in scan_line(line, pii):
                findings.append(finding("error" if check == "secret" else "warn", check, message, path=path, line=number, detail=detail))
    return findings


def match_glob(name, pattern):
    from fnmatch import fnmatch
    return fnmatch(name, pattern) or fnmatch(os.path.basename(name), pattern)


def history_findings(root, pii=True, ignore=(), limit_lines=2_000_000):
    """Everything ever added in any commit, reported once, with the commit that added it."""
    seen, findings = set(), []
    process = subprocess.Popen(["git", "-C", root, "log", "--all", "--no-color", "-p", "-U0", "--format=@@@%H"],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    commit, path, count = "", "", 0
    for raw in process.stdout:
        count += 1
        if count > limit_lines:
            findings.append(finding("info", "history", f"history scan stopped after {limit_lines} lines"))
            process.kill()
            break
        line = raw.decode("utf-8", "replace").rstrip("\n")
        if line.startswith("@@@"):
            commit = line[3:10]
        elif line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else ""
        elif line.startswith("+") and path and not any(match_glob(path, p) for p in ignore):
            for check, message, detail in scan_line(line[1:], pii):
                key = (check, message, path, detail)
                if key not in seen:
                    seen.add(key)
                    findings.append(finding("error" if check == "secret" else "warn", check, message + " (in history)", path=path, detail=detail, commit=commit))
    process.wait()
    return findings


def commits(root):
    out = git(root, "log", "--all", "--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%cI%x1f%ct%x1f%at%x1f%P", check=False).decode("utf-8", "replace")
    rows = []
    for line in out.splitlines():
        parts = line.split("\x1f")
        if len(parts) == 8:
            rows.append({"sha": parts[0], "name": parts[1], "email": parts[2], "author_iso": parts[3], "committer_iso": parts[4],
                         "committed": int(parts[5]), "authored": int(parts[6]), "parents": parts[7].split()})
    return rows


def date_findings(rows, now=None, ignore_noreply=True):
    findings = []
    now = time.time() if now is None else now
    by_sha = {r["sha"]: r for r in rows}
    future = [r for r in rows if max(r["authored"], r["committed"]) > now + 300]
    for r in future:
        when = max(r["author_iso"], r["committer_iso"])[:10]
        findings.append(finding("error", "commit-date", f"commit is dated in the future ({when})", commit=r["sha"][:7]))
    backwards = [r for r in rows if any(p in by_sha and r["committed"] < by_sha[p]["committed"] for p in r["parents"])]
    if backwards:
        findings.append(finding("warn", "commit-date", f"{len(backwards)} commit(s) are dated earlier than their parent, which happens after a history rewrite or with a wrong clock",
                                detail=", ".join(r["sha"][:7] for r in backwards[:5])))
    gaps = [r for r in rows if abs(r["authored"] - r["committed"]) > 24 * 3600]
    if gaps:
        findings.append(finding("info", "commit-date", f"{len(gaps)} commit(s) have an author date more than a day away from the commit date (rebases and amends do this)",
                                detail=", ".join(r["sha"][:7] for r in gaps[:5])))
    clock = defaultdict(list)
    for r in rows:
        clock[r["author_iso"][11:19]].append(r)
    for stamp, group in clock.items():
        days = {r["author_iso"][:10] for r in group}
        if len(group) >= 3 and len(days) >= 3:
            findings.append(finding("warn", "commit-date", f"{len(group)} commits on {len(days)} different days all have the exact time {stamp}, which usually means the dates were set by a script",
                                    detail=", ".join(r["sha"][:7] for r in group[:5])))
    emails = sorted({r["email"] for r in rows if not r["email"].lower().endswith(("@users.noreply.github.com", "@noreply.github.com"))})
    for email in emails:
        findings.append(finding("warn", "author-email", "commits are authored with a personal email address, which becomes public", detail=mask_email(email)))
    return findings


def hygiene_findings(root, paths):
    names = {os.path.basename(p).lower() for p in paths}
    findings = []
    if not any(n.startswith("readme") for n in names):
        findings.append(finding("warn", "hygiene", "no README"))
    if not any(n.startswith(("license", "copying")) for n in names):
        findings.append(finding("warn", "hygiene", "no LICENSE file, so others have no right to reuse the code"))
    if ".gitignore" not in names:
        findings.append(finding("warn", "hygiene", "no .gitignore"))
    if not any(p.startswith(".github/workflows/") for p in paths):
        findings.append(finding("info", "hygiene", "no CI workflow"))
    return findings


def run(root, history=False, pii=True, dates=True, ignore=(), now=None):
    root = os.path.abspath(root)
    try:
        top = git(root, "rev-parse", "--show-toplevel").decode().strip()
    except PreflightError:
        raise PreflightError(f"{root} is not inside a git repository")
    paths = [p for p in git(top, "ls-files", "-z").decode("utf-8", "replace").split("\x00") if p]
    findings = file_findings(top, paths, pii, ignore) + hygiene_findings(top, paths)
    if history:
        findings += history_findings(top, pii, ignore)
    rows = commits(top)
    if dates:
        findings += date_findings(rows, now)
    findings.sort(key=lambda f: (-LEVELS[f["level"]], f["check"], f.get("path", ""), f.get("line", 0)))
    return {"root": top, "files": len(paths), "commits": len(rows), "findings": findings}


def render(report):
    lines = [f"preflight {__version__}: {report['root']}", f"{report['files']} tracked files, {report['commits']} commits", ""]
    if not report["findings"]:
        lines.append("Nothing found.")
    for f in report["findings"]:
        where = f.get("path", "")
        if "line" in f:
            where += f":{f['line']}"
        if "commit" in f:
            where += f" [{f['commit']}]"
        detail = f" -> {f['detail']}" if "detail" in f else ""
        lines.append(f"{f['level'].upper():5} {f['check']:13} {where + ': ' if where else ''}{f['message']}{detail}")
    counts = {level: sum(1 for f in report["findings"] if f["level"] == level) for level in ("error", "warn", "info")}
    lines += ["", f"{counts['error']} error(s), {counts['warn']} warning(s), {counts['info']} note(s)"]
    return "\n".join(lines)


HOOK = """#!/bin/sh
# Installed by preflight. Blocks a push when preflight finds an error.
exec python3 "{script}" --fail-on error "$(git rev-parse --show-toplevel)"
"""


def install_hook(root, force=False):
    top = git(root, "rev-parse", "--show-toplevel").decode().strip()
    hooks = git(top, "rev-parse", "--git-path", "hooks").decode().strip()
    hooks = hooks if os.path.isabs(hooks) else os.path.join(top, hooks)
    os.makedirs(hooks, exist_ok=True)
    target = os.path.join(hooks, "pre-push")
    if os.path.exists(target) and not force:
        raise PreflightError(f"{target} already exists; use --force-hook to replace it")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(HOOK.format(script=os.path.abspath(__file__)))
    os.chmod(target, os.stat(target).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return target


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("path", nargs="?", default=".", help="the repository (default: current directory)")
    ap.add_argument("--history", action="store_true", help="also scan everything ever added in any commit (slower)")
    ap.add_argument("--no-pii", action="store_true", help="skip personal-data checks (emails, MAC addresses, phone numbers, IBANs, card numbers)")
    ap.add_argument("--no-dates", action="store_true", help="skip the commit date and author checks")
    ap.add_argument("--ignore", action="append", default=[], metavar="GLOB", help="skip files matching this pattern (repeatable)")
    ap.add_argument("--fail-on", choices=["error", "warn", "never"], default="error", help="exit with status 1 at this level (default: error)")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--install-hook", action="store_true", help="install a git pre-push hook that runs this check")
    ap.add_argument("--force-hook", action="store_true", help="replace an existing pre-push hook")
    ap.add_argument("--version", action="version", version=f"preflight {__version__}")
    args = ap.parse_args(argv)
    try:
        if args.install_hook:
            print(f"installed {install_hook(args.path, args.force_hook)}")
            return 0
        report = run(args.path, args.history, not args.no_pii, not args.no_dates, args.ignore)
    except PreflightError as err:
        print(f"preflight: {err}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2) if args.json else render(report))
    if args.fail_on == "never":
        return 0
    worst = max((LEVELS[f["level"]] for f in report["findings"]), default=-1)
    return 1 if worst >= LEVELS[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
