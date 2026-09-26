# repo-preflight

A small command-line tool that looks through a git repository **before you publish it** and tells you about secrets, personal data, risky files and suspicious commit dates. It is one Python file with no dependencies, and it only reads your repository. The single thing it can write is a git pre-push hook, and only when you ask for it.

It never prints a full secret. A finding shows the first characters and the length, for example `AKIA… (20 characters)`, and emails are shown as `a***@gmail.com`.

```text
$ preflight .
preflight 0.2.0: /path/to/demo
5 tracked files, 3 commits

ERROR risky-file    .env: an environment file with real values is tracked
ERROR secret        config.py:1: matches the pattern of: AWS access key id -> AKIA… (20 characters)
WARN  commit-date   3 commits on 3 different days all have the exact time 12:00:00, which usually means the dates were set by a script -> 4d5585f, 962397d, 361d3c3
WARN  hygiene       no .gitignore
WARN  personal-data notes.txt:1: an email address -> a***@gmail.com
WARN  personal-data notes.txt:2: a MAC address (a device identifier) -> AA:BB:CC:**:**:**
INFO  hygiene       no CI workflow

2 error(s), 4 warning(s), 1 note(s)
```

(That output is from a throwaway demo repository that contains deliberately fake leaks.)

## Use

```bash
python preflight.py                   # check the repository in the current folder
python preflight.py path/to/repo
python preflight.py --history         # also check everything ever added in any commit
python preflight.py --json            # machine-readable report
python preflight.py --research        # check artifacts declared in .research-evidence.json
python preflight.py --research-manifest evidence.json path/to/repo
python preflight.py --install-hook    # block `git push` when there is an error
```

After `pip install .` the command is called `preflight`. Exit status: 0 when nothing at or above `--fail-on` was found (default `error`), 1 when something was, 2 for a usage problem such as a folder that is not a repository.

## What it checks

**Secrets** (an error): AWS access key ids, GitHub tokens, Google API keys, Slack tokens, OpenAI-style and Anthropic keys, private key blocks, JSON Web Tokens, Honcho keys, and any high-entropy value assigned to a name such as `api_key`, `secret`, `token` or `password`. Obvious placeholders (`your_key_here`, `changeme`, `${VAR}`) are ignored. With `--history` it also finds a secret that was committed and deleted later, and names the commit that added it.

**Personal data** (a warning): email addresses (GitHub noreply and `example.com` addresses are fine), MAC addresses, phone numbers, IBANs and credit card numbers. IBANs must pass the mod-97 checksum, and card numbers must have a real card prefix and length and pass the Luhn checksum, so timestamps, ids and long decimals are not reported. `--no-pii` turns this group off.

**Risky files:** a tracked `.env` or `.env.*` (but not `.env.example`), `*.pem`, `*.key`, `*.p12`, `id_rsa` and similar (errors); databases (`*.sqlite`, `*.db`) and pickle files (warnings, because a pickle can run code when loaded); files over 5 MB; `.DS_Store`.

**Commit dates and authors** (`--no-dates` turns this group off):
- a commit dated in the future is an error;
- a commit dated earlier than its parent, and three or more commits on different days that all share the exact same time of day (such as `12:00:00`), are warnings, because they usually mean the dates were edited or set by a script rather than by a clock;
- an author date more than a day away from the commit date is a note (rebases and amends do this);
- commits authored with a personal email address, which becomes public, are a warning.

**Basics:** no README, LICENSE or `.gitignore` (warnings), no CI workflow (a note).

Put `preflight: ignore` in a comment on a line to silence that one line, pass `--ignore 'tests/fixtures/*'` to skip files, or list the patterns, one per line, in a `.preflightignore` file at the repository root (lines starting with `#` are comments).

## Research evidence mode

Research checks are opt-in so ordinary repository scans keep their existing scope. Add a `.research-evidence.json` file and run `preflight --research`, or pass a custom manifest with `preflight --research-manifest path/to/evidence.json`. Manifest and artifact paths are relative to the repository root and cannot resolve outside it.

The manifest can declare any combination of a dataset, model, citation and evaluation result:

```json
{
  "version": 1,
  "dataset": {
    "path": "data/packets.csv",
    "rows": 23481,
    "columns": 14,
    "required_columns": ["device_id", "payload"]
  },
  "model": {
    "path": "models/detector.tflite",
    "max_bytes": 5120
  },
  "citation": {
    "path": "CITATION.cff",
    "required_fields": ["title", "authors", "date"]
  },
  "evaluation": {
    "results": "results/metrics.json",
    "procedure": "scripts/evaluate.py",
    "metrics": {
      "accuracy": {"min": 0.9},
      "false_positive_rate": {"max": 0.05}
    }
  }
}
```

Dataset row counts exclude the header, and every CSV row must have the header's field count. Model checks can enforce a size ceiling and, optionally, a 64-character hexadecimal `sha256` digest. Citation checks confirm that required YAML-style keys are present; they do not validate citation semantics. Evaluation results must be JSON with numeric metrics either at the top level or under `metrics`; declared `min` and `max` bounds are inclusive. The optional `procedure` path is checked for existence only. Preflight never runs it, loads a model, or makes network requests. This checks that declared evidence files match simple claims in the manifest; it does not establish that a study is scientifically valid or reproduce its results.

## Pre-push hook

`preflight --install-hook` writes `.git/hooks/pre-push`, which runs the check and stops the push when it finds an error. It will not overwrite an existing hook unless you add `--force-hook`.

## Tests

```bash
python -m unittest discover -s tests
```

The tests build real temporary git repositories (with chosen commit dates and authors), so every check is exercised against actual git output. Test secrets are assembled at run time so the test file itself contains nothing that looks like one, and a final test runs the tool on its own repository.

## Limits you should know about

- **It is a first line of defence, not a replacement for a full scanner.** The secret patterns cover common formats and are not exhaustive; a secret in another format, or one that is encoded or split across lines, will be missed. For serious use, also run a dedicated tool such as gitleaks or trufflehog.
- **Warnings can be wrong.** A real contact email in your docs is reported as personal data. The date checks are heuristics: a legitimate rebase, a squash or a changed clock can trigger them, and they cannot prove that a date is wrong, only that it is unusual.
- **A found secret is already out of your control if you pushed it.** Rotate or revoke it first; rewriting history afterwards does not make it safe.
- **The history scan reads only added lines**, skips binary files and files over 2 MB, and stops after 2 million lines of history.
- It does not check other branches' working files, submodules, or anything outside git's tracked files.

## Notes

Written with AI assistance (Claude Code); the idea, the scope and the review of the checks are mine.

## License

MIT
