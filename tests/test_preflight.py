import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import preflight as pf  # noqa: E402

# Test secrets are assembled at run time so this file itself contains nothing that looks like one.
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GITHUB = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC2eF4hJ6"
GOOGLE = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
SLACK = "xoxb-" + "123456789012-abcdefghijkl"
OPENAI = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
ANTHROPIC = "sk-ant-" + "api03-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
PRIVATE_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----"
JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + "." + "abcdefghijklmnop"
HONCHO = "hch-v3-" + "fty3dumjw7feal3ppru443cojnej1qnjvffw597t5ui3o5tjdl7vfatq15wbf0ob"
EMAIL = "someone" + "@" + "gmail.com"


class Repo:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="preflight-test-")
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "123+test@users.noreply.github.com")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args, env=None):
        return subprocess.run(["git", "-C", self.dir] + list(args), capture_output=True, check=True, env=env)

    def write(self, name, content="", binary=False):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb" if binary else "w") as handle:
            handle.write(content)
        return path

    def commit(self, message="change", date="2026-10-01T10:15:30 +0000", committer_date=None, email=None):
        env = dict(os.environ, GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=committer_date or date)
        if email:
            env.update(GIT_AUTHOR_EMAIL=email, GIT_COMMITTER_EMAIL=email)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message, env=env)

    def clean_base(self):
        self.write("README.md", "# demo\n")
        self.write("LICENSE", "MIT\n")
        self.write(".gitignore", ".env\n")
        self.write(".github/workflows/ci.yml", "name: ci\n")
        self.commit("base")

    def report(self, **kwargs):
        return pf.run(self.dir, **kwargs)

    def checks(self, **kwargs):
        return [(f["level"], f["check"]) for f in self.report(**kwargs)["findings"]]


class PreflightCase(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()
        self.addCleanup(shutil.rmtree, self.repo.dir, True)

    def messages(self, **kwargs):
        return [f["message"] for f in self.repo.report(**kwargs)["findings"]]


class SecretTests(PreflightCase):
    def test_a_clean_repository_has_no_findings(self):
        self.repo.clean_base()
        self.assertEqual(self.repo.report()["findings"], [])

    def test_every_known_secret_format_is_found_and_never_printed_in_full(self):
        secrets = {"AWS access key id": AWS, "GitHub token": GITHUB, "Google API key": GOOGLE, "Slack token": SLACK,
                   "OpenAI-style API key": OPENAI, "Anthropic API key": ANTHROPIC, "Private key block": PRIVATE_KEY,
                   "JSON Web Token": JWT, "Honcho API key": HONCHO}
        self.repo.clean_base()
        self.repo.write("config.txt", "\n".join(f"line {i}: {value}" for i, value in enumerate(secrets.values())) + "\n")
        self.repo.commit("add config")
        report = self.repo.report()
        text = json.dumps(report) + pf.render(report)
        found = [f["message"] for f in report["findings"] if f["check"] == "secret"]
        for name in secrets:
            self.assertTrue(any(name in m for m in found), name)
        for name, value in secrets.items():
            if len(value) > 20:
                self.assertNotIn(value, text, name)
        self.assertTrue(all(f["level"] == "error" for f in report["findings"] if f["check"] == "secret"))

    def test_findings_carry_the_file_and_line(self):
        self.repo.clean_base()
        self.repo.write("src/app.py", f"import os\n\nKEY = '{AWS}'\n")
        self.repo.commit("add")
        item = next(f for f in self.repo.report()["findings"] if f["check"] == "secret")
        self.assertEqual((item["path"], item["line"]), ("src/app.py", 3))
        self.assertTrue(item["detail"].startswith("AKIA"))

    def test_assigned_high_entropy_values_are_flagged_but_placeholders_are_not(self):
        self.repo.clean_base()
        self.repo.write("settings.py", "api_key = \"q9Zr7TxB3mLw8VnC2dKs5HpY\"\nsecret = 'your_secret_goes_here_now'\n"
                                       "password: \"changeme-changeme-123\"\ntoken = \"aaaaaaaaaaaaaaaaaaaaaaaa\"\n"
                                       "TOKEN_URL = \"https://example.com/oauth/token\"\n")
        self.repo.commit("settings")
        lines = [f["line"] for f in self.repo.report()["findings"] if f["check"] == "secret"]
        self.assertEqual(lines, [1])

    def test_an_ignore_comment_silences_one_line(self):
        self.repo.clean_base()
        self.repo.write("docs.md", f"example {AWS}  preflight: ignore\nreal {AWS}\n")
        self.repo.commit("docs")
        self.assertEqual([f["line"] for f in self.repo.report()["findings"] if f["check"] == "secret"], [2])

    def test_a_secret_removed_later_is_still_found_in_history_only(self):
        self.repo.clean_base()
        self.repo.write("a.txt", f"token {GITHUB}\n")
        self.repo.commit("oops")
        self.repo.write("a.txt", "token removed\n")
        self.repo.commit("fix")
        self.assertNotIn("secret", [c for _, c in self.repo.checks()])
        history = [f for f in self.repo.report(history=True)["findings"] if f["check"] == "secret"]
        self.assertEqual(len(history), 1)
        self.assertIn("(in history)", history[0]["message"])
        self.assertEqual(history[0]["path"], "a.txt")
        self.assertTrue(history[0]["commit"])
        self.assertNotIn(GITHUB, json.dumps(history))

    def test_binary_and_huge_text_files_are_not_scanned_as_text(self):
        self.repo.clean_base()
        self.repo.write("blob.bin", b"\x00\x01" + AWS.encode(), binary=True)
        self.repo.write("big.txt", "x" * (pf.MAX_TEXT_BYTES + 10) + AWS)
        self.repo.commit("blobs")
        self.assertNotIn("secret", [c for _, c in self.repo.checks()])


class PersonalDataTests(PreflightCase):
    def found(self, text):
        """The personal-data findings for a repository holding just this text (a fresh one each call)."""
        repo = Repo()
        self.addCleanup(shutil.rmtree, repo.dir, True)
        repo.clean_base()
        repo.write("notes.txt", text)
        repo.commit("notes")
        self.last_report = repo.report()
        return [f["message"] for f in self.last_report["findings"] if f["check"] == "personal-data"]

    def test_emails(self):
        self.assertEqual(len(self.found(f"mail {EMAIL}\n")), 1)
        self.assertEqual(self.found("a@example.com 123+x@users.noreply.github.com b@mail.example.org\n"), [])
        self.found(f"mail {EMAIL}\n")
        self.assertNotIn("someone", json.dumps(self.last_report))     # masked: only the first letter shows

    def test_mac_addresses(self):
        self.assertEqual(len(self.found("device AA:BB:CC:11:22:33 seen\n")), 1)
        self.assertEqual(self.found("zero 00:00:00:00:00:00 and ff:ff:ff:ff:ff:ff\n"), [])

    def test_phone_numbers(self):
        self.assertEqual(len(self.found("call (212) 555-0142 today\n")), 1)
        self.assertEqual(len(self.found("call +1 212-555-0142\n")), 1)
        self.assertEqual(self.found("version 1.2.3 and 2026-10-13 and 12345\n"), [])

    def test_iban_must_pass_its_checksum(self):
        self.assertEqual(len(self.found("pay DE89 3704 0044 0532 0130 00 please\n")), 1)
        self.assertEqual(self.found("pay DE89 3704 0044 0532 0130 01 please\n"), [])

    def test_card_numbers_must_pass_the_luhn_checksum(self):
        self.assertEqual(len(self.found("card 4111 1111 1111 1111\n")), 1)
        self.assertEqual(self.found("order 4111 1111 1111 1112\n"), [])
        self.assertEqual(self.found("zeros 0000 0000 0000 0000\n"), [])

    def test_numbers_that_only_look_like_cards_are_not_reported(self):
        for text in ("timestamp 1790000000000 ms\n",                           # 13 digits, not a card prefix
                     '"scaler_mean": [0.46380123456789, -1.2231987654321]\n',   # long decimals
                     "order 4111111111111111.5 units\n"):                       # a decimal, not a card
            self.assertEqual(self.found(text), [], text)
        self.assertEqual(len(self.found("card 4111111111111111.\n")), 1)         # a sentence end is fine
        self.assertEqual(len(self.found("amex 378282246310005 on file\n")), 1)

    def test_package_versions_are_not_email_addresses(self):
        self.assertEqual(self.found("platform = espressif32@6.6.0 and pkg@1.2.3\n"), [])

    def test_a_number_matched_by_both_phone_patterns_is_reported_once(self):
        self.assertEqual(len(self.found("call +1 212-555-0142 now\n")), 1)

    def test_no_pii_switch(self):
        self.repo.clean_base()
        self.repo.write("n.txt", f"{EMAIL} AA:BB:CC:11:22:33\n")
        self.repo.commit("n")
        self.assertEqual([c for _, c in self.repo.checks(pii=False)], [])


class FileAndHygieneTests(PreflightCase):
    def test_risky_files(self):
        self.repo.clean_base()
        for name in (".env", ".env.local", "keys/server.pem", "id_rsa", "app.sqlite", "model.pkl", ".DS_Store"):
            self.repo.write(name, "x")
        self.repo.write(".env.example", "KEY=\n")
        self.repo.git("add", "-f", ".env")          # .gitignore keeps .env out, so force it in as a mistake would
        self.repo.commit("files", date="2026-10-02T10:15:30 +0000")
        by_path = {f["path"]: f["level"] for f in self.repo.report()["findings"] if f["check"] == "risky-file"}
        self.assertEqual(by_path, {".env": "error", ".env.local": "error", "keys/server.pem": "error", "id_rsa": "error",
                                   "app.sqlite": "warn", "model.pkl": "warn", ".DS_Store": "info"})

    def test_large_files(self):
        self.repo.clean_base()
        self.repo.write("data.bin", b"\x00" * (pf.BIG_FILE_BYTES + 1), binary=True)
        self.repo.commit("big")
        self.assertIn(("warn", "large-file"), self.repo.checks())

    def test_missing_readme_license_gitignore_and_ci(self):
        self.repo.write("main.py", "print(1)\n")
        self.repo.commit("code")
        messages = self.messages()
        for expected in ("no README", "no LICENSE", "no .gitignore", "no CI workflow"):
            self.assertTrue(any(m.startswith(expected) for m in messages), expected)

    def test_a_preflightignore_file_skips_files_and_allows_comments(self):
        self.repo.clean_base()
        self.repo.write(".preflightignore", "# test fixtures hold fake numbers on purpose\n\ntests/*\n")
        self.repo.write("tests/fixture.txt", f"{AWS}\n")
        self.repo.write("real.txt", f"{AWS}\n")
        self.repo.commit("ignore file")
        paths = [f["path"] for f in self.repo.report()["findings"] if f["check"] == "secret"]
        self.assertEqual(paths, ["real.txt"])
        self.assertEqual(pf.read_ignore_file(self.repo.dir), ["tests/*"])
        self.assertEqual(pf.read_ignore_file(tempfile.gettempdir() + "/no-such-folder"), [])

    def test_ignore_globs_skip_files(self):
        self.repo.clean_base()
        self.repo.write("tests/fixtures/sample.txt", f"{AWS}\n")
        self.repo.write("real.txt", f"{AWS}\n")
        self.repo.commit("fixtures")
        paths = [f["path"] for f in self.repo.report(ignore=["tests/*"])["findings"] if f["check"] == "secret"]
        self.assertEqual(paths, ["real.txt"])


class DateTests(PreflightCase):
    def test_a_future_dated_commit_is_an_error(self):
        self.repo.clean_base()
        self.repo.write("a.txt", "a")
        self.repo.commit("later", date="2099-11-11T10:00:00 +0000")
        findings = [f for f in self.repo.report()["findings"] if f["check"] == "commit-date" and f["level"] == "error"]
        self.assertEqual(len(findings), 1)
        self.assertIn("2099-11-11", findings[0]["message"])

    def test_commits_that_all_share_one_exact_time_of_day_are_flagged(self):
        self.repo.write("README.md", "x")
        self.repo.write("LICENSE", "x")
        self.repo.write(".gitignore", "x")
        for day in ("2026-01-20", "2026-01-21", "2026-01-22"):
            self.repo.write(f"{day}.txt", day)
            self.repo.commit(day, date=f"{day}T12:00:00 -0500")
        item = next(f for f in self.repo.report()["findings"] if f["check"] == "commit-date")
        self.assertEqual(item["level"], "warn")
        self.assertIn("exact time 12:00:00", item["message"])

    def test_two_matching_times_or_one_day_are_not_enough(self):
        self.repo.clean_base()
        for day in ("2026-02-01", "2026-02-02"):
            self.repo.write(f"{day}.txt", day)
            self.repo.commit(day, date=f"{day}T12:00:00 +0000")
        for n in range(4):
            self.repo.write(f"same{n}.txt", "x")
            self.repo.commit(f"same{n}", date="2026-03-01T09:00:00 +0000")
        self.assertNotIn("exact time", " ".join(self.messages()))

    def test_a_commit_dated_before_its_parent_is_noted(self):
        self.repo.clean_base()
        self.repo.write("b.txt", "b")
        self.repo.commit("older", date="2026-09-01T10:00:00 +0000")
        self.assertTrue(any("earlier than their parent" in m for m in self.messages()))

    def test_a_large_gap_between_author_and_commit_date_is_only_a_note(self):
        self.repo.clean_base()
        self.repo.write("c.txt", "c")
        self.repo.commit("rebased", date="2026-10-02T10:00:00 +0000", committer_date="2026-10-09T10:00:00 +0000")
        gap = [f for f in self.repo.report()["findings"] if "author date" in f["message"]]
        self.assertEqual([f["level"] for f in gap], ["info"])

    def test_personal_author_emails_are_warned_about_and_masked(self):
        self.repo.clean_base()
        self.repo.write("d.txt", "d")
        self.repo.commit("mine", date="2026-10-03T10:00:00 +0000", email=EMAIL)
        item = next(f for f in self.repo.report()["findings"] if f["check"] == "author-email")
        self.assertEqual(item["detail"], "s***@gmail.com")
        self.assertNotIn("someone", json.dumps(self.repo.report()))

    def test_no_dates_switch(self):
        self.repo.clean_base()
        self.repo.write("a.txt", "a")
        self.repo.commit("later", date="2099-11-11T10:00:00 +0000")
        self.assertNotIn("commit-date", [c for _, c in self.repo.checks(dates=False)])

    def test_date_logic_uses_the_clock_it_is_given(self):
        rows = [{"sha": "a" * 40, "name": "n", "email": "1+n@users.noreply.github.com", "author_iso": "2026-10-01T10:00:00+00:00",
                 "committer_iso": "2026-10-01T10:00:00+00:00", "committed": 1_790_000_000, "authored": 1_790_000_000, "parents": []}]
        self.assertEqual(pf.date_findings(rows, now=1_800_000_000), [])
        self.assertEqual(pf.date_findings(rows, now=1_700_000_000)[0]["level"], "error")


class CliTests(PreflightCase):
    def cli(self, *args):
        result = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "..", "preflight.py")] + list(args),
                                capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr

    def test_exit_codes_follow_fail_on(self):
        self.repo.clean_base()
        self.assertEqual(self.cli(self.repo.dir)[0], 0)
        self.repo.write("a.txt", f"{EMAIL}\n")
        self.repo.commit("warn only")
        self.assertEqual(self.cli(self.repo.dir)[0], 0)
        self.assertEqual(self.cli(self.repo.dir, "--fail-on", "warn")[0], 1)
        self.repo.write("b.txt", f"{AWS}\n")
        self.repo.commit("error")
        self.assertEqual(self.cli(self.repo.dir)[0], 1)
        self.assertEqual(self.cli(self.repo.dir, "--fail-on", "never")[0], 0)

    def test_json_output_is_valid_and_masked(self):
        self.repo.clean_base()
        self.repo.write("a.txt", f"{AWS}\n")
        self.repo.commit("secret")
        code, out, _ = self.cli(self.repo.dir, "--json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data["findings"][0]["check"], "secret")
        self.assertNotIn(AWS, out)

    def test_text_report_names_the_counts(self):
        self.repo.clean_base()
        _, out, _ = self.cli(self.repo.dir)
        self.assertIn("Nothing found.", out)
        self.assertIn("0 error(s), 0 warning(s), 0 note(s)", out)

    def test_a_folder_that_is_not_a_repository_is_a_usage_error(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder, True)
        code, _, err = self.cli(folder)
        self.assertEqual(code, 2)
        self.assertIn("not inside a git repository", err)

    def test_works_from_a_subfolder(self):
        self.repo.clean_base()
        self.repo.write("sub/x.txt", f"{AWS}\n")
        self.repo.commit("sub")
        self.assertEqual(self.cli(os.path.join(self.repo.dir, "sub"))[0], 1)

    def test_the_pre_push_hook_is_installed_executable_and_blocks_bad_pushes(self):
        self.repo.clean_base()
        code, out, _ = self.cli(self.repo.dir, "--install-hook")
        hook = os.path.join(self.repo.dir, ".git", "hooks", "pre-push")
        self.assertEqual(code, 0)
        self.assertTrue(os.access(hook, os.X_OK))
        self.assertEqual(self.cli(self.repo.dir, "--install-hook")[0], 2)          # will not overwrite
        self.assertEqual(self.cli(self.repo.dir, "--install-hook", "--force-hook")[0], 0)
        self.assertEqual(subprocess.run(["sh", hook], cwd=self.repo.dir, capture_output=True).returncode, 0)
        self.repo.write("leak.txt", f"{AWS}\n")
        self.repo.commit("leak")
        self.assertEqual(subprocess.run(["sh", hook], cwd=self.repo.dir, capture_output=True).returncode, 1)


class ResearchEvidenceTests(CliTests):
    def test_research_manifest_valid_all_sections(self):
        self.repo.clean_base()
        self.repo.write("data/packets.csv", "device_id,payload\n1,abc\n2,def\n")
        model_bytes = b"tiny-model"
        self.repo.write("models/detector.bin", model_bytes.decode("latin1"))
        import hashlib
        model_sha = hashlib.sha256(model_bytes).hexdigest()
        self.repo.write("CITATION.cff", "title: Demo\nauthors:\n  - name: Test\ndate: 2026-09-01\n")
        self.repo.write("results/metrics.json", json.dumps({"accuracy": 0.95, "loss": 0.04}))
        self.repo.write("scripts/eval.py", "print('eval')\n")
        manifest = {
            "version": 1,
            "dataset": {"path": "data/packets.csv", "rows": 2, "columns": 2, "required_columns": ["device_id", "payload"]},
            "model": {"path": "models/detector.bin", "max_bytes": 100, "sha256": model_sha},
            "citation": {"path": "CITATION.cff", "required_fields": ["title", "authors", "date"]},
            "evaluation": {"results": "results/metrics.json", "procedure": "scripts/eval.py", "metrics": {"accuracy": {"min": 0.9}, "loss": {"max": 0.1}}}
        }
        self.repo.write(".research-evidence.json", json.dumps(manifest))
        self.repo.commit("add research evidence")
        report = self.repo.report(research_manifest=".research-evidence.json")
        errors = [f for f in report["findings"] if f["level"] == "error"]
        self.assertEqual(errors, [])

    def test_research_manifest_dataset_and_metric_failures(self):
        self.repo.clean_base()
        self.repo.write("data/packets.csv", "device_id,payload\n1,abc\n")
        self.repo.write("results/metrics.json", json.dumps({"accuracy": 0.70}))
        manifest = {
            "version": 1,
            "dataset": {"path": "data/packets.csv", "rows": 10, "columns": 3, "required_columns": ["device_id", "missing_col"]},
            "evaluation": {"results": "results/metrics.json", "metrics": {"accuracy": {"min": 0.90}}}
        }
        self.repo.write("manifest.json", json.dumps(manifest))
        self.repo.commit("add research manifest")
        report = self.repo.report(research_manifest="manifest.json")
        checks = [f["check"] for f in report["findings"] if f["level"] == "error"]
        self.assertIn("research-dataset", checks)
        self.assertIn("research-evaluation", checks)

    def test_research_cli_flag(self):
        self.repo.clean_base()
        self.repo.write("CITATION.cff", "title: Demo\n")
        manifest = {"version": 1, "citation": {"path": "CITATION.cff", "required_fields": ["title"]}}
        self.repo.write(".research-evidence.json", json.dumps(manifest))
        self.repo.commit("add evidence")
        code, out, _ = self.cli(self.repo.dir, "--research")
        self.assertEqual(code, 0)
        self.assertIn("research-citation", out)


class DogfoodTests(unittest.TestCase):
    def test_this_repository_has_no_errors_of_its_own(self):
        root = os.path.join(os.path.dirname(__file__), "..")
        if not os.path.isdir(os.path.join(root, ".git")):
            self.skipTest("not running inside a git checkout")
        report = pf.run(root, dates=False)
        errors = [f for f in report["findings"] if f["level"] == "error"]
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
