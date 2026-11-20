"""No real identifiers in the repository.

Reads `.pii-denylist` at the repo root (untracked and gitignored: one term per
line, `#` comments) and fails if any term appears in a file git would commit.
Matching is case-insensitive and on word boundaries, so a name such as `Ann`
does not match inside `channel`. Skips when the denylist is absent (CI).
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).parents[1]
DENYLIST = ROOT / ".pii-denylist"


def repo_files() -> list[Path]:
    try:
        out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT,
                             capture_output=True, check=True).stdout.decode()
        return [ROOT / p for p in out.split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        return [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]


def terms() -> list[str]:
    lines = DENYLIST.read_text().splitlines()
    return [t.strip() for t in lines if t.strip() and not t.lstrip().startswith("#")]


@unittest.skipUnless(DENYLIST.is_file(), "no .pii-denylist (local-only check)")
class PiiTests(unittest.TestCase):
    def test_no_denylisted_identifier_in_any_committable_file(self):
        rx = re.compile("|".join(rf"(?<![A-Za-z0-9]){re.escape(t)}(?![A-Za-z0-9])" for t in terms()), re.I)
        hits = []
        for path in repo_files():
            if path == DENYLIST or not path.is_file():
                continue
            try:
                text = path.read_text()
            except UnicodeDecodeError:
                text = path.read_bytes().decode("latin-1")
            for n, line in enumerate(text.splitlines(), 1):
                m = rx.search(line)
                if m:
                    hits.append(f"{path.relative_to(ROOT)}:{n}: {m.group(0)!r}")
        self.assertEqual(hits, [])

    def test_denylist_is_ignored_by_git(self):
        res = subprocess.run(["git", "check-ignore", "-q", ".pii-denylist"], cwd=ROOT, check=False)
        self.assertEqual(res.returncode, 0, ".pii-denylist must be gitignored")
