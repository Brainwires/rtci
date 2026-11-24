#!/usr/bin/env python3
"""What upstream did since we last looked: a read-only report for a person, not a CI gate.

The fork descends from webrtc-rs ``rtc``. ``FORK.md`` records two points (its "Sync point"
table): the last upstream commit merged, and the day open upstream work (pull requests, issues)
was last triaged against this tree. This prints, from GitHub's API:

- ``webrtc-rs/rtc`` commits on ``master`` after the merged commit (code to merge; FORK.md's
  standing rules say how);
- ``webrtc-rs/rtc`` pull requests and issues opened or updated since the triage day, open or
  closed (an open fix may be a defect this tree shares; a closed one may have been merged);
- ``webrtc-rs/webrtc`` commits since the triage day on ``master`` and on the maintained
  ``v0.17.x`` branch: the async layer the fork does not use, read for fixes to protocol code
  both have (STUN, ICE, DTLS, SCTP, TURN).

It only reads (GET requests); it never posts, comments or opens anything. It uses the network,
so no workflow runs it: a CI gate must not depend on GitHub's API or on upstream's activity.
A token is taken from ``GITHUB_TOKEN`` or ``gh auth token`` when there is one (60 anonymous
requests an hour are usually enough).

Usage: ``python3 scripts/upstream-watch.py [--since YYYY-MM-DD] [--json]``. After triaging,
update the "Open upstream work last triaged" row of FORK.md. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORK_MD = os.path.join(ROOT, "FORK.md")
API = "https://api.github.com"
RTC = "webrtc-rs/rtc"
WEBRTC = "webrtc-rs/webrtc"
WEBRTC_BRANCHES = ("master", "v0.17.x")


def recorded_points(text: str) -> tuple[str, str | None]:
    """The merged upstream commit and the triage day, from FORK.md's sync point table."""
    merged = re.search(r"^\| Last upstream commit merged \| `([0-9a-f]{7,40})`", text, re.M)
    if not merged:
        sys.exit("FORK.md: no 'Last upstream commit merged' row")
    triaged = re.search(r"^\| Open upstream work last triaged \| (\d{4}-\d{2}-\d{2})", text, re.M)
    return merged.group(1), triaged.group(1) if triaged else None


def token() -> str | None:
    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() or None


def get(path: str, params: dict[str, str] | None = None, auth: str | None = None):
    url = f"{API}/{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    if auth:
        req.add_header("Authorization", f"Bearer {auth}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as err:
        sys.exit(f"GET {url}: {err.code} {err.reason}")


def first_line(message: str) -> str:
    return message.splitlines()[0] if message else ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--since", help="triage day to report from (default: FORK.md's)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = ap.parse_args()

    with open(FORK_MD, encoding="utf-8") as f:
        merged, triaged = recorded_points(f.read())
    auth = token()

    compare = get(f"repos/{RTC}/compare/{merged}...master", auth=auth)
    merged_date = compare["base_commit"]["commit"]["committer"]["date"][:10]
    since = args.since or triaged or merged_date
    since_ts = f"{since}T00:00:00Z"

    report = {
        "merged": merged,
        "since": since,
        "rtc_commits": [
            {"sha": c["sha"][:8], "date": c["commit"]["committer"]["date"][:10],
             "title": first_line(c["commit"]["message"])}
            for c in compare.get("commits", [])
        ],
        "rtc_items": [],
        "webrtc_commits": {},
    }
    # Issues and pull requests share the issues endpoint; `since` is "updated at or after".
    page = 1
    while True:
        items = get(f"repos/{RTC}/issues", {"state": "all", "since": since_ts,
                                             "per_page": "100", "page": str(page),
                                             "sort": "updated"}, auth)
        for it in items:
            report["rtc_items"].append({
                "number": it["number"],
                "kind": "pr" if "pull_request" in it else "issue",
                "state": it["state"],
                "merged": bool(it.get("pull_request", {}).get("merged_at")),
                "new": it["created_at"] >= since_ts,
                "updated": it["updated_at"][:10],
                "author": it["user"]["login"],
                "title": it["title"],
            })
        if len(items) < 100:
            break
        page += 1
    for branch in WEBRTC_BRANCHES:
        commits = get(f"repos/{WEBRTC}/commits", {"sha": branch, "since": since_ts,
                                                   "per_page": "100"}, auth)
        report["webrtc_commits"][branch] = [
            {"sha": c["sha"][:8], "date": c["commit"]["committer"]["date"][:10],
             "title": first_line(c["commit"]["message"])}
            for c in commits
        ]

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
        return 0

    print(f"{RTC} master after the merged commit {merged} ({compare['ahead_by']} commits):")
    for c in report["rtc_commits"]:
        print(f"  {c['sha']} {c['date']} {c['title']}")
    print(f"\n{RTC} pull requests and issues opened or updated since {since}:")
    for it in sorted(report["rtc_items"], key=lambda i: (i["kind"], -i["number"])):
        state = "merged" if it["merged"] else it["state"]
        mark = "new" if it["new"] else "upd"
        print(f"  {it['kind']:5} #{it['number']:<4} {state:6} {mark} {it['updated']} "
              f"@{it['author']}: {it['title']}")
    for branch, commits in report["webrtc_commits"].items():
        print(f"\n{WEBRTC} {branch} since {since} ({len(commits)} commits):")
        for c in commits:
            print(f"  {c['sha']} {c['date']} {c['title']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
