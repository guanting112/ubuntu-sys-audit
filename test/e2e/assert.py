#!/usr/bin/env python3
"""Checks a scan report against what the end to end test expects."""
import json
import re
import sys

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3, "ok": 4, "skipped": 5}

# Finding ID -> the least severe level that still counts as detected.
PLANTED = {
    "accounts.uid0": "critical",
    "accounts.empty_password": "critical",
    "accounts.sudo_system": "critical",
    "accounts.service_shell": "high",
    "accounts.history_wiped": "high",
    "ssh.root_login": "high",
    "ssh.service_keys": "high",
    "ssh.key_perms": "medium",
    "persistence.malicious": "critical",
    "persistence.systemd_temp": "critical",
    "integrity.preload": "critical",
    "integrity.binaries_key": "critical",
    "filesystem.suid_critical": "critical",
    "filesystem.cap_danger": "high",
    "filesystem.temp_elf": "high",
    "network.dns53.listener": "critical",
    "network.bpfdoor": "critical",
    "network.listener_bad_exe": "critical",
    "process.fake_kernel": "critical",
    "process.masquerade": "critical",
    "process.reverse_shell": "critical",
    "process.temp_exe": "critical",
    "web.shell.critical": "critical",
    "web.shell.uploads": "high",
    "web.shell.double_ext": "medium",
    "web.nginx.upstream": "high",
    "web.php.upstream": "high",
}

# Secrets planted on the host. None may appear anywhere in a report.
SECRETS = ["AAAABBBBCCCCDDDD", "hunter2", "$6$saltsalt"]


def load(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def worst_by_id(report):
    worst = {}
    for finding in report["findings"]:
        rank = SEVERITY_RANK[finding["severity"]]
        if finding["id"] not in worst or rank < worst[finding["id"]]:
            worst[finding["id"]] = rank
    return worst


def check_clean(report):
    worst = worst_by_id(report)
    return [
        f"clean host wrongly reports {fid} at {required} or above"
        for fid, required in PLANTED.items()
        if worst.get(fid, 99) <= SEVERITY_RANK[required]
    ]


def check_planted(report, raw):
    worst = worst_by_id(report)
    failures = [
        f"missed {fid} (need {required}, got rank {worst.get(fid, 'none')})"
        for fid, required in PLANTED.items()
        if worst.get(fid, 99) > SEVERITY_RANK[required]
    ]
    failures += [f"secret leaked into report: {s}" for s in SECRETS if s in raw]
    if "\x1b" in raw or "\\u001b" in raw:
        failures.append("raw terminal escape in report")
    if "NOPASSWD:ALL" not in raw:
        failures.append("redaction mangled sudoers evidence")
    return failures


def check_text(raw):
    """Report text must be English, with no broken format verbs from Sprintf."""
    failures = []
    han = re.search(r"[\u4e00-\u9fff]", raw)
    if han:
        start = max(han.start() - 40, 0)
        failures.append("non English text in report: " + raw[start:han.end() + 20].replace("\n", " "))
    if "%!" in raw:
        failures.append("broken format verb in report")
    return failures


def main():
    mode, path = sys.argv[1], sys.argv[2]
    raw = load(path)
    report = json.loads(raw)
    failures = check_clean(report) if mode == "clean" else check_planted(report, raw)
    failures += check_text(raw)
    failures += [f"check {c['id']} errored: {c['error']}" for c in report["checks"] if c.get("error")]
    summary = report["summary"]
    print(f"  {mode}: {summary} in {report['duration_ms']} ms")
    for failure in failures:
        print("  FAIL", failure)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
