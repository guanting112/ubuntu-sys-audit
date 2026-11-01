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
    "accounts.passwd_empty": "critical",
    "accounts.passwd_hash": "critical",
    "integrity.pam_rogue": "critical",
    "persistence.home_symlink": "high",
    "cve.lxd.advisories": "high",
    "network.lxd_privileged": "high",
    "network.ufw_policy": "medium",
    "network.ufw_ipv6": "medium",
    "docker.ufw_bypass": "medium",
    "network.hosts_override": "high",
    "integrity.nss_unmanaged": "high",
    "persistence.tcp_wrappers": "high",
    "network.tunnel_suspicious": "high",
    "network.exposed.etcd": "high",
    "network.exposed.snmp": "medium",
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
SECRETS = ["AAAABBBBCCCCDDDD", "hunter2", "$6$saltsalt", "S3CRET1", "S3CRET2", "S3CRET3", "S3CRET4", "S3CRET5"]

# Categories where a critical or high finding on a stock host is a false alarm.
# CVEs and support status are real on old releases.
NO_ALARM_WHEN_CLEAN = {"accounts", "ssh", "network", "process", "integrity", "persistence", "filesystem", "web"}


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


def evidence(report, finding_id):
    return " ".join(
        line
        for finding in report["findings"]
        if finding["id"] == finding_id
        for line in finding.get("evidence", [])
    )


def check_clean(report):
    worst = worst_by_id(report)
    failures = [
        f"clean host wrongly reports {fid} at {required} or above"
        for fid, required in PLANTED.items()
        if worst.get(fid, 99) <= SEVERITY_RANK[required]
    ]
    failures += [
        f"false alarm on a clean host: {f['id']} [{f['severity']}] {f['title']}"
        for f in report["findings"]
        if f["category"] in NO_ALARM_WHEN_CLEAN and SEVERITY_RANK[f["severity"]] <= SEVERITY_RANK["high"]
    ]
    return failures


def check_planted(report, raw):
    worst = worst_by_id(report)
    failures = [
        f"missed {fid} (need {required}, got rank {worst.get(fid, 'none')})"
        for fid, required in PLANTED.items()
        if worst.get(fid, 99) > SEVERITY_RANK[required]
    ]
    # Case insensitive: lowercasing a value must not count as hiding it.
    failures += [f"secret leaked into report: {s}" for s in SECRETS if s.lower() in raw.lower()]
    if "\x1b" in raw or "\\u001b" in raw:
        failures.append("raw terminal escape in report")
    if "NOPASSWD:ALL" not in raw:
        failures.append("redaction mangled sudoers evidence")
    masquerade = evidence(report, "process.masquerade")
    if "/usr/sbin/auditd" not in masquerade:
        failures.append("attacker made symlink was accepted as a legitimate alias")
    if "systemd-udevd" in masquerade:
        failures.append("udevd reported as masquerading after a package upgrade")

    def expect(finding_id, text, message):
        if text not in evidence(report, finding_id):
            failures.append(f"{message} ({finding_id} lacks {text!r})")

    def refuse(finding_id, text, message):
        if text in evidence(report, finding_id):
            failures.append(f"{message} ({finding_id} has {text!r})")

    expect("integrity.binaries_key", "/login", "a trojaned login was not found")
    expect("integrity.binaries_key", "/usr/bin/passwd", "a binary replaced by a symlink was not found")
    expect("integrity.binaries_missing", "/usr/bin/chage", "a deleted binary was not reported")
    expect("web.shell.critical", "/data/www2/hidden.php", "a webshell behind a symlinked release was not found")
    expect("persistence.systemd_temp", "linked.service", "a unit linked from a temp directory was not found")
    expect("process.deleted_exe", "nginx", "the stale nginx test did not run")
    expect("network.lxd_privileged", "priv1", "a privileged LXD container was not named")
    expect("network.ufw_ipv6", "2001:db8::1 on eth0", "the public IPv6 address was not named")
    expect("network.ufw_ipv6", "[::]:", "a service listening on IPv6 was not named")
    expect("docker.ufw_bypass", "web1  0.0.0.0:6379 -> 6379/tcp", "a published port was not named")
    refuse("docker.ufw_bypass", "127.0.0.1", "a port published on loopback was reported")
    refuse("docker.ufw_bypass", "stopped1", "a stopped container was reported")
    refuse("docker.ufw_bypass", "hostnet1", "a container on the host network was reported")
    expect("network.protocols", "rds", "a loadable protocol was not reported")
    expect("network.protocols", "sctp", "a blacklist in a file modprobe ignores was accepted")
    refuse("network.protocols", "tipc", "a blocked protocol was reported")
    expect("network.hosts_override", "security.ubuntu.com", "an overridden update domain was not named")
    expect("network.hosts_override", "ports.ubuntu.com", "a domain pointing at a private address was not named")
    expect("integrity.nss_unmanaged", "libnss_evilnss.so.2", "a rogue NSS library was not named")
    expect("integrity.nss_other", "missingnss", "a module with no library was not listed")
    refuse("integrity.nss_unmanaged", "NOTFOUND", "an NSS action was read as a module")
    expect("persistence.tcp_wrappers", "spawn", "a TCP Wrappers command was not named")
    expect("network.tunnel_suspicious", "e2etun0", "a tun interface was not tied to the process holding it")
    expect("network.tunnel_suspicious", "/var/tmp/vpn", "the program holding a tunnel was not named")
    expect("network.tunnels", "e2etun0 (tun)", "a tunnel was not listed")
    refuse("network.listener_bad_exe", "nginx", "a service awaiting restart was called malware")
    refuse("process.temp_exe", "/tmp/audit", "the tool flagged itself")
    refuse("filesystem.temp_elf", "/tmp/audit", "the tool flagged its own binary")
    durations = {c["id"]: c["duration_ms"] for c in report["checks"]}
    if durations.get("web.nginx", 0) > 30000:
        failures.append(f"a FIFO stalled the nginx check for {durations['web.nginx']} ms")
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
