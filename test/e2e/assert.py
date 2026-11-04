#!/usr/bin/env python3
"""Checks a scan report against what the end to end test expects."""
import calendar
import json
import os
import re
import sys
import time

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
    "persistence.systemd_malicious": "critical",
    "persistence.systemd_generator_malicious": "critical",
    "persistence.systemd_generator_unowned": "high",
    "persistence.systemd_dropin_malicious": "critical",
    "persistence.systemd_dropin_unowned": "high",
    "persistence.systemd_dropin_package": "medium",
    "persistence.systemd_env_inject": "high",
    "persistence.systemd_env_temp": "high",
    "persistence.systemd_linger_units": "medium",
    "persistence.systemd_links": "medium",
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
    "web.caddy.upstream": "high",
    "web.caddy.admin": "high",
    "web.caddy.browse": "medium",
    "network.exposed.caddy": "critical",
    "web.php.upstream": "high",
    "web.tls.default_cert": "high",
    "stack.eol": "high",
}

# Secrets planted on the host. None may appear anywhere in a report.
SECRETS = ["AAAABBBBCCCCDDDD", "hunter2", "$6$saltsalt"] + [f"S3CRET{n}" for n in range(1, 11)]

# Categories where a critical or high finding on a stock host is a false alarm.
# CVEs and support status are real on old releases.
NO_ALARM_WHEN_CLEAN = {"accounts", "ssh", "network", "process", "integrity", "persistence", "filesystem", "web", "stack"}


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
    failures += check_stack_clean(report)
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
    expect("persistence.systemd_generator_unowned", "/etc/systemd/system-generators/e2e-unowned", "a generator from no package was not named")
    expect("persistence.systemd_generator_malicious", "e2e-malicious", "a signature split across generator lines was not found")
    expect("persistence.systemd_generator_malicious", "e2e-linked -> /var/tmp/p/gen", "a generator linked to a temp directory was not found")
    expect("persistence.systemd_generator_malicious", "e2e-dangling -> /tmp/e2e-not-there-yet", "a dangling generator link into a temp directory was not found")
    expect("persistence.systemd_temp", "e2e-generated.service", "generator output was not scanned")
    refuse("persistence.systemd_unowned", "generator.late", "generator output was compared with packages")
    expect("persistence.systemd_transient", "e2e-transient.service", "a real systemd-run unit was not listed")
    expect("persistence.systemd_transient", "/bin/true", "a transient unit's command was not shown")
    expect("persistence.systemd_temp", "e2e-transient-temp.service", "a transient unit running from a temp directory was not found")
    refuse("persistence.systemd_unowned", "/run/systemd/transient", "a transient unit was compared with packages")
    expect("persistence.systemd_malicious", "e2e-split.service", "a signature behind a line continuation was not found")
    expect("persistence.systemd_temp", "e2e-condition.service", "ExecCondition was not read")
    expect("persistence.systemd_temp", "e2e-spaced.service", "spaces around the equals sign hid a command")
    expect("persistence.systemd_temp", "e2e-chained.service", "an escaped second command was not found")
    expect("persistence.systemd_env_inject", "e2e-preload.service: LD_PRELOAD=/opt/e2e-evil/hook.so", "LD_PRELOAD in a unit was not reported")
    expect("persistence.systemd_env_inject", "e2e-envfile.service: EnvironmentFile=/etc/e2e-app.env: LD_AUDIT=/opt/e2e-evil/audit.so", "a loader variable in an environment file was not reported")
    refuse("persistence.systemd_env_inject", "APP_CRED", "an unrelated variable reached the report")
    expect("persistence.systemd_env_temp", "e2e-envtemp.service", "an environment file in a temp directory was not reported")
    expect("persistence.systemd_env_links", "/etc/e2e-linked.env -> /root/e2e-secret.env", "an environment file link was not reported")
    expect("persistence.systemd_dropin_package", "cron.service.d/e2e.conf", "a drop-in using a package's program was not reported")
    expect("persistence.systemd_dropin_package", "Original ExecStart: /usr/sbin/cron", "a drop-in's original command was not shown")
    expect("persistence.systemd_dropin_package", "New ExecStart: /usr/sbin/cron -f -L 15", "a drop-in's new command was not shown")
    expect("persistence.systemd_dropin_unowned", "nginx.service.d/e2e.conf", "a drop-in using an unpackaged program was not reported")
    expect("persistence.systemd_dropin_unowned", "New ExecStart: /opt/e2e-evil/nginx", "a drop-in's new command was not shown")
    expect("persistence.systemd_dropin_malicious", "ssh.service.d/e2e.conf", "a drop-in running from a temp directory was not reported")
    refuse("persistence.systemd_temp", "ssh.service.d", "a drop-in was reported twice")
    expect("persistence.systemd_linger", "bob (uid", "a lingering user was not listed")
    expect("persistence.systemd_linger_units", "bob: /home/bob/.config/systemd/user/e2e-job.service", "a lingering user's unit was not listed")
    expect("persistence.systemd_links", "e2e-leak.service -> /root/e2e-secret.service", "a unit linking out of a home was not reported")
    expect("persistence.systemd_links", "/home/bob/.local/share/systemd/user -> /root/e2e-hidden/share/systemd/user", "a linked parent of a unit directory was not reported")
    expect("persistence.malicious", "/etc/logrotate.d/e2e-app", "a logrotate script split across lines was not found")
    expect("persistence.temp_exec", "/etc/logrotate.d/e2e-temp: /tmp/.x/rotate", "a logrotate script running from a temp directory was not found")
    expect("persistence.temp_exec", "/etc/logrotate.d/e2e-temp: compresscmd /dev/shm/.z", "a logrotate compresscmd in a temp directory was not found")
    expect("persistence.temp_exec", "/etc/logrotate.conf: include /var/tmp/p/lr", "a logrotate include of a temp directory was not found")
    expect("persistence.unowned", "[logrotate script] /etc/logrotate.d/e2e-temp: /tmp/.x/rotate", "an unpackaged logrotate script was not listed")
    refuse("persistence.temp_exec", "e2e-tmplog", "a log kept in /tmp was read as a program")
    refuse("persistence.malicious", "e2e-app.dpkg-old", "a backup logrotate never reads was scanned")
    expect("persistence.malicious", "/etc/networkd-dispatcher/routable.d/50-e2e", "a malicious networkd-dispatcher hook was not found")
    expect("persistence.unowned", "[network hook] /etc/network/if-up.d/e2e-routes", "an unpackaged if-up.d hook was not listed")
    expect("persistence.temp_exec", "/etc/dhcp/dhclient-exit-hooks.d/e2e", "a dhclient hook running from a temp directory was not found")
    expect("persistence.temp_exec", "e2e.job", "an anacron job running from a temp directory was not found")
    expect("persistence.unowned", "[anacron job] /etc/anacrontab:", "an added anacron job was not listed")
    refuse("persistence.unowned", "run-parts --report /etc/cron.daily", "a stock anacron job was listed")
    expect("persistence.temp_exec", "/etc/cron.yearly/e2e", "a cron.yearly script was not read")
    expect("persistence.temp_exec", "/etc/xdg/autostart/e2e.desktop: Exec=/tmp/.x/desk", "a system wide autostart entry was not read")
    refuse("persistence.temp_exec", "e2e-icon", "an icon path was read as a program")
    expect("web.caddy", "caddy 2.6.4", "Caddy's version was not read from its build information")
    expect("web.caddy", "/opt/caddy/caddy", "the running Caddy was not found")
    expect("web.caddy.upstream", "github.com/caddyserver/caddy/v2 2.6.4", "an old Caddy was not matched against Go's vulnerability database")
    expect("web.caddy.upstream", "Go standard library", "the Go version Caddy was built with was not checked")
    expect("web.caddy.admin", "/etc/caddy/Caddyfile: admin 0.0.0.0:2019", "an open admin API in the Caddyfile was not reported")
    expect("web.caddy.admin", "autosave.json", "Caddy's saved configuration was not read")
    expect("web.caddy.browse", "/etc/caddy/Caddyfile", "Caddy directory listing was not reported")
    expect("web.tls.default_cert", "0.0.0.0:443 via 127.0.0.1", "nginx's default certificate on 443 was not checked at loopback")
    expect("web.tls.default_cert", "shop.e2e-audit.com, www.e2e-audit.com (self-signed)", "the domains in the default certificate were not named")
    refuse("web.tls.default_cert", ":8443", "a port whose default server has a localhost certificate was reported")
    if any(f["id"] == "web.tls.default_cert_timeout" for f in report["findings"]):
        failures.append("a TLS handshake timed out: " + evidence(report, "web.tls.default_cert_timeout"))
    expect("network.exposed.caddy", ":2019", "a listening Caddy admin API was not reported")
    expect("web.shell.critical", "/srv/e2e-site/up.php", "a webshell under a Caddy root was not found")
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
    expect("stack.eol", "e2e-pg11", "an end of life PostgreSQL container published to the network was not reported")
    expect("stack.eol", "e2e-mongo", "an end of life MongoDB container was not reported")
    expect("stack.eol", "/root/.nvm/versions/node/v14.21.3", "Node.js 14 from nvm was not reported")
    expect("stack.eol", "/home/bob/.pyenv/versions/3.7.17", "Python 3.7 from pyenv was not reported")
    expect("stack.eol", "/opt/jdk-16.0.2", "a JDK unpacked by hand was not reported")
    expect("stack.eol", "/usr/local/go", "a Go toolchain unpacked by hand was not reported")
    refuse("stack.inventory", "2.6.10", "a version manager behind a symlink was read")
    stack = report.get("stack") or []
    pg = [i for i in stack if i.get("container") == "e2e-pg11"]
    if not (pg and pg[0].get("version") == "11.22" and pg[0]["status"] == "eol" and pg[0]["exposed"]):
        failures.append(f"the PostgreSQL 11 container is wrong in the stack list: {pg}")
    redis = [i for i in stack if i.get("path") == "/opt/redis/bin/redis-server"]
    if not (redis and redis[0]["source"] == "unpackaged" and redis[0]["running"] and redis[0]["exposed"] and redis[0].get("version")):
        failures.append(f"the unpackaged Redis on every address is wrong in the stack list: {redis}")
    durations = {c["id"]: c["duration_ms"] for c in report["checks"]}
    if durations.get("web.nginx", 0) > 30000:
        failures.append(f"a FIFO stalled the nginx check for {durations['web.nginx']} ms")
    return failures


# Packages the e2e image installs that the stack check must list, as the
# product each one is.
STACK_PACKAGES = [
    (re.compile(r"^postgresql-\d+(\.\d+)?$"), "postgresql"),
    (re.compile(r"^redis-server$"), "redis"),
    (re.compile(r"^valkey-server$"), "valkey"),
    (re.compile(r"^mysql-server-core-[\d.]+$"), "mysql"),
    (re.compile(r"^mariadb-server(-core)?(-[\d.]+)?$"), "mariadb"),
    (re.compile(r"^libsqlite3-0$"), "sqlite"),
    (re.compile(r"^nodejs$"), "nodejs"),
    (re.compile(r"^python3\.\d+$"), "python"),
]


def installed_packages(path="/var/lib/dpkg/status"):
    names, name = set(), None
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.startswith("Package: "):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Status: ") and line.rstrip().endswith(" installed") and name:
                names.add(name)
    return names


def running_names(scanned_at):
    """Names of processes that started before the scan and still run.

    A service caught in a restart loop has processes that come and go, or
    are exiting with no executable left, so only one that was already up
    when the scan began and is still up now must be marked as running.
    """
    with open("/proc/stat", encoding="utf-8") as handle:
        btime = int(next(line.split()[1] for line in handle if line.startswith("btime")))
    ticks = os.sysconf("SC_CLK_TCK")
    stamp = scanned_at.split(".")[0].rstrip("Z")
    scan_start = calendar.timegm(time.strptime(stamp, "%Y-%m-%dT%H:%M:%S"))
    names = set()
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as handle:
                stat = handle.read()
            fields = stat[stat.rindex(")") + 2:].split()
            started = btime + int(fields[19]) / ticks
            os.readlink(f"/proc/{pid}/exe")
            with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as handle:
                name = handle.read().strip()
        except (OSError, ValueError, IndexError):
            continue
        if fields[0] != "Z" and started < scan_start:
            names.add(name)
    return names


def check_stack_clean(report):
    """Ubuntu's own packages must be listed as such and never judged by upstream dates."""
    failures = []
    stack = report.get("stack") or []
    listed = {(item["product"], item["source"]) for item in stack}
    for name in sorted(installed_packages()):
        for pattern, product in STACK_PACKAGES:
            if pattern.match(name) and (product, "ubuntu") not in listed:
                failures.append(f"installed package {name} is not listed as Ubuntu's {product}")
    for item in stack:
        if item["source"] == "unpackaged":
            failures.append(f"packaged software listed as unpackaged: {item['name']} at {item.get('path')}")
        if item["source"] == "ubuntu" and (item["status"] != "ubuntu" or item.get("eol")):
            failures.append(f"an Ubuntu package was judged by upstream dates: {item['name']} {item.get('version')}")
    # A service that failed to start, such as Valkey losing port 6379 to
    # Redis, is not expected to show as running.
    running = running_names(report["scanned_at"])
    for names, products in (
        ({"postgres"}, {"postgresql"}),
        ({"redis-server"}, {"redis"}),
        ({"valkey-server"}, {"valkey"}),
        ({"mysqld", "mariadbd"}, {"mysql", "mariadb"}),
    ):
        if running & names and not any(i["product"] in products and i["running"] for i in stack):
            failures.append(f"a running {'/'.join(sorted(names))} is not marked as running")
    failures += [
        f"end of life reported on a clean host: {f['title']}"
        for f in report["findings"]
        if f["id"].startswith("stack.eol")
    ]
    return failures


def check_lookup(report):
    """--cve must run only the lookup and answer every CVE asked about."""
    failures = []
    ran = [c["id"] for c in report["checks"]]
    if ran != ["cve.lookup"]:
        failures.append(f"--cve ran {ran} instead of only the lookup")
    found = {f["id"]: f for f in report["findings"]}
    for cve in ("CVE-2024-6387", "CVE-2026-98432"):
        if "cve.lookup." + cve not in found:
            failures.append(f"no answer for {cve}")
    kernel = found.get("cve.lookup.CVE-2026-98432")
    if kernel and kernel["severity"] != "skipped":
        failures.append(f"a kernel CVE was answered for a kernel Ubuntu does not ship: [{kernel['severity']}] {kernel['title']}")
    ssh = found.get("cve.lookup.CVE-2024-6387")
    if ssh and ssh["severity"] == "skipped":
        failures.append(f"an openssh CVE was not answered: {ssh['title']}")
    for f in report["findings"]:
        if f["id"].startswith("cve.lookup."):
            print(f"    [{f['severity']}] {f['title']}")
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
    if mode == "clean":
        failures = check_clean(report)
    elif mode == "lookup":
        failures = check_lookup(report)
    else:
        failures = check_planted(report, raw)
    failures += check_text(raw)
    failures += [f"check {c['id']} errored: {c['error']}" for c in report["checks"] if c.get("error")]
    summary = report["summary"]
    print(f"  {mode}: {summary} in {report['duration_ms']} ms")
    for failure in failures:
        print("  FAIL", failure)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
