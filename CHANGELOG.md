# Changelog

Notable changes in each release. The release workflow publishes a version's section as its release notes.

## [Unreleased]

### Fixed

- Debian version comparison now stops at a NUL byte, as dpkg does. Before, such a version could break the ordering. Found by fuzzing.
- Go version comparison no longer depends on argument order when two prerelease numbers are equal but written differently, such as `rc.1` and `rc.01`. Found by fuzzing.
- `authorized_keys` lines: after the key type, the key and comment are split on whitespace alone, as sshd does, so a stray quote can no longer pull spaces into the key. Found by fuzzing.

### Added

- A Stack tab listing the databases (PostgreSQL, MySQL, MariaDB, Redis, Valkey, MongoDB, SQLite), language runtimes (Node.js, Python, Ruby, Java, PHP, Go) and servers (nginx, Apache, HAProxy, Docker, containerd) on the host. It finds them in packages, version managers such as nvm, pyenv and SDKMAN!, hand-unpacked installs, Docker containers and running processes, and says whether each listens beyond loopback. A release past its end of life is Medium, or High when it listens beyond loopback. Ubuntu's own packages are not judged by upstream dates. JSON reports carry the list as `stack`.
- Fuzz tests for the parsers of host content and for both version orders, run with `make fuzz`. The Debian order is also checked against dpkg itself.

## [0.1.17] - 2026-11-04

### Fixed

- systemd unit escapes that systemd rejects, such as `\777` or `\UFFFFFFFF`, were decoded into other bytes. They now stand for themselves, so the command the persistence checks judge matches what systemd reads. Found by CodeQL.

### Added

- Each release carries its build provenance attestation as `ubuntu-sys-audit.sigstore.json`, so `gh attestation verify --bundle` checks a binary without a GitHub login. The bundles of v0.1.4 to v0.1.16 were attached afterwards.
- A security policy (SECURITY.md) with private vulnerability reporting, plus CodeQL, Dependabot and OpenSSF Scorecard for the repository.

## [0.1.16] - 2026-11-03

### Added

- `web.tls.default_cert`: the tool makes a TLS handshake without a server name to the host's own HTTPS ports, as Censys and Shodan do, and reports High when the certificate names a domain. That ties the server's address to its domains, even behind Cloudflare. No request is sent.

## [0.1.15] - 2026-11-03

### Changed

- When `integrity.binaries_other` lists a replaced Caddy binary, it says which Caddy build now holds the path and the usual causes. Reinstall advice names the real packages.

## [0.1.14] - 2026-11-03

### Fixed

- Files listed with a leading `./` in a package's md5sums, as in Caddy's packages up to 2.10.2, were skipped by the binary hash check. A Caddy binary swapped by `caddy upgrade` is now caught, by its hash or by a version that differs from the package's.

## [0.1.13] - 2026-11-03

### Fixed

- An xcaddy build copied over the packaged `/usr/bin/caddy` was labeled as Caddy's apt repository build, with advice to `apt upgrade`, which would remove its plugins. It is now reported as self-compiled, with advice to install custom builds beside the package.

## [0.1.12] - 2026-11-02

### Added

- Caddy checks. The version, Go toolchain and plugins are read from the binary without running it, including xcaddy builds and a Caddy in a container. Builds other than Ubuntu's are compared against Go's vulnerability database. The admin API on a non-loopback address is Critical, configuration that sets it is High, and directory listing is Medium. Caddy's site roots join the webshell scan.

## [0.1.11] - 2026-11-02

### Added

- `--cve CVE-ID,...` answers single CVEs for the host from Canonical's CVE OVAL feed, including ones with no fix released yet. An affected host gets the CVE's priority as severity, and exit code 2 marks hosts a High or Critical CVE reaches.

## [0.1.10] - 2026-11-02

### Added

- Commands that run automatically from logrotate scripts, network hooks (ifupdown, networkd-dispatcher, NetworkManager, dhclient, pppd), `/etc/anacrontab`, `/etc/cron.yearly` and `/etc/xdg/autostart`.

### Fixed

- The notice that reading BPF filters made the kernel load `af_packet_diag` never appeared, because the check looked for the wrong module name.

## [0.1.9] - 2026-11-02

### Added

- systemd persistence: generators, transient units, lingering users and their user units, units that set `LD_PRELOAD`, `LD_LIBRARY_PATH` or `LD_AUDIT`, and drop-ins that replace a packaged unit's `ExecStart`.

### Changed

- Exec lines are read the way systemd reads them, including continuations, quotes and escapes.

## [0.1.8] - 2026-11-02

### Added

- Name resolution tampering: `/etc/hosts` entries that override Ubuntu's domains, NSS modules outside package management and TCP Wrappers rules that run commands.
- Tunnel interfaces with the programs holding them, IP forwarding nothing explains, and unusual default routes.
- More exposed services (etcd, the Kubernetes API, RabbitMQ, Prometheus, rsync, RDP, CUPS, SNMP) and kernel parameters (`rp_filter`, `send_redirects`, IPv6 redirects and source routes).

## [0.1.7] - 2026-11-02

### Added

- Firewall gaps: ufw allowing incoming traffic by default, public IPv6 listeners ufw leaves unfiltered, and containers publishing ports around it.
- Rarely used network protocols that are loaded or can be auto-loaded, and unprivileged user namespaces.

### Fixed

- ARM hosts got Intel and AMD microcode advice for unmitigated CPU vulnerabilities. They now get kernel and firmware advice.

### Changed

- The project is released under the MIT License. Building requires Go 1.27.3.

## [0.1.6] - 2026-11-02

### Changed

- The TUI figure is now a hooded hacker that reacts when a Critical or High finding turns up.

## [0.1.5] - 2026-11-02

### Added

- An animated opening screen and a figure beside the check list in the TUI. Any key skips the opening screen, which costs no scan time.

## [0.1.4] - 2026-11-02

### Added

- LXD checks. The snap, which USN data does not cover, is compared against Canonical's LXD advisories and its branch's latest version. Unsupported branches, an API on a non-loopback address and containers that can escape to the host are reported.
- Exit code 3 when a check did not finish, so an incomplete scan no longer looks clean.

### Fixed

- Missed detections and false alarms found in a review, including sshd_config parsing (`=` and `Match` blocks), password fields in `/etc/passwd`, sudo's `!authenticate`, binaries in `/bin` on hosts without merged `/usr`, and empty or wrong-release OVAL data.
- File handling a local user could abuse: files are type-checked before opening, so FIFOs and devices are never opened, and `-o` only creates new files where the sudo user can write.

### Changed

- Releases are built with the latest Go, gated on govulncheck, and carry build provenance attestations.

## [0.1.3] - 2026-11-01

### Added

- MPTCP enabled is reported as Medium, with the commands to turn it off and a warning when sockets use it.

## [0.1.2] - 2026-11-01

### Fixed

- From 22.04 on, `systemd-udevd` is a symlink to `udevadm`, so every host with udev got a Critical masquerading process finding. A packaged symlink to the running packaged binary is now exempt, while one made by an attacker is still reported.

## [0.1.1] - 2026-11-01

### Fixed

- The scan screen overflowed small terminals.

## [0.1.0] - 2026-11-01

### Added

- First release: a read-only security audit for Ubuntu 18.04 to 26.04 as one static binary, with a terminal UI and text and JSON output for runs over SSH. It checks missing CVE fixes against Canonical's USN data, port 53 listeners, BPFDoor-style packet filters, webshells, tampered binaries, persistence, accounts, SSH and filesystem issues, and never runs a program from the host.

[Unreleased]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.17...HEAD
[0.1.17]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.16...v0.1.17
[0.1.16]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.15...v0.1.16
[0.1.15]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.14...v0.1.15
[0.1.14]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.13...v0.1.14
[0.1.13]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.12...v0.1.13
[0.1.12]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.11...v0.1.12
[0.1.11]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.10...v0.1.11
[0.1.10]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/guanting112/ubuntu-sys-audit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/guanting112/ubuntu-sys-audit/releases/tag/v0.1.0
