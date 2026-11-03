# Security policy

`ubuntu-sys-audit` runs as root on the servers it audits, so a flaw in the tool itself can do more harm than many of the problems it looks for. Please report vulnerabilities privately.

## Supported versions

Only the latest release receives security fixes. A fix ships as a new release; older releases are not patched.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

https://github.com/guanting112/ubuntu-sys-audit/security/advisories/new

Do not open a public issue, pull request or discussion for a vulnerability.

Please include:

- the output of `ubuntu-sys-audit --version`
- the Ubuntu release and architecture
- the steps, file or host content that reproduces the problem, and what you expected instead

## What to expect

- You will get an acknowledgement within 7 days.
- A confirmed vulnerability is fixed in a new release, normally within 30 days. If it needs longer, you will be told why.
- The fix is announced in a GitHub security advisory, crediting you unless you prefer otherwise. Please keep the details private until that advisory is published.

## Scope

The tool reads host content that an attacker on the host may control, so these are vulnerabilities:

- host content (files, file names, process names, configuration, logs, package metadata) that makes the tool run a program, write or change a file, read a file it should refuse, or hang
- host content that hides other findings or turns a compromised host into a clean report
- terminal control sequences that reach the terminal unescaped
- credentials or password hashes that appear unmasked in a report
- downloads of vulnerability data that can be tampered with in transit
- a release binary that does not match this repository's source and workflow

These are ordinary bugs; please open a public issue for them:

- a backdoor, CVE or misconfiguration the tool does not detect, unless host content is used to hide it as above
- a false positive
- anything that requires control of the kernel, since a kernel rootkit can falsify everything a local tool sees (see [Limitations](README.md#limitations))
