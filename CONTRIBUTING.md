# Contributing

Bug reports, false positive reports and pull requests are welcome. Please write them in English.

## Reporting a bug

Open an issue at https://github.com/guanting112/ubuntu-sys-audit/issues and include:

- the output of `ubuntu-sys-audit --version`
- the Ubuntu release and architecture (`grep PRETTY_NAME /etc/os-release`, `dpkg --print-architecture`)
- the finding's ID, such as `process.masquerade`, and what you expected instead

Reports can hold host names, addresses, user names and paths. Remove what you do not want to publish before pasting a report.

A vulnerability in the tool itself is not an ordinary bug. Report it privately as described in [SECURITY.md](SECURITY.md).

## Proposing a change

For a new check or a change in how a check rates something, open an issue first, so we can agree on the scope and severity before you write code. Small fixes can go straight to a pull request.

Scope: the tool audits the Ubuntu host. Dependency checks for applications, such as Node, Ruby or PHP lockfiles, belong in each application's own CI and are out of scope.

Pull requests go against `main`. CI runs `go vet`, the unit tests and govulncheck, plus CodeQL, and a pull request is merged only when they pass. Dependabot's pull requests follow the same rule.

## Design rules

These come from the [design principles](README.md#design-principles) in the README. A change that breaks one will not be merged.

- **Read-only.** No writes to the host other than a report the user asks for.
- **Never run a program from the host.** Read files and `/proc` instead, so a replaced binary cannot feed the tool false output.
- **Treat host content as hostile.** Do not follow symlinks into files users control, refuse FIFOs and devices, and limit how much is read. The runner passes every finding through `model.CleanFinding`. Any other host text that reaches the report, such as a new field, must go through `model.Clean`.
- **Outbound traffic only downloads public data,** with plain GET requests that send nothing about the host. A new domain needs discussion first.
- **One static binary.** CGO stays off, and the binary must run unchanged on every supported Ubuntu release.

## Tests

Every change in behavior comes with tests:

- New or changed logic gets unit tests. A bug fix gets a test that fails without the fix.
- A new detection gets an end to end case in `test/e2e`: plant the indicator in the test container and check that the report finds it, at the right severity, and that clean hosts stay clean.
- A new parser of host content gets a fuzz target next to its tests.

Run them in Docker, since the code only compiles for Linux:

```sh
make test                  # unit tests
make e2e                   # every Ubuntu release, one after another
sh test/e2e/run.sh 24.04   # one release; start one per release to run them in parallel
make fuzz                  # every fuzz target at once (FUZZTIME=5m for longer)
```

When developing on macOS, set `GOOS=linux` for `go build` and `go vet`.

## Style

- Format with `gofmt` and keep `go vet` clean.
- Tool output and documentation are in English. `README.zh-TW.md` mirrors `README.md`, so change both.
- Commit messages start with a short summary in the imperative ("Check Caddy's admin API"). The body says why the change is needed and what it does differently.
- Add a line to the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md) for anything a user would notice.

## License

By contributing, you agree that your contribution is released under the [MIT License](LICENSE).
