// ubuntu-sys-audit is a read only security audit for Ubuntu 18.04 to 26.04,
// distributed as one static binary. It is meant to be downloaded and run with
// sudo: it needs no compiler, no packages and leaves nothing on the host.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/x/term"

	"ubuntu-sys-audit/internal/checks"
	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/output"
	"ubuntu-sys-audit/internal/tui"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `ubuntu-sys-audit: read-only security audit for Ubuntu 18.04 to 26.04

Usage:
  sudo ./ubuntu-sys-audit [options]

Opens the TUI on a terminal. Without a TTY, for example under
ssh host 'sudo ./ubuntu-sys-audit', it writes JSON instead.

Options:
  --json               Write JSON to stdout without opening the TUI
  --text               Write plain text to stdout without opening the TUI
  --min-severity LV    In text mode, list only this level and above: critical, high, medium, info, ok (default medium).
                       Items that could not be checked are always listed
  -o, --output FILE    Also save the JSON report to a new FILE (mode 0600). An existing file is never overwritten
  --cve LIST           Only look up these CVEs, separated by commas, including ones with no fix
                       released yet. Downloads Canonical's CVE data for this release (5 to 15 MB)
  --offline            Do not use the network. CVEs are not checked unless --oval-file is given
  --oval-file PATH     Use a local OVAL file (.xml or .xml.bz2), for hosts without internet access.
                       With --cve, this is the CVE feed (com.ubuntu.<codename>.cve.oval.xml.bz2)
  --proxy URL          HTTP proxy for downloading advisory data
  --skip-fs            Skip the full filesystem scan (SUID, capabilities, temp directories)
  --fs-timeout TIME    Time limit for the full filesystem scan (default 5m)
  --no-netlink         Do not read BPF filters, which keeps the kernel from loading af_packet_diag
  --version            Show the version

Exit codes: 0 nothing to act on, 1 medium findings, 2 critical or high findings,
3 scan incomplete (some items could not be checked), 130 scan aborted
`

func main() {
	os.Exit(run())
}

func run() int {
	var (
		asJSON, asText, offline, skipFS, noNetlink, showVersion bool
		outPath, ovalFile, proxy, minSev, cveList               string
		fsTimeout                                               time.Duration
	)
	fs := flag.NewFlagSet("ubuntu-sys-audit", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	fs.BoolVar(&asJSON, "json", false, "")
	fs.BoolVar(&asText, "text", false, "")
	fs.StringVar(&minSev, "min-severity", "medium", "")
	fs.StringVar(&outPath, "output", "", "")
	fs.StringVar(&outPath, "o", "", "")
	fs.StringVar(&cveList, "cve", "", "")
	fs.BoolVar(&offline, "offline", false, "")
	fs.StringVar(&ovalFile, "oval-file", "", "")
	fs.StringVar(&proxy, "proxy", "", "")
	fs.BoolVar(&skipFS, "skip-fs", false, "")
	fs.DurationVar(&fsTimeout, "fs-timeout", 5*time.Minute, "")
	fs.BoolVar(&noNetlink, "no-netlink", false, "")
	fs.BoolVar(&showVersion, "version", false, "")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 64
	}
	if showVersion {
		fmt.Printf("ubuntu-sys-audit %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0
	}
	threshold, ok := parseSeverity(minSev)
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid --min-severity value: %s\n", minSev)
		return 64
	}
	var cves []string
	if cveList != "" {
		var err error
		if cves, err = checks.ParseCVEList(cveList); err != nil {
			fmt.Fprintf(os.Stderr, "invalid --cve value: %v\n", err)
			return 64
		}
	}

	// Two threads of work is enough, and keeps the scan from competing with
	// production traffic on the host being audited.
	if runtime.NumCPU() > 2 {
		runtime.GOMAXPROCS(2)
	}

	opts := checks.Options{
		Version: version, Offline: offline, OVALFile: ovalFile, Proxy: proxy,
		SkipFS: skipFS, NoNetlink: noNetlink, FSTimeout: fsTimeout, CVEs: cves,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	interactive := !asJSON && !asText && isTerminal(os.Stdin) && isTerminal(os.Stdout)
	if interactive {
		report, err := tui.Run(ctx, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, "TUI error:", err)
			return 70
		}
		if report == nil {
			fmt.Fprintln(os.Stderr, "Scan aborted.")
			return 130
		}
		fmt.Println(output.Summary(report))
		return saveReport(outPath, report, report.ExitCode())
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Warning: not running as root, so some items were not checked. Run with sudo.")
	}
	report := checks.Run(ctx, opts, nil)
	code := report.ExitCode()
	if ctx.Err() != nil {
		code = 130
	}
	if asText {
		output.Text(os.Stdout, report, threshold)
	} else if err := output.JSON(os.Stdout, report); err != nil {
		fmt.Fprintln(os.Stderr, "Cannot write JSON:", err)
		code = failedOutput(code)
	}
	return saveReport(outPath, report, code)
}

// saveReport runs after the report has reached stdout, so a bad path cannot cost
// the operator the results.
func saveReport(path string, report *model.Report, code int) int {
	if path == "" {
		return code
	}
	if err := output.SaveJSON(path, report); err != nil {
		fmt.Fprintln(os.Stderr, "Cannot write report:", err)
		return failedOutput(code)
	}
	fmt.Fprintln(os.Stderr, "Report saved to", path)
	return code
}

// failedOutput returns the exit code after an output error. It must not replace
// the code for critical or high findings, which a batch script is watching for.
func failedOutput(code int) int {
	if code == 2 {
		return 2
	}
	return 74
}

func parseSeverity(s string) (model.Severity, bool) {
	for _, sev := range model.AllSeverities {
		if strings.EqualFold(s, sev.String()) {
			return sev, true
		}
	}
	return model.Medium, false
}

// isTerminal asks the kernel, because a character device check would also
// accept /dev/null, which is what stdin and stdout are under cron and most
// deployment tools.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(f.Fd())
}
