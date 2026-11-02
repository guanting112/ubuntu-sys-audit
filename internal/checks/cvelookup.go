package checks

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/oval"
)

var cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// ParseCVEList reads the --cve value: IDs separated by commas or spaces, in any
// case. Repeats are dropped and the order is kept.
func ParseCVEList(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, field := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		id := strings.ToUpper(field)
		if !cveIDPattern.MatchString(id) {
			return nil, fmt.Errorf("not a CVE ID: %s", field)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no CVE IDs given")
	}
	return out, nil
}

// ChecksFor returns the checks a scan with these options runs. Looking up CVEs
// is a quick question asked across a fleet, so it runs on its own.
func ChecksFor(opts Options) []Check {
	if len(opts.CVEs) > 0 {
		return []Check{{"cve.lookup", "CVE lookup", model.CatCVE, 5 * time.Minute, checkCVELookup}}
	}
	return All()
}

func loadCVEFeed(c *Context) (*oval.Feed, error) {
	if path := c.Opts.OVALFile; path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return oval.ParseCVEs(f, strings.HasSuffix(path, ".bz2"), c.Opts.CVEs)
	}
	var feed *oval.Feed
	err := fetch(c.Ctx, newHTTPClient(c.Opts.Proxy), oval.CVEFeedURL(c.Host.Codename), 128<<20, func(r io.Reader) error {
		parsed, err := oval.ParseCVEs(r, true, c.Opts.CVEs)
		if err != nil {
			return err
		}
		feed = parsed
		return nil
	})
	return feed, err
}

func checkCVELookup(c *Context) []model.Finding {
	const cat = model.CatCVE
	title := "CVE lookup"
	if _, known := releases[c.Host.Codename]; !known && c.Opts.OVALFile == "" {
		return []model.Finding{skipped("cve.lookup", cat, title, "No CVE data for this release ("+c.Host.Codename+").")}
	}
	if c.Opts.Offline && c.Opts.OVALFile == "" {
		f := requested("cve.lookup", cat, title, "Offline mode without --oval-file, so the CVEs were not looked up.")
		f.Remediation = "On a machine with internet access, download " + oval.CVEFeedURL(c.Host.Codename) + " and pass it with --oval-file."
		return []model.Finding{f}
	}
	if _, err := c.Packages(); err != nil {
		return []model.Finding{skipped("cve.lookup", cat, title, "Cannot read the dpkg database: "+err.Error())}
	}
	feed, err := loadCVEFeed(c)
	if err != nil {
		f := skipped("cve.lookup", cat, title, "Cannot get CVE data: "+err.Error())
		f.Remediation = "Confirm the host can reach security-metadata.canonical.com, use --proxy, or download " + oval.CVEFeedURL(c.Host.Codename) + " and pass it with --oval-file."
		return []model.Finding{f}
	}
	// Bad data must not read as "not affected".
	if feed.VulnerabilityCount() == 0 {
		f := skipped("cve.lookup", cat, title, "The OVAL data holds no CVE definitions. With --cve, --oval-file takes the CVE feed, not the USN feed.")
		f.Remediation = "Use " + oval.CVEFeedURL(c.Host.Codename)
		return []model.Finding{f}
	}
	if feed.Release != c.Host.Codename {
		f := skipped("cve.lookup", cat, title, fmt.Sprintf("The CVE data is for %q but this host runs %q, so results would be meaningless.", feed.Release, c.Host.Codename))
		f.Remediation = "Use " + oval.CVEFeedURL(c.Host.Codename)
		return []model.Finding{f}
	}
	var out []model.Finding
	if f := feedAgeFinding(feed.Timestamp); f != nil {
		out = append(out, *f)
	}
	// Inside a container the kernel belongs to the host, so leave it out.
	release := c.Host.Kernel
	if c.Host.InContainer {
		release = ""
	}
	pro := esmEnabled()
	for _, r := range feed.LookupCVEs(c.Opts.CVEs, c.PackageVersions(), release) {
		f := lookupFinding(r, c.Host, pro)
		f.Detail = strings.TrimSpace(f.Detail + " Data dated " + feed.Timestamp + ".")
		out = append(out, f)
	}
	return out
}

// lookupFinding turns one answer into a finding. A host that is affected gets
// the CVE's own priority as severity, whether or not a fix exists, so the exit
// code tells a fleet script which hosts the CVE reaches.
func lookupFinding(r oval.CVEResult, host model.Host, pro bool) model.Finding {
	const cat = model.CatCVE
	id := "cve.lookup." + r.ID
	ref := "https://ubuntu.com/security/" + r.ID
	release := strings.TrimSpace(host.OSVersion + " (" + host.Codename + ")")
	if !r.Known {
		f := finding(id, cat, model.Info, r.ID+": not in Ubuntu's CVE data for "+release)
		f.Detail = "Ubuntu lists no affected package for this release. The CVE may not affect Ubuntu, may be too new to be in the data, or may be mistyped."
		f.Refs = []string{ref}
		f.Focus = true
		return f
	}

	var available, unfixed, fixed, binaries []string
	kernelFix, proOnly := false, true
	for _, comp := range r.Components {
		switch comp.Status {
		case oval.FixAvailable:
			for _, line := range comp.Installed {
				if comp.Kernel {
					kernelFix = true
					available = append(available, fmt.Sprintf("kernel %s running %s, fixed in %s", comp.Source, line, comp.Fixed))
					continue
				}
				available = append(available, fmt.Sprintf("%s installed, fixed in %s", line, comp.Fixed))
				binaries = append(binaries, strings.Fields(line)[0])
			}
			proOnly = proOnly && comp.Pro
		case oval.Unfixed:
			if comp.Kernel {
				unfixed = append(unfixed, fmt.Sprintf("kernel %s running %s: no fix released", comp.Source, strings.Join(comp.Installed, ", ")))
			} else {
				unfixed = append(unfixed, fmt.Sprintf("%s (%s): no fix released", comp.Source, strings.Join(comp.Installed, ", ")))
			}
		case oval.Fixed:
			what := strings.Join(comp.Installed, ", ")
			if comp.Kernel {
				what = "kernel " + comp.Source + " running " + what
			}
			fixed = append(fixed, fmt.Sprintf("%s: includes the fix from %s", what, comp.Fixed))
		}
	}

	meta := "Priority " + orDash(r.Priority)
	if r.CVSS > 0 {
		meta += fmt.Sprintf(", CVSS %.1f", r.CVSS)
	}
	if len(r.Public) == 8 {
		meta += ", public " + r.Public[:4] + "-" + r.Public[4:6] + "-" + r.Public[6:]
	}
	evidence := append([]string{meta}, available...)
	evidence = append(append(evidence, unfixed...), fixed...)
	kernelNote := ""
	if r.KernelUnknown {
		kernelNote = " The CVE concerns Ubuntu kernels, but the running kernel was not checked: it matches no Ubuntu kernel flavour, or this is a container, where the kernel belongs to the host."
	}

	var f model.Finding
	sev := priorityRank(r.Priority)
	switch {
	case len(available) > 0:
		head := ": affected, fix available"
		if len(unfixed) > 0 {
			head = ": affected, a fix is available for part of it"
		}
		f = finding(id, cat, sev, r.ID+head)
		f.Detail = "An installed package or the running kernel is older than the fixed version."
		switch {
		case proOnly && !pro && !kernelFix:
			f.Detail += " The fix is available only through Ubuntu Pro (ESM), which this host has not enabled."
			f.Remediation = "sudo pro attach <token>, then sudo pro fix " + r.ID
		case kernelFix:
			f.Detail += " A kernel fix takes effect only after a reboot."
			f.Remediation = "sudo apt update && sudo apt full-upgrade, then reboot."
		default:
			sort.Strings(binaries)
			f.Remediation = "sudo apt update && sudo apt install --only-upgrade " + strings.Join(dedupe(binaries), " ")
		}
	case len(unfixed) > 0:
		f = finding(id, cat, sev, r.ID+": affected, no fix released yet")
		f.Detail = "Ubuntu marks an installed package or the running kernel as possibly affected, with no fix released. This includes CVEs still being triaged, so it may turn out not to apply."
		f.Remediation = "No update exists yet. Follow " + ref + " for the fix and any mitigation."
	case r.KernelUnknown:
		f = skipped(id, cat, r.ID+": kernel not checked", strings.TrimSpace(kernelNote))
		kernelNote = ""
	case len(fixed) > 0:
		f = finding(id, cat, model.OK, r.ID+": fixed in the installed versions")
	default:
		f = finding(id, cat, model.OK, r.ID+": not affected, no affected package is installed")
		if len(r.Sources) > 0 {
			evidence = append(evidence, "Affected in Ubuntu: "+limitList(r.Sources, 12))
		}
	}
	f.Detail = strings.TrimSpace(f.Detail + kernelNote)
	f.Evidence = evidence
	f.Refs = []string{ref}
	f.Focus = true
	return f
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func dedupe(sorted []string) []string {
	var out []string
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func limitList(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" and %d more", len(items)-n)
}
