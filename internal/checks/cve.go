package checks

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"ubuntu-sys-audit/internal/dpkg"
	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/oval"
)

func loadFeed(c *Context) (*oval.Feed, error) {
	if path := c.Opts.OVALFile; path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return oval.Parse(f, strings.HasSuffix(path, ".bz2"))
	}
	var feed *oval.Feed
	client := newHTTPClient(c.Opts.Proxy)
	err := fetch(c.Ctx, client, oval.FeedURL(c.Host.Codename), 128<<20, func(r io.Reader) error {
		parsed, err := oval.Parse(r, true)
		if err != nil {
			return err
		}
		feed = parsed
		return nil
	})
	return feed, err
}

// plural formats a count with its noun, such as "1 CVE" or "2 advisories".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	if stem, ok := strings.CutSuffix(noun, "y"); ok {
		return fmt.Sprintf("%d %sies", n, stem)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func priorityRank(p string) model.Severity {
	switch strings.ToLower(p) {
	case "critical":
		return model.Critical
	case "high":
		return model.High
	case "medium":
		return model.Medium
	}
	return model.Info
}

var focusSources = regexp.MustCompile(`^(linux.*|nginx|php.*|openssl.*|openssh|sudo|glibc|apache2|xz-utils|bash|curl|policykit-1|polkit|systemd|libapache2-mod.*)$`)

type sourceGroup struct {
	source   string
	kernel   bool
	hits     []oval.Hit
	binaries map[string]*oval.PkgHit
	worst    model.Severity
	cves     map[string]bool
	proOnly  bool
}

func groupHits(hits []oval.Hit) []*sourceGroup {
	groups := map[string]*sourceGroup{}
	for _, h := range hits {
		sources := map[string]bool{}
		for _, p := range h.Packages {
			src := p.Source
			if src == "" {
				src = p.Binary
			}
			g := groups[src]
			if g == nil {
				g = &sourceGroup{source: src, binaries: map[string]*oval.PkgHit{}, worst: model.Info, cves: map[string]bool{}, proOnly: true}
				groups[src] = g
			}
			if p.Kernel {
				g.kernel = true
			}
			pc := p
			if prev, ok := g.binaries[p.Binary]; !ok || dpkg.Compare(prev.Fixed, p.Fixed) < 0 {
				g.binaries[p.Binary] = &pc
			}
			if !p.RequiresPro() {
				g.proOnly = false
			}
			if !sources[src] {
				sources[src] = true
				g.hits = append(g.hits, h)
				if s := priorityRank(h.Severity); s < g.worst {
					g.worst = s
				}
				for _, cve := range h.CVEs {
					g.cves[cve.ID] = true
					if s := priorityRank(cve.Priority); s < g.worst {
						g.worst = s
					}
				}
			}
		}
	}
	out := make([]*sourceGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].worst != out[j].worst {
			return out[i].worst < out[j].worst
		}
		return out[i].source < out[j].source
	})
	return out
}

func describeHit(h oval.Hit) string {
	date := h.Issued
	if len(date) >= 10 {
		date = date[:10]
	}
	sev := h.Severity
	if sev == "" || sev == "none" {
		sev = "-"
	}
	title := h.Title
	if i := strings.Index(title, " -- "); i >= 0 {
		title = title[i+4:]
	}
	line := fmt.Sprintf("%s  %s  [%s]  %s", h.USN, date, sev, title)
	if len(h.CVEs) > 0 {
		ids := make([]string, 0, 6)
		sorted := append([]oval.CVE(nil), h.CVEs...)
		sort.SliceStable(sorted, func(i, j int) bool {
			return priorityRank(sorted[i].Priority) < priorityRank(sorted[j].Priority)
		})
		for i, cve := range sorted {
			if i == 6 {
				ids = append(ids, fmt.Sprintf("…%d total", len(sorted)))
				break
			}
			ids = append(ids, cve.ID)
		}
		line += "  " + strings.Join(ids, " ")
	}
	return line
}

func checkCVE(c *Context) []model.Finding {
	const cat = model.CatCVE
	title := "CVE check (Ubuntu USN)"
	if _, known := releases[c.Host.Codename]; !known && c.Opts.OVALFile == "" {
		return []model.Finding{skipped("cve.usn", cat, title, "No OVAL data for this release ("+c.Host.Codename+").")}
	}
	if c.Opts.Offline && c.Opts.OVALFile == "" {
		f := requested("cve.usn", cat, title, "Offline mode without --oval-file, so CVEs were not checked.")
		f.Remediation = "On a machine with internet access, download " + oval.FeedURL(c.Host.Codename) + " and pass it with --oval-file."
		return []model.Finding{f}
	}
	pkgs, err := c.Packages()
	if err != nil {
		return []model.Finding{skipped("cve.usn", cat, title, "Cannot read the dpkg database: "+err.Error())}
	}
	if len(pkgs) == 0 {
		return []model.Finding{skipped("cve.usn", cat, title, "The dpkg database lists no installed packages, so there was nothing to compare.")}
	}
	feed, err := loadFeed(c)
	if err != nil {
		f := skipped("cve.usn", cat, title, "Cannot get OVAL data: "+err.Error())
		f.Remediation = "Confirm the host can reach security-metadata.canonical.com, use --proxy, or download the file and pass it with --oval-file."
		return []model.Finding{f}
	}
	// Bad data must not read as a pass: an empty or wrong file finds nothing to fix.
	if feed.DefinitionCount() == 0 {
		f := skipped("cve.usn", cat, title, "The OVAL data holds no USN definitions. It may be the wrong kind of file.")
		f.Remediation = "Use " + oval.FeedURL(c.Host.Codename)
		return []model.Finding{f}
	}
	if feed.Release != c.Host.Codename {
		f := skipped("cve.usn", cat, title, fmt.Sprintf("The OVAL data is for %q but this host runs %q, so results would be meaningless.", feed.Release, c.Host.Codename))
		f.Remediation = "Use " + oval.FeedURL(c.Host.Codename)
		return []model.Finding{f}
	}
	var out []model.Finding
	ts, tsErr := time.Parse("2006-01-02T15:04:05", feed.Timestamp)
	switch {
	case tsErr != nil:
		f := finding("cve.feed_stale", cat, model.Medium, "OVAL data has no readable date")
		f.Detail = "This scan cannot tell how old the data is, so it may miss recent vulnerabilities."
		f.Remediation = "Download the latest OVAL file."
		out = append(out, f)
	case time.Since(ts) > 14*24*time.Hour:
		f := finding("cve.feed_stale", cat, model.Medium, fmt.Sprintf("OVAL data is %d days old", int(time.Since(ts).Hours()/24)))
		f.Detail = "The data is dated " + feed.Timestamp + ", so vulnerabilities announced later are not covered."
		f.Remediation = "Download the latest OVAL file."
		out = append(out, f)
	}
	if !feed.KernelRecognized(c.Host.Kernel) {
		reason := "This kernel matches no flavour in Ubuntu's USN data, as with mainline or custom kernels, so kernel CVEs were not checked."
		if c.Host.InContainer {
			f := finding("cve.kernel", cat, model.Info, "Kernel CVEs not checked inside a container")
			f.Detail = "The kernel belongs to the host, so run this scan there."
			out = append(out, f)
		} else {
			out = append(out, skipped("cve.kernel", cat, "Kernel CVEs for "+c.Host.Kernel, reason))
		}
	}
	hits := feed.Evaluate(c.PackageVersions(), c.Host.Kernel)
	if len(hits) == 0 {
		f := finding("cve.usn", cat, model.OK, fmt.Sprintf("Checked %d USNs, no fixes missing", feed.DefinitionCount()))
		f.Detail = "Data dated " + feed.Timestamp + ". USNs cover only vulnerabilities Ubuntu has fixed and packages installed with apt. For self-compiled or third-party software, see the Web category."
		return append(out, f)
	}

	groups := groupHits(hits)
	counts := map[model.Severity]int{}
	allCVEs := map[string]bool{}
	for _, g := range groups {
		counts[g.worst]++
		for id := range g.cves {
			allCVEs[id] = true
		}
	}
	overview := finding("cve.overview", cat, model.Info,
		fmt.Sprintf("Packages with missing fixes: %d (%d USNs, %d CVEs)", len(groups), len(hits), len(allCVEs)))
	overview.Detail = fmt.Sprintf("OVAL data dated %s, %d USNs checked. Severity is the highest of all USNs and CVEs for the package.", feed.Timestamp, feed.DefinitionCount())
	overview.Evidence = []string{
		fmt.Sprintf("Packages by severity: critical %d, high %d, medium %d, info %d", counts[model.Critical], counts[model.High], counts[model.Medium], counts[model.Info]),
	}
	overview.Focus = true
	out = append(out, overview)

	pro := esmEnabled()
	for _, g := range groups {
		f := finding("cve.pkg."+g.source, cat, g.worst, fmt.Sprintf("%s: %s missing, %s", g.source, plural(len(g.hits), "security notice"), plural(len(g.cves), "CVE")))
		f.Focus = focusSources.MatchString(g.source)

		var names []string
		for name := range g.binaries {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			p := g.binaries[name]
			f.Evidence = append(f.Evidence, fmt.Sprintf("%s  installed %s, fixed in %s", p.Binary, p.Installed, p.Fixed))
		}
		for _, h := range g.hits {
			f.Evidence = append(f.Evidence, describeHit(h))
			if len(f.Refs) < 5 {
				f.Refs = append(f.Refs, "https://ubuntu.com/security/notices/"+h.USN)
			}
		}
		switch {
		case g.kernel:
			f.Detail = "This compares the running kernel. Even with a newer kernel installed, the host stays affected until it reboots."
			f.Remediation = "sudo apt update && sudo apt full-upgrade, then reboot."
		case g.proOnly && !pro:
			f.Detail = "The fix is available only through Ubuntu Pro (ESM), which this host has not enabled."
			f.Remediation = "sudo pro attach <token>, then sudo pro fix " + g.hits[0].USN
		default:
			f.Remediation = "sudo apt update && sudo apt install --only-upgrade " + strings.Join(names, " ")
			if !pro {
				for _, name := range names {
					if g.binaries[name].RequiresPro() {
						f.Detail = "apt can apply some of these. Newer fixes are available only through Ubuntu Pro (ESM), which this host has not enabled."
						break
					}
				}
			}
		}
		out = append(out, f)
	}
	return out
}
