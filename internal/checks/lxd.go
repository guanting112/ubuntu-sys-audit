package checks

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
)

// LXD gets its own check because Ubuntu installs it as a snap, which USN data does
// not cover, so the CVE check cannot see it. Canonical publishes its advisories on
// GitHub instead, and the snap store says what each branch is at.
const (
	lxdSnapYAML    = "/snap/lxd/current/meta/snap.yaml"
	lxdAdvisoryAPI = "https://api.github.com/repos/canonical/lxd/security-advisories?per_page=100"
	lxdSnapAPI     = "https://api.snapcraft.io/v2/snaps/info/lxd?fields=version,channel-map"
	lxdAdvisoryURL = "https://github.com/canonical/lxd/security/advisories"
)

// lxdSupportedBranches are the branches Canonical still patches, as of the
// 2026-10-29 releases 4.0.15, 5.0.11, 5.21.9 and 6.10.1.
var lxdSupportedBranches = map[string]bool{"4.0": true, "5.0": true, "5.21": true, "6": true}

var lxdNumber = regexp.MustCompile(`\d+(?:\.\d+)+`)

// lxdVersionNumber reduces a version like 5.21.9-2313ff2 or v6.10 to its number.
func lxdVersionNumber(raw string) string {
	return lxdNumber.FindString(raw)
}

// lxdBranch returns the release branch: 5.21.9 is on 5.21, while the 6 series is
// one rolling branch whose minor numbers are feature releases.
func lxdBranch(number string) string {
	parts := strings.Split(number, ".")
	if len(parts) < 2 {
		return number
	}
	if parts[0] >= "6" && len(parts[0]) == 1 {
		return parts[0]
	}
	return parts[0] + "." + parts[1]
}

type lxdInstall struct {
	Version string
	Source  string // "snap", "apt" or "unknown"
	Where   string
}

// snapYAMLVersion reads the top level version key from a snap's metadata.
func snapYAMLVersion(data string) string {
	for _, line := range strings.Split(data, "\n") {
		if v, ok := strings.CutPrefix(line, "version:"); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

func findLXD(c *Context) *lxdInstall {
	if b, err := fsx.Read(lxdSnapYAML, 1<<16); err == nil {
		if v := snapYAMLVersion(string(b)); v != "" {
			return &lxdInstall{Version: v, Source: "snap", Where: lxdSnapYAML}
		}
	}
	// From 20.04 the lxd deb is only a transitional package pulling in the snap,
	// and it is versioned 1:0.x.
	for _, v := range c.PackageVersions()["lxd"] {
		if !strings.HasPrefix(v, "1:") {
			return &lxdInstall{Version: v, Source: "apt", Where: "apt package"}
		}
	}
	if procs, err := c.Procs(); err == nil {
		for _, p := range procs {
			if !p.KernelTh && !p.InContainer && base(p.Exe) == "lxd" {
				return &lxdInstall{Source: "unknown", Where: "running from " + p.Exe}
			}
		}
	}
	return nil
}

type lxdAdvisory struct {
	GHSA            string `json:"ghsa_id"`
	CVE             string `json:"cve_id"`
	Summary         string `json:"summary"`
	Severity        string `json:"severity"`
	URL             string `json:"html_url"`
	Vulnerabilities []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Range   string `json:"vulnerable_version_range"`
		Patched string `json:"patched_versions"`
	} `json:"vulnerabilities"`
}

// isLXDPackage filters out entries in the same advisories that concern Incus or
// the LXD web UI, whose version numbers mean something else.
func isLXDPackage(name string) bool {
	switch strings.ToLower(name) {
	case "", "lxd", "github.com/canonical/lxd":
		return true
	}
	return false
}

var lxdRangeTerm = regexp.MustCompile(`(>=|<=|>|<)?\s*v?(\d+(?:\.\d+)*)`)

// inLXDRange evaluates a range such as ">= 4.0.2 < 6.9". All terms must hold.
func inLXDRange(rng, version string) bool {
	terms := lxdRangeTerm.FindAllStringSubmatch(rng, -1)
	if len(terms) == 0 {
		return false
	}
	for _, t := range terms {
		c := compareDotted(version, t[2])
		ok := false
		switch t[1] {
		case ">=":
			ok = c >= 0
		case "<=":
			ok = c <= 0
		case ">":
			ok = c > 0
		case "<":
			ok = c < 0
		default:
			ok = c == 0
		}
		if !ok {
			return false
		}
	}
	return true
}

// affects reports whether an advisory applies to a version, and where it was fixed.
//
// The patched list decides, because it names a fix per branch. A supported branch
// missing from the list was not affected, as with a feature added after that branch
// was cut. An unsupported branch gets no fixes, so only the vulnerable range can
// answer for it.
func (a lxdAdvisory) affects(version string) (bool, string) {
	branch := lxdBranch(version)
	for _, v := range a.Vulnerabilities {
		if !isLXDPackage(v.Package.Name) {
			continue
		}
		fixed := ""
		for _, tok := range lxdNumber.FindAllString(v.Patched, -1) {
			if lxdBranch(tok) == branch && (fixed == "" || compareDotted(tok, fixed) < 0) {
				fixed = tok
			}
		}
		if fixed != "" {
			if compareDotted(version, fixed) < 0 {
				return true, fixed
			}
			continue
		}
		if !lxdSupportedBranches[branch] && inLXDRange(v.Range, version) {
			return true, ""
		}
	}
	return false, ""
}

func lxdSeverity(s string) model.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return model.Critical
	case "high":
		return model.High
	case "medium", "moderate":
		return model.Medium
	}
	return model.Info
}

// parseSnapChannels maps a track to its stable version for one architecture.
func parseSnapChannels(data []byte, arch string) (map[string]string, error) {
	var info struct {
		ChannelMap []struct {
			Channel struct {
				Architecture string `json:"architecture"`
				Risk         string `json:"risk"`
				Track        string `json:"track"`
			} `json:"channel"`
			Version string `json:"version"`
		} `json:"channel-map"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, c := range info.ChannelMap {
		if c.Channel.Architecture == arch && c.Channel.Risk == "stable" {
			out[c.Channel.Track] = c.Version
		}
	}
	return out, nil
}

// lxdEscapeSettings find instance settings that let a container reach the host.
var lxdEscapeSettings = []struct {
	re   *regexp.Regexp
	name string
}{
	{regexp.MustCompile(`(?m)^\s*security\.privileged:\s*"?(true|1|yes|on)"?\s*$`), "security.privileged"},
	{regexp.MustCompile(`(?m)^\s*raw\.lxc:`), "raw.lxc"},
	{regexp.MustCompile(`(?m)^\s*source:\s*"?/"?\s*$`), "host root mounted"},
}

// lxdEscapes lists the settings in an instance's backup.yaml that break isolation.
func lxdEscapes(backupYAML string) []string {
	var out []string
	for _, s := range lxdEscapeSettings {
		if s.re.MatchString(backupYAML) {
			out = append(out, s.name)
		}
	}
	return out
}

func checkLXDPrivileged(c *Context) []model.Finding {
	const cat = model.CatNetwork
	var ev []string
	for _, pat := range []string{
		"/var/snap/lxd/common/lxd/storage-pools/*/containers/*/backup.yaml",
		"/var/lib/lxd/storage-pools/*/containers/*/backup.yaml",
	} {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			if c.Ctx.Err() != nil {
				break
			}
			// Not followed: an image once used a symlinked backup.yaml to attack
			// the host, so this file cannot be assumed to be what it claims.
			b, err := fsx.ReadNoFollow(m, 1<<20)
			if err != nil {
				continue
			}
			if bad := lxdEscapes(string(b)); len(bad) > 0 {
				ev = append(ev, base(filepath.Dir(m))+": "+strings.Join(bad, ", "))
			}
		}
	}
	if len(ev) == 0 {
		return nil
	}
	sort.Strings(ev)
	f := finding("network.lxd_privileged", cat, model.High, fmt.Sprintf("LXD containers with privileges that allow escaping to the host (%d)", len(ev)))
	f.Detail = "Root inside these containers can reach the host, so a compromised container means a compromised host. Containers on an unmounted storage pool are not visible to this check."
	f.Evidence = ev
	f.Remediation = "Unset security.privileged and raw.lxc unless they are required, and avoid mounting the host's root."
	return []model.Finding{f}
}

func checkLXDExposure(c *Context) []model.Finding {
	const cat = model.CatNetwork
	if _, err := c.Procs(); err != nil {
		return nil
	}
	view := c.Net()
	var ev []string
	for _, s := range view.Sockets {
		if !s.Listening() || !strings.HasPrefix(s.Proto, "tcp") || s.LocalIP.IsLoopback() || !s.HostNS {
			continue
		}
		p := view.ByInode[s.Inode]
		// forkdns is a DNS helper for fan and cluster networks, not the API.
		if p == nil || p.InContainer || base(p.Exe) != "lxd" || strings.Contains(p.CmdlineString(), "forkdns") {
			continue
		}
		ev = append(ev, s.Proto+" "+s.Local()+"  "+p.Label())
	}
	if len(ev) == 0 {
		return nil
	}
	sort.Strings(ev)
	f := finding("network.lxd_api", cat, model.Medium, "LXD API is bound to a non-loopback address")
	f.Detail = "Anyone who reaches this port can try to authenticate, and trusted clients are effectively root unless restricted. This tool cannot see external firewalls, so check those too."
	f.Evidence = ev
	f.Remediation = "If remote access is not needed, run lxc config unset core.https_address. Otherwise restrict the source addresses."
	return []model.Finding{f}
}

func checkLXD(c *Context) []model.Finding {
	const cat = model.CatCVE
	inst := findLXD(c)
	if inst == nil {
		return []model.Finding{finding("cve.lxd", cat, model.OK, "LXD is not installed")}
	}
	label := inst.Version
	if label == "" {
		label = "version unknown"
	}
	info := finding("cve.lxd", cat, model.Info, "LXD "+label+" ("+inst.Source+")")
	info.Evidence = []string{inst.Where}
	info.Focus = true
	out := []model.Finding{info}
	out = append(out, checkLXDExposure(c)...)
	out = append(out, checkLXDPrivileged(c)...)

	version := lxdVersionNumber(inst.Version)
	switch {
	case inst.Source == "apt":
		out[0].Detail = "Installed from apt, so Ubuntu's USN data covers it under the CVE category."
		return out
	case version == "":
		return append(out, skipped("cve.lxd.advisories", cat, "LXD advisories", "Could not determine the LXD version."))
	case c.Opts.Offline:
		return append(out, requested("cve.lxd.advisories", cat, "LXD advisories", "Offline mode, so LXD advisories were not checked."))
	}
	return append(out, lxdVersionFindings(c, version)...)
}

func lxdVersionFindings(c *Context, version string) []model.Finding {
	const cat = model.CatCVE
	client := newHTTPClient(c.Opts.Proxy)
	branch := lxdBranch(version)
	refresh := "Run sudo snap refresh lxd --channel=" + branch + "/stable. If refreshes are held, run sudo snap refresh --unhold lxd first."

	var out []model.Finding
	var advisories []lxdAdvisory
	advisoryErr := fetchWithHeaders(c.Ctx, client, lxdAdvisoryAPI, map[string]string{"Accept": "application/vnd.github+json"}, 16<<20, func(r io.Reader) error {
		return json.NewDecoder(r).Decode(&advisories)
	})

	latest := ""
	var channelData []byte
	snapErr := fetchWithHeaders(c.Ctx, client, lxdSnapAPI, map[string]string{"Snap-Device-Series": "16"}, 16<<20, func(r io.Reader) error {
		var err error
		channelData, err = io.ReadAll(r)
		return err
	})
	if snapErr == nil {
		channels, err := parseSnapChannels(channelData, runtime.GOARCH)
		if err != nil {
			snapErr = err
		} else {
			latest = lxdVersionNumber(channels[branch])
		}
	}

	if !lxdSupportedBranches[branch] {
		f := finding("cve.lxd.eol", cat, model.High, "LXD "+version+" is on a branch that no longer gets fixes")
		f.Detail = "Canonical currently patches the 4.0, 5.0, 5.21 and 6 branches."
		f.Remediation = "Move to a supported branch, for example sudo snap refresh lxd --channel=5.21/stable. Check the upgrade path first."
		f.Focus = true
		out = append(out, f)
	}

	var affected []string
	worst := model.Info
	var refs []string
	if advisoryErr == nil {
		for _, a := range advisories {
			hit, fixed := a.affects(version)
			if !hit {
				continue
			}
			id := a.CVE
			if id == "" {
				id = a.GHSA
			}
			line := fmt.Sprintf("%s [%s] %s", id, a.Severity, a.Summary)
			if fixed != "" {
				line += "  fixed in " + fixed
			} else {
				line += "  no fix on this branch"
			}
			affected = append(affected, line)
			if s := lxdSeverity(a.Severity); s < worst {
				worst = s
			}
			if len(refs) < 5 && a.URL != "" {
				refs = append(refs, a.URL)
			}
		}
		if len(affected) > 0 {
			f := finding("cve.lxd.advisories", cat, worst, fmt.Sprintf("LXD %s is affected by %s", version, plural(len(affected), "published advisory")))
			f.Detail = "Ubuntu's USN data does not cover the LXD snap, so these come from Canonical's LXD advisories. Many need access to the LXD API or a malicious image, so check who can reach it."
			f.Evidence = affected
			f.Remediation = refresh
			f.Refs = append(refs, lxdAdvisoryURL)
			f.Focus = true
			out = append(out, f)
		}
	} else {
		out = append(out, skipped("cve.lxd.advisories", cat, "LXD advisories", "Cannot get LXD advisories: "+advisoryErr.Error()))
	}

	behind := latest != "" && compareDotted(version, latest) < 0
	switch {
	case behind && len(affected) == 0:
		// Fixes can ship before their advisory is published, so being behind is a
		// finding of its own, and more serious when advisories could not be read.
		sev := model.Medium
		if advisoryErr != nil {
			sev = model.High
		}
		f := finding("cve.lxd.outdated", cat, sev, "LXD "+version+" is behind the latest on its branch, "+latest)
		f.Remediation = refresh
		f.Refs = []string{lxdAdvisoryURL}
		f.Focus = true
		out = append(out, f)
	case snapErr != nil && advisoryErr == nil && len(affected) == 0 && lxdSupportedBranches[branch]:
		out = append(out, skipped("cve.lxd.latest", cat, "LXD latest version", "Cannot get the latest version from the snap store: "+snapErr.Error()))
	case !behind && len(affected) == 0 && advisoryErr == nil && snapErr == nil && lxdSupportedBranches[branch]:
		out = append(out, finding("cve.lxd.latest", cat, model.OK, "LXD "+version+" is the latest on its branch, with no published advisories affecting it"))
	}
	return out
}
