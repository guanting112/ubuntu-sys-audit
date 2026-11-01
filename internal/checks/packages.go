package checks

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"ubuntu-sys-audit/internal/dpkg"
	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
)

func checkUpdates(c *Context) []model.Finding {
	const cat = model.CatPackages
	pkgs, err := c.Packages()
	if err != nil {
		return []model.Finding{skipped("packages.updates", cat, "Security updates", "Cannot read the dpkg database: "+err.Error())}
	}
	var out []model.Finding

	var held []string
	installed := make(map[string][]dpkg.Package, len(pkgs))
	for _, p := range pkgs {
		installed[p.Name] = append(installed[p.Name], p)
		if p.Held {
			held = append(held, p.Name+"  "+p.Version)
		}
	}
	if len(held) > 0 {
		f := finding("packages.held", cat, model.Medium, fmt.Sprintf("Packages on apt hold (%d)", len(held)))
		f.Detail = "Held packages get no updates, including security fixes."
		f.Evidence = held
		f.Remediation = "Find out why. If no longer needed, run apt-mark unhold <package>."
		out = append(out, f)
	}

	// Lists fetched by apt already say which security updates exist. This
	// works even when the host cannot reach Canonical's OVAL feed.
	lists, _ := filepath.Glob("/var/lib/apt/lists/*-security_*_Packages")
	var compressed []string
	for _, pat := range []string{"*-security_*_Packages.lz4", "*-security_*_Packages.gz", "*-security_*_Packages.xz", "*-security_*_Packages.zst"} {
		m, _ := filepath.Glob("/var/lib/apt/lists/" + pat)
		compressed = append(compressed, m...)
	}
	newest := time.Time{}
	allLists, _ := filepath.Glob("/var/lib/apt/lists/*")
	for _, l := range allLists {
		if st, err := os.Stat(l); err == nil && st.Mode().IsRegular() && st.ModTime().After(newest) {
			newest = st.ModTime()
		}
	}
	switch {
	case len(lists) == 0 && len(compressed) > 0:
		out = append(out, skipped("packages.pending", cat, "Available security updates", "The apt lists are compressed and this tool does not parse that format. The CVE check is not affected."))
	case len(lists) == 0:
		out = append(out, skipped("packages.pending", cat, "Available security updates", "No apt security lists found. Run apt update first."))
	default:
		pending := map[string]string{}
		for _, l := range lists {
			if c.Ctx.Err() != nil {
				break
			}
			b, err := fsx.Read(l, 512<<20)
			if err != nil {
				continue
			}
			scanPackagesList(b, installed, pending)
		}
		var ev []string
		for name, v := range pending {
			ev = append(ev, fmt.Sprintf("%s  %s -> %s", name, installed[name][0].Version, v))
		}
		sort.Strings(ev)
		if len(ev) > 0 {
			f := finding("packages.pending", cat, model.High, fmt.Sprintf("Security updates not yet installed (%d)", len(ev)))
			f.Detail = "Based on the local apt lists, last updated " + newest.Format("2006-01-02") + "."
			f.Evidence = ev
			f.Remediation = "sudo apt update && sudo apt upgrade"
			f.Focus = true
			out = append(out, f)
		} else {
			out = append(out, finding("packages.pending", cat, model.OK, "No pending security updates according to the local apt lists"))
		}
	}
	if !newest.IsZero() && time.Since(newest) > 7*24*time.Hour {
		f := finding("packages.stale_lists", cat, model.Medium, fmt.Sprintf("apt lists not updated for %d days", int(time.Since(newest).Hours()/24)))
		f.Detail = "Last updated " + newest.Format("2006-01-02") + ". With stale lists, the pending update count will be too low."
		f.Remediation = "sudo apt update"
		out = append(out, f)
	}

	autoEnabled := false
	if b, err := fsx.Read("/etc/apt/apt.conf.d/20auto-upgrades", 1<<14); err == nil {
		autoEnabled = regexp.MustCompile(`Unattended-Upgrade\s+"[1-9]`).Match(b)
	}
	_, hasPkg := installed["unattended-upgrades"]
	switch {
	case !hasPkg:
		f := finding("packages.unattended", cat, model.Medium, "unattended-upgrades is not installed")
		f.Detail = "This host does not apply security updates automatically, so every CVE fix relies on manual work."
		f.Remediation = "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"
		out = append(out, f)
	case !autoEnabled:
		f := finding("packages.unattended", cat, model.Medium, "unattended-upgrades is installed but not enabled")
		f.Remediation = "sudo dpkg-reconfigure -plow unattended-upgrades"
		out = append(out, f)
	default:
		f := finding("packages.unattended", cat, model.OK, "Automatic security updates are enabled")
		if st, err := os.Stat("/var/lib/apt/periodic/unattended-upgrades-stamp"); err == nil && time.Since(st.ModTime()) > 7*24*time.Hour {
			f.Severity = model.Medium
			f.Title = fmt.Sprintf("Automatic security updates have not run for %d days", int(time.Since(st.ModTime()).Hours()/24))
			f.Remediation = "Check /var/log/unattended-upgrades/ and apt-daily-upgrade.timer."
		}
		out = append(out, f)
	}

	if b, err := fsx.Tail("/var/log/dpkg.log", 16<<20); err == nil {
		last := ""
		lines := strings.Split(string(b), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			if strings.Contains(lines[i], " upgrade ") {
				last = lines[i]
				break
			}
		}
		if last != "" {
			f := finding("packages.last_upgrade", cat, model.Info, "Last package upgrade: "+strings.Join(strings.Fields(last + " x x")[:2], " "))
			f.Evidence = []string{last}
			out = append(out, f)
		}
	}
	return out
}

// scanPackagesList records the newest version offered for installed packages
// when that version is newer than what is installed.
func scanPackagesList(data []byte, installed map[string][]dpkg.Package, pending map[string]string) {
	nameKey, verKey := []byte("Package: "), []byte("Version: ")
	var name string
	for len(data) > 0 {
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		switch {
		case bytes.HasPrefix(line, nameKey):
			name = string(line[len(nameKey):])
		case bytes.HasPrefix(line, verKey) && name != "":
			if have, ok := installed[name]; ok {
				v := string(line[len(verKey):])
				if dpkg.Compare(have[0].Version, v) < 0 {
					if prev, seen := pending[name]; !seen || dpkg.Compare(prev, v) < 0 {
						pending[name] = v
					}
				}
			}
			name = ""
		}
	}
}

var aptURIRe = regexp.MustCompile(`(?i)https?://([^/\s]+)`)
var ubuntuHosts = regexp.MustCompile(`(?i)(^|\.)(ubuntu\.com|canonical\.com)$`)

func checkAptSources(c *Context) []model.Finding {
	const cat = model.CatPackages
	files := []string{"/etc/apt/sources.list"}
	for _, pat := range []string{"/etc/apt/sources.list.d/*.list", "/etc/apt/sources.list.d/*.sources"} {
		m, _ := filepath.Glob(pat)
		files = append(files, m...)
	}
	hosts := map[string]bool{}
	for _, p := range files {
		b, err := fsx.Read(p, 1<<20)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			for _, m := range aptURIRe.FindAllStringSubmatch(line, -1) {
				// A mirror URL can carry user:password@, which must not reach the report.
				host := strings.ToLower(m[1][strings.LastIndexByte(m[1], '@')+1:])
				if !ubuntuHosts.MatchString(host) {
					hosts[host] = true
				}
			}
		}
	}
	if len(hosts) == 0 {
		return []model.Finding{finding("packages.sources", cat, model.OK, "Only official Ubuntu package sources are used")}
	}
	var ev []string
	for h := range hosts {
		ev = append(ev, h)
	}
	sort.Strings(ev)
	f := finding("packages.sources", cat, model.Info, fmt.Sprintf("Third-party package sources (%d)", len(ev)))
	f.Detail = "Packages from these sources install as root and are not covered by USNs. Internal mirrors appear here too."
	f.Evidence = ev
	return []model.Finding{f}
}

var inventoryPattern = regexp.MustCompile(`^(linux-image-[0-9].*|openssl|libssl[0-9.]+[a-z0-9]*|openssh-server|openssh-client|sudo|libc6|bash|curl|systemd|xz-utils|liblzma[0-9]+|policykit-1|polkitd|snapd|nginx|nginx-core|nginx-full|nginx-light|nginx-extras|apache2|php[0-9.]+-fpm|php[0-9.]+-cli|libapache2-mod-php[0-9.]+|mysql-server[-0-9.a-z]*|mariadb-server[-0-9.a-z]*|postgresql-[0-9]+|redis-server|docker-ce|docker\.io|containerd(\.io)?|memcached|haproxy|tomcat[0-9]*|openjdk-[0-9]+-jre[a-z-]*|nodejs|python3)$`)

func checkInventory(c *Context) []model.Finding {
	const cat = model.CatPackages
	pkgs, err := c.Packages()
	if err != nil {
		return []model.Finding{skipped("packages.inventory", cat, "Key software versions", err.Error())}
	}
	var ev []string
	for _, p := range pkgs {
		if !inventoryPattern.MatchString(p.Name) {
			continue
		}
		origin := dpkg.Origin(p.Version)
		ev = append(ev, fmt.Sprintf("%-28s %s  [%s]", p.Name, p.Version, origin))
		c.AddInventory(model.InventoryItem{Name: p.Name, Version: p.Version, Source: origin})
	}
	sort.Strings(ev)
	f := finding("packages.inventory", cat, model.Info, fmt.Sprintf("Key software versions (%d packages installed)", len(pkgs)))
	f.Detail = "When a new CVE lands, use this list or the JSON output to compare quickly. Ubuntu package versions may already include backported fixes, so do not judge by the upstream version alone."
	f.Evidence = ev
	f.Focus = true
	return []model.Finding{f}
}
