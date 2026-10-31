package checks

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
)

type lineRule struct {
	re   *regexp.Regexp
	name string
}

// Patterns with no ordinary use in a scheduled job or login script.
var maliciousRules = []lineRule{
	{regexp.MustCompile(`(curl|wget|fetch)\b[^|;&]*\|\s*(sudo\s+)?(/\S*/)?(ba|z|da|k)?sh\b`), "downloads and pipes into a shell"},
	{regexp.MustCompile(`/dev/(tcp|udp)/`), "bash network redirection (reverse shell)"},
	{regexp.MustCompile(`\bbash\s+-i\b`), "interactive bash (reverse shell)"},
	{regexp.MustCompile(`\b(nc|ncat|netcat)\b[^|;&]*\s-[a-zA-Z]*[ec]\b`), "netcat executes a command"},
	{regexp.MustCompile(`python[0-9.]*\s+-c\s*['"].*socket`), "python one-liner socket"},
	{regexp.MustCompile(`perl\s+-e\s*['"].*socket`), "perl one-liner socket"},
	{regexp.MustCompile(`socat\b.*\b(exec|system):`), "socat executes a command"},
	{regexp.MustCompile(`base64\s+(-d|--decode)\b[^|;&]*\|\s*(ba|z|da)?sh\b`), "decodes base64 into a shell"},
	{regexp.MustCompile(`\bmkfifo\b.*\b(nc|ncat|sh)\b`), "named pipe reverse shell"},
	{regexp.MustCompile(`\b(xmrig|kinsing|kdevtmpfsi)\b|stratum\+tcp://`), "crypto miner indicator"},
}

var tempPathRe = regexp.MustCompile(`(^|[\s'";&|(=])((?:/tmp|/var/tmp|/dev/shm)/[^\s'";&|)]+)`)

func matchMalicious(line string) string {
	for _, r := range maliciousRules {
		if r.re.MatchString(line) {
			return r.name
		}
	}
	return ""
}

// referencesTempExec looks for a command run out of a temporary directory. Log
// redirections and cleanup jobs mention these paths all the time, so those are
// excluded.
func referencesTempExec(line string) bool {
	for _, loc := range tempPathRe.FindAllStringIndex(line, -1) {
		before := strings.TrimRight(line[:loc[0]+1], " \t'\"=")
		if strings.HasSuffix(line[:loc[0]+1], ">") || strings.HasSuffix(before, ">") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "find /") || strings.Contains(lower, "rm ") || strings.Contains(lower, "tmpreaper") ||
			strings.Contains(lower, "mkdir") || strings.Contains(lower, "chown ") {
			continue
		}
		return true
	}
	return false
}

type persistTarget struct {
	glob     string
	group    string
	noFollow bool
}

var persistTargets = []persistTarget{
	{glob: "/etc/crontab", group: "cron"},
	{glob: "/etc/cron.d/*", group: "cron"},
	{glob: "/etc/cron.hourly/*", group: "cron"},
	{glob: "/etc/cron.daily/*", group: "cron"},
	{glob: "/etc/cron.weekly/*", group: "cron"},
	{glob: "/etc/cron.monthly/*", group: "cron"},
	{glob: "/var/spool/cron/crontabs/*", group: "user crontab", noFollow: true},
	{glob: "/var/spool/cron/atjobs/*", group: "at job", noFollow: true},
	{glob: "/etc/rc.local", group: "rc.local"},
	{glob: "/etc/init.d/*", group: "init.d"},
	{glob: "/etc/profile", group: "login script"},
	{glob: "/etc/bash.bashrc", group: "login script"},
	{glob: "/etc/environment", group: "login script"},
	{glob: "/etc/profile.d/*", group: "login script"},
	{glob: "/etc/update-motd.d/*", group: "motd"},
	{glob: "/etc/apt/apt.conf.d/*", group: "apt hook"},
	{glob: "/etc/udev/rules.d/*", group: "udev"},
	{glob: "/etc/ld.so.conf.d/*", group: "dynamic linker config"},
	{glob: "/etc/modules-load.d/*", group: "module loading"},
	{glob: "/etc/modprobe.d/*", group: "module loading"},
}

var userInitFiles = []string{
	".bashrc", ".profile", ".bash_profile", ".bash_login", ".bash_logout", ".zshrc", ".zprofile",
	".config/fish/config.fish",
}

// Files administrators or Ubuntu's own tooling generate outside dpkg's lists,
// where being unowned says nothing.
var expectedUnowned = regexp.MustCompile(`^/etc/(crontab|environment|profile|bash\.bashrc|cron\.d/\.placeholder|cron\.\w+/\.placeholder|apt/apt\.conf\.d/(20auto-upgrades|50unattended-upgrades|01autoremove|01-vendor-ubuntu|70debconf|99[-\w]*|docker-\w+)|ld\.so\.conf\.d/(libc\.conf|.*-linux-gnu.*\.conf|fakeroot.*\.conf)|modprobe\.d/\w+\.conf|modules-load\.d/modules\.conf)$`)

func checkPersistence(c *Context) []model.Finding {
	const cat = model.CatPersistence
	var malicious, tempRefs []string
	unowned := map[string][]string{}
	scanned := 0
	cutoff := time.Now().Add(-7 * 24 * time.Hour)

	scan := func(path, group string, noFollow bool, userFile bool) {
		var b []byte
		var err error
		if noFollow {
			b, err = fsx.ReadNoFollow(path, 1<<20)
		} else {
			b, err = fsx.Read(path, 1<<20)
		}
		if err != nil {
			return
		}
		scanned++
		owned := c.Owned(path)
		for _, raw := range strings.Split(string(b), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if name := matchMalicious(line); name != "" {
				malicious = append(malicious, fmt.Sprintf("%s (%s): %s", path, name, line))
			} else if !owned && referencesTempExec(line) {
				tempRefs = append(tempRefs, path+": "+line)
			}
		}
		if owned || userFile || expectedUnowned.MatchString(path) {
			return
		}
		entry := path
		if st, err := os.Lstat(path); err == nil && st.ModTime().After(cutoff) {
			entry += " (modified in the last 7 days)"
		}
		// Crontab entries are the content an operator actually wants to read.
		if strings.HasPrefix(path, "/var/spool/cron/crontabs/") {
			for _, raw := range strings.Split(string(b), "\n") {
				line := strings.TrimSpace(raw)
				if line != "" && !strings.HasPrefix(line, "#") {
					entry += "\n" + line
				}
			}
			for _, e := range strings.Split(entry, "\n")[1:] {
				unowned[group] = append(unowned[group], base(path)+": "+e)
			}
			return
		}
		unowned[group] = append(unowned[group], entry)
	}

	for _, t := range persistTargets {
		matches, _ := filepath.Glob(t.glob)
		for _, m := range matches {
			if c.Ctx.Err() != nil {
				break
			}
			if base(m) == ".placeholder" {
				continue
			}
			scan(m, t.group, t.noFollow, false)
		}
	}
	for _, u := range c.Homes() {
		for _, name := range userInitFiles {
			scan(filepath.Join(u.Home, name), "home login script", true, true)
		}
		auto, _ := filepath.Glob(filepath.Join(u.Home, ".config/autostart/*"))
		for _, a := range auto {
			scan(a, "desktop autostart", true, false)
		}
	}

	var out []model.Finding
	if len(malicious) > 0 {
		f := finding("persistence.malicious", cat, model.Critical, fmt.Sprintf("Scheduled job or login script lines with malicious signs (%d)", len(malicious)))
		f.Detail = "These patterns rarely appear outside post-intrusion persistence, such as downloading and running code or reverse shells."
		f.Evidence = malicious
		f.Remediation = "Back up the file as evidence, remove the entry and investigate how the attacker got in."
		out = append(out, f)
	}
	if len(tempRefs) > 0 {
		f := finding("persistence.temp_exec", cat, model.High, "Scheduled jobs or login scripts run programs from temp directories")
		f.Evidence = tempRefs
		f.Remediation = "Confirm the purpose. Anyone can write to temp directories, which is a privilege escalation risk in itself."
		out = append(out, f)
	}
	var groups []string
	for g := range unowned {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	var ev []string
	for _, g := range groups {
		for _, line := range unowned[g] {
			ev = append(ev, "["+g+"] "+line)
		}
	}
	if len(ev) > 0 {
		f := finding("persistence.unowned", cat, model.Info, fmt.Sprintf("Scheduled and startup items that belong to no package (%d)", len(ev)))
		f.Detail = "Administrators add items here, and attackers hide persistence here. Confirm you recognize them all."
		f.Evidence = ev
		out = append(out, f)
	}
	if len(malicious)+len(tempRefs) == 0 {
		out = append(out, finding("persistence.clean", cat, model.OK, fmt.Sprintf("Scanned %d scheduled and startup files, no malicious signs", scanned)))
	}
	return out
}

var systemdDirs = []string{
	"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/user", "/usr/lib/systemd/user",
}

var execKeyRe = regexp.MustCompile(`^(ExecStart|ExecStartPre|ExecStartPost|ExecStop|ExecStopPost|ExecReload)=(.*)$`)

func checkSystemd(c *Context) []model.Finding {
	const cat = model.CatPersistence
	var malicious, tempExec, unowned []string
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	seen := map[string]bool{}
	scanned := 0

	scanUnit := func(path string, noFollow bool) {
		real := path
		if seen[real] {
			return
		}
		seen[real] = true
		var b []byte
		var err error
		if noFollow {
			b, err = fsx.ReadNoFollow(path, 1<<20)
		} else {
			b, err = fsx.Read(path, 1<<20)
		}
		if err != nil {
			return
		}
		scanned++
		var execs []string
		for _, raw := range strings.Split(string(b), "\n") {
			line := strings.TrimSpace(raw)
			m := execKeyRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			cmd := strings.TrimLeft(m[2], "-@:+!")
			execs = append(execs, cmd)
			if name := matchMalicious(cmd); name != "" {
				malicious = append(malicious, fmt.Sprintf("%s (%s): %s", path, name, cmd))
				continue
			}
			first := strings.Fields(cmd + " x")[0]
			if inTemp(first) {
				tempExec = append(tempExec, path+": "+cmd)
			}
		}
		if !c.Owned(path) && len(execs) > 0 {
			entry := path + " -> " + execs[0]
			if st, err := os.Lstat(path); err == nil && st.ModTime().After(cutoff) {
				entry = "(modified in the last 7 days) " + entry
			}
			unowned = append(unowned, entry)
		}
	}

	wanted := func(name string) bool {
		return strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".conf") ||
			strings.HasSuffix(name, ".timer") || strings.HasSuffix(name, ".path") || strings.HasSuffix(name, ".socket")
	}
	for _, dir := range systemdDirs {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if c.Ctx.Err() != nil {
				return filepath.SkipAll
			}
			// Enablement symlinks point at units scanned at their real path.
			if d.Type().IsRegular() && wanted(d.Name()) {
				scanUnit(p, false)
			}
			return nil
		})
	}
	for _, u := range c.Homes() {
		dir := filepath.Join(u.Home, ".config/systemd/user")
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.Type().IsRegular() && wanted(d.Name()) {
				scanUnit(p, true)
			}
			return nil
		})
	}
	var out []model.Finding
	if len(malicious) > 0 {
		f := finding("persistence.systemd_malicious", cat, model.Critical, "systemd services with malicious signs")
		f.Evidence = malicious
		f.Remediation = "Back up the unit file as evidence, stop it with systemctl disable --now and investigate how the attacker got in."
		out = append(out, f)
	}
	if len(tempExec) > 0 {
		f := finding("persistence.systemd_temp", cat, model.Critical, "systemd services run programs from temp directories")
		f.Detail = "Nothing in a temp directory should run as a systemd service."
		f.Evidence = tempExec
		out = append(out, f)
	}
	if len(unowned) > 0 {
		sort.Strings(unowned)
		f := finding("persistence.systemd_unowned", cat, model.Info, fmt.Sprintf("systemd services that belong to no package (%d)", len(unowned)))
		f.Detail = "Services you deployed yourself appear here. Confirm you recognize them all."
		f.Evidence = unowned
		out = append(out, f)
	}
	if len(malicious)+len(tempExec) == 0 {
		out = append(out, finding("persistence.systemd_clean", cat, model.OK, fmt.Sprintf("Scanned %d systemd units, no malicious signs", scanned)))
	}
	return out
}
