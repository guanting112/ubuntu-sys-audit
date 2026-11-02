package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ubuntu-sys-audit/internal/fsx"
)

// networkHookTargets are scripts run as root when an interface comes up or goes
// down, or a DHCP lease changes: ifupdown, networkd-dispatcher (Ubuntu Server's
// default), NetworkManager, dhclient and pppd. Packages ship some under /usr/lib.
var networkHookTargets = []persistTarget{
	{glob: "/etc/network/if-up.d/*", group: "network hook"},
	{glob: "/etc/network/if-down.d/*", group: "network hook"},
	{glob: "/etc/network/if-pre-up.d/*", group: "network hook"},
	{glob: "/etc/network/if-post-down.d/*", group: "network hook"},
	{glob: "/etc/networkd-dispatcher/*.d/*", group: "network hook"},
	{glob: "/usr/lib/networkd-dispatcher/*.d/*", group: "network hook"},
	{glob: "/etc/NetworkManager/dispatcher.d/*", group: "network hook"},
	{glob: "/etc/NetworkManager/dispatcher.d/*/*", group: "network hook"},
	{glob: "/usr/lib/NetworkManager/dispatcher.d/*", group: "network hook"},
	{glob: "/usr/lib/NetworkManager/dispatcher.d/*/*", group: "network hook"},
	{glob: "/etc/dhcp/dhclient-enter-hooks", group: "network hook"},
	{glob: "/etc/dhcp/dhclient-exit-hooks", group: "network hook"},
	{glob: "/etc/dhcp/dhclient-enter-hooks.d/*", group: "network hook"},
	{glob: "/etc/dhcp/dhclient-exit-hooks.d/*", group: "network hook"},
	{glob: "/etc/ppp/ip-up.d/*", group: "network hook"},
	{glob: "/etc/ppp/ip-down.d/*", group: "network hook"},
}

const logrotateMain = "/etc/logrotate.conf"

var logrotateTarget = persistTarget{group: "logrotate script", commands: logrotateCommands}

var (
	// logrotate runs these blocks with /bin/sh as root, up to a line reading
	// endscript.
	logrotateScript = regexp.MustCompile(`^(postrotate|prerotate|firstaction|lastaction|preremove)\b\s*(.*)$`)
	// These name a program logrotate runs on every rotated file.
	logrotateProgram = regexp.MustCompile(`^(compresscmd|uncompresscmd)\s+\S`)
	logrotateInclude = regexp.MustCompile(`^include\s+(\S+)`)
)

// parseLogrotate returns the lines of a logrotate file that run something, and
// the paths it includes. The rest is log paths and options: a log kept under
// /tmp is not a program run from there. Script lines continued with a trailing
// backslash are joined, as the shell joins them.
func parseLogrotate(src string) (commands, includes []string) {
	inScript := false
	pending := ""
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case inScript:
			if line == "endscript" || strings.HasPrefix(line, "endscript ") {
				inScript = false
				if pending != "" {
					commands = append(commands, strings.TrimSpace(pending))
					pending = ""
				}
				continue
			}
			if line == "" && pending != "" {
				// A blank line ends the continued command.
				commands = append(commands, strings.TrimSpace(pending))
				pending = ""
				continue
			}
			if line == "" || strings.HasPrefix(line, "#") && pending == "" {
				continue
			}
			if slashes := len(line) - len(strings.TrimRight(line, `\`)); slashes%2 == 1 {
				pending += line[:len(line)-1] + " "
				continue
			}
			commands = append(commands, strings.TrimSpace(pending+line))
			pending = ""
		case strings.HasPrefix(line, "#"):
		case logrotateScript.MatchString(line):
			inScript = true
			if rest := logrotateScript.FindStringSubmatch(line)[2]; rest != "" {
				commands = append(commands, rest)
			}
		case logrotateProgram.MatchString(line):
			commands = append(commands, line)
		default:
			if m := logrotateInclude.FindStringSubmatch(line); m != nil {
				includes = append(includes, m[1])
			}
		}
	}
	return commands, includes
}

func logrotateCommands(src string) []string {
	commands, _ := parseLogrotate(src)
	return commands
}

// logrotateTaboo lists the endings logrotate skips in an included directory, so
// a backup such as nginx.dpkg-old is never read by it.
var logrotateTaboo = []string{
	",v", ".cfsaved", ".disabled", ".dpkg-bak", ".dpkg-del", ".dpkg-dist", ".dpkg-new", ".dpkg-old",
	".dpkg-tmp", ".rpmnew", ".rpmorig", ".rpmsave", ".swp", ".ucf-dist", ".ucf-new", ".ucf-old", "~",
}

func logrotateSkips(name string) bool {
	if strings.Contains(name, ".rhn-cfg-tmp-") {
		return true
	}
	for _, t := range logrotateTaboo {
		if strings.HasSuffix(name, t) {
			return true
		}
	}
	return false
}

// logrotateConfigs follows the main file's includes to every file logrotate
// reads. /etc/logrotate.d is always covered, in case the include was removed
// from the main file. An include or a file that resolves into a temp directory
// is returned on its own and not read: anyone could write that configuration.
// root is prepended only to touch the filesystem, for tests.
func logrotateConfigs(root string) (files, temp []string) {
	type entry struct {
		path    string
		fromDir bool // an entry of an included directory, which logrotate does not descend into
	}
	queue := []entry{{path: logrotateMain}, {path: "/etc/logrotate.d"}}
	seen := map[string]bool{}
	for len(queue) > 0 && len(seen) < 4096 {
		e := queue[0]
		queue = queue[1:]
		if seen[e.path] {
			continue
		}
		seen[e.path] = true
		if real, err := filepath.EvalSymlinks(root + e.path); err == nil {
			if real = strings.TrimPrefix(real, root); real != e.path && inTemp(real+"/") {
				temp = append(temp, e.path+" -> "+real)
				continue
			}
		}
		st, err := os.Stat(root + e.path)
		if err != nil {
			continue
		}
		if st.IsDir() {
			if e.fromDir {
				continue
			}
			names, _ := os.ReadDir(root + e.path)
			for _, d := range names {
				if !logrotateSkips(d.Name()) {
					queue = append(queue, entry{path: e.path + "/" + d.Name(), fromDir: true})
				}
			}
			continue
		}
		files = append(files, e.path)
		b, err := fsx.Read(root+e.path, persistLimit)
		if err != nil {
			continue
		}
		_, includes := parseLogrotate(string(b))
		for _, inc := range includes {
			if !filepath.IsAbs(inc) {
				continue
			}
			inc = filepath.Clean(inc)
			if inTemp(inc + "/") {
				temp = append(temp, e.path+": include "+inc)
				continue
			}
			queue = append(queue, entry{path: inc})
		}
	}
	return files, temp
}

// anacronStock matches the jobs anacron ships, which only run the cron
// directories this scan already reads.
var anacronStock = regexp.MustCompile(`^(cd / && )?(nice )?run-parts( --report)? /etc/cron\.(daily|weekly|monthly|yearly)$`)

// anacronCommands returns anacrontab job lines other than the stock ones.
// Variable assignments such as SHELL= are settings, not jobs.
func anacronCommands(src string) []string {
	var out []string
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || shellAssign.MatchString(line) {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 || anacronStock.MatchString(strings.Join(f[3:], " ")) {
			continue
		}
		out = append(out, line)
	}
	return out
}

// desktopExec returns the commands in a desktop entry. Other keys hold names and
// icon paths, which run nothing.
func desktopExec(src string) []string {
	var out []string
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "Exec=") || strings.HasPrefix(line, "Exec =") {
			out = append(out, line)
		}
	}
	return out
}
