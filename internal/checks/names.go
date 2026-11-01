package checks

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
)

// protectedDomains serve Ubuntu's packages and security data. Overriding them in
// /etc/hosts can block updates, which is why malware does it.
var protectedDomains = []string{"ubuntu.com", "canonical.com", "launchpad.net", "snapcraft.io"}

func isProtectedDomain(name string) bool {
	for _, d := range protectedDomains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// hostsOverrides finds /etc/hosts lines that redirect a protected domain. A
// private address may be an internal mirror, so it is kept apart from loopback,
// which blocks the domain, and from public addresses. self is this host's name,
// which a machine inside one of these domains may legitimately list.
func hostsOverrides(src, self string) (suspicious, private []string) {
	self = strings.ToLower(strings.TrimSuffix(self, "."))
	for _, line := range strings.Split(src, "\n") {
		text, _, _ := strings.Cut(line, "#")
		f := strings.Fields(text)
		if len(f) < 2 {
			continue
		}
		addr, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		for _, raw := range f[1:] {
			name := strings.ToLower(strings.TrimSuffix(raw, "."))
			if name == self || !isProtectedDomain(name) {
				continue
			}
			if addr.IsPrivate() {
				private = append(private, strings.TrimSpace(text))
			} else {
				suspicious = append(suspicious, strings.TrimSpace(text))
			}
			break
		}
	}
	return suspicious, private
}

func hostsOverrideFinding(suspicious, private []string) model.Finding {
	f := finding("network.hosts_override", model.CatNetwork, model.High, "/etc/hosts overrides Ubuntu update or security domains")
	f.Detail = "This can block security updates or send requests to another server. Package signatures still protect against altered packages, but a blocked update leaves the host unpatched."
	f.Evidence = append(append([]string(nil), suspicious...), private...)
	f.Remediation = "Remove these lines unless you added them on purpose. To use a mirror, set it in the apt sources instead."
	if len(suspicious) == 0 {
		f.Severity = model.Medium
		f.Detail += " A private address may be an internal mirror, so confirm who added it."
	}
	return f
}

// knownNSSModules ship with Ubuntu or are common, documented integrations.
var knownNSSModules = map[string]bool{
	"files": true, "compat": true, "db": true, "dns": true, "myhostname": true, "mymachines": true,
	"resolve": true, "systemd": true, "mdns": true, "mdns_minimal": true, "mdns4": true,
	"mdns4_minimal": true, "mdns6": true, "mdns6_minimal": true, "nis": true, "nisplus": true,
	"hesiod": true, "sss": true, "ldap": true, "winbind": true, "wins": true, "cache": true,
	"extrausers": true, "libvirt": true, "libvirt_guest": true, "oslogin": true, "cache_oslogin": true,
}

// unknownNSSModules lists modules in nsswitch.conf outside the known set, each
// with the databases that use it. Bracketed actions such as [NOTFOUND=return] are
// not modules.
func unknownNSSModules(src string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(src, "\n") {
		text, _, _ := strings.Cut(line, "#")
		db, list, ok := strings.Cut(text, ":")
		if !ok {
			continue
		}
		db = strings.TrimSpace(db)
		inAction := false
		for _, field := range strings.Fields(list) {
			switch {
			case strings.HasPrefix(field, "["):
				inAction = !strings.HasSuffix(field, "]")
			case inAction:
				inAction = !strings.HasSuffix(field, "]")
			case !knownNSSModules[field]:
				out[field] = append(out[field], db)
			}
		}
	}
	return out
}

var safeModuleName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// nssLibraries finds the files glibc would load for an NSS module.
func nssLibraries(module string) []string {
	if !safeModuleName.MatchString(module) {
		return nil
	}
	var found []string
	for _, dir := range []string{"/lib/*", "/usr/lib/*", "/lib", "/usr/lib", "/lib64", "/usr/lib64", "/usr/local/lib"} {
		matches, _ := filepath.Glob(dir + "/libnss_" + module + ".so*")
		found = append(found, matches...)
	}
	return found
}

// nssFindings reports NSS modules that are not known. These libraries run inside
// every process that looks up a user or host, including sshd and sudo.
func nssFindings(src string, libraries func(string) []string, owned func(string) bool) []model.Finding {
	var unmanaged, other []string
	for module, dbs := range unknownNSSModules(src) {
		line := fmt.Sprintf("%s (used for %s)", module, strings.Join(dbs, ", "))
		found := libraries(module)
		var rogue []string
		for _, p := range found {
			if !owned(p) {
				rogue = append(rogue, p)
			}
		}
		switch {
		case len(rogue) > 0:
			unmanaged = append(unmanaged, line+": "+strings.Join(rogue, ", "))
		case len(found) > 0:
			other = append(other, line+": from a package")
		default:
			other = append(other, line+": no library found")
		}
	}
	sort.Strings(unmanaged)
	sort.Strings(other)
	var out []model.Finding
	if len(unmanaged) > 0 {
		f := finding("integrity.nss_unmanaged", model.CatIntegrity, model.High, "An NSS module outside package management is enabled")
		f.Detail = "NSS modules are loaded into every process that looks up a user or host, including sshd and sudo running as root. A rogue module can steal passwords or add hidden accounts."
		f.Evidence = unmanaged
		f.Remediation = "Find out who installed it. If nobody did, preserve the file, treat the host as compromised and remove the module from /etc/nsswitch.conf."
		out = append(out, f)
	}
	if len(other) > 0 {
		f := finding("integrity.nss_other", model.CatIntegrity, model.Info, "Uncommon NSS modules in nsswitch.conf")
		f.Detail = "NSS modules are loaded into every process that looks up a user or host. Confirm you recognise these."
		f.Evidence = other
		out = append(out, f)
	}
	return out
}

var tcpWrapperCommand = regexp.MustCompile(`(?i):\s*(spawn|twist)\b`)

// tcpWrapperCommands finds hosts.allow and hosts.deny rules that run a command
// when someone connects, which is a way to keep access through a firewall.
func tcpWrapperCommands(src string) []string {
	var out []string
	joined := strings.ReplaceAll(src, "\\\n", " ")
	for _, line := range strings.Split(joined, "\n") {
		text := strings.TrimSpace(line)
		if !strings.HasPrefix(text, "#") && tcpWrapperCommand.MatchString(text) {
			out = append(out, text)
		}
	}
	return out
}

func tcpWrapperFinding(lines []string) model.Finding {
	f := finding("persistence.tcp_wrappers", model.CatPersistence, model.High, "TCP Wrappers rules run a command on connection")
	f.Detail = "A spawn or twist option runs a command, usually as root, whenever someone connects to the service. This is rare today, and a known way to keep access to a host."
	f.Evidence = lines
	f.Remediation = "Remove the rule unless you added it on purpose. If you did not, investigate the host for other signs of compromise."
	return f
}

func checkNameResolution(c *Context) []model.Finding {
	var out []model.Finding
	if b, err := fsx.Read("/etc/hosts", 1<<20); err == nil {
		suspicious, private := hostsOverrides(string(b), c.Host.Hostname)
		if len(suspicious)+len(private) > 0 {
			out = append(out, hostsOverrideFinding(suspicious, private))
		}
	}
	if b, err := fsx.Read("/etc/nsswitch.conf", 1<<18); err == nil {
		out = append(out, nssFindings(string(b), nssLibraries, c.Owned)...)
	}
	var commands []string
	for _, p := range []string{"/etc/hosts.allow", "/etc/hosts.deny"} {
		if b, err := fsx.Read(p, 1<<18); err == nil {
			for _, line := range tcpWrapperCommands(string(b)) {
				commands = append(commands, filepath.Base(p)+": "+line)
			}
		}
	}
	if len(commands) > 0 {
		out = append(out, tcpWrapperFinding(commands))
	}
	if len(out) == 0 {
		out = append(out, finding("network.names", model.CatNetwork, model.OK, "No signs of tampering in /etc/hosts, nsswitch.conf or TCP Wrappers"))
	}
	return out
}
