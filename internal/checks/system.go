package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"ubuntu-sys-audit/internal/dpkg"
	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
)

// releaseInfo holds Canonical's published support dates from distro-info-data.
type releaseInfo struct {
	version  string
	standard string
	esm      string
}

var releases = map[string]releaseInfo{
	"bionic":   {"18.04", "2023-05-31", "2028-04-26"},
	"focal":    {"20.04", "2025-05-29", "2030-04-23"},
	"jammy":    {"22.04", "2027-06-01", "2032-04-21"},
	"noble":    {"24.04", "2029-05-31", "2034-04-25"},
	"resolute": {"26.04", "2031-05-29", "2036-04-23"},
}

func parseDay(s string) time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return t
}

// esmEnabled reports whether the host is attached to Ubuntu Pro. Only presence
// and the machine name are examined; the token itself is never read into a
// finding.
func esmEnabled() bool {
	for _, p := range []string{"/etc/apt/auth.conf.d/90ubuntu-advantage", "/etc/apt/auth.conf.d/90ubuntu-pro"} {
		if b, err := fsx.Read(p, 1<<16); err == nil && strings.Contains(string(b), "esm.ubuntu.com") {
			return true
		}
	}
	return false
}

func checkOS(c *Context) []model.Finding {
	const cat = model.CatSystem
	h := c.Host
	name := strings.TrimSpace(h.OSName + " " + h.OSVersion)
	if name == "" {
		name = "unknown OS"
	}
	info := finding("system.os", cat, model.Info, "Operating system: "+name+" ("+h.Codename+")")
	info.Evidence = []string{
		"Hostname: " + h.Hostname,
		"Kernel: " + h.Kernel,
		"Architecture: " + h.Arch,
		"Uptime: " + formatDuration(time.Duration(h.UptimeSec)*time.Second),
	}
	if h.InContainer {
		info.Evidence = append(info.Evidence, "Environment: container (the kernel and some network results belong to the host)")
	}
	out := []model.Finding{info}

	rel, known := releases[h.Codename]
	if !known || !strings.EqualFold(strings.TrimSpace(h.OSName), "ubuntu") {
		f := finding("system.os.unsupported", cat, model.Medium, "This tool has not been validated on "+name)
		f.Detail = "Supported releases are Ubuntu 18.04, 20.04, 22.04, 24.04 and 26.04. Other results are still reported, but the CVE check may not run."
		return append(out, f)
	}
	now := time.Now()
	std, esm := parseDay(rel.standard), parseDay(rel.esm)
	pro := esmEnabled()
	switch {
	case now.After(esm):
		f := finding("system.os.eol", cat, model.Critical, "Ubuntu "+rel.version+" is past the end of ESM support")
		f.Detail = "ESM ended on " + rel.esm + ", so security updates are no longer available through normal channels."
		f.Remediation = "Upgrade to a supported LTS release."
		out = append(out, f)
	case now.After(std) && !pro:
		f := finding("system.os.eol", cat, model.High, "Ubuntu "+rel.version+" is past standard support and ESM is not enabled")
		f.Detail = "Standard support ended on " + rel.standard + ". Without Ubuntu Pro, main packages including the kernel, nginx and OpenSSL get no new security fixes. ESM is available until " + rel.esm + "."
		f.Remediation = "Enable Ubuntu Pro (sudo pro attach <token>) or upgrade to a supported LTS release."
		f.Refs = []string{"https://ubuntu.com/about/release-cycle"}
		f.Focus = true
		out = append(out, f)
	case now.After(std):
		f := finding("system.os.esm", cat, model.OK, "Ubuntu "+rel.version+" has ESM enabled, supported until "+rel.esm)
		out = append(out, f)
	default:
		f := finding("system.os.support", cat, model.OK, "Ubuntu "+rel.version+" is in standard support until "+rel.standard)
		if until := std.Sub(now); until < 180*24*time.Hour {
			f.Severity = model.Medium
			f.Title = "Ubuntu " + rel.version + " standard support ends on " + rel.standard
			f.Remediation = "Plan an upgrade, or enable Ubuntu Pro for ESM."
		}
		out = append(out, f)
	}
	return out
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	return fmt.Sprintf("%dh %dm", hours, int(d.Minutes())%60)
}

// kernelVersionFromImage extracts a comparable version from a vmlinuz name:
// vmlinuz-5.15.0-91-generic becomes 5.15.0-91.
func kernelVersion(release string) string {
	parts := strings.Split(release, "-")
	if len(parts) >= 2 {
		return parts[0] + "-" + parts[1]
	}
	return release
}

func checkKernel(c *Context) []model.Finding {
	const cat = model.CatSystem
	running := c.Host.Kernel
	info := finding("system.kernel", cat, model.Info, "Running kernel: "+running)
	info.Evidence = []string{fsx.ProcString("/proc/version")}
	info.Focus = true
	out := []model.Finding{info}
	if c.Host.InContainer {
		f := skipped("system.kernel.reboot", cat, "Kernel update status", "Running inside a container, so the kernel belongs to the host. Check it on the host.")
		return append(out, f)
	}

	matches, _ := filepath.Glob("/boot/vmlinuz-*")
	var installed []string
	for _, m := range matches {
		installed = append(installed, strings.TrimPrefix(filepath.Base(m), "vmlinuz-"))
	}
	sort.Slice(installed, func(i, j int) bool {
		return dpkg.Compare(kernelVersion(installed[i]), kernelVersion(installed[j])) < 0
	})
	if len(installed) > 0 {
		info.Evidence = append(info.Evidence, "Kernels in /boot: "+strings.Join(installed, ", "))
		out[0] = info
		newest := installed[len(installed)-1]
		if dpkg.Compare(kernelVersion(running), kernelVersion(newest)) < 0 {
			f := finding("system.kernel.stale", cat, model.High, "Running kernel is not the newest installed")
			f.Detail = "Running " + running + ", but /boot has " + newest + ". Kernel fixes take effect only after a reboot, so the host stays exposed until then."
			f.Remediation = "Schedule a reboot."
			f.Focus = true
			out = append(out, f)
		}
	}

	if b, err := fsx.Read("/var/run/reboot-required", 1<<12); err == nil {
		_ = b
		f := finding("system.reboot", cat, model.Medium, "System is flagged as needing a reboot")
		f.Detail = "/var/run/reboot-required exists, so installed updates need a reboot to take effect."
		if pk, err := fsx.Read("/var/run/reboot-required.pkgs", 1<<16); err == nil {
			f.Evidence = strings.Fields(string(pk))
		}
		f.Remediation = "Schedule a reboot."
		out = append(out, f)
	}
	if _, err := os.Stat("/snap/bin/canonical-livepatch"); err == nil {
		f := finding("system.livepatch", cat, model.Info, "Canonical Livepatch is installed")
		f.Detail = "The CVE check compares kernel versions, so issues already fixed by Livepatch may still be listed. Run canonical-livepatch status to confirm."
		out = append(out, f)
	}
	return out
}

type sysctlRule struct {
	path   string
	name   string
	bad    func(string) bool
	sev    model.Severity
	why    string
	expect string
}

func notEqual(want string) func(string) bool {
	return func(v string) bool { return v != want }
}

var sysctlRules = []sysctlRule{
	{"kernel/randomize_va_space", "kernel.randomize_va_space", notEqual("2"), model.High, "ASLR is not fully enabled, which makes memory bugs easier to exploit.", "2"},
	{"fs/protected_symlinks", "fs.protected_symlinks", notEqual("1"), model.Medium, "Symlink attack protection for temp directories is off.", "1"},
	{"fs/protected_hardlinks", "fs.protected_hardlinks", notEqual("1"), model.Medium, "Hardlink attack protection is off.", "1"},
	{"fs/suid_dumpable", "fs.suid_dumpable", notEqual("0"), model.Info, "SUID programs may produce core dumps with sensitive data. Ubuntu defaults to 2.", "0"},
	{"kernel/unprivileged_bpf_disabled", "kernel.unprivileged_bpf_disabled", func(v string) bool { return v == "0" }, model.Medium, "Unprivileged users can load eBPF, a common route into kernel privilege escalation bugs.", "1 or 2"},
	{"kernel/kptr_restrict", "kernel.kptr_restrict", notEqual("1"), model.Info, "Kernel addresses may leak, weakening KASLR.", "1"},
	{"kernel/dmesg_restrict", "kernel.dmesg_restrict", notEqual("1"), model.Info, "Unprivileged users can read dmesg.", "1"},
	{"kernel/yama/ptrace_scope", "kernel.yama.ptrace_scope", func(v string) bool { return v == "0" }, model.Medium, "Any process can ptrace others of the same user, which makes stealing credentials easy.", "1"},
	{"net/ipv4/tcp_syncookies", "net.ipv4.tcp_syncookies", notEqual("1"), model.Info, "SYN flood protection is off.", "1"},
	{"net/ipv4/conf/all/accept_source_route", "net.ipv4.conf.all.accept_source_route", notEqual("0"), model.Medium, "Source routed packets are accepted.", "0"},
	{"net/ipv4/conf/all/accept_redirects", "net.ipv4.conf.all.accept_redirects", notEqual("0"), model.Info, "ICMP redirects are accepted and could be used to change routes.", "0"},
}

func checkSysctl(c *Context) []model.Finding {
	const cat = model.CatSystem
	var out []model.Finding
	var weak []string
	worst := model.OK
	missing := 0
	for _, r := range sysctlRules {
		v := fsx.ProcString("/proc/sys/" + r.path)
		if v == "" {
			missing++
			continue
		}
		if r.bad(v) {
			weak = append(weak, fmt.Sprintf("%s = %s (recommended %s): %s", r.name, v, r.expect, r.why))
			if r.sev < worst {
				worst = r.sev
			}
		}
	}
	if missing == len(sysctlRules) {
		out = append(out, skipped("system.sysctl", cat, "Kernel security parameters", "Could not read any setting from /proc/sys."))
	} else if len(weak) == 0 {
		out = append(out, finding("system.sysctl", cat, model.OK, "Kernel security parameters match recommendations"))
	} else {
		f := finding("system.sysctl", cat, worst, fmt.Sprintf("Weak kernel security parameters (%d)", len(weak)))
		f.Evidence = weak
		f.Remediation = "Set the recommended values in /etc/sysctl.d/ and run sysctl --system. Check dependent services first."
		out = append(out, f)
	}

	// A handler piped from core_pattern or a changed modprobe path runs as
	// root inside the kernel's usermode helper, a known persistence trick.
	// Inside a container this setting belongs to the host, whose files are not here.
	if cp := fsx.ProcString("/proc/sys/kernel/core_pattern"); strings.HasPrefix(cp, "|") && !c.Host.InContainer {
		handler := strings.Fields(strings.TrimPrefix(cp, "|"))
		if len(handler) == 0 || !c.Owned(handler[0]) {
			f := finding("system.core_pattern", model.CatIntegrity, model.Critical, "core_pattern points to a handler from no package")
			f.Detail = "When a program crashes, the kernel runs this handler as root, which makes it a common persistence trick."
			f.Evidence = []string{cp}
			out = append(out, f)
		}
	}
	if mp := fsx.ProcString("/proc/sys/kernel/modprobe"); mp != "" && dpkg.NormalizePath(mp) != "/usr/sbin/modprobe" {
		f := finding("system.modprobe", model.CatIntegrity, model.Critical, "kernel.modprobe path has been changed")
		f.Detail = "The kernel runs this path as root when it needs to load a module. The default is /sbin/modprobe."
		f.Evidence = []string{mp}
		out = append(out, f)
	}
	return out
}

func checkCPUVulns(c *Context) []model.Finding {
	const cat = model.CatSystem
	files, err := filepath.Glob("/sys/devices/system/cpu/vulnerabilities/*")
	if err != nil || len(files) == 0 {
		return []model.Finding{skipped("system.cpu", cat, "CPU vulnerability mitigations", "Cannot read /sys/devices/system/cpu/vulnerabilities.")}
	}
	var vuln []string
	for _, p := range files {
		s := fsx.ProcString(p)
		if strings.HasPrefix(s, "Vulnerable") {
			vuln = append(vuln, filepath.Base(p)+": "+s)
		}
	}
	if len(vuln) == 0 {
		return []model.Finding{finding("system.cpu", cat, model.OK, "All "+strconv.Itoa(len(files))+" CPU vulnerabilities checked are mitigated or not applicable")}
	}
	f := finding("system.cpu", cat, model.Medium, fmt.Sprintf("Unmitigated CPU vulnerabilities (%d)", len(vuln)))
	f.Evidence = vuln
	f.Remediation = cpuVulnRemediation(c.Host.Arch)
	return []model.Finding{f}
}

// cpuVulnRemediation gives advice for the host's architecture. Ubuntu's microcode
// packages exist only for x86. ARM CPUs get these fixes through firmware instead.
func cpuVulnRemediation(arch string) string {
	const bootParams = "check whether the boot parameters include mitigations=off."
	if arch == "arm64" {
		return "Update the kernel and the firmware from the board, server or cloud vendor, and " + bootParams
	}
	return "Update intel-microcode or amd64-microcode and the kernel, and " + bootParams
}
