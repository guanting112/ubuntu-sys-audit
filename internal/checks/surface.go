package checks

import (
	"fmt"
	"path/filepath"
	"strings"

	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
)

// rareProtocols are kernel network protocols few servers need. Any local user
// can make the kernel load them by opening a socket, so a loadable module is
// attack surface even when it is not loaded yet.
var rareProtocols = []string{"dccp", "sctp", "rds", "tipc"}

const rareProtocolsDetail = "Few servers need DCCP, SCTP, RDS or TIPC, and these protocols have a history of kernel vulnerabilities, such as CVE-2017-6074 in DCCP, CVE-2010-3904 in RDS and CVE-2021-43267 in TIPC. Any local user can make the kernel load one by opening a socket."

// parseModuleBlocks adds the modules a modprobe configuration file prevents from
// auto-loading. "blacklist" stops loading by alias, which is how sockets trigger
// it, and "install NAME /bin/false" stops every load.
func parseModuleBlocks(src string, blocked map[string]bool) {
	for _, line := range strings.Split(src, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 2 && f[0] == "blacklist":
			blocked[f[1]] = true
		case len(f) >= 3 && f[0] == "install" && (base(f[2]) == "true" || base(f[2]) == "false"):
			blocked[f[1]] = true
		}
	}
}

// parseCmdlineBlocks adds modules blocked on the kernel command line.
func parseCmdlineBlocks(cmdline string, blocked map[string]bool) {
	for _, arg := range strings.Fields(cmdline) {
		key, value, ok := strings.Cut(arg, "=")
		if ok && (key == "modprobe.blacklist" || key == "module_blacklist") {
			for _, name := range strings.Split(value, ",") {
				blocked[name] = true
			}
		}
	}
}

// assessRareProtocols sorts the protocols into those active now and those a
// local user could still activate. procModules is /proc/modules, while modulesDep
// and modulesBuiltin are the files of the same name for the running kernel.
func assessRareProtocols(procModules, modulesDep, modulesBuiltin string, blocked map[string]bool, loadingDisabled bool) (loaded, loadable []string) {
	inMemory := map[string]bool{}
	for _, line := range strings.Split(procModules, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			inMemory[f[0]] = true
		}
	}
	listed := func(file, name string) bool {
		return strings.Contains("\n"+file, fmt.Sprintf("\nkernel/net/%s/%s.ko", name, name))
	}
	for _, name := range rareProtocols {
		switch {
		case inMemory[name] || listed(modulesBuiltin, name):
			loaded = append(loaded, name)
		case !blocked[name] && !loadingDisabled && listed(modulesDep, name):
			loadable = append(loadable, name)
		}
	}
	return loaded, loadable
}

// rareProtocolsFinding reports the assessment. moduleListKnown is false when the
// running kernel's modules.dep could not be read.
func rareProtocolsFinding(loaded, loadable []string, moduleListKnown bool) model.Finding {
	const id, cat = "network.protocols", model.CatNetwork
	if len(loaded) == 0 && len(loadable) == 0 {
		if !moduleListKnown {
			f := finding(id, cat, model.Info, "Rarely used network protocols are not loaded")
			f.Detail = "The kernel's modules.dep could not be read, so whether they can be auto-loaded was not assessed."
			return f
		}
		return finding(id, cat, model.OK, "Rarely used network protocols are not loaded and cannot be auto-loaded")
	}
	f := finding(id, cat, model.Info, "Rarely used network protocols can be auto-loaded: "+strings.Join(loadable, ", "))
	f.Detail = rareProtocolsDetail
	example := append(append([]string(nil), loaded...), loadable...)[0]
	f.Remediation = fmt.Sprintf("For each protocol you do not use, add a line such as install %s /bin/false to /etc/modprobe.d/90-disable-rare-protocols.conf.", example)
	if len(loaded) > 0 {
		f.Severity = model.Medium
		f.Title = "Rarely used network protocols are loaded: " + strings.Join(loaded, ", ")
		f.Detail += " A loaded protocol may be in use, so confirm nothing needs it before disabling it."
		f.Remediation += " Loaded modules also need sudo modprobe -r NAME or a reboot."
		f.Evidence = []string{"Loaded: " + strings.Join(loaded, ", ")}
	}
	if len(loadable) > 0 {
		f.Evidence = append(f.Evidence, "Can be auto-loaded: "+strings.Join(loadable, ", "))
	}
	return f
}

func checkRareProtocols(c *Context) []model.Finding {
	const id, cat, title = "network.protocols", model.CatNetwork, "Rarely used network protocols"
	if c.Host.InContainer {
		f := finding(id, cat, model.Info, "Rarely used network protocols were not assessed inside a container")
		f.Detail = "These modules belong to the host's kernel, and its modprobe configuration is not visible here."
		return []model.Finding{f}
	}
	modules, err := fsx.ReadProc("/proc/modules")
	if err != nil {
		return []model.Finding{skipped(id, cat, title, "Cannot read /proc/modules: "+err.Error())}
	}
	blocked := map[string]bool{}
	for _, dir := range []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"} {
		// modprobe ignores files in these directories without the .conf suffix.
		files, _ := filepath.Glob(dir + "/*.conf")
		for _, p := range files {
			if b, err := fsx.Read(p, 1<<18); err == nil {
				parseModuleBlocks(string(b), blocked)
			}
		}
	}
	parseCmdlineBlocks(fsx.ProcString("/proc/cmdline"), blocked)
	kernelDir := filepath.Join("/lib/modules", c.Host.Kernel)
	dep, depErr := fsx.Read(filepath.Join(kernelDir, "modules.dep"), 32<<20)
	builtin, _ := fsx.Read(filepath.Join(kernelDir, "modules.builtin"), 8<<20)
	loaded, loadable := assessRareProtocols(string(modules), string(dep), string(builtin), blocked, fsx.ProcString("/proc/sys/kernel/modules_disabled") == "1")
	return []model.Finding{rareProtocolsFinding(loaded, loadable, depErr == nil)}
}

// usernsSettings holds the kernel settings that limit unprivileged user
// namespaces. A setting the kernel does not have is empty.
type usernsSettings struct {
	MaxNamespaces    string // user.max_user_namespaces
	Clone            string // kernel.unprivileged_userns_clone, an Ubuntu and Debian patch
	AppArmorRestrict string // kernel.apparmor_restrict_unprivileged_userns, Ubuntu 23.10 and later
	AppArmorEnabled  string // /sys/module/apparmor/parameters/enabled
}

func readUsernsSettings() usernsSettings {
	return usernsSettings{
		MaxNamespaces:    fsx.ProcString("/proc/sys/user/max_user_namespaces"),
		Clone:            fsx.ProcString("/proc/sys/kernel/unprivileged_userns_clone"),
		AppArmorRestrict: fsx.ProcString("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
		AppArmorEnabled:  fsx.ProcString("/sys/module/apparmor/parameters/enabled"),
	}
}

// usernsFinding reports whether unprivileged users can create user namespaces.
// Many local kernel exploits start there, to gain network admin rights inside
// the namespace and reach code such as nf_tables.
func usernsFinding(s usernsSettings, inContainer bool) model.Finding {
	const id, cat = "system.userns", model.CatSystem
	switch {
	case s.MaxNamespaces == "":
		return finding(id, cat, model.OK, "User namespaces are not available on this kernel")
	case s.MaxNamespaces == "0":
		return finding(id, cat, model.OK, "User namespaces are disabled")
	case s.Clone == "0":
		return finding(id, cat, model.OK, "Unprivileged user namespaces are disabled")
	case s.AppArmorRestrict == "1" && s.AppArmorEnabled == "Y":
		f := finding(id, cat, model.OK, "Unprivileged user namespaces are restricted by AppArmor")
		f.Detail = "This narrows the attack path but does not close every way around it."
		return f
	}
	f := finding(id, cat, model.Medium, "Unprivileged users can create user namespaces")
	f.Detail = "Many local kernel exploits start by creating a user namespace to gain network admin rights inside it, such as those against nf_tables (CVE-2024-1086). Restricting this closes that path."
	f.Evidence = []string{"user.max_user_namespaces = " + s.MaxNamespaces}
	if s.Clone != "" {
		f.Evidence = append(f.Evidence, "kernel.unprivileged_userns_clone = "+s.Clone)
	}
	if s.AppArmorRestrict != "" {
		f.Evidence = append(f.Evidence, "kernel.apparmor_restrict_unprivileged_userns = "+s.AppArmorRestrict)
	}
	setting := "user.max_user_namespaces=0"
	switch {
	case s.AppArmorRestrict != "":
		setting = "kernel.apparmor_restrict_unprivileged_userns=1"
	case s.Clone != "":
		setting = "kernel.unprivileged_userns_clone=0"
	}
	f.Remediation = fmt.Sprintf("Test first, because this can break Chrome sandboxes, rootless containers and some snaps. Run sudo sysctl -w %s and add the same setting to /etc/sysctl.d/90-restrict-userns.conf to keep it after a reboot.", setting)
	if s.AppArmorRestrict == "1" {
		f.Detail += " The AppArmor restriction is set, but AppArmor is not enabled, so it has no effect."
		f.Remediation = "Enable AppArmor, so that kernel.apparmor_restrict_unprivileged_userns takes effect."
	}
	if inContainer {
		f.Severity = model.Info
		f.Detail += " Inside a container these settings belong to the host, and the container runtime may block this anyway."
	}
	return f
}
