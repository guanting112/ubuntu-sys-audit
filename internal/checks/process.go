package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ubuntu-sys-audit/internal/dpkg"
	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/procinfo"
)

var minerPattern = regexp.MustCompile(`(?i)\b(xmrig|kinsing|kdevtmpfsi|kthreaddi|minerd|cpuminer|nbminer|lolminer|phoenixminer|ethminer|cgminer|bfgminer|t-rex|teamredminer)\b|stratum\+(tcp|ssl)://`)

// Names implants borrow for their argv[0]. BPFDoor's published list includes
// /sbin/udevd, dbus-daemon, auditd, hald-* and postfix's pickup and master.
var masqueradeNames = map[string]bool{
	"sshd": true, "udevd": true, "systemd-udevd": true, "cron": true, "crond": true, "rsyslogd": true,
	"auditd": true, "dbus-daemon": true, "agetty": true, "mingetty": true, "master": true,
	"pickup": true, "qmgr": true, "console-kit-daemon": true, "hald-runner": true,
	"hald-addon-acpi": true, "avahi-daemon": true, "systemd-journald": true, "systemd-logind": true,
	"systemd-networkd": true, "systemd-resolved": true, "polkitd": true, "acpid": true, "atd": true,
	"irqbalance": true, "nginx": true, "php-fpm": true, "apache2": true, "httpd": true,
}

var shellNames = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true, "fish": true, "rbash": true}

var interactiveNetTools = map[string]bool{
	"python": true, "python2": true, "python3": true, "perl": true, "php": true, "ruby": true,
	"lua": true, "nc": true, "ncat": true, "netcat": true, "socat": true, "telnet": true, "openssl": true,
}

var webServers = map[string]bool{"nginx": true, "apache2": true, "httpd": true, "lighttpd": true, "caddy": true}

func isWebParent(name string) bool {
	return webServers[name] || strings.HasPrefix(name, "php-fpm") || strings.HasPrefix(name, "php")
}

// Directories where people legitimately install tools inside a hidden folder.
var hiddenDirAllow = []string{
	".vscode-server", ".cursor-server", ".nvm", ".pyenv", ".rbenv", ".cargo", ".local", ".sdkman",
	".rustup", ".asdf", ".npm", ".cache/ms-playwright", ".windsurf-server", ".antigravity-server",
}

func hiddenPathComponent(path string) bool {
	if !strings.Contains(path, "/.") {
		return false
	}
	for _, allow := range hiddenDirAllow {
		if strings.Contains(path, "/"+allow+"/") {
			return false
		}
	}
	return true
}

func argv0Base(p *procinfo.Process) string {
	if len(p.Cmdline) == 0 {
		return ""
	}
	first := strings.Fields(p.Cmdline[0] + " x")[0]
	first = strings.TrimSuffix(first, ":")
	return strings.TrimLeft(first[strings.LastIndexByte(first, '/')+1:], "-@")
}

var multiCallBinaries = map[string]bool{"busybox": true, "toybox": true}

// argv0IsAlias reports whether argv[0] legitimately names the running binary by
// another path. Multi-call binaries do this: from 22.04 on,
// /lib/systemd/systemd-udevd is a symlink to /usr/bin/udevadm, so every host
// running udev would otherwise look like it hosts a masquerading process.
func argv0IsAlias(c *Context, p *procinfo.Process) bool {
	if len(p.Cmdline) == 0 {
		return false
	}
	argv0 := strings.Fields(p.Cmdline[0] + " x")[0]
	if p.InContainer {
		// Alpine and other small images run everything through one binary, so
		// crond's executable really is busybox there.
		if multiCallBinaries[base(p.Exe)] {
			return true
		}
		// The host's dpkg database says nothing about a container's files, so
		// all that can be checked is that the path is the running binary.
		return pathIsProcessExe(p.PID, argv0)
	}
	return isPackagedAlias(argv0, p.Exe, filepath.EvalSymlinks, c.Owned)
}

// isPackagedAlias requires both paths to come from packages. A process name is
// attacker controlled, and so is a symlink an attacker creates, but neither can
// add an entry to the package file lists without also tampering with dpkg.
//
// Paths are compared as strings rather than by inode so this still holds after
// a package upgrade, when the process runs a binary replaced on disk. That case
// is reported separately as a stale binary.
func isPackagedAlias(argv0, exe string, resolve func(string) (string, error), owned func(string) bool) bool {
	if !filepath.IsAbs(argv0) || !owned(argv0) || !owned(exe) {
		return false
	}
	real, err := resolve(argv0)
	return err == nil && dpkg.NormalizePath(real) == dpkg.NormalizePath(exe)
}

// pathIsProcessExe reports whether a path inside the process's own root is the
// file it is running.
func pathIsProcessExe(pid int, path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	dir := "/proc/" + strconv.Itoa(pid)
	named, err := os.Stat(dir + "/root" + path)
	if err != nil {
		return false
	}
	running, err := os.Stat(dir + "/exe")
	return err == nil && os.SameFile(named, running)
}

func checkProcesses(c *Context) []model.Finding {
	const cat = model.CatProcess
	procs, err := c.Procs()
	if err != nil {
		return []model.Finding{skipped("process.suspicious", cat, "Suspicious processes", err.Error())}
	}
	byPID := map[int]*procinfo.Process{}
	for _, p := range procs {
		byPID[p.PID] = p
	}
	view := c.Net()
	estTCP := map[uint64]procinfo.Socket{}
	for _, s := range view.Sockets {
		if (s.Proto == "tcp" || s.Proto == "tcp6") && s.State == procinfo.StateEstablished {
			estTCP[s.Inode] = s
		}
	}

	self := os.Getpid()
	var fakeKernel, masquerade, tempExe, contTempExe, memfd, deletedExe, hidden, unmanaged, miners, revShell, webShell, preload []string
	user := 0
	for _, p := range procs {
		if p.KernelTh {
			continue
		}
		user++
		// This scan itself, often copied to /tmp to run once.
		if p.PID == self {
			continue
		}
		line := p.Label()
		if cmd := p.CmdlineString(); cmd != "" {
			line += "  command: " + cmd
		}
		exeBase := base(p.Exe)

		if len(p.Cmdline) > 0 {
			a := p.Cmdline[0]
			if strings.HasPrefix(a, "[") && strings.HasSuffix(strings.Fields(a + " x")[0], "]") {
				fakeKernel = append(fakeKernel, line)
			}
		}
		if p.Exe != "" {
			if argv := argv0Base(p); masqueradeNames[argv] && !strings.HasPrefix(exeBase, argv) && !strings.HasPrefix(argv, exeBase) && !argv0IsAlias(c, p) {
				masquerade = append(masquerade, line)
			}
		}
		if miner := minerPattern.FindString(exeBase + " " + p.Comm + " " + p.CmdlineString()); miner != "" {
			miners = append(miners, line)
		}

		switch {
		case strings.HasPrefix(p.Exe, "/memfd:"):
			if !strings.Contains(p.Exe, "runc") && !strings.Contains(p.Exe, "crun") {
				memfd = append(memfd, line)
			}
		case inTemp(p.Exe):
			if p.InContainer {
				contTempExe = append(contTempExe, line)
			} else {
				tempExe = append(tempExe, line)
			}
		case p.ExeDeleted && !p.InContainer:
			deletedExe = append(deletedExe, line)
		case p.Exe != "" && !p.InContainer && hiddenPathComponent(p.Exe):
			hidden = append(hidden, line)
		case p.Exe != "" && !p.InContainer && c.Host.IsRoot && !c.Owned(p.Exe) && inDirs(p.Exe, "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib", "/lib"):
			unmanaged = append(unmanaged, line)
		}

		// A shell whose stdin and stdout are a TCP connection is the textbook
		// reverse shell. sshd sessions use a pty or a UNIX socketpair instead.
		if len(p.StdioSocket) >= 2 {
			s0, ok0 := estTCP[p.StdioSocket[0]]
			_, ok1 := estTCP[p.StdioSocket[1]]
			if ok0 && ok1 && (shellNames[exeBase] || interactiveNetTools[strings.TrimRight(exeBase, "0123456789.")]) {
				revShell = append(revShell, line+"  connection: "+s0.Remote())
			}
		}
		if shellNames[exeBase] || shellNames[p.Comm] {
			if parent := byPID[p.PPID]; parent != nil && isWebParent(base(parent.Exe)) {
				webShell = append(webShell, line+"  parent: "+parent.Label())
			}
		}
		if v, ok := procinfo.Environ(p.PID, "LD_PRELOAD"); ok && strings.TrimSpace(v) != "" {
			for _, lib := range strings.FieldsFunc(v, func(r rune) bool { return r == ':' || r == ' ' }) {
				if !c.Owned(lib) && !p.InContainer {
					preload = append(preload, p.Label()+"  LD_PRELOAD="+v)
					break
				}
			}
		}
	}

	var out []model.Finding
	add := func(id string, sev model.Severity, title, detail, fix string, ev []string) {
		if len(ev) == 0 {
			return
		}
		f := finding("process."+id, cat, sev, title)
		f.Detail, f.Remediation, f.Evidence = detail, fix, ev
		out = append(out, f)
	}
	isolate := "Preserve /proc/<pid>/exe and connection details, then isolate the host and investigate. Do not kill the process first."
	add("fake_kernel", model.Critical, "User process poses as a kernel thread", "It is named like [kworker] but has a real binary. Real kernel threads have none.", isolate, fakeKernel)
	add("masquerade", model.Critical, "Process poses as a system service", "argv[0] names a system service, but the real binary is something else. Backdoors such as BPFDoor hide this way.", isolate, masquerade)
	add("reverse_shell", model.Critical, "Possible reverse shell", "Standard input and output are both attached to a TCP connection, the classic sign of a reverse shell.", isolate, revShell)
	add("miner", model.Critical, "Crypto miner indicators found", "", isolate, miners)
	add("temp_exe", model.Critical, "Process runs from a temp directory", "Normal services do not run from /tmp, /var/tmp or /dev/shm. Tools dropped after an intrusion often do.", isolate, tempExe)
	add("memfd_exe", model.Critical, "Process runs from a memory file", "The binary exists only in a memfd and not on disk, a fileless attack technique.", isolate, memfd)
	add("container_temp_exe", model.High, "Container process runs from a temp directory", "", "Check whether the container is compromised, and rebuild it from a clean image if needed.", contTempExe)
	add("web_shell_child", model.High, "Shell running under a web service", "This may be a webshell running commands, though applications that call a shell look the same. Judge by the command.", "Review the Web category results and access logs.", webShell)
	add("hidden_dir", model.Medium, "Process runs from a hidden directory", "", "Find out where these programs came from.", hidden)
	add("ld_preload", model.High, "Process has an LD_PRELOAD from outside any package", "This injects an external library into the process, which can hide files or steal data.", "Find out where the library came from.", preload)
	add("unmanaged", model.Medium, "Processes run from system directories but belong to no package", "These binaries are in /usr/bin, /usr/sbin or /usr/lib without belonging to a package. They may be manual installs, or they may have been dropped there.", "Check where they came from and when they were installed.", unmanaged)
	add("deleted_exe", model.Medium, "Process binary was deleted or replaced", "Most often a service was not restarted after a package upgrade, so it still runs the old version. If no upgrade explains it, suspect malware that deleted itself.", "Restart the service to apply the fix. If the path is not a package file, investigate further.", deletedExe)

	summary := finding("process.summary", cat, model.Info, fmt.Sprintf("Processes, excluding kernel threads (%d)", user))
	if !c.Host.IsRoot {
		summary.Detail = "Without root, binaries and sockets of other users' processes are hidden, so results are incomplete."
	}
	out = append(out, summary)
	if len(fakeKernel)+len(masquerade)+len(tempExe)+len(memfd)+len(miners)+len(revShell) == 0 {
		out = append(out, finding("process.clean", cat, model.OK, "No signs of masquerading, temp directory execution or reverse shells"))
	}
	return out
}

var soPathPattern = regexp.MustCompile(`(/\S*\.so(?:\.[0-9.]+)?)( \(deleted\))?$`)

func checkStaleLibs(c *Context) []model.Finding {
	const cat = model.CatProcess
	if !c.Host.IsRoot {
		return []model.Finding{needRoot("process.libs", cat, "Deleted libraries still in use")}
	}
	procs, err := c.Procs()
	if err != nil {
		return []model.Finding{skipped("process.libs", cat, "Deleted libraries still in use", err.Error())}
	}
	stale := map[string]map[string]bool{}
	var tempLibs []string
	for _, p := range procs {
		if c.Ctx.Err() != nil {
			break
		}
		if p.KernelTh || p.InContainer {
			continue
		}
		b, err := fsx.ReadProc("/proc/" + strconv.Itoa(p.PID) + "/maps")
		if err != nil {
			continue
		}
		seen := map[string]bool{}
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, ".so") {
				continue
			}
			m := soPathPattern.FindStringSubmatch(line)
			if m == nil || seen[m[1]] {
				continue
			}
			seen[m[1]] = true
			if inTemp(m[1]) {
				tempLibs = append(tempLibs, p.Label()+"  loaded "+m[1])
				continue
			}
			if m[2] != "" {
				key := p.Comm + " (pid " + strconv.Itoa(p.PID) + ")"
				if stale[key] == nil {
					stale[key] = map[string]bool{}
				}
				stale[key][m[1]] = true
			}
		}
	}
	var out []model.Finding
	if len(tempLibs) > 0 {
		f := finding("process.temp_lib", cat, model.High, "Processes load libraries from temp directories")
		f.Detail = "Some Java or PyInstaller programs unpack .so files into /tmp, but this is also how malicious libraries get injected. Check the source."
		f.Evidence = tempLibs
		out = append(out, f)
	}
	if len(stale) == 0 {
		return append(out, finding("process.libs", cat, model.OK, "No processes use replaced libraries"))
	}
	var ev []string
	for proc, libs := range stale {
		var names []string
		for l := range libs {
			names = append(names, l)
		}
		sort.Strings(names)
		ev = append(ev, proc+": "+strings.Join(names, ", "))
	}
	sort.Strings(ev)
	f := finding("process.libs", cat, model.Medium, fmt.Sprintf("Processes still using updated libraries (%d)", len(stale)))
	f.Detail = "For example, OpenSSL was updated but nginx was not restarted, so the vulnerable old version is still in memory. The CVE check only sees versions on disk, and this covers that blind spot."
	f.Evidence = ev
	f.Remediation = "Restart the listed services."
	return append(out, f)
}

// checkHiddenProcesses compares two views of the PID space. A kernel rootkit
// that hooks directory listings removes a process from /proc's readdir, but
// kill(pid, 0) and direct lookups by number usually still see it. Signal 0
// only tests existence; nothing is delivered.
func checkHiddenProcesses(c *Context) []model.Finding {
	const cat = model.CatProcess
	if !c.Host.IsRoot {
		return []model.Finding{needRoot("process.hidden", cat, "Hidden processes")}
	}
	maxPID := 4194304
	if v, err := strconv.Atoi(fsx.ProcString("/proc/sys/kernel/pid_max")); err == nil && v > 0 {
		maxPID = v
	}
	listed, err := listPIDs()
	if err != nil {
		return []model.Finding{skipped("process.hidden", cat, "Hidden processes", err.Error())}
	}
	var candidates []int
	for pid := 1; pid <= maxPID; pid++ {
		if pid&0xffff == 0 && c.Ctx.Err() != nil {
			return []model.Finding{skipped("process.hidden", cat, "Hidden processes", "Ran out of time, so the scan did not finish.")}
		}
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			continue
		}
		if !listed[pid] {
			candidates = append(candidates, pid)
		}
	}
	// Candidates are mostly threads, which kill() accepts but readdir of /proc
	// never lists, and processes started during the sweep. Re-read to rule both out.
	time.Sleep(200 * time.Millisecond)
	fresh, err := listPIDs()
	if err != nil {
		return []model.Finding{skipped("process.hidden", cat, "Hidden processes", err.Error())}
	}
	var hidden []string
	for _, pid := range candidates {
		if fresh[pid] {
			continue
		}
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			continue
		}
		status, err := fsx.ReadProc("/proc/" + strconv.Itoa(pid) + "/status")
		if err != nil {
			hidden = append(hidden, fmt.Sprintf("pid=%d  not visible in /proc, but kill(pid,0) says it exists", pid))
			continue
		}
		tgid, name := parseTgid(string(status))
		if tgid != pid {
			continue // an ordinary thread
		}
		hidden = append(hidden, fmt.Sprintf("pid=%d  %s  missing from the /proc directory listing", pid, name))
	}
	if len(hidden) == 0 {
		return []model.Finding{finding("process.hidden", cat, model.OK, fmt.Sprintf("No hidden processes across %d PIDs", maxPID))}
	}
	f := finding("process.hidden", cat, model.Critical, fmt.Sprintf("Hidden processes found (%d)", len(hidden)))
	f.Detail = "These processes exist in the kernel but are missing from the /proc listing, typical behaviour of a kernel rootkit."
	f.Evidence = hidden
	f.Remediation = "Output from tools on this host can no longer be trusted. Isolate it, boot from clean media and perform offline forensics."
	return []model.Finding{f}
}

func listPIDs() (map[int]bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make(map[int]bool, len(entries))
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			out[pid] = true
		}
	}
	return out, nil
}

func parseTgid(status string) (int, string) {
	tgid, name := 0, ""
	for _, line := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(line, "Tgid:"); ok {
			tgid, _ = strconv.Atoi(strings.TrimSpace(v))
		} else if v, ok := strings.CutPrefix(line, "Name:"); ok {
			name = strings.TrimSpace(v)
		}
	}
	return tgid, name
}
