package checks

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"

	"ubuntu-sys-audit/internal/model"
)

// Check is one audit step.
type Check struct {
	ID       string
	Name     string
	Category model.Category
	Timeout  time.Duration
	Run      func(*Context) []model.Finding
}

// Event reports progress to a front end.
type Event struct {
	Index    int
	Total    int
	Check    Check
	Done     bool
	Findings []model.Finding
	Err      string
}

// All returns the checks in execution order. Quick local checks go first so
// the operator sees results before the network and filesystem work starts.
func All() []Check {
	const quick = 30 * time.Second
	return []Check{
		{"system.os", "OS and support status", model.CatSystem, quick, checkOS},
		{"system.kernel", "Kernel version and reboot status", model.CatSystem, quick, checkKernel},
		{"system.sysctl", "Kernel security parameters", model.CatSystem, quick, checkSysctl},
		{"system.cpu", "CPU vulnerability mitigations", model.CatSystem, quick, checkCPUVulns},
		{"accounts.users", "Account list", model.CatAccounts, quick, checkUsers},
		{"accounts.privilege", "Privileged accounts and sudo", model.CatAccounts, quick, checkPrivilege},
		{"accounts.logins", "Login history", model.CatAccounts, quick, checkLogins},
		{"ssh.config", "sshd configuration", model.CatSSH, quick, checkSSHConfig},
		{"ssh.keys", "SSH authorized keys", model.CatSSH, quick, checkAuthorizedKeys},
		{"network.dns53", "Port 53 and DNS traffic", model.CatNetwork, quick, checkDNS53},
		{"network.listeners", "Listening ports", model.CatNetwork, quick, checkListeners},
		{"network.raw", "Raw and packet sockets (BPFDoor)", model.CatNetwork, quick, checkRawSockets},
		{"network.iface", "Promiscuous interfaces", model.CatNetwork, quick, checkPromisc},
		{"network.firewall", "Firewall status", model.CatNetwork, quick, checkFirewall},
		{"network.mptcp", "Multipath TCP (MPTCP)", model.CatNetwork, quick, checkMPTCP},
		{"network.docker", "Docker and containers", model.CatNetwork, quick, checkDocker},
		{"process.suspicious", "Suspicious processes", model.CatProcess, quick, checkProcesses},
		{"process.libs", "Deleted libraries still in use", model.CatProcess, quick, checkStaleLibs},
		{"process.hidden", "Hidden processes", model.CatProcess, time.Minute, checkHiddenProcesses},
		{"integrity.preload", "ld.so.preload", model.CatIntegrity, quick, checkPreload},
		{"integrity.modules", "Kernel modules", model.CatIntegrity, quick, checkModules},
		{"integrity.pam", "PAM modules", model.CatIntegrity, quick, checkPAM},
		{"integrity.binaries", "System binary hashes", model.CatIntegrity, 3 * time.Minute, checkBinaries},
		{"persistence.files", "Scheduled jobs and startup scripts", model.CatPersistence, time.Minute, checkPersistence},
		{"persistence.systemd", "systemd services", model.CatPersistence, time.Minute, checkSystemd},
		{"filesystem.walk", "SUID, capabilities and temp directories", model.CatFilesystem, 6 * time.Minute, checkFilesystem},
		{"packages.updates", "Security and automatic updates", model.CatPackages, time.Minute, checkUpdates},
		{"packages.sources", "Third-party package sources", model.CatPackages, quick, checkAptSources},
		{"packages.inventory", "Key software versions", model.CatPackages, quick, checkInventory},
		{"web.shell", "Webshell scan", model.CatWeb, 4 * time.Minute, checkWebshells},
		{"web.nginx", "nginx version and configuration", model.CatWeb, 2 * time.Minute, checkNginx},
		{"web.php", "PHP version and configuration", model.CatWeb, 2 * time.Minute, checkPHP},
		{"cve.usn", "CVE check (Ubuntu USN)", model.CatCVE, 5 * time.Minute, checkCVE},
	}
}

// lowerPriority makes the scan polite on production hosts by moving existing
// threads to a low CPU priority and the idle I/O class. These calls apply per
// thread on Linux, so threads spawned later may not all inherit them.
func lowerPriority() {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return
	}
	for _, t := range tasks {
		tid, err := strconv.Atoi(t.Name())
		if err != nil {
			continue
		}
		_ = syscall.Setpriority(syscall.PRIO_PROCESS, tid, 10)
		setIdleIO(tid)
	}
}

// Run executes all checks in sequence and returns the report. A check that
// panics or exceeds its timeout becomes a "not checked" finding rather than
// taking the scan down or being silently dropped.
func Run(ctx context.Context, opts Options, onEvent func(Event)) *model.Report {
	if onEvent == nil {
		onEvent = func(Event) {}
	}
	lowerPriority()
	start := time.Now()
	c := NewContext(ctx, opts)
	report := &model.Report{
		Tool:      "ubuntu-sys-audit",
		Version:   opts.Version,
		ScannedAt: start.UTC(),
		Host:      c.Host,
		Findings:  []model.Finding{},
	}
	all := All()
	for i, chk := range all {
		if ctx.Err() != nil {
			break
		}
		// The walk stops itself at --fs-timeout and reports partial results.
		// Its hard limit stays above that, so a long budget is not cut short
		// and the partial results are not thrown away.
		if chk.ID == "filesystem.walk" && opts.FSTimeout > 0 {
			chk.Timeout = opts.FSTimeout + time.Minute
		}
		onEvent(Event{Index: i, Total: len(all), Check: chk})
		t0 := time.Now()
		found, errText := runOne(ctx, c, chk)
		for j := range found {
			found[j] = model.CleanFinding(found[j])
		}
		report.Findings = append(report.Findings, found...)
		report.Checks = append(report.Checks, model.CheckResult{
			ID: chk.ID, Name: chk.Name, DurationMS: time.Since(t0).Milliseconds(), Error: errText,
		})
		onEvent(Event{Index: i, Total: len(all), Check: chk, Done: true, Findings: found, Err: errText})
	}
	c.mu.Lock()
	report.Inventory = append(report.Inventory, c.inventory...)
	c.mu.Unlock()
	for i := range report.Inventory {
		report.Inventory[i].Name = model.Clean(report.Inventory[i].Name)
		report.Inventory[i].Version = model.Clean(report.Inventory[i].Version)
	}
	report.DurationMS = time.Since(start).Milliseconds()
	report.Finalize()
	return report
}

func runOne(parent context.Context, base *Context, chk Check) ([]model.Finding, string) {
	timeout := chk.Timeout
	if timeout <= 0 {
		timeout = time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	type result struct {
		found []model.Finding
		err   string
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{err: fmt.Sprintf("internal error: %v", r)}
			}
		}()
		done <- result{found: chk.Run(base.withCtx(ctx))}
	}()

	select {
	case r := <-done:
		if r.err != "" {
			return []model.Finding{skipped(chk.ID+".error", chk.Category, chk.Name+": check failed", r.err)}, r.err
		}
		return r.found, ""
	case <-ctx.Done():
		msg := "Hit the " + timeout.String() + " time limit, so this check did not finish."
		if parent.Err() != nil {
			msg = "Scan aborted."
		}
		return []model.Finding{skipped(chk.ID+".timeout", chk.Category, chk.Name+": not finished", msg)}, msg
	}
}

// withCtx returns a view of the context bound to a per check deadline while
// sharing the lazily loaded host data.
func (c *Context) withCtx(ctx context.Context) *Context {
	view := *c
	view.Ctx = ctx
	return &view
}
