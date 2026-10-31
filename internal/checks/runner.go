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
		{"system.os", "作業系統與支援狀態", model.CatSystem, quick, checkOS},
		{"system.kernel", "Kernel 版本與重開機狀態", model.CatSystem, quick, checkKernel},
		{"system.sysctl", "Kernel 安全參數", model.CatSystem, quick, checkSysctl},
		{"system.cpu", "CPU 漏洞緩解", model.CatSystem, quick, checkCPUVulns},
		{"accounts.users", "帳號清單", model.CatAccounts, quick, checkUsers},
		{"accounts.privilege", "特權帳號與 sudo", model.CatAccounts, quick, checkPrivilege},
		{"accounts.logins", "登入紀錄", model.CatAccounts, quick, checkLogins},
		{"ssh.config", "sshd 設定", model.CatSSH, quick, checkSSHConfig},
		{"ssh.keys", "SSH 授權金鑰", model.CatSSH, quick, checkAuthorizedKeys},
		{"network.dns53", "53 Port 與 DNS 流量", model.CatNetwork, quick, checkDNS53},
		{"network.listeners", "監聽中的 Port", model.CatNetwork, quick, checkListeners},
		{"network.raw", "Raw／Packet Socket（BPFDoor）", model.CatNetwork, quick, checkRawSockets},
		{"network.iface", "網卡混雜模式", model.CatNetwork, quick, checkPromisc},
		{"network.firewall", "防火牆狀態", model.CatNetwork, quick, checkFirewall},
		{"network.docker", "Docker 與容器", model.CatNetwork, quick, checkDocker},
		{"process.suspicious", "可疑程序", model.CatProcess, quick, checkProcesses},
		{"process.libs", "已刪除的函式庫", model.CatProcess, quick, checkStaleLibs},
		{"process.hidden", "隱藏程序", model.CatProcess, time.Minute, checkHiddenProcesses},
		{"integrity.preload", "ld.so.preload 與核心掛鉤", model.CatIntegrity, quick, checkPreload},
		{"integrity.modules", "Kernel 模組", model.CatIntegrity, quick, checkModules},
		{"integrity.pam", "PAM 模組", model.CatIntegrity, quick, checkPAM},
		{"integrity.binaries", "系統執行檔雜湊", model.CatIntegrity, 3 * time.Minute, checkBinaries},
		{"persistence.files", "排程與啟動腳本", model.CatPersistence, time.Minute, checkPersistence},
		{"persistence.systemd", "systemd 服務", model.CatPersistence, time.Minute, checkSystemd},
		{"filesystem.walk", "SUID、Capabilities 與暫存目錄", model.CatFilesystem, 6 * time.Minute, checkFilesystem},
		{"packages.updates", "安全更新與自動更新", model.CatPackages, time.Minute, checkUpdates},
		{"packages.sources", "第三方套件來源", model.CatPackages, quick, checkAptSources},
		{"packages.inventory", "重要軟體版本", model.CatPackages, quick, checkInventory},
		{"web.shell", "Webshell 掃描", model.CatWeb, 4 * time.Minute, checkWebshells},
		{"web.nginx", "nginx 版本與設定", model.CatWeb, 2 * time.Minute, checkNginx},
		{"web.php", "PHP 版本與設定", model.CatWeb, 2 * time.Minute, checkPHP},
		{"cve.usn", "CVE 比對（Ubuntu USN）", model.CatCVE, 5 * time.Minute, checkCVE},
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
				done <- result{err: fmt.Sprintf("內部錯誤：%v", r)}
			}
		}()
		done <- result{found: chk.Run(base.withCtx(ctx))}
	}()

	select {
	case r := <-done:
		if r.err != "" {
			return []model.Finding{skipped(chk.ID+".error", chk.Category, chk.Name+"：檢查失敗", r.err)}, r.err
		}
		return r.found, ""
	case <-ctx.Done():
		msg := "超過時間上限 " + timeout.String() + "，此項未完成。"
		if parent.Err() != nil {
			msg = "掃描已中止。"
		}
		return []model.Finding{skipped(chk.ID+".timeout", chk.Category, chk.Name+"：未完成", msg)}, msg
	}
}

// withCtx returns a view of the context bound to a per check deadline while
// sharing the lazily loaded host data.
func (c *Context) withCtx(ctx context.Context) *Context {
	view := *c
	view.Ctx = ctx
	return &view
}
