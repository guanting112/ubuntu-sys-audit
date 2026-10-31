package checks

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

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

func checkProcesses(c *Context) []model.Finding {
	const cat = model.CatProcess
	procs, err := c.Procs()
	if err != nil {
		return []model.Finding{skipped("process.suspicious", cat, "可疑程序", err.Error())}
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

	var fakeKernel, masquerade, tempExe, contTempExe, memfd, deletedExe, hidden, unmanaged, miners, revShell, webShell, preload []string
	user := 0
	for _, p := range procs {
		if p.KernelTh {
			continue
		}
		user++
		line := p.Label()
		if cmd := p.CmdlineString(); cmd != "" {
			line += "  指令：" + cmd
		}
		exeBase := base(p.Exe)

		if len(p.Cmdline) > 0 {
			a := p.Cmdline[0]
			if strings.HasPrefix(a, "[") && strings.HasSuffix(strings.Fields(a + " x")[0], "]") {
				fakeKernel = append(fakeKernel, line)
			}
		}
		if p.Exe != "" {
			if argv := argv0Base(p); masqueradeNames[argv] && !strings.HasPrefix(exeBase, argv) && !strings.HasPrefix(argv, exeBase) {
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
				revShell = append(revShell, line+"  連線："+s0.Remote())
			}
		}
		if shellNames[exeBase] || shellNames[p.Comm] {
			if parent := byPID[p.PPID]; parent != nil && isWebParent(base(parent.Exe)) {
				webShell = append(webShell, line+"  父程序："+parent.Label())
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
	isolate := "先保留 /proc/<pid>/exe 與連線資訊，再隔離主機調查。不要先把程序砍掉。"
	add("fake_kernel", model.Critical, "使用者程序偽裝成 kernel thread", "它的名稱像 [kworker]，卻有實際的執行檔。真正的 kernel thread 沒有執行檔。", isolate, fakeKernel)
	add("masquerade", model.Critical, "程序偽裝成系統服務", "argv[0] 寫的是系統服務名稱，實際執行檔卻是別的程式。BPFDoor 等後門會這樣隱藏自己。", isolate, masquerade)
	add("reverse_shell", model.Critical, "疑似 Reverse shell", "標準輸入與輸出都接到 TCP 連線，這是 reverse shell 的典型特徵。", isolate, revShell)
	add("miner", model.Critical, "發現挖礦程式特徵", "", isolate, miners)
	add("temp_exe", model.Critical, "程序從暫存目錄執行", "正常服務不會從 /tmp、/var/tmp 或 /dev/shm 執行，這很常見於入侵後投放的工具。", isolate, tempExe)
	add("memfd_exe", model.Critical, "程序從記憶體檔案執行", "執行檔只存在 memfd，磁碟上找不到，這是無檔案攻擊的手法。", isolate, memfd)
	add("container_temp_exe", model.High, "容器內的程序從暫存目錄執行", "", "檢查該容器是否遭入侵，必要時從乾淨映像重建。", contTempExe)
	add("web_shell_child", model.High, "Web 服務底下跑著 shell", "這可能是 webshell 正在執行指令；應用程式自己呼叫 shell 時也會如此。請對照指令內容判斷。", "檢查 Web 類別的掃描結果與存取紀錄。", webShell)
	add("hidden_dir", model.Medium, "程序從隱藏目錄執行", "", "確認這些程式的來源。", hidden)
	add("ld_preload", model.High, "程序帶有非套件的 LD_PRELOAD", "這會把外部函式庫注入程序，可用來隱藏檔案或竊取資料。", "確認該函式庫的來源。", preload)
	add("unmanaged", model.Medium, "系統目錄內有非套件管理的程序在跑", "這些執行檔位於 /usr/bin、/usr/sbin 或 /usr/lib，卻不屬於任何套件。可能是手動安裝，也可能是被投放的。", "確認來源與安裝時間。", unmanaged)
	add("deleted_exe", model.Medium, "程序的執行檔已被刪除或更新", "最常見的原因是套件升級後服務沒有重啟，這代表還在跑舊版本。若不是升級造成，就要懷疑惡意程式自刪。", "重啟服務以套用修補。若路徑不是套件檔案，請深入調查。", deletedExe)

	summary := finding("process.summary", cat, model.Info, fmt.Sprintf("共 %d 個程序（不含 kernel thread）", user))
	if !c.Host.IsRoot {
		summary.Detail = "沒有 root 權限，看不到其他使用者程序的執行檔與 socket，結果不完整。"
	}
	out = append(out, summary)
	if len(fakeKernel)+len(masquerade)+len(tempExe)+len(memfd)+len(miners)+len(revShell) == 0 {
		out = append(out, finding("process.clean", cat, model.OK, "沒有發現偽裝、暫存目錄執行或 reverse shell 特徵"))
	}
	return out
}

var soPathPattern = regexp.MustCompile(`(/\S*\.so(?:\.[0-9.]+)?)( \(deleted\))?$`)

func checkStaleLibs(c *Context) []model.Finding {
	const cat = model.CatProcess
	if !c.Host.IsRoot {
		return []model.Finding{needRoot("process.libs", cat, "已刪除的函式庫")}
	}
	procs, err := c.Procs()
	if err != nil {
		return []model.Finding{skipped("process.libs", cat, "已刪除的函式庫", err.Error())}
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
				tempLibs = append(tempLibs, p.Label()+"  載入 "+m[1])
				continue
			}
			if m[2] != "" {
				key := p.Comm + "（pid " + strconv.Itoa(p.PID) + "）"
				if stale[key] == nil {
					stale[key] = map[string]bool{}
				}
				stale[key][m[1]] = true
			}
		}
	}
	var out []model.Finding
	if len(tempLibs) > 0 {
		f := finding("process.temp_lib", cat, model.High, "程序載入暫存目錄內的函式庫")
		f.Detail = "部分 Java 或 PyInstaller 程式會解壓 .so 到 /tmp，但這也是注入惡意函式庫的手法。請確認來源。"
		f.Evidence = tempLibs
		out = append(out, f)
	}
	if len(stale) == 0 {
		return append(out, finding("process.libs", cat, model.OK, "沒有程序還在使用已被取代的函式庫"))
	}
	var ev []string
	for proc, libs := range stale {
		var names []string
		for l := range libs {
			names = append(names, l)
		}
		sort.Strings(names)
		ev = append(ev, proc+"："+strings.Join(names, ", "))
	}
	sort.Strings(ev)
	f := finding("process.libs", cat, model.Medium, fmt.Sprintf("%d 個程序還在使用已被更新的函式庫", len(stale)))
	f.Detail = "例如 OpenSSL 已更新，但 nginx 沒有重啟，記憶體內仍是有漏洞的舊版。CVE 比對只看磁碟上的版本，這一項補上這個盲點。"
	f.Evidence = ev
	f.Remediation = "重啟列出的服務。"
	return append(out, f)
}

// checkHiddenProcesses compares two views of the PID space. A kernel rootkit
// that hooks directory listings removes a process from /proc's readdir, but
// kill(pid, 0) and direct lookups by number usually still see it. Signal 0
// only tests existence; nothing is delivered.
func checkHiddenProcesses(c *Context) []model.Finding {
	const cat = model.CatProcess
	if !c.Host.IsRoot {
		return []model.Finding{needRoot("process.hidden", cat, "隱藏程序")}
	}
	maxPID := 4194304
	if v, err := strconv.Atoi(fsx.ProcString("/proc/sys/kernel/pid_max")); err == nil && v > 0 {
		maxPID = v
	}
	listed, err := listPIDs()
	if err != nil {
		return []model.Finding{skipped("process.hidden", cat, "隱藏程序", err.Error())}
	}
	var candidates []int
	for pid := 1; pid <= maxPID; pid++ {
		if pid&0xffff == 0 && c.Ctx.Err() != nil {
			return []model.Finding{skipped("process.hidden", cat, "隱藏程序", "時間不足，掃描未完成。")}
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
		return []model.Finding{skipped("process.hidden", cat, "隱藏程序", err.Error())}
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
			hidden = append(hidden, fmt.Sprintf("pid=%d  /proc 內看不到，但 kill(pid,0) 顯示存在", pid))
			continue
		}
		tgid, name := parseTgid(string(status))
		if tgid != pid {
			continue // an ordinary thread
		}
		hidden = append(hidden, fmt.Sprintf("pid=%d  %s  未出現在 /proc 目錄列表", pid, name))
	}
	if len(hidden) == 0 {
		return []model.Finding{finding("process.hidden", cat, model.OK, fmt.Sprintf("比對 %d 個 PID，沒有發現隱藏程序", maxPID))}
	}
	f := finding("process.hidden", cat, model.Critical, fmt.Sprintf("發現 %d 個隱藏程序", len(hidden)))
	f.Detail = "這些程序存在於 kernel 中，卻從 /proc 目錄列表消失，這是 kernel rootkit 的典型行為。"
	f.Evidence = hidden
	f.Remediation = "這台主機的工具輸出已不可信。隔離主機，從乾淨媒體開機做離線鑑識。"
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
