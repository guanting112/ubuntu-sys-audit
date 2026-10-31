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
		name = "未知作業系統"
	}
	info := finding("system.os", cat, model.Info, "作業系統："+name+" ("+h.Codename+")")
	info.Evidence = []string{
		"主機名稱：" + h.Hostname,
		"Kernel：" + h.Kernel,
		"架構：" + h.Arch,
		"開機時間：" + formatDuration(time.Duration(h.UptimeSec)*time.Second),
	}
	if h.InContainer {
		info.Evidence = append(info.Evidence, "執行環境：容器（kernel 與部分網路結果屬於宿主機）")
	}
	out := []model.Finding{info}

	rel, known := releases[h.Codename]
	if !known || !strings.EqualFold(strings.TrimSpace(h.OSName), "ubuntu") {
		f := finding("system.os.unsupported", cat, model.Medium, "此工具未針對這個發行版驗證："+name)
		f.Detail = "工具支援 Ubuntu 18.04、20.04、22.04、24.04 與 26.04。其餘結果仍會輸出，但 CVE 比對可能無法執行。"
		return append(out, f)
	}
	now := time.Now()
	std, esm := parseDay(rel.standard), parseDay(rel.esm)
	pro := esmEnabled()
	switch {
	case now.After(esm):
		f := finding("system.os.eol", cat, model.Critical, "Ubuntu "+rel.version+" 已超過 ESM 支援期限")
		f.Detail = "ESM 已於 " + rel.esm + " 結束，一般管道不再提供安全更新。"
		f.Remediation = "升級到仍受支援的 LTS 版本。"
		out = append(out, f)
	case now.After(std) && !pro:
		f := finding("system.os.eol", cat, model.High, "Ubuntu "+rel.version+" 已過標準支援且未啟用 ESM")
		f.Detail = "標準支援已於 " + rel.standard + " 結束。沒有 Ubuntu Pro 時，main 套件收不到新的安全修補，包含 kernel、nginx、OpenSSL。ESM 可用到 " + rel.esm + "。"
		f.Remediation = "啟用 Ubuntu Pro（sudo pro attach <token>）或升級到受支援的 LTS。"
		f.Refs = []string{"https://ubuntu.com/about/release-cycle"}
		f.Focus = true
		out = append(out, f)
	case now.After(std):
		f := finding("system.os.esm", cat, model.OK, "Ubuntu "+rel.version+" 已啟用 ESM，支援到 "+rel.esm)
		out = append(out, f)
	default:
		f := finding("system.os.support", cat, model.OK, "Ubuntu "+rel.version+" 在標準支援期內，到 "+rel.standard)
		if until := std.Sub(now); until < 180*24*time.Hour {
			f.Severity = model.Medium
			f.Title = "Ubuntu " + rel.version + " 標準支援將於 " + rel.standard + " 結束"
			f.Remediation = "規劃升級，或啟用 Ubuntu Pro 取得 ESM。"
		}
		out = append(out, f)
	}
	return out
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if days > 0 {
		return fmt.Sprintf("%d 天 %d 小時", days, hours)
	}
	return fmt.Sprintf("%d 小時 %d 分", hours, int(d.Minutes())%60)
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
	info := finding("system.kernel", cat, model.Info, "執行中的 Kernel："+running)
	info.Evidence = []string{fsx.ProcString("/proc/version")}
	info.Focus = true
	out := []model.Finding{info}
	if c.Host.InContainer {
		f := skipped("system.kernel.reboot", cat, "Kernel 更新狀態", "在容器內執行，kernel 屬於宿主機，請在宿主機上檢查。")
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
		info.Evidence = append(info.Evidence, "/boot 內的 Kernel："+strings.Join(installed, ", "))
		out[0] = info
		newest := installed[len(installed)-1]
		if dpkg.Compare(kernelVersion(running), kernelVersion(newest)) < 0 {
			f := finding("system.kernel.stale", cat, model.High, "執行中的 Kernel 不是最新安裝的版本")
			f.Detail = "執行 " + running + "，但 /boot 已有 " + newest + "。kernel 修補要重開機才會生效，在那之前主機仍有舊版本的漏洞。"
			f.Remediation = "安排維護時段重新開機。"
			f.Focus = true
			out = append(out, f)
		}
	}

	if b, err := fsx.Read("/var/run/reboot-required", 1<<12); err == nil {
		_ = b
		f := finding("system.reboot", cat, model.Medium, "系統標記為需要重新開機")
		f.Detail = "/var/run/reboot-required 存在，代表已安裝的更新要重開機才會生效。"
		if pk, err := fsx.Read("/var/run/reboot-required.pkgs", 1<<16); err == nil {
			f.Evidence = strings.Fields(string(pk))
		}
		f.Remediation = "安排維護時段重新開機。"
		out = append(out, f)
	}
	if _, err := os.Stat("/snap/bin/canonical-livepatch"); err == nil {
		f := finding("system.livepatch", cat, model.Info, "已安裝 Canonical Livepatch")
		f.Detail = "CVE 類別比對的是 kernel 版本，已由 Livepatch 修補的項目仍可能列出。請執行 canonical-livepatch status 確認。"
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
	{"kernel/randomize_va_space", "kernel.randomize_va_space", notEqual("2"), model.High, "ASLR 未完整啟用，記憶體漏洞更容易被利用。", "2"},
	{"fs/protected_symlinks", "fs.protected_symlinks", notEqual("1"), model.Medium, "暫存目錄的 symlink 攻擊防護已關閉。", "1"},
	{"fs/protected_hardlinks", "fs.protected_hardlinks", notEqual("1"), model.Medium, "hardlink 攻擊防護已關閉。", "1"},
	{"fs/suid_dumpable", "fs.suid_dumpable", notEqual("0"), model.Info, "SUID 程序可能產生含敏感資料的 core dump；Ubuntu 預設為 2。", "0"},
	{"kernel/unprivileged_bpf_disabled", "kernel.unprivileged_bpf_disabled", func(v string) bool { return v == "0" }, model.Medium, "一般使用者可載入 eBPF，常是 kernel 提權漏洞的入口。", "1 或 2"},
	{"kernel/kptr_restrict", "kernel.kptr_restrict", notEqual("1"), model.Info, "kernel 位址可能外洩，降低 KASLR 效果。", "1"},
	{"kernel/dmesg_restrict", "kernel.dmesg_restrict", notEqual("1"), model.Info, "一般使用者可讀 dmesg。", "1"},
	{"kernel/yama/ptrace_scope", "kernel.yama.ptrace_scope", func(v string) bool { return v == "0" }, model.Medium, "任何程序都能 ptrace 同使用者的程序，便於竊取憑證。", "1"},
	{"net/ipv4/tcp_syncookies", "net.ipv4.tcp_syncookies", notEqual("1"), model.Info, "SYN flood 防護未啟用。", "1"},
	{"net/ipv4/conf/all/accept_source_route", "net.ipv4.conf.all.accept_source_route", notEqual("0"), model.Medium, "接受 source routing 封包。", "0"},
	{"net/ipv4/conf/all/accept_redirects", "net.ipv4.conf.all.accept_redirects", notEqual("0"), model.Info, "接受 ICMP redirect，可能被用來改路由。", "0"},
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
			weak = append(weak, fmt.Sprintf("%s = %s（建議 %s）：%s", r.name, v, r.expect, r.why))
			if r.sev < worst {
				worst = r.sev
			}
		}
	}
	if len(weak) == 0 {
		out = append(out, finding("system.sysctl", cat, model.OK, "Kernel 安全參數符合建議"))
	} else {
		f := finding("system.sysctl", cat, worst, fmt.Sprintf("%d 個 Kernel 安全參數偏弱", len(weak)))
		f.Evidence = weak
		f.Remediation = "在 /etc/sysctl.d/ 設定建議值後執行 sysctl --system。修改前先確認相依服務。"
		out = append(out, f)
	}

	// A handler piped from core_pattern or a changed modprobe path runs as
	// root inside the kernel's usermode helper, a known persistence trick.
	if cp := fsx.ProcString("/proc/sys/kernel/core_pattern"); strings.HasPrefix(cp, "|") {
		handler := strings.Fields(strings.TrimPrefix(cp, "|"))
		known := []string{"apport", "systemd-coredump", "whoopsie", "abrt", "orbstack"}
		ok := false
		for _, k := range known {
			if len(handler) > 0 && strings.Contains(handler[0], k) {
				ok = true
			}
		}
		if !ok {
			f := finding("system.core_pattern", model.CatIntegrity, model.Critical, "core_pattern 指向未知的處理程式")
			f.Detail = "程式崩潰時，kernel 會以 root 身分執行這個處理程式，常被用來持久化。"
			f.Evidence = []string{cp}
			out = append(out, f)
		}
	}
	if mp := fsx.ProcString("/proc/sys/kernel/modprobe"); mp != "" && dpkg.NormalizePath(mp) != "/usr/sbin/modprobe" {
		f := finding("system.modprobe", model.CatIntegrity, model.Critical, "kernel.modprobe 路徑遭更動")
		f.Detail = "kernel 需要載入模組時會以 root 身分執行這個路徑。預設值是 /sbin/modprobe。"
		f.Evidence = []string{mp}
		out = append(out, f)
	}
	return out
}

func checkCPUVulns(c *Context) []model.Finding {
	const cat = model.CatSystem
	files, err := filepath.Glob("/sys/devices/system/cpu/vulnerabilities/*")
	if err != nil || len(files) == 0 {
		return []model.Finding{skipped("system.cpu", cat, "CPU 漏洞緩解", "無法讀取 /sys/devices/system/cpu/vulnerabilities。")}
	}
	var vuln []string
	for _, p := range files {
		s := fsx.ProcString(p)
		if strings.HasPrefix(s, "Vulnerable") {
			vuln = append(vuln, filepath.Base(p)+"："+s)
		}
	}
	if len(vuln) == 0 {
		return []model.Finding{finding("system.cpu", cat, model.OK, "已檢查的 "+strconv.Itoa(len(files))+" 項 CPU 漏洞都有緩解或不受影響")}
	}
	f := finding("system.cpu", cat, model.Medium, fmt.Sprintf("%d 項 CPU 漏洞未緩解", len(vuln)))
	f.Evidence = vuln
	f.Remediation = "更新 intel-microcode 或 amd64-microcode 與 kernel，並檢查開機參數是否含 mitigations=off。"
	return []model.Finding{f}
}
