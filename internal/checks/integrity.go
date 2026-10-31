package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"ubuntu-sys-audit/internal/dpkg"
	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
)

func checkPreload(c *Context) []model.Finding {
	const cat = model.CatIntegrity
	b, err := fsx.Read("/etc/ld.so.preload", 1<<16)
	if err != nil {
		if os.IsNotExist(err) {
			return []model.Finding{finding("integrity.preload", cat, model.OK, "/etc/ld.so.preload 不存在")}
		}
		return []model.Finding{skipped("integrity.preload", cat, "ld.so.preload", err.Error())}
	}
	var entries []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			entries = append(entries, line)
		}
	}
	if len(entries) == 0 {
		return []model.Finding{finding("integrity.preload", cat, model.OK, "/etc/ld.so.preload 是空的")}
	}
	f := finding("integrity.preload", cat, model.Critical, "/etc/ld.so.preload 有內容")
	f.Detail = "列出的函式庫會注入每一個程序。使用者層 rootkit（如 Jynx、Azazel）靠這招讓 ps、ls、ss 說謊。部分 EDR 也會用，請比對是否為自家的代理程式。此工具直接讀 /proc，不受這個注入影響。"
	f.Evidence = entries
	f.Remediation = "確認函式庫來源。若非預期，視為主機已遭入侵。"
	return []model.Finding{f}
}

// parseModuleFlags returns the taint flags printed for a /proc/modules row, for
// example "(OE)".
func parseModuleFlags(line string) (name, flags string) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return "", ""
	}
	name = f[0]
	if last := f[len(f)-1]; strings.HasPrefix(last, "(") && strings.HasSuffix(last, ")") {
		flags = strings.Trim(last, "()")
	}
	return name, flags
}

var knownThirdPartyModules = regexp.MustCompile(`^(nvidia|zfs|spl|vbox|vmw|vmmon|vmnet|wireguard|falcon|sentinel|ena|xt_|nv_|openvswitch|drbd|lkrg|cbsensor)`)

func checkModules(c *Context) []model.Finding {
	const cat = model.CatIntegrity
	b, err := fsx.ReadProc("/proc/modules")
	if err != nil {
		return []model.Finding{skipped("integrity.modules", cat, "Kernel 模組", err.Error())}
	}
	listed := map[string]bool{}
	var thirdParty, unknownThird []string
	for _, line := range strings.Split(string(b), "\n") {
		name, flags := parseModuleFlags(line)
		if name == "" {
			continue
		}
		listed[name] = true
		if flags != "" && strings.ContainsAny(flags, "OEPF") {
			entry := name + "  (" + flags + ")"
			if knownThirdPartyModules.MatchString(name) {
				thirdParty = append(thirdParty, entry)
			} else {
				unknownThird = append(unknownThird, entry)
			}
		}
	}
	var out []model.Finding
	// Rootkits such as Diamorphine unlink themselves from the list behind
	// /proc/modules, but the sysfs entry usually survives. Built-in modules
	// also live in /sys/module; they have no initstate file.
	var hidden []string
	if dirs, err := os.ReadDir("/sys/module"); err == nil {
		for _, d := range dirs {
			if _, err := os.Stat(filepath.Join("/sys/module", d.Name(), "initstate")); err != nil {
				continue
			}
			if !listed[d.Name()] {
				hidden = append(hidden, d.Name())
			}
		}
	}
	if len(hidden) > 0 {
		f := finding("integrity.hidden_module", cat, model.Critical, "Kernel 模組從 /proc/modules 隱藏")
		f.Detail = "這些模組出現在 /sys/module，卻不在 /proc/modules，這是 kernel rootkit 的典型行為。"
		f.Evidence = hidden
		f.Remediation = "隔離主機，從乾淨媒體開機做離線鑑識。這台主機本身的輸出已不可信。"
		out = append(out, f)
	} else if c.Host.IsRoot {
		out = append(out, finding("integrity.hidden_module", cat, model.OK, "/proc/modules 與 /sys/module 一致"))
	}
	if len(unknownThird) > 0 {
		f := finding("integrity.tainted_module", cat, model.Medium, "載入了未簽章或樹外的 Kernel 模組")
		f.Detail = "O 代表樹外模組，E 代表未簽章，P 代表專有授權。請確認都是自己安裝的驅動程式。"
		f.Evidence = unknownThird
		out = append(out, f)
	}
	if len(thirdParty) > 0 {
		f := finding("integrity.known_modules", cat, model.Info, "載入了常見的第三方 Kernel 模組")
		f.Evidence = thirdParty
		out = append(out, f)
	}
	return out
}

func checkPAM(c *Context) []model.Finding {
	const cat = model.CatIntegrity
	var out []model.Finding
	var mods []string
	for _, pat := range []string{"/lib/security/*.so", "/lib/*-linux-gnu*/security/*.so", "/usr/lib/security/*.so", "/usr/lib/*-linux-gnu*/security/*.so"} {
		m, _ := filepath.Glob(pat)
		mods = append(mods, m...)
	}
	if _, err := c.Owners(); err != nil {
		return []model.Finding{skipped("integrity.pam", cat, "PAM 模組", "無法讀取 dpkg 資料庫："+err.Error())}
	}
	seen := map[string]bool{}
	var rogue []string
	for _, m := range mods {
		real, err := filepath.EvalSymlinks(m)
		if err != nil {
			real = m
		}
		if seen[real] {
			continue
		}
		seen[real] = true
		if !c.Owned(real) {
			rogue = append(rogue, real)
		}
	}
	if len(rogue) > 0 {
		f := finding("integrity.pam_rogue", cat, model.Critical, "發現不屬於任何套件的 PAM 模組")
		f.Detail = "惡意 PAM 模組可以記錄所有密碼，或接受一組萬用密碼。"
		f.Evidence = rogue
		f.Remediation = "比對 /etc/pam.d 是否引用它。若非預期，視為主機已遭入侵。"
		out = append(out, f)
	} else {
		out = append(out, finding("integrity.pam_modules", cat, model.OK, fmt.Sprintf("%d 個 PAM 模組都來自套件", len(seen))))
	}

	configs, _ := filepath.Glob("/etc/pam.d/*")
	var execLines []string
	for _, p := range configs {
		b, err := fsx.Read(p, 1<<18)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if strings.Contains(t, "pam_exec") || strings.Contains(t, "pam_permit.so") && strings.HasPrefix(t, "auth") && strings.Contains(t, "sufficient") {
				execLines = append(execLines, base(p)+"："+t)
			}
		}
	}
	if len(execLines) > 0 {
		f := finding("integrity.pam_config", cat, model.High, "PAM 設定含 pam_exec 或無條件放行的規則")
		f.Detail = "pam_exec 會在認證時執行外部程式；auth sufficient pam_permit.so 則會讓任何密碼都通過。"
		f.Evidence = execLines
		out = append(out, f)
	}
	return out
}

var keyBinary = regexp.MustCompile(`/(ssh|sshd|sshd-session|sshd-auth|scp|sftp|sudo|sudo\.ws|sudo-rs|su|login|passwd|ps|ss|netstat|lsof|ls|top|find|who|w|last|lastlog|id|dpkg|apt|apt-get|bash|dash|sh|systemctl|crontab|ip|ifconfig|iptables|md5sum|sha256sum|kill|pgrep|pkill|mount|cron|rsyslogd|pam_unix\.so|libpam\.so[.0-9]*|libkeyutils\.so[.0-9]*|liblzma\.so[.0-9]*|libaudit\.so[.0-9]*|libc\.so[.0-9]*|libcrypto\.so[.0-9]*)$`)

var verifiedLib = regexp.MustCompile(`/(security/[^/]+\.so|libpam[^/]*\.so[.0-9]*|libkeyutils\.so[.0-9]*|liblzma\.so[.0-9]*|libaudit\.so[.0-9]*|libc\.so[.0-9]*|libcrypto\.so[.0-9]*|libssl\.so[.0-9]*|ld-linux[^/]*\.so[.0-9]*)$`)

// verifiedDirs holds real executables. /usr/lib/cargo/bin matters from 26.04 on:
// ls, who and the rest of coreutils are symlinks into it, so checking /usr/bin
// alone would miss a trojaned ls there.
var verifiedDirs = []string{"/usr/bin/", "/usr/sbin/", "/usr/lib/openssh/", "/usr/libexec/", "/usr/lib/cargo/bin/"}

func wantVerify(path string) bool {
	for _, dir := range verifiedDirs {
		if strings.HasPrefix(path, dir) {
			return true
		}
	}
	return strings.HasPrefix(path, "/usr/lib/") && verifiedLib.MatchString(path)
}

func checkBinaries(c *Context) []model.Finding {
	const cat = model.CatIntegrity
	owners, err := c.Owners()
	if err != nil {
		return []model.Finding{skipped("integrity.binaries", cat, "系統執行檔雜湊", "無法讀取 dpkg 資料庫："+err.Error())}
	}
	ctx, cancel := context.WithCancel(c.Ctx)
	defer cancel()
	res, err := dpkg.Verify(ctx, owners, wantVerify)
	if err != nil {
		return []model.Finding{skipped("integrity.binaries", cat, "系統執行檔雜湊", err.Error())}
	}
	var out []model.Finding
	var key, other []string
	for _, m := range res.Mismatches {
		line := m.Path + "  （套件 " + m.Package + "）"
		if keyBinary.MatchString(m.Path) {
			key = append(key, line)
		} else {
			other = append(other, line)
		}
	}
	sort.Strings(key)
	sort.Strings(other)
	hint := "可用 apt install --reinstall <套件> 還原。先把可疑檔案複製出來保留，再做還原。"
	if len(key) > 0 {
		f := finding("integrity.binaries_key", cat, model.Critical, fmt.Sprintf("%d 個關鍵系統檔案與套件雜湊不符", len(key)))
		f.Detail = "ssh、sudo、ps 這類檔案被換掉，是木馬化或 rootkit 的典型跡象。"
		f.Evidence = key
		f.Remediation = hint
		f.Focus = true
		out = append(out, f)
	}
	if len(other) > 0 {
		f := finding("integrity.binaries_other", cat, model.High, fmt.Sprintf("%d 個系統檔案與套件雜湊不符", len(other)))
		f.Detail = "可能是手動修改或本地修補，也可能遭到竄改。"
		f.Evidence = other
		f.Remediation = hint
		out = append(out, f)
	}
	if len(key)+len(other) == 0 {
		f := finding("integrity.binaries", cat, model.OK, "已驗證 "+strconv.Itoa(res.Checked)+" 個系統檔案，雜湊都與套件一致")
		f.Detail = "比對基準是本機 dpkg 資料庫。若攻擊者連資料庫一起改，這項就驗不出來。"
		out = append(out, f)
	}
	if res.Incomplete {
		out = append(out, skipped("integrity.binaries_partial", cat, "系統執行檔雜湊未全部完成", "時間不足，只驗證了 "+strconv.Itoa(res.Checked)+" 個檔案。"))
	}
	return out
}
