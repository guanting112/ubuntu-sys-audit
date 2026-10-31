package checks

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
)

type lineRule struct {
	re   *regexp.Regexp
	name string
}

// Patterns with no ordinary use in a scheduled job or login script.
var maliciousRules = []lineRule{
	{regexp.MustCompile(`(curl|wget|fetch)\b[^|;&]*\|\s*(sudo\s+)?(/\S*/)?(ba|z|da|k)?sh\b`), "下載後直接交給 shell"},
	{regexp.MustCompile(`/dev/(tcp|udp)/`), "bash 網路重導向（reverse shell）"},
	{regexp.MustCompile(`\bbash\s+-i\b`), "互動式 bash（reverse shell）"},
	{regexp.MustCompile(`\b(nc|ncat|netcat)\b[^|;&]*\s-[a-zA-Z]*[ec]\b`), "netcat 執行指令"},
	{regexp.MustCompile(`python[0-9.]*\s+-c\s*['"].*socket`), "python 單行 socket"},
	{regexp.MustCompile(`perl\s+-e\s*['"].*socket`), "perl 單行 socket"},
	{regexp.MustCompile(`socat\b.*\b(exec|system):`), "socat 執行指令"},
	{regexp.MustCompile(`base64\s+(-d|--decode)\b[^|;&]*\|\s*(ba|z|da)?sh\b`), "解碼 base64 後交給 shell"},
	{regexp.MustCompile(`\bmkfifo\b.*\b(nc|ncat|sh)\b`), "named pipe reverse shell"},
	{regexp.MustCompile(`\b(xmrig|kinsing|kdevtmpfsi)\b|stratum\+tcp://`), "挖礦程式特徵"},
}

var tempPathRe = regexp.MustCompile(`(^|[\s'";&|(=])((?:/tmp|/var/tmp|/dev/shm)/[^\s'";&|)]+)`)

func matchMalicious(line string) string {
	for _, r := range maliciousRules {
		if r.re.MatchString(line) {
			return r.name
		}
	}
	return ""
}

// referencesTempExec looks for a command run out of a temporary directory. Log
// redirections and cleanup jobs mention these paths all the time, so those are
// excluded.
func referencesTempExec(line string) bool {
	for _, loc := range tempPathRe.FindAllStringIndex(line, -1) {
		before := strings.TrimRight(line[:loc[0]+1], " \t'\"=")
		if strings.HasSuffix(line[:loc[0]+1], ">") || strings.HasSuffix(before, ">") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "find /") || strings.Contains(lower, "rm ") || strings.Contains(lower, "tmpreaper") ||
			strings.Contains(lower, "mkdir") || strings.Contains(lower, "chown ") {
			continue
		}
		return true
	}
	return false
}

type persistTarget struct {
	glob     string
	group    string
	noFollow bool
}

var persistTargets = []persistTarget{
	{glob: "/etc/crontab", group: "cron"},
	{glob: "/etc/cron.d/*", group: "cron"},
	{glob: "/etc/cron.hourly/*", group: "cron"},
	{glob: "/etc/cron.daily/*", group: "cron"},
	{glob: "/etc/cron.weekly/*", group: "cron"},
	{glob: "/etc/cron.monthly/*", group: "cron"},
	{glob: "/var/spool/cron/crontabs/*", group: "使用者 crontab", noFollow: true},
	{glob: "/var/spool/cron/atjobs/*", group: "at 工作", noFollow: true},
	{glob: "/etc/rc.local", group: "rc.local"},
	{glob: "/etc/init.d/*", group: "init.d"},
	{glob: "/etc/profile", group: "登入腳本"},
	{glob: "/etc/bash.bashrc", group: "登入腳本"},
	{glob: "/etc/environment", group: "登入腳本"},
	{glob: "/etc/profile.d/*", group: "登入腳本"},
	{glob: "/etc/update-motd.d/*", group: "motd"},
	{glob: "/etc/apt/apt.conf.d/*", group: "apt hook"},
	{glob: "/etc/udev/rules.d/*", group: "udev"},
	{glob: "/etc/ld.so.conf.d/*", group: "動態連結設定"},
	{glob: "/etc/modules-load.d/*", group: "模組載入"},
	{glob: "/etc/modprobe.d/*", group: "模組載入"},
}

var userInitFiles = []string{
	".bashrc", ".profile", ".bash_profile", ".bash_login", ".bash_logout", ".zshrc", ".zprofile",
	".config/fish/config.fish",
}

// Files administrators or Ubuntu's own tooling generate outside dpkg's lists,
// where being unowned says nothing.
var expectedUnowned = regexp.MustCompile(`^/etc/(crontab|environment|profile|bash\.bashrc|cron\.d/\.placeholder|cron\.\w+/\.placeholder|apt/apt\.conf\.d/(20auto-upgrades|50unattended-upgrades|01autoremove|01-vendor-ubuntu|70debconf|99[-\w]*|docker-\w+)|ld\.so\.conf\.d/(libc\.conf|.*-linux-gnu.*\.conf|fakeroot.*\.conf)|modprobe\.d/\w+\.conf|modules-load\.d/modules\.conf)$`)

func checkPersistence(c *Context) []model.Finding {
	const cat = model.CatPersistence
	var malicious, tempRefs []string
	unowned := map[string][]string{}
	scanned := 0
	cutoff := time.Now().Add(-7 * 24 * time.Hour)

	scan := func(path, group string, noFollow bool, userFile bool) {
		var b []byte
		var err error
		if noFollow {
			b, err = fsx.ReadNoFollow(path, 1<<20)
		} else {
			b, err = fsx.Read(path, 1<<20)
		}
		if err != nil {
			return
		}
		scanned++
		owned := c.Owned(path)
		for _, raw := range strings.Split(string(b), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if name := matchMalicious(line); name != "" {
				malicious = append(malicious, fmt.Sprintf("%s（%s）：%s", path, name, line))
			} else if !owned && referencesTempExec(line) {
				tempRefs = append(tempRefs, path+"："+line)
			}
		}
		if owned || userFile || expectedUnowned.MatchString(path) {
			return
		}
		entry := path
		if st, err := os.Lstat(path); err == nil && st.ModTime().After(cutoff) {
			entry += "（7 天內修改）"
		}
		// Crontab entries are the content an operator actually wants to read.
		if strings.HasPrefix(path, "/var/spool/cron/crontabs/") {
			for _, raw := range strings.Split(string(b), "\n") {
				line := strings.TrimSpace(raw)
				if line != "" && !strings.HasPrefix(line, "#") {
					entry += "\n" + line
				}
			}
			for _, e := range strings.Split(entry, "\n")[1:] {
				unowned[group] = append(unowned[group], base(path)+"："+e)
			}
			return
		}
		unowned[group] = append(unowned[group], entry)
	}

	for _, t := range persistTargets {
		matches, _ := filepath.Glob(t.glob)
		for _, m := range matches {
			if c.Ctx.Err() != nil {
				break
			}
			if base(m) == ".placeholder" {
				continue
			}
			scan(m, t.group, t.noFollow, false)
		}
	}
	for _, u := range c.Homes() {
		for _, name := range userInitFiles {
			scan(filepath.Join(u.Home, name), "家目錄登入腳本", true, true)
		}
		auto, _ := filepath.Glob(filepath.Join(u.Home, ".config/autostart/*"))
		for _, a := range auto {
			scan(a, "桌面自動啟動", true, false)
		}
	}

	var out []model.Finding
	if len(malicious) > 0 {
		f := finding("persistence.malicious", cat, model.Critical, fmt.Sprintf("%d 行排程或登入腳本含惡意特徵", len(malicious)))
		f.Detail = "這些寫法幾乎只出現在入侵後的持久化，例如下載後直接執行或 reverse shell。"
		f.Evidence = malicious
		f.Remediation = "先備份檔案當證據，再移除，並調查入侵途徑。"
		out = append(out, f)
	}
	if len(tempRefs) > 0 {
		f := finding("persistence.temp_exec", cat, model.High, "排程或登入腳本從暫存目錄執行程式")
		f.Evidence = tempRefs
		f.Remediation = "確認用途。暫存目錄任何人都能寫入，這本身就有提權風險。"
		out = append(out, f)
	}
	var groups []string
	for g := range unowned {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	var ev []string
	for _, g := range groups {
		for _, line := range unowned[g] {
			ev = append(ev, "["+g+"] "+line)
		}
	}
	if len(ev) > 0 {
		f := finding("persistence.unowned", cat, model.Info, fmt.Sprintf("%d 筆排程與啟動項目不屬於任何套件", len(ev)))
		f.Detail = "這些是管理者自行加入的項目，也是攻擊者會放持久化的地方。請確認都認得。"
		f.Evidence = ev
		out = append(out, f)
	}
	if len(malicious)+len(tempRefs) == 0 {
		out = append(out, finding("persistence.clean", cat, model.OK, fmt.Sprintf("已掃描 %d 個排程與啟動檔案，沒有惡意特徵", scanned)))
	}
	return out
}

var systemdDirs = []string{
	"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/user", "/usr/lib/systemd/user",
}

var execKeyRe = regexp.MustCompile(`^(ExecStart|ExecStartPre|ExecStartPost|ExecStop|ExecStopPost|ExecReload)=(.*)$`)

func checkSystemd(c *Context) []model.Finding {
	const cat = model.CatPersistence
	var malicious, tempExec, unowned []string
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	seen := map[string]bool{}
	scanned := 0

	scanUnit := func(path string, noFollow bool) {
		real := path
		if seen[real] {
			return
		}
		seen[real] = true
		var b []byte
		var err error
		if noFollow {
			b, err = fsx.ReadNoFollow(path, 1<<20)
		} else {
			b, err = fsx.Read(path, 1<<20)
		}
		if err != nil {
			return
		}
		scanned++
		var execs []string
		for _, raw := range strings.Split(string(b), "\n") {
			line := strings.TrimSpace(raw)
			m := execKeyRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			cmd := strings.TrimLeft(m[2], "-@:+!")
			execs = append(execs, cmd)
			if name := matchMalicious(cmd); name != "" {
				malicious = append(malicious, fmt.Sprintf("%s（%s）：%s", path, name, cmd))
				continue
			}
			first := strings.Fields(cmd + " x")[0]
			if inTemp(first) {
				tempExec = append(tempExec, path+"："+cmd)
			}
		}
		if !c.Owned(path) && len(execs) > 0 {
			entry := path + " -> " + execs[0]
			if st, err := os.Lstat(path); err == nil && st.ModTime().After(cutoff) {
				entry = "（7 天內修改）" + entry
			}
			unowned = append(unowned, entry)
		}
	}

	wanted := func(name string) bool {
		return strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".conf") ||
			strings.HasSuffix(name, ".timer") || strings.HasSuffix(name, ".path") || strings.HasSuffix(name, ".socket")
	}
	for _, dir := range systemdDirs {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if c.Ctx.Err() != nil {
				return filepath.SkipAll
			}
			// Enablement symlinks point at units scanned at their real path.
			if d.Type().IsRegular() && wanted(d.Name()) {
				scanUnit(p, false)
			}
			return nil
		})
	}
	for _, u := range c.Homes() {
		dir := filepath.Join(u.Home, ".config/systemd/user")
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.Type().IsRegular() && wanted(d.Name()) {
				scanUnit(p, true)
			}
			return nil
		})
	}
	var out []model.Finding
	if len(malicious) > 0 {
		f := finding("persistence.systemd_malicious", cat, model.Critical, "systemd 服務含惡意特徵")
		f.Evidence = malicious
		f.Remediation = "先備份 unit 檔當證據，再 systemctl disable --now 停用，並調查入侵途徑。"
		out = append(out, f)
	}
	if len(tempExec) > 0 {
		f := finding("persistence.systemd_temp", cat, model.Critical, "systemd 服務從暫存目錄執行程式")
		f.Detail = "暫存目錄內的東西不該被 systemd 當成服務執行。"
		f.Evidence = tempExec
		out = append(out, f)
	}
	if len(unowned) > 0 {
		sort.Strings(unowned)
		f := finding("persistence.systemd_unowned", cat, model.Info, fmt.Sprintf("%d 個 systemd 服務不屬於任何套件", len(unowned)))
		f.Detail = "自行部署的服務都會列在這裡，請確認都認得。"
		f.Evidence = unowned
		out = append(out, f)
	}
	if len(malicious)+len(tempExec) == 0 {
		out = append(out, finding("persistence.systemd_clean", cat, model.OK, fmt.Sprintf("已掃描 %d 個 systemd unit，沒有惡意特徵", scanned)))
	}
	return out
}
