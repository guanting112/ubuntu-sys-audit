package checks

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
)

func uidMin() int {
	b, err := fsx.Read("/etc/login.defs", 1<<18)
	if err != nil {
		return 1000
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "UID_MIN" {
			if v, err := strconv.Atoi(f[1]); err == nil {
				return v
			}
		}
	}
	return 1000
}

func checkUsers(c *Context) []model.Finding {
	const cat = model.CatAccounts
	users, err := c.Users()
	if err != nil {
		return []model.Finding{skipped("accounts.users", cat, "帳號清單", "無法讀取 /etc/passwd："+err.Error())}
	}
	min := uidMin()
	shadow, shadowErr := c.Shadow()

	human, loginable := 0, 0
	var rows []string
	for _, u := range users {
		login := isLoginShell(u.Shell)
		if u.UID >= min && u.UID < 65534 {
			human++
		}
		if login {
			loginable++
		}
		if login || (u.UID >= min && u.UID < 65534) {
			pw := "未知"
			if e, ok := shadow[u.Name]; ok {
				pw = passwordLabel(e)
			}
			rows = append(rows, fmt.Sprintf("%s  uid=%d  shell=%s  密碼=%s", u.Name, u.UID, u.Shell, pw))
		}
	}
	summary := finding("accounts.summary", cat, model.Info,
		fmt.Sprintf("共 %d 個帳號：一般使用者 %d 個，可登入 %d 個", len(users), human, loginable))
	summary.Evidence = rows
	summary.Focus = true
	out := []model.Finding{summary}

	var uid0, gid0, sysLogin, webLogin []string
	uidSeen := map[int][]string{}
	for _, u := range users {
		uidSeen[u.UID] = append(uidSeen[u.UID], u.Name)
		if u.UID == 0 && u.Name != "root" {
			uid0 = append(uid0, fmt.Sprintf("%s  shell=%s  home=%s", u.Name, u.Shell, u.Home))
		}
		if u.GID == 0 && u.UID != 0 && u.Name != "sync" {
			gid0 = append(gid0, u.Name)
		}
		if u.UID > 0 && u.UID < min && isLoginShell(u.Shell) {
			line := fmt.Sprintf("%s  uid=%d  shell=%s", u.Name, u.UID, u.Shell)
			if isServiceAccount(u.Name) {
				webLogin = append(webLogin, line)
			} else {
				sysLogin = append(sysLogin, line)
			}
		}
	}
	if len(uid0) > 0 {
		f := finding("accounts.uid0", cat, model.Critical, fmt.Sprintf("發現 %d 個非 root 的 UID 0 帳號", len(uid0)))
		f.Detail = "UID 0 就是 root。除非是刻意建立，否則這是常見的後門手法。"
		f.Evidence = uid0
		f.Remediation = "確認來源，若非預期請停用該帳號，並視為主機已遭入侵處理。"
		out = append(out, f)
	} else {
		out = append(out, finding("accounts.uid0", cat, model.OK, "只有 root 使用 UID 0"))
	}
	if len(gid0) > 0 {
		f := finding("accounts.gid0", cat, model.Medium, "有帳號的主要群組是 root")
		f.Evidence = gid0
		out = append(out, f)
	}
	if len(webLogin) > 0 {
		f := finding("accounts.service_shell", cat, model.High, "Web 或資料庫服務帳號可以登入")
		f.Detail = "這些帳號應該是 nologin。攻擊者拿到 webshell 後常靠它們取得互動式登入。"
		f.Evidence = webLogin
		f.Remediation = "usermod -s /usr/sbin/nologin <帳號>"
		out = append(out, f)
	}
	if len(sysLogin) > 0 {
		f := finding("accounts.system_shell", cat, model.Medium, "系統帳號設有可登入的 shell")
		f.Evidence = sysLogin
		f.Remediation = "確認用途，不需要就改為 /usr/sbin/nologin。"
		out = append(out, f)
	}
	var dupes []string
	for uid, names := range uidSeen {
		if len(names) > 1 && uid != 0 {
			dupes = append(dupes, fmt.Sprintf("uid=%d：%s", uid, strings.Join(names, ", ")))
		}
	}
	if len(dupes) > 0 {
		sort.Strings(dupes)
		f := finding("accounts.dup_uid", cat, model.Medium, "有多個帳號共用同一個 UID")
		f.Evidence = dupes
		out = append(out, f)
	}

	if shadowErr != nil {
		if !c.Host.IsRoot {
			return append(out, needRoot("accounts.shadow", cat, "密碼狀態"))
		}
		return append(out, skipped("accounts.shadow", cat, "密碼狀態", "無法讀取 /etc/shadow："+shadowErr.Error()))
	}
	return append(out, shadowFindings(c, users, shadow, min)...)
}

func passwordLabel(e ShadowEntry) string {
	switch e.Status {
	case "empty":
		return "空白"
	case "locked":
		return "鎖定"
	}
	return "已設定（" + e.Algo + "）"
}

func isServiceAccount(name string) bool {
	switch name {
	case "www-data", "nginx", "apache", "httpd", "mysql", "postgres", "redis", "mongodb", "nobody", "php-fpm", "tomcat":
		return true
	}
	return false
}

func shadowFindings(c *Context, users []User, shadow map[string]ShadowEntry, min int) []model.Finding {
	const cat = model.CatAccounts
	var out []model.Finding
	var empty, weak, sysPw, recent []string
	today := int(time.Now().Unix() / 86400)
	for _, u := range users {
		e, ok := shadow[u.Name]
		if !ok {
			continue
		}
		switch e.Status {
		case "empty":
			empty = append(empty, fmt.Sprintf("%s  shell=%s", u.Name, u.Shell))
		case "password":
			if e.Algo == "md5" || e.Algo == "des" {
				weak = append(weak, u.Name+"（"+e.Algo+"）")
			}
			if u.UID > 0 && u.UID < min {
				sysPw = append(sysPw, u.Name)
			}
			if e.LastChange > 0 && today-e.LastChange <= 7 {
				recent = append(recent, fmt.Sprintf("%s（%d 天前）", u.Name, today-e.LastChange))
			}
		}
	}
	if len(empty) > 0 {
		f := finding("accounts.empty_password", cat, model.Critical, fmt.Sprintf("%d 個帳號沒有密碼", len(empty)))
		f.Evidence = empty
		f.Remediation = "passwd -l <帳號> 鎖定，或設定強密碼。"
		out = append(out, f)
	} else {
		out = append(out, finding("accounts.empty_password", cat, model.OK, "沒有空白密碼的帳號"))
	}
	if len(weak) > 0 {
		f := finding("accounts.weak_hash", cat, model.Medium, "有帳號使用弱密碼雜湊")
		f.Evidence = weak
		f.Remediation = "重設密碼，新雜湊會使用系統預設的強演算法。"
		out = append(out, f)
	}
	if len(sysPw) > 0 {
		f := finding("accounts.system_password", cat, model.High, "系統帳號設有可用密碼")
		f.Detail = "系統帳號通常是鎖定的。密碼被設定過可能代表帳號遭到挪用。"
		f.Evidence = sysPw
		out = append(out, f)
	}
	if len(recent) > 0 {
		f := finding("accounts.recent_password", cat, model.Info, "最近 7 天內有帳號變更密碼")
		f.Evidence = recent
		out = append(out, f)
	}
	return out
}

func checkPrivilege(c *Context) []model.Finding {
	const cat = model.CatAccounts
	var out []model.Finding
	groups := c.Groups()
	var evidence []string
	risky := false
	for _, g := range []string{"sudo", "admin", "wheel", "docker", "lxd", "disk", "shadow", "adm"} {
		members := groups[g]
		if len(members) == 0 {
			continue
		}
		evidence = append(evidence, g+"："+strings.Join(members, ", "))
		if g == "docker" || g == "lxd" || g == "disk" || g == "shadow" {
			risky = true
		}
	}
	if len(evidence) > 0 {
		f := finding("accounts.groups", cat, model.Info, "高權限群組成員")
		f.Evidence = evidence
		if risky {
			f.Detail = "docker、lxd、disk 群組的成員實質上等同 root；shadow 群組可讀取密碼雜湊。"
		}
		out = append(out, f)
	}

	users, _ := c.Users()
	uidOf := map[string]int{}
	for _, u := range users {
		uidOf[u.Name] = u.UID
	}
	min := uidMin()
	files := []string{"/etc/sudoers"}
	more, _ := filepath.Glob("/etc/sudoers.d/*")
	files = append(files, more...)
	readable := 0
	var nopass, sysSudo []string
	for _, p := range files {
		b, err := fsx.Read(p, 1<<20)
		if err != nil {
			continue
		}
		readable++
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") {
				continue
			}
			if !strings.Contains(line, "NOPASSWD") {
				continue
			}
			who := strings.Fields(line)[0]
			if uid, ok := uidOf[who]; ok && uid > 0 && uid < min {
				sysSudo = append(sysSudo, p+"："+line)
				continue
			}
			nopass = append(nopass, p+"："+line)
		}
	}
	if readable == 0 && !c.Host.IsRoot {
		out = append(out, needRoot("accounts.sudoers", cat, "sudoers 規則"))
	}
	if len(sysSudo) > 0 {
		f := finding("accounts.sudo_system", cat, model.Critical, "系統帳號可以免密碼 sudo")
		f.Detail = "例如 www-data 有免密碼 sudo 時，任何 webshell 都能直接變成 root。"
		f.Evidence = sysSudo
		f.Remediation = "移除這條規則，並調查它何時、由誰加入。"
		out = append(out, f)
	}
	if len(nopass) > 0 {
		f := finding("accounts.sudo_nopasswd", cat, model.Medium, fmt.Sprintf("%d 條免密碼 sudo 規則", len(nopass)))
		f.Detail = "雲端映像的預設帳號常有這條規則，請確認清單內都是預期的帳號。"
		f.Evidence = nopass
		out = append(out, f)
	} else if readable > 0 && len(sysSudo) == 0 {
		out = append(out, finding("accounts.sudo_nopasswd", cat, model.OK, "沒有免密碼 sudo 規則"))
	}

	var badPerm []string
	for _, p := range []struct {
		path string
		mask os.FileMode
	}{
		{"/etc/passwd", 0o022}, {"/etc/shadow", 0o037}, {"/etc/group", 0o022},
		{"/etc/gshadow", 0o037}, {"/etc/sudoers", 0o027},
	} {
		st, err := os.Stat(p.path)
		if err == nil && st.Mode().Perm()&p.mask != 0 {
			badPerm = append(badPerm, fmt.Sprintf("%s  權限 %o", p.path, st.Mode().Perm()))
		}
	}
	if len(badPerm) > 0 {
		f := finding("accounts.file_perms", cat, model.Critical, "帳號相關檔案權限過寬")
		f.Evidence = badPerm
		out = append(out, f)
	}

	var historyLinks []string
	for _, u := range c.Homes() {
		for _, name := range []string{".bash_history", ".zsh_history", ".mysql_history", ".psql_history"} {
			p := filepath.Join(u.Home, name)
			st, err := os.Lstat(p)
			if err != nil {
				continue
			}
			if st.Mode()&os.ModeSymlink != 0 {
				target, _ := os.Readlink(p)
				if target == "/dev/null" {
					historyLinks = append(historyLinks, p+" -> /dev/null")
				}
			}
		}
	}
	if len(historyLinks) > 0 {
		f := finding("accounts.history_wiped", cat, model.High, "Shell 歷史紀錄被導向 /dev/null")
		f.Detail = "攻擊者常用這招避免留下指令紀錄。"
		f.Evidence = historyLinks
		out = append(out, f)
	}
	return out
}

// utmp record layout on amd64 and arm64.
const (
	utmpSize     = 384
	utUserProc   = 7
	utDeadProc   = 8
	utOffLine    = 8
	utOffUser    = 44
	utOffHost    = 76
	utOffTime    = 340
	utLineLen    = 32
	utUserLen    = 32
	utHostLen    = 256
	lastLogLimit = 16 << 20
)

type loginRecord struct {
	Type int
	User string
	Line string
	Host string
	Time time.Time
}

func cstr(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func parseUtmp(data []byte) []loginRecord {
	var out []loginRecord
	for len(data) >= utmpSize {
		rec := data[:utmpSize]
		data = data[utmpSize:]
		typ := int(int16(binary.LittleEndian.Uint16(rec[0:])))
		if typ != utUserProc {
			continue
		}
		out = append(out, loginRecord{
			Type: typ,
			Line: cstr(rec[utOffLine : utOffLine+utLineLen]),
			User: cstr(rec[utOffUser : utOffUser+utUserLen]),
			Host: cstr(rec[utOffHost : utOffHost+utHostLen]),
			Time: time.Unix(int64(int32(binary.LittleEndian.Uint32(rec[utOffTime:]))), 0),
		})
	}
	return out
}

var (
	authAccepted = regexp.MustCompile(`sshd(?:-session)?\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port`)
	authFailed   = regexp.MustCompile(`sshd(?:-session)?\[\d+\]: (?:Failed \S+ for (?:invalid user )?(\S+)|Invalid user (\S*)) from (\S+)`)
)

func isPublicAddr(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return !(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast())
}

func checkLogins(c *Context) []model.Finding {
	const cat = model.CatAccounts
	var out []model.Finding

	// Current sessions: systemd's session files exist on every release, while
	// utmp is on its way out on recent ones.
	var current []string
	sessions, _ := filepath.Glob("/run/systemd/sessions/*")
	for _, s := range sessions {
		if strings.HasSuffix(s, ".ref") {
			continue
		}
		b, err := fsx.Read(s, 1<<14)
		if err != nil {
			continue
		}
		vals := map[string]string{}
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				vals[k] = v
			}
		}
		if vals["USER"] == "" && vals["UID"] == "" {
			continue
		}
		if vals["CLASS"] == "manager" || vals["CLASS"] == "manager-early" {
			continue
		}
		user := vals["USER"]
		if user == "" {
			user = "uid=" + vals["UID"]
		}
		current = append(current, strings.TrimSpace(fmt.Sprintf("%s  %s  %s  來源=%s", user, vals["TTY"], vals["SERVICE"], vals["REMOTE_HOST"])))
	}
	if len(current) == 0 {
		if b, err := fsx.Read("/var/run/utmp", lastLogLimit); err == nil {
			for _, r := range parseUtmp(b) {
				current = append(current, fmt.Sprintf("%s  %s  來源=%s  %s", r.User, r.Line, r.Host, r.Time.Format("2006-01-02 15:04")))
			}
		}
	}
	if len(current) > 0 {
		sort.Strings(current)
		f := finding("accounts.sessions", cat, model.Info, fmt.Sprintf("目前有 %d 個登入階段", len(current)))
		f.Evidence = current
		out = append(out, f)
	}

	// wtmp is absent on releases that moved to wtmpdb, so it is one source.
	var recent []string
	if b, err := fsx.Tail("/var/log/wtmp", lastLogLimit); err == nil {
		recs := parseUtmp(b[len(b)%utmpSize:])
		if n := len(recs); n > 15 {
			recs = recs[n-15:]
		}
		for i := len(recs) - 1; i >= 0; i-- {
			r := recs[i]
			recent = append(recent, fmt.Sprintf("%s  %s  %s  來源=%s", r.Time.Format("2006-01-02 15:04"), r.User, r.Line, r.Host))
		}
	}
	if len(recent) > 0 {
		f := finding("accounts.lastlog", cat, model.Info, fmt.Sprintf("最近 %d 筆登入（wtmp）", len(recent)))
		f.Evidence = recent
		out = append(out, f)
	}

	var authData []byte
	for _, p := range []string{"/var/log/auth.log.1", "/var/log/auth.log"} {
		if b, err := fsx.Tail(p, 32<<20); err == nil {
			authData = append(authData, b...)
		}
	}
	if len(authData) == 0 {
		if !c.Host.IsRoot {
			return append(out, needRoot("accounts.authlog", cat, "SSH 登入紀錄"))
		}
		out = append(out, skipped("accounts.authlog", cat, "SSH 登入紀錄", "找不到 /var/log/auth.log。此主機可能只用 journald，請用 journalctl -u ssh 檢視。"))
		return out
	}
	acceptedBy := map[string]int{}
	failedFrom := map[string]int{}
	var rootPublic []string
	total := 0
	for _, line := range strings.Split(string(authData), "\n") {
		if m := authAccepted.FindStringSubmatch(line); m != nil {
			total++
			acceptedBy[m[2]+" 從 "+m[3]+"（"+m[1]+"）"]++
			if m[2] == "root" && isPublicAddr(m[3]) {
				rootPublic = append(rootPublic, m[3])
			}
			continue
		}
		if m := authFailed.FindStringSubmatch(line); m != nil {
			failedFrom[m[3]]++
		}
	}
	f := finding("accounts.ssh_accepted", cat, model.Info, fmt.Sprintf("auth.log 內有 %d 次成功 SSH 登入，來自 %d 種帳號與來源組合", total, len(acceptedBy)))
	f.Evidence = topCounts(acceptedBy, 30)
	out = append(out, f)

	if len(rootPublic) > 0 {
		g := finding("accounts.root_public", cat, model.High, "root 曾從公網 IP 登入成功")
		g.Evidence = uniqueStrings(rootPublic)
		g.Remediation = "確認來源 IP 是否屬於自己，並設定 PermitRootLogin no。"
		out = append(out, g)
	}
	if len(failedFrom) > 0 {
		failTotal := 0
		for _, n := range failedFrom {
			failTotal += n
		}
		g := finding("accounts.ssh_failed", cat, model.Info, fmt.Sprintf("auth.log 內有 %d 次 SSH 登入失敗，來自 %d 個 IP", failTotal, len(failedFrom)))
		g.Evidence = topCounts(failedFrom, 15)
		if failTotal > 1000 {
			g.Remediation = "SSH 正被暴力嘗試。考慮限制來源 IP、關閉密碼登入或使用 fail2ban。"
		}
		out = append(out, g)
	}
	return out
}

func topCounts(m map[string]int, limit int) []string {
	type kv struct {
		k string
		v int
	}
	var all []kv
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	if len(all) > limit {
		all = all[:limit]
	}
	out := make([]string, len(all))
	for i, e := range all {
		out[i] = fmt.Sprintf("%6d  %s", e.v, e.k)
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
