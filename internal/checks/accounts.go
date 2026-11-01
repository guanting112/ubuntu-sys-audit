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
		return []model.Finding{skipped("accounts.users", cat, "Account list", "Cannot read /etc/passwd ("+err.Error()+")")}
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
			pw := "unknown"
			if e, ok := shadow[u.Name]; ok {
				pw = passwordLabel(e)
			}
			rows = append(rows, fmt.Sprintf("%s  uid=%d  shell=%s  password %s", u.Name, u.UID, u.Shell, pw))
		}
	}
	summary := finding("accounts.summary", cat, model.Info,
		fmt.Sprintf("Accounts: %d total, %d regular, %d can log in", len(users), human, loginable))
	summary.Evidence = rows
	summary.Focus = true
	out := []model.Finding{summary}

	versions := c.PackageVersions()
	var uid0, gid0, sysLogin, webLogin, passwdEmpty, passwdHash []string
	uidSeen := map[int][]string{}
	for _, u := range users {
		uidSeen[u.UID] = append(uidSeen[u.UID], u.Name)
		// pam_unix reads this field before /etc/shadow, so a value here is a
		// working password whatever shadow says. It is a classic backdoor.
		switch u.Password {
		case "empty":
			passwdEmpty = append(passwdEmpty, fmt.Sprintf("%s  uid=%d  shell=%s", u.Name, u.UID, u.Shell))
		case "inline":
			passwdHash = append(passwdHash, fmt.Sprintf("%s  uid=%d  shell=%s", u.Name, u.UID, u.Shell))
		}
		if u.UID == 0 && u.Name != "root" {
			uid0 = append(uid0, fmt.Sprintf("%s  shell=%s  home=%s", u.Name, u.Shell, u.Home))
		}
		if u.GID == 0 && u.UID != 0 && u.Name != "sync" {
			gid0 = append(gid0, u.Name)
		}
		if u.UID > 0 && u.UID < min && isLoginShell(u.Shell) && !stockServiceShell(u, versions) {
			line := fmt.Sprintf("%s  uid=%d  shell=%s", u.Name, u.UID, u.Shell)
			if isServiceAccount(u.Name) {
				webLogin = append(webLogin, line)
			} else {
				sysLogin = append(sysLogin, line)
			}
		}
	}
	if len(passwdEmpty) > 0 {
		f := finding("accounts.passwd_empty", cat, model.Critical, fmt.Sprintf("Accounts with an empty password field in /etc/passwd (%d)", len(passwdEmpty)))
		f.Detail = "These accounts may log in with no password at all, and /etc/shadow is not consulted for them."
		f.Evidence = passwdEmpty
		f.Remediation = "Set the field to x and manage the password in /etc/shadow, or lock the account. Treat the host as compromised if you did not do this."
		out = append(out, f)
	}
	if len(passwdHash) > 0 {
		f := finding("accounts.passwd_hash", cat, model.Critical, fmt.Sprintf("Accounts with a password hash in /etc/passwd (%d)", len(passwdHash)))
		f.Detail = "Ubuntu keeps hashes in /etc/shadow. A hash in the world-readable /etc/passwd overrides it, and is a classic way to add a backdoor password."
		f.Evidence = passwdHash
		f.Remediation = "Set the field to x. Treat the host as compromised if you did not do this."
		out = append(out, f)
	}
	if len(uid0) > 0 {
		f := finding("accounts.uid0", cat, model.Critical, fmt.Sprintf("UID 0 accounts other than root (%d)", len(uid0)))
		f.Detail = "UID 0 is root. Unless this was created on purpose, it is a common backdoor technique."
		f.Evidence = uid0
		f.Remediation = "Find out where it came from. If unexpected, disable the account and treat the host as compromised."
		out = append(out, f)
	} else {
		out = append(out, finding("accounts.uid0", cat, model.OK, "Only root uses UID 0"))
	}
	if len(gid0) > 0 {
		f := finding("accounts.gid0", cat, model.Medium, "Accounts with root as primary group")
		f.Evidence = gid0
		out = append(out, f)
	}
	if len(webLogin) > 0 {
		f := finding("accounts.service_shell", cat, model.High, "Web or database service accounts can log in")
		f.Detail = "These accounts should use nologin. After planting a webshell, attackers often use them to get an interactive login."
		f.Evidence = webLogin
		f.Remediation = "usermod -s /usr/sbin/nologin <account>"
		out = append(out, f)
	}
	if len(sysLogin) > 0 {
		f := finding("accounts.system_shell", cat, model.Medium, "System accounts have a login shell")
		f.Evidence = sysLogin
		f.Remediation = "Confirm the purpose. If not needed, change it to /usr/sbin/nologin."
		out = append(out, f)
	}
	var dupes []string
	for uid, names := range uidSeen {
		if len(names) > 1 && uid != 0 {
			dupes = append(dupes, fmt.Sprintf("uid=%d: %s", uid, strings.Join(names, ", ")))
		}
	}
	if len(dupes) > 0 {
		sort.Strings(dupes)
		f := finding("accounts.dup_uid", cat, model.Medium, "Multiple accounts share a UID")
		f.Evidence = dupes
		out = append(out, f)
	}

	if shadowErr != nil {
		if !c.Host.IsRoot {
			return append(out, needRoot("accounts.shadow", cat, "Password status"))
		}
		return append(out, skipped("accounts.shadow", cat, "Password status", "Cannot read /etc/shadow: "+shadowErr.Error()))
	}
	return append(out, shadowFindings(c, users, shadow, min, len(passwdEmpty) > 0)...)
}

// stockServiceShell recognizes the login shell a package gives its own account.
// postgresql-common creates postgres with /bin/bash, so flagging it would raise an
// alert on every database host.
func stockServiceShell(u User, versions map[string][]string) bool {
	return u.Name == "postgres" && u.Shell == "/bin/bash" && len(versions["postgresql-common"]) > 0
}

func passwordLabel(e ShadowEntry) string {
	switch e.Status {
	case "empty":
		return "empty"
	case "locked":
		return "locked"
	}
	return "set (" + e.Algo + ")"
}

func isServiceAccount(name string) bool {
	switch name {
	case "www-data", "nginx", "apache", "httpd", "mysql", "postgres", "redis", "mongodb", "nobody", "php-fpm", "tomcat":
		return true
	}
	return false
}

func shadowFindings(c *Context, users []User, shadow map[string]ShadowEntry, min int, passwdEmpty bool) []model.Finding {
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
				weak = append(weak, u.Name+" ("+e.Algo+")")
			}
			if u.UID > 0 && u.UID < min {
				sysPw = append(sysPw, u.Name)
			}
			if e.LastChange > 0 && today-e.LastChange <= 7 {
				recent = append(recent, fmt.Sprintf("%s (%dd ago)", u.Name, today-e.LastChange))
			}
		}
	}
	if len(empty) > 0 {
		f := finding("accounts.empty_password", cat, model.Critical, fmt.Sprintf("Accounts with an empty password (%d)", len(empty)))
		f.Evidence = empty
		f.Remediation = "Lock with passwd -l <account>, or set a strong password."
		out = append(out, f)
	} else if !passwdEmpty {
		out = append(out, finding("accounts.empty_password", cat, model.OK, "No accounts with an empty password"))
	}
	if len(weak) > 0 {
		f := finding("accounts.weak_hash", cat, model.Medium, "Accounts use weak password hashes")
		f.Evidence = weak
		f.Remediation = "Reset the password. The new hash will use the system's strong default."
		out = append(out, f)
	}
	if len(sysPw) > 0 {
		f := finding("accounts.system_password", cat, model.High, "System accounts have a usable password")
		f.Detail = "System accounts are normally locked. A password being set may mean the account was hijacked."
		f.Evidence = sysPw
		out = append(out, f)
	}
	if len(recent) > 0 {
		f := finding("accounts.recent_password", cat, model.Info, "Passwords changed in the last 7 days")
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
		evidence = append(evidence, g+": "+strings.Join(members, ", "))
		if g == "docker" || g == "lxd" || g == "disk" || g == "shadow" {
			risky = true
		}
	}
	if len(evidence) > 0 {
		f := finding("accounts.groups", cat, model.Info, "Members of privileged groups")
		f.Evidence = evidence
		if risky {
			f.Detail = "Members of docker, lxd and disk are effectively root. The shadow group can read password hashes."
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
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "Defaults") {
				// Same effect as NOPASSWD, but for every rule it applies to.
				if strings.Contains(line, "!authenticate") {
					nopass = append(nopass, p+": "+line)
				}
				continue
			}
			if !strings.Contains(line, "NOPASSWD") {
				continue
			}
			who := strings.Fields(line)[0]
			if uid, ok := uidOf[who]; ok && uid > 0 && uid < min {
				sysSudo = append(sysSudo, p+": "+line)
				continue
			}
			nopass = append(nopass, p+": "+line)
		}
	}
	if readable == 0 && !c.Host.IsRoot {
		out = append(out, needRoot("accounts.sudoers", cat, "sudoers rules"))
	}
	if len(sysSudo) > 0 {
		f := finding("accounts.sudo_system", cat, model.Critical, "System accounts have passwordless sudo")
		f.Detail = "If www-data has passwordless sudo, for example, any webshell becomes root immediately."
		f.Evidence = sysSudo
		f.Remediation = "Remove the rule and find out when and by whom it was added."
		out = append(out, f)
	}
	if len(nopass) > 0 {
		f := finding("accounts.sudo_nopasswd", cat, model.Medium, fmt.Sprintf("Passwordless sudo rules (%d)", len(nopass)))
		f.Detail = "Default accounts on cloud images often have this rule. Confirm every account listed is expected."
		f.Evidence = nopass
		out = append(out, f)
	} else if readable > 0 && len(sysSudo) == 0 {
		out = append(out, finding("accounts.sudo_nopasswd", cat, model.OK, "No passwordless sudo rules"))
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
			badPerm = append(badPerm, fmt.Sprintf("%s  mode %o", p.path, st.Mode().Perm()))
		}
	}
	if len(badPerm) > 0 {
		f := finding("accounts.file_perms", cat, model.Critical, "Account files have overly broad permissions")
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
		f := finding("accounts.history_wiped", cat, model.High, "Shell history is redirected to /dev/null")
		f.Detail = "Attackers often do this to avoid leaving a command history."
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
		current = append(current, strings.TrimSpace(fmt.Sprintf("%s  %s  %s  from=%s", user, vals["TTY"], vals["SERVICE"], vals["REMOTE_HOST"])))
	}
	if len(current) == 0 {
		if b, err := fsx.Read("/var/run/utmp", lastLogLimit); err == nil {
			for _, r := range parseUtmp(b) {
				current = append(current, fmt.Sprintf("%s  %s  from=%s  %s", r.User, r.Line, r.Host, r.Time.Format("2006-01-02 15:04")))
			}
		}
	}
	if len(current) > 0 {
		sort.Strings(current)
		f := finding("accounts.sessions", cat, model.Info, fmt.Sprintf("Current login sessions (%d)", len(current)))
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
			recent = append(recent, fmt.Sprintf("%s  %s  %s  from=%s", r.Time.Format("2006-01-02 15:04"), r.User, r.Line, r.Host))
		}
	}
	if len(recent) > 0 {
		f := finding("accounts.lastlog", cat, model.Info, fmt.Sprintf("Recent logins from wtmp (%d)", len(recent)))
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
			return append(out, needRoot("accounts.authlog", cat, "SSH login history"))
		}
		// Normal on hosts that log only to journald, so this is not a failed check.
		f := finding("accounts.authlog", cat, model.Info, "SSH login history not available from auth.log")
		f.Detail = "/var/log/auth.log not found. This host may use journald only. Use journalctl -u ssh instead."
		return append(out, f)
	}
	acceptedBy := map[string]int{}
	failedFrom := map[string]int{}
	var rootPublic []string
	total := 0
	for _, line := range strings.Split(string(authData), "\n") {
		if m := authAccepted.FindStringSubmatch(line); m != nil {
			total++
			acceptedBy[m[2]+" from "+m[3]+" ("+m[1]+")"]++
			if m[2] == "root" && isPublicAddr(m[3]) {
				rootPublic = append(rootPublic, m[3])
			}
			continue
		}
		if m := authFailed.FindStringSubmatch(line); m != nil {
			failedFrom[m[3]]++
		}
	}
	f := finding("accounts.ssh_accepted", cat, model.Info, fmt.Sprintf("Successful SSH logins in auth.log (%d, from %d account and source pairs)", total, len(acceptedBy)))
	f.Evidence = topCounts(acceptedBy, 30)
	out = append(out, f)

	if len(rootPublic) > 0 {
		g := finding("accounts.root_public", cat, model.High, "root logged in from a public IP")
		g.Evidence = uniqueStrings(rootPublic)
		g.Remediation = "Confirm the source IPs are yours, and set PermitRootLogin no."
		out = append(out, g)
	}
	if len(failedFrom) > 0 {
		failTotal := 0
		for _, n := range failedFrom {
			failTotal += n
		}
		g := finding("accounts.ssh_failed", cat, model.Info, fmt.Sprintf("Failed SSH logins in auth.log (%d, from %d source IPs)", failTotal, len(failedFrom)))
		g.Evidence = topCounts(failedFrom, 15)
		if failTotal > 1000 {
			g.Remediation = "SSH is being brute forced. Consider restricting source IPs, disabling password login or using fail2ban."
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
