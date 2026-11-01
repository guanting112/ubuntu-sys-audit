package model

import (
	"strings"
	"testing"
)

func TestSanitizeNeutralizesTerminalEscapes(t *testing.T) {
	cases := map[string]string{
		"plain name":            "plain name",
		"evil\x1b[2Jname":       `evil\x1b[2Jname`,
		"\x1b]52;c;AAAA\x07":    `\x1b]52;c;AAAA\x07`,
		"a‮b":                   `a\x202eb`,
		"中文路徑":                  "中文路徑",
		"\u009b31m":             `\x9b31m`,
		"\x9b31m":               "\\ufffd31m",
		"keep\ttabs\nand lines": "keep\ttabs\nand lines",
		"bad\xffbyte":           "bad\\ufffdbyte",
	}
	for in, want := range cases {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactMasksCredentials(t *testing.T) {
	cases := []struct{ in, leak string }{
		{"mysql --password=hunter2 -u root", "hunter2"},
		{"app --token abc123def", "abc123def"},
		{"curl https://bob:s3cret@example.com/x", "s3cret"},
		{"API_KEY=zzzyyy ./run", "zzzyyy"},
		{`password: "two words"`, "two words"},
		{"root:$6$abcdefgh$AAAABBBBCCCCDDDD:19000", "AAAABBBBCCCCDDDD"},
		{"root:$y$j9T$saltsalt$hashhashhash:19000", "hashhashhash"},
		{"0 1 * * * mysqldump -uroot -pS3CRET1 db", "S3CRET1"},
		{"/usr/bin/mysql --user=root -pS3CRET2", "S3CRET2"},
		{"PGPASSWORD=S3CRET3 pg_dump x", "S3CRET3"},
		{"DBPASS=S3CRET4 ./run", "S3CRET4"},
		{"MYSQL_PWD=S3CRET5 mysql", "S3CRET5"},
		{"curl -u admin:S3CRET6 http://h/", "S3CRET6"},
		{"curl --user admin:S3CRET7 http://h/", "S3CRET7"},
		{`curl -H "Authorization: Bearer S3CRET8" http://h/`, "S3CRET8"},
		{"sshpass -p S3CRET9 ssh host", "S3CRET9"},
		{"redis-cli -h db -a S3CRETA ping", "S3CRETA"},
		{`{"password": "S3CRETB"}`, "S3CRETB"},
	}
	for _, c := range cases {
		if got := Redact(c.in); strings.Contains(got, c.leak) {
			t.Errorf("Redact(%q) = %q still contains %q", c.in, got, c.leak)
		}
	}
	for _, benign := range []string{
		"nginx: worker process", "www-data ALL=(ALL) NOPASSWD:ALL", "PasswordAuthentication no",
		"Cannot read /etc/passwd: permission denied", "ssh -p 2222 host", "mkdir -p /var/tmp/x",
		"alice  uid=1000  shell=/bin/bash  password locked", "curl -fsSL https://example.com/a",
	} {
		if got := Redact(benign); got != benign {
			t.Errorf("Redact changed benign text: %q -> %q", benign, got)
		}
	}
	if got := Redact("DB_PASSWORD=hunter2 ./app"); strings.Contains(got, "hunter2") {
		t.Errorf("underscore prefixed keyword leaked: %q", got)
	}
}

func TestCleanFindingFlattensSingleLineFields(t *testing.T) {
	f := CleanFinding(Finding{
		Title:    "x\ny\x1b[31m",
		Evidence: []string{"a\nb"},
	})
	if strings.Contains(f.Title, "\n") || strings.Contains(f.Title, "\x1b") {
		t.Errorf("title not flattened: %q", f.Title)
	}
	if strings.Contains(f.Evidence[0], "\n") {
		t.Errorf("evidence not flattened: %q", f.Evidence[0])
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		name     string
		findings []Finding
		want     int
	}{
		{"clean", []Finding{{Severity: Info}, {Severity: OK}}, 0},
		{"skipped because the operator asked", []Finding{{Severity: OK}, {Severity: Skipped, Requested: true}}, 0},
		{"medium", []Finding{{Severity: Medium}}, 1},
		{"medium and a requested skip", []Finding{{Severity: Medium}, {Severity: Skipped, Requested: true}}, 1},
		{"could not check", []Finding{{Severity: OK}, {Severity: Skipped}}, 3},
		{"incomplete outranks medium", []Finding{{Severity: Medium}, {Severity: Skipped}}, 3},
		{"high outranks incomplete", []Finding{{Severity: High}, {Severity: Skipped}}, 2},
		{"critical", []Finding{{Severity: Critical}}, 2},
	}
	for _, c := range cases {
		r := Report{Findings: c.findings}
		r.Finalize()
		if got := r.ExitCode(); got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
	r := Report{Findings: []Finding{{Severity: Info}, {Severity: High}}}
	r.Finalize()
	if r.Findings[0].Severity != High {
		t.Errorf("findings not sorted by severity: %+v", r.Findings[0])
	}
}
