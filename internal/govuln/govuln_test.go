package govuln

import (
	"archive/zip"
	"bytes"
	"os"
	"reflect"
	"testing"
)

func buildDB(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var testFiles = map[string]string{
	"index/db.json": `{"modified":"2026-10-27T21:16:18Z"}`,
	"index/modules.json": `[
		{"path":"github.com/caddyserver/caddy/v2","vulns":[{"id":"GO-1"},{"id":"GO-2"},{"id":"GO-3"},{"id":"GO-4"}]},
		{"path":"stdlib","vulns":[{"id":"GO-10"},{"id":"GO-10"},{"id":"GO-11"},{"id":"GO-12"},{"id":"GO-13"}]}
	]`,
	"ID/GO-1.json": `{"id":"GO-1","aliases":["CVE-2026-1","GHSA-a"],"summary":"one","affected":[
		{"package":{"name":"github.com/caddyserver/caddy/v2"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.11.4"}]}]}]}`,
	"ID/GO-2.json": `{"id":"GO-2","summary":"two spans","affected":[
		{"package":{"name":"github.com/caddyserver/caddy/v2"},"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"2.6.5"},{"introduced":"2.7.0-beta.1"},{"fixed":"2.7.2"}]}]}]}`,
	"ID/GO-3.json": `{"id":"GO-3","summary":"withdrawn","withdrawn":"2026-01-01T00:00:00Z","affected":[
		{"package":{"name":"github.com/caddyserver/caddy/v2"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	"ID/GO-4.json": `{"id":"GO-4","summary":"no fix yet","affected":[
		{"package":{"name":"other/module"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]},
		{"package":{"name":"github.com/caddyserver/caddy/v2"},"ranges":[{"type":"SEMVER","events":[{"introduced":"2.10.0"}]}]}]}`,
	"ID/GO-10.json": `{"id":"GO-10","summary":"net/http","affected":[
		{"package":{"name":"stdlib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.26.10"},{"introduced":"1.27.0-0"},{"fixed":"1.27.3"}]}],"ecosystem_specific":{"imports":[{"path":"net/http"}]}},
		{"package":{"name":"stdlib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.26.10"}]}],"ecosystem_specific":{"imports":[{"path":"net/http/internal/http2"}]}}]}`,
	"ID/GO-11.json": `{"id":"GO-11","summary":"windows only","affected":[
		{"package":{"name":"stdlib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}],"ecosystem_specific":{"imports":[{"path":"os","goos":["windows"]},{"path":"internal/syscall/windows","goos":["windows"]}]}}]}`,
	"ID/GO-12.json": `{"id":"GO-12","summary":"linux or windows","affected":[
		{"package":{"name":"stdlib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}],"ecosystem_specific":{"imports":[{"path":"os","goos":["windows"]},{"path":"syscall","goos":["linux"]}]}}]}`,
	"ID/GO-13.json": `{"id":"GO-13","summary":"other arch","affected":[
		{"package":{"name":"stdlib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}],"ecosystem_specific":{"imports":[{"path":"crypto/x","goos":["linux"],"goarch":["ppc64le"]}]}}]}`,
}

func ids(entries []Entry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.ID+"@"+e.Fixed)
	}
	return out
}

func TestMatch(t *testing.T) {
	db, err := Open(buildDB(t, testFiles))
	if err != nil {
		t.Fatal(err)
	}
	if db.Modified != "2026-10-27T21:16:18Z" {
		t.Errorf("modified: %q", db.Modified)
	}
	cases := []struct {
		module, version string
		want            []string
	}{
		{"github.com/caddyserver/caddy/v2", "2.6.4", []string{"GO-1@2.11.4", "GO-2@2.6.5"}},
		{"github.com/caddyserver/caddy/v2", "2.6.5", []string{"GO-1@2.11.4"}},
		{"github.com/caddyserver/caddy/v2", "2.7.0-beta.1", []string{"GO-1@2.11.4", "GO-2@2.7.2"}},
		{"github.com/caddyserver/caddy/v2", "2.7.0-alpha.1", []string{"GO-1@2.11.4"}},
		{"github.com/caddyserver/caddy/v2", "2.10.2", []string{"GO-1@2.11.4", "GO-4@"}},
		{"github.com/caddyserver/caddy/v2", "2.11.7", []string{"GO-4@"}},
		{Stdlib, "1.26.8", []string{"GO-10@1.26.10", "GO-12@"}},
		{Stdlib, "1.26.10", []string{"GO-12@"}},
		{Stdlib, "1.27.0-rc.1", []string{"GO-10@1.27.3", "GO-12@"}},
		{Stdlib, "1.27.3", []string{"GO-12@"}},
		{"unknown/module", "1.0.0", nil},
	}
	for _, c := range cases {
		got, err := db.Match(c.module, c.version)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(ids(got), c.want) {
			t.Errorf("%s %s: got %v, want %v", c.module, c.version, ids(got), c.want)
		}
	}
	got, _ := db.Match("github.com/caddyserver/caddy/v2", "2.6.4")
	if got[0].Summary != "one" || !reflect.DeepEqual(got[0].Aliases, []string{"CVE-2026-1", "GHSA-a"}) || got[0].Version != "2.6.4" {
		t.Errorf("entry fields: %+v", got[0])
	}
}

func TestOpenRejectsBadData(t *testing.T) {
	if _, err := Open([]byte("not a zip")); err == nil {
		t.Error("a non zip must fail")
	}
	if _, err := Open(buildDB(t, map[string]string{"index/db.json": `{}`})); err == nil {
		t.Error("a zip without the module index must fail")
	}
	if _, err := Open(buildDB(t, map[string]string{"index/db.json": `{}`, "index/modules.json": `[]`})); err == nil {
		t.Error("an empty index must fail, or every check would pass")
	}
}

func TestCompare(t *testing.T) {
	ordered := []string{"0", "0.0.0-20240101000000-abcdef", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0"}
	for i := range ordered {
		for j := range ordered {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := Compare(ordered[i], ordered[j]); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	if Compare("1.27.0-0", "1.27.0-rc.1") != -1 {
		t.Error("the database opens a Go release with -0, which must come before its release candidates")
	}
}

func TestGoVersion(t *testing.T) {
	cases := map[string]string{
		"go1.26.8":                "1.26.8",
		"go1.21":                  "1.21.0",
		"go1.22rc1":               "1.22.0-rc.1",
		"go1.23beta2":             "1.23.0-beta.2",
		"go1.25.0 X:boringcrypto": "1.25.0",
		"devel go1.27-abcdef":     "",
		"":                        "",
		"gox":                     "",
	}
	for in, want := range cases {
		if got := GoVersion(in); got != want {
			t.Errorf("GoVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestModuleVersion(t *testing.T) {
	cases := map[string]string{
		"v2.11.7":                            "2.11.7",
		"v0.0.0-20240101000000-abcdef123456": "0.0.0-20240101000000-abcdef123456",
		"v2.0.0+incompatible":                "2.0.0",
		"(devel)":                            "",
		"":                                   "",
		"vX":                                 "",
	}
	for in, want := range cases {
		if got := ModuleVersion(in); got != want {
			t.Errorf("ModuleVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRealDB runs against a downloaded vulndb.zip when GOVULN_ZIP is set.
func TestRealDB(t *testing.T) {
	path := os.Getenv("GOVULN_ZIP")
	if path == "" {
		t.Skip("GOVULN_ZIP not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(b)
	if err != nil {
		t.Fatal(err)
	}
	old, err := db.Match("github.com/caddyserver/caddy/v2", "2.6.4")
	if err != nil {
		t.Fatal(err)
	}
	std, _ := db.Match(Stdlib, "1.20.1")
	t.Logf("database %s: caddy 2.6.4 has %d entries, Go 1.20.1 has %d", db.Modified, len(old), len(std))
	if len(old) == 0 || len(std) == 0 {
		t.Error("an old Caddy and an old Go must match real entries")
	}
}
