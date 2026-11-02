package checks

import (
	"os"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"ubuntu-sys-audit/internal/govuln"
	"ubuntu-sys-audit/internal/model"
)

func TestParseCaddyfile(t *testing.T) {
	src := strings.Join([]string{
		"# admin 0.0.0.0:2019 in a comment",
		"{",
		"\temail ops@example.com",
		"\tadmin 0.0.0.0:2019",
		"\tservers {",
		"\t\tadmin :9999",
		"\t}",
		"}",
		"",
		"(common) {",
		"\troot * /srv/snippet",
		"}",
		"",
		"example.com {",
		"\troot * /srv/example # trailing comment",
		"\tfile_server",
		"\timport common",
		"}",
		"",
		"files.example.com {",
		"\troot \"/srv/with space\"",
		"\tfile_server {",
		"\t\tbrowse",
		"\t}",
		"\trespond <<EOF",
		"\t\troot /not/a/directive",
		"\t\tEOF",
		"\troot @api /srv/api",
		"}",
		"import sites/*.caddy",
	}, "\n")
	cfg, imports := parseCaddyfile(src)
	wantRoots := []string{"/srv/snippet", "/srv/example", "/srv/with space", "/srv/api"}
	if !reflect.DeepEqual(cfg.Roots, wantRoots) {
		t.Errorf("roots: got %q, want %q", cfg.Roots, wantRoots)
	}
	if !reflect.DeepEqual(cfg.Admin, []string{"0.0.0.0:2019"}) {
		t.Errorf("admin: %q", cfg.Admin)
	}
	if !cfg.Browse {
		t.Error("browse inside a file_server block was missed")
	}
	if !reflect.DeepEqual(imports, []string{"common", "sites/*.caddy"}) {
		t.Errorf("imports: %q", imports)
	}

	inline, _ := parseCaddyfile(":8080 {\n\tfile_server browse\n}\n")
	if !inline.Browse || len(inline.Admin) != 0 {
		t.Errorf("inline browse: %+v", inline)
	}
	// A site block, not global options: no address on the line.
	notGlobal, _ := parseCaddyfile("localhost {\n\tadmin 0.0.0.0:2019\n}\n")
	if len(notGlobal.Admin) != 0 {
		t.Errorf("admin is a global option only: %+v", notGlobal)
	}
	plain, _ := parseCaddyfile("example.com\nroot * /srv/plain\nfile_server\n")
	if !reflect.DeepEqual(plain.Roots, []string{"/srv/plain"}) || plain.Browse {
		t.Errorf("a Caddyfile without braces: %+v", plain)
	}
}

func TestParseCaddyJSON(t *testing.T) {
	src := `{"admin":{"listen":"0.0.0.0:2019"},"apps":{"http":{"servers":{"srv0":{"listen":[":8088"],"routes":[
		{"handle":[{"handler":"vars","root":"/srv/e2e-site"},{"browse":{},"handler":"file_server"}]},
		{"handle":[{"handler":"reverse_proxy","transport":{"protocol":"fastcgi","root":"/srv/php"}}]}]}}}}}`
	cfg, err := parseCaddyJSON([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.Roots, []string{"/srv/e2e-site", "/srv/php"}) || !cfg.Browse || !reflect.DeepEqual(cfg.Admin, []string{"0.0.0.0:2019"}) {
		t.Errorf("got %+v", cfg)
	}
	off, _ := parseCaddyJSON([]byte(`{"admin":{"disabled":true,"listen":"0.0.0.0:2019"}}`))
	if !reflect.DeepEqual(off.Admin, []string{"off"}) {
		t.Errorf("a disabled admin API listens nowhere: %+v", off)
	}
	none, _ := parseCaddyJSON([]byte(`{"apps":{"http":{"servers":{"s":{"routes":[{"handle":[{"handler":"file_server"}]}]}}}}}`))
	if none.Browse || len(none.Admin) != 0 {
		t.Errorf("defaults: %+v", none)
	}
	if _, err := parseCaddyJSON([]byte("example.com {\n}\n")); err == nil {
		t.Error("a Caddyfile is not JSON")
	}
}

func TestAdminExposed(t *testing.T) {
	exposed := []string{"0.0.0.0:2019", ":2019", "10.0.0.5:2019", "[::]:2019", "tcp/0.0.0.0:2019", "admin.example.com:2019"}
	for _, a := range exposed {
		if !adminExposed(a) {
			t.Errorf("%s is reachable from other hosts", a)
		}
	}
	local := []string{"", "off", "localhost:2019", "127.0.0.1:2019", "[::1]:2019", "unix//run/caddy-admin.sock", "{$ADMIN_ADDR}", "localhost"}
	for _, a := range local {
		if adminExposed(a) {
			t.Errorf("%s is not reachable from other hosts", a)
		}
	}
}

func TestCaddyFromBuild(t *testing.T) {
	xcaddy := &debug.BuildInfo{
		GoVersion: "go1.26.8",
		Main:      debug.Module{Path: "caddy", Version: "(devel)"},
		Deps: []*debug.Module{
			{Path: "github.com/caddyserver/caddy/v2", Version: "v2.11.7"},
			{Path: "github.com/caddyserver/certmagic", Version: "v0.25.6"},
			{Path: "github.com/caddy-dns/cloudflare", Version: "v0.2.1"},
			{Path: "github.com/greenpau/caddy-security", Version: "v1.1.29"},
			{Path: "github.com/mholt/caddy-l4", Version: "v0.0.0-20250102174933-6e5f5e311ead", Replace: &debug.Module{Path: "../caddy-l4"}},
			{Path: "golang.org/x/net", Version: "v0.45.0"},
			{Path: "github.com/quic-go/quic-go", Version: "v0.55.0", Replace: &debug.Module{Path: "github.com/quic-go/quic-go", Version: "v0.55.1"}},
		},
	}
	inst, ok := caddyFromBuild(xcaddy)
	if !ok || inst.Version != "2.11.7" || inst.Go != "go1.26.8" {
		t.Fatalf("xcaddy build: %+v", inst)
	}
	wantPlugins := []string{"github.com/caddy-dns/cloudflare v0.2.1", "github.com/greenpau/caddy-security v1.1.29", "github.com/mholt/caddy-l4 replaced by ../caddy-l4"}
	if !reflect.DeepEqual(inst.Plugins, wantPlugins) {
		t.Errorf("plugins: %q", inst.Plugins)
	}
	if _, kept := inst.Modules["github.com/mholt/caddy-l4"]; kept {
		t.Error("a module replaced by a local copy has no version to match")
	}
	if inst.Modules["github.com/quic-go/quic-go"] != "0.55.1" || inst.Modules["golang.org/x/net"] != "0.45.0" {
		t.Errorf("modules: %v", inst.Modules)
	}

	// What Ubuntu's caddy package records: the main package and nothing else.
	ubuntu := &debug.BuildInfo{GoVersion: "go1.22.2", Path: "github.com/caddyserver/caddy/v2/cmd/caddy"}
	if inst, ok := caddyFromBuild(ubuntu); !ok || inst.Version != "" || len(inst.Plugins) != 0 {
		t.Errorf("Ubuntu's build has no module versions: %+v %v", inst, ok)
	}
	other := &debug.BuildInfo{GoVersion: "go1.26.8", Main: debug.Module{Path: "example.com/caddy-helper"}, Deps: []*debug.Module{{Path: "github.com/caddyserver/certmagic", Version: "v0.25.6"}}}
	if _, ok := caddyFromBuild(other); ok {
		t.Error("a program that only uses certmagic is not Caddy")
	}
}

func TestCaddyPackageOrigin(t *testing.T) {
	cases := map[string]string{
		"2.6.2-6ubuntu0.24.04.3": "ubuntu",
		"2.6.2-14":               "ubuntu",
		"2.11.7":                 "upstream-repo",
	}
	for v, want := range cases {
		if got := caddyPackageOrigin(v); got != want {
			t.Errorf("%s: got %s, want %s", v, got, want)
		}
	}
}

func TestReadBuildInfoReadsWithoutRunning(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	info, err := readBuildInfo(exe)
	if err != nil || !strings.HasPrefix(info.GoVersion, "go") {
		t.Fatalf("the test binary is a Go binary: %v %+v", err, info)
	}
	if _, err := readBuildInfo("/dev/null"); err == nil {
		t.Error("a device is refused before it is opened")
	}
}

func TestCaddyVulnFinding(t *testing.T) {
	core := govuln.Entry{ID: "GO-2026-6512", Aliases: []string{"GHSA-j8px-rmrx-76h9", "CVE-2026-77281"}, Summary: "placeholder layer", Module: caddyModule, Version: "2.6.4", Fixed: "2.11.4"}
	plugin := govuln.Entry{ID: "GO-2025-3000", Summary: "auth bypass", Module: "github.com/greenpau/caddy-security", Version: "1.1.0"}
	std := govuln.Entry{ID: "GO-2026-0001", Aliases: []string{"CVE-2026-0001"}, Summary: "net/http", Module: govuln.Stdlib, Version: "1.20.1", Fixed: "1.20.5"}
	dep := govuln.Entry{ID: "GO-2025-0002", Summary: "quic", Module: "github.com/quic-go/quic-go", Version: "0.40.0", Fixed: "0.42.0"}
	built := caddyInstance{Version: "2.6.4", Go: "go1.20.1", Origin: "compiled", Plugins: []string{"github.com/greenpau/caddy-security v1.1.0", "github.com/x/caddy-local replaced by ../local"}}

	f := caddyVulnFinding(built, []govuln.Entry{core, plugin}, []govuln.Entry{dep}, []govuln.Entry{std}, "2026-10-27")
	if f.Severity != model.High || f.Title != "caddy 2.6.4 (self-compiled) has known vulnerabilities: 2 in Caddy and its plugins, 1 in go1.20.1, 1 in other modules" {
		t.Errorf("got [%v] %s", f.Severity, f.Title)
	}
	wantEvidence := []string{
		"GO-2026-6512 (CVE-2026-77281)  github.com/caddyserver/caddy/v2 2.6.4, fixed in 2.11.4: placeholder layer",
		"GO-2025-3000  github.com/greenpau/caddy-security 1.1.0, no fix yet: auth bypass",
		"GO-2026-0001 (CVE-2026-0001)  Go standard library 1.20.1, fixed in 1.20.5: net/http",
		"GO-2025-0002  github.com/quic-go/quic-go 0.40.0, fixed in 0.42.0: quic",
	}
	if !reflect.DeepEqual(f.Evidence, wantEvidence) {
		t.Errorf("evidence:\n got %q\nwant %q", f.Evidence, wantEvidence)
	}
	if f.Remediation != "Rebuild with the latest Caddy and Go: xcaddy build --with github.com/greenpau/caddy-security, then replace the binary and restart Caddy." {
		t.Errorf("remediation: %s", f.Remediation)
	}
	if f.Refs[0] != "https://pkg.go.dev/vuln/GO-2026-6512" {
		t.Errorf("refs: %q", f.Refs)
	}

	goOnly := caddyVulnFinding(caddyInstance{Version: "2.11.7", Go: "go1.26.8", Origin: "upstream-repo"}, nil, nil, []govuln.Entry{std}, "x")
	if goOnly.Severity != model.Medium || !strings.Contains(goOnly.Title, "(Caddy's apt repository)") || !strings.HasPrefix(goOnly.Remediation, "sudo apt update") {
		t.Errorf("Go only: [%v] %s / %s", goOnly.Severity, goOnly.Title, goOnly.Remediation)
	}
	if !strings.Contains(goOnly.Remediation, "the rest clear with the next Caddy release") || slices.Contains(goOnly.Refs, caddyCustomBuildDoc) {
		t.Errorf("Go only remediation: %s / %q", goOnly.Remediation, goOnly.Refs)
	}

	// An xcaddy build copied over /usr/bin/caddy can have the package's version,
	// but apt would overwrite it, so the advice must not be an apt upgrade.
	over := caddyInstance{Version: "2.11.7", Go: "go1.26.4", Origin: "compiled", Replaced: "/usr/bin/caddy", Plugins: []string{"github.com/caddy-dns/cloudflare v0.2.1"}}
	o := caddyVulnFinding(over, nil, nil, []govuln.Entry{std}, "x")
	if o.Title != "caddy 2.11.7 (replaces the packaged binary) has known vulnerabilities: 1 in go1.26.4" {
		t.Errorf("replaced title: %s", o.Title)
	}
	if !strings.HasPrefix(o.Remediation, "Rebuild with the latest Caddy and Go: xcaddy build --with github.com/caddy-dns/cloudflare, then") ||
		!strings.Contains(o.Remediation, "replaced /usr/bin/caddy from the caddy package, by a copy or by caddy upgrade or add-package, so the next apt upgrade of caddy puts the stock build back") ||
		strings.Contains(o.Remediation, "--only-upgrade") || !slices.Contains(o.Refs, caddyCustomBuildDoc) {
		t.Errorf("replaced remediation: %s / %q", o.Remediation, o.Refs)
	}
	over.Plugins = nil
	if r := caddyVulnFinding(over, nil, nil, []govuln.Entry{std}, "x").Remediation; !strings.HasPrefix(r, "Rebuild with the latest Caddy and Go using xcaddy") || !strings.Contains(r, "sudo apt install --reinstall caddy") {
		t.Errorf("replaced without plugins: %s", r)
	}
	if l := caddyLabel(over); !strings.Contains(l, "[replaces the packaged binary]") {
		t.Errorf("label: %s", l)
	}

	clean := caddyVulnFinding(caddyInstance{Version: "2.11.7", Go: "go1.26.10", Origin: "container"}, nil, nil, nil, "x")
	if clean.Severity != model.OK || !strings.Contains(clean.Title, "no known vulnerabilities") {
		t.Errorf("clean: [%v] %s", clean.Severity, clean.Title)
	}
	for _, g := range []model.Finding{f, goOnly, o, clean} {
		if containsHan(g.Title + g.Detail + g.Remediation) {
			t.Errorf("text must be English: %s", g.Title)
		}
	}
}

func TestCaddyConfigFindings(t *testing.T) {
	got := caddyConfigFindings([]caddyConfig{
		{Path: "/etc/caddy/Caddyfile", Admin: []string{"0.0.0.0:2019"}, Browse: true},
		{Path: "/var/lib/caddy/.config/caddy/autosave.json", Admin: []string{"0.0.0.0:2019"}},
		{Path: "/etc/caddy/local.caddy", Admin: []string{"localhost:2019"}},
	})
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].ID != "web.caddy.admin" || got[0].Severity != model.High || len(got[0].Evidence) != 2 {
		t.Errorf("admin: %+v", got[0])
	}
	if got[1].ID != "web.caddy.browse" || got[1].Severity != model.Medium || !reflect.DeepEqual(got[1].Evidence, []string{"/etc/caddy/Caddyfile"}) {
		t.Errorf("browse: %+v", got[1])
	}
	if got := caddyConfigFindings([]caddyConfig{{Path: "x", Admin: []string{"off"}}}); len(got) != 0 {
		t.Errorf("a safe configuration reports nothing: %+v", got)
	}
}

func TestCaddyAdminPortIsRisky(t *testing.T) {
	if r, ok := riskyPorts[2019]; !ok || r.sev != model.Critical {
		t.Errorf("port 2019: %+v", r)
	}
}

func TestCaddyReplaced(t *testing.T) {
	// No md5sums exist here, so only the version can tell.
	cases := []struct {
		version, pkg string
		want         bool
	}{
		{"2.11.7", "2.10.2", true}, // caddy upgrade over the 2.10.2 package
		{"2.11.7", "2.11.7", false},
		{"2.6.2", "2.6.2-6ubuntu0.24.04.3", false},
		{"", "2.6.2-14", false}, // Ubuntu's build records no version
		{"2.11.0-beta.2", "2.11.0~beta.2", false},
		{"2.11.7", "1:2.10.2-1", true},
	}
	for _, c := range cases {
		if got := caddyReplaced(c.version, c.pkg, "/nonexistent/caddy", "/nonexistent/caddy"); got != c.want {
			t.Errorf("caddyReplaced(%q, %q) = %v, want %v", c.version, c.pkg, got, c.want)
		}
	}
}
