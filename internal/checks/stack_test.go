package checks

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"ubuntu-sys-audit/internal/dpkg"
	"ubuntu-sys-audit/internal/eol"
	"ubuntu-sys-audit/internal/model"
)

func TestStackProductsHaveEOLData(t *testing.T) {
	for _, p := range stackProducts {
		if p.id == "openjdk" {
			continue // Ubuntu's own builds, which are never judged by upstream dates
		}
		if !eol.Known(p.id) {
			t.Errorf("no end of life data for %s; add it to internal/eol/gen", p.id)
		}
	}
}

func TestStackVersion(t *testing.T) {
	cases := map[string]string{
		"5:6.0.16-1ubuntu1":         "6.0.16",
		"16.4-0ubuntu0.24.04.2":     "16.4",
		"1:10.11.6+maria~ubu2204":   "10.11.6",
		"8.0.36-1.el8":              "8.0.36",
		"jdk-21.0.2+13":             "21.0.2",
		"jdk8u392-b08":              "8",
		"1.8.0_392":                 "8.0.392",
		"v20.11.1":                  "20.11.1",
		"go1.22.0":                  "1.22.0",
		"12.22.9~dfsg-1ubuntu3.6":   "12.22.9",
		"13-alpine":                 "13",
		"7.0.15-debian-12-r3":       "7.0.15",
		"latest":                    "",
		"":                          "",
		"6:7.2.4-1rl1~jammy1":       "7.2.4",
		"16.1-1.pgdg120+1":          "16.1",
		"3.12.3-1ubuntu0.1":         "3.12.3",
		"5:24.0.7-1~ubuntu.22.04~j": "24.0.7",
	}
	for in, want := range cases {
		if got := stackVersion(in); got != want {
			t.Errorf("stackVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestImageRef(t *testing.T) {
	cases := []struct{ in, repo, tag string }{
		{"postgres:11", "postgres", "11"},
		{"docker.io/library/redis:7.2.4-alpine", "redis", "7.2.4-alpine"},
		{"localhost:5000/mysql:8.0", "mysql", "8.0"},
		{"registry.example.com:443/team/app:1", "team/app", "1"},
		{"bitnami/redis:7.0.15-debian-12-r3", "bitnami/redis", "7.0.15-debian-12-r3"},
		{"mongo@sha256:0123", "mongo", ""},
		{"mongo:7.0@sha256:0123", "mongo", "7.0"},
		{"localhost:5000/valkey", "valkey", ""},
	}
	for _, c := range cases {
		if repo, tag := imageRef(c.in); repo != c.repo || tag != c.tag {
			t.Errorf("imageRef(%q) = %q, %q; want %q, %q", c.in, repo, tag, c.repo, c.tag)
		}
	}
}

func TestContainerProducts(t *testing.T) {
	cases := []struct {
		image string
		env   []string
		want  map[string]string
	}{
		{"postgres:11", []string{"PG_MAJOR=11", "PG_VERSION=11.22-1.pgdg120+1"}, map[string]string{"postgresql": "11.22"}},
		{"myapp:1.0", []string{"NODE_VERSION=16.20.2", "YARN_VERSION=1.22.19"}, map[string]string{"nodejs": "16.20.2"}},
		{"redis:6.0", nil, map[string]string{"redis": "6.0"}},
		{"redis:latest", nil, map[string]string{"redis": ""}},
		{"bitnami/mongodb:6.0", []string{"BITNAMI_APP_NAME=mongodb", "APP_VERSION=6.0.13"}, map[string]string{"mongodb": "6.0.13"}},
		{"eclipse-temurin:17", []string{"JAVA_VERSION=jdk-17.0.9+9"}, map[string]string{"eclipse-temurin": "17.0.9"}},
		{"mariadb:10.6", []string{"MARIADB_VERSION=1:10.6.16+maria~ubu2004"}, map[string]string{"mariadb": "10.6.16"}},
		{"busybox", []string{"PATH=/bin"}, map[string]string{}},
	}
	for _, c := range cases {
		if got := containerProducts(c.image, c.env); !reflect.DeepEqual(got, c.want) {
			t.Errorf("containerProducts(%q, %q) = %v, want %v", c.image, c.env, got, c.want)
		}
	}
}

func TestStackOrigin(t *testing.T) {
	cases := []struct{ pkg, version, want string }{
		{"docker-ce", "5:24.0.7-1~ubuntu.22.04~jammy", "upstream-repo"},
		{"docker.io", "24.0.7-0ubuntu2~22.04.1", "ubuntu"},
		{"postgresql-16", "16.4-1.pgdg24.04+1", "upstream-repo"},
		{"postgresql-16", "16.4-0ubuntu0.24.04.2", "ubuntu"},
		{"redis-server", "6:7.2.4-1rl1~jammy1", "upstream-repo"},
		{"redis-server", "5:6.0.16-1ubuntu1", "ubuntu"},
		{"nodejs", "20.11.1-1nodesource1", "upstream-repo"},
		{"mariadb-server-core", "1:10.11.6+maria~ubu2204", "upstream-repo"},
		{"mysql-community-server-core", "8.0.36-1ubuntu22.04", "upstream-repo"},
		{"mongodb-org-server", "7.0.5", "upstream-repo"},
		{"python3.11", "3.11.9-1+jammy1", "third-party"},
	}
	for _, c := range cases {
		if got := stackOrigin(c.pkg, c.version); got != c.want {
			t.Errorf("stackOrigin(%q, %q) = %q, want %q", c.pkg, c.version, got, c.want)
		}
	}
}

// TestStackOriginNeedsEvidence covers the false end of life a version string
// alone gave on 22.04: Ubuntu's python3.10 is 3.10.12-1~22.04.18.
func TestStackOriginNeedsEvidence(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("ports.ubuntu.com_ubuntu-ports_dists_jammy-security_InRelease", "Origin: Ubuntu\n")
	write("ports.ubuntu.com_ubuntu-ports_dists_jammy-security_main_binary-arm64_Packages", "Package: python3.10\nVersion: 3.10.12-1~22.04.18\n")
	write("ppa.launchpadcontent.net_deadsnakes_ppa_ubuntu_dists_jammy_InRelease", "Origin: LP-PPA-deadsnakes\n")
	write("ppa.launchpadcontent.net_deadsnakes_ppa_ubuntu_dists_jammy_main_binary-arm64_Packages", "Package: python3.7\nVersion: 3.7.17-1+jammy1\n")
	old := dpkg.AptListsDir
	dpkg.AptListsDir = dir
	defer func() { dpkg.AptListsDir = old }()
	idx := dpkg.LoadAptIndex(context.Background(), map[string]bool{"python3.10": true, "python3.7": true})

	with, without := &stackCollector{apt: idx}, &stackCollector{}
	cases := []struct {
		s            *stackCollector
		pkg, version string
		source       string
		confirmed    bool
	}{
		{with, "python3.10", "3.10.12-1~22.04.18", "ubuntu", true},
		{with, "python3.7", "3.7.17-1+jammy1", "third-party", true},
		{without, "python3.10", "3.10.12-1~22.04.18", "third-party", false},
		{without, "python3.12", "3.12.3-1ubuntu0.1", "ubuntu", true},
		{without, "postgresql-16", "16.4-1.pgdg24.04+1", "upstream-repo", true},
	}
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	for _, c := range cases {
		source, confirmed := c.s.origin(c.pkg, c.version)
		if source != c.source || confirmed != c.confirmed {
			t.Errorf("origin(%s, %s) = %s, %v; want %s, %v", c.pkg, c.version, source, confirmed, c.source, c.confirmed)
		}
		e := &stackEntry{StackItem: model.StackItem{Product: "python", Version: stackVersion(c.version), Source: source}, unconfirmed: !confirmed}
		judgeStack(e, now)
		if !confirmed && e.Status != "unknown" {
			t.Errorf("%s from an unconfirmed source was judged %q", c.pkg, e.Status)
		}
	}
}

func TestStackPackageNames(t *testing.T) {
	cases := map[string]string{
		"postgresql-16": "postgresql", "postgresql-9.5": "postgresql", "postgresql-client-16": "",
		"mysql-server-core-8.0": "mysql", "mysql-community-server-core": "mysql", "mysql-client-8.0": "",
		"mariadb-server-core-10.6": "mariadb", "mariadb-server-core": "mariadb", "mariadb-server": "mariadb",
		"redis-server": "redis", "redis-tools": "", "valkey-server": "valkey",
		"mongodb-org-server": "mongodb", "mongodb-org-shell": "",
		"libsqlite3-0": "sqlite", "sqlite3": "sqlite", "nodejs": "nodejs",
		"python3.12": "python", "python3.12-minimal": "python", "python3-pip": "", "python3": "",
		"ruby3.0": "ruby", "php8.1-fpm": "php", "php8.1-common": "", "golang-1.22-go": "go",
		"openjdk-17-jre-headless": "openjdk", "temurin-21-jdk": "eclipse-temurin",
		"nginx-core": "nginx", "apache2-bin": "apache-http-server", "haproxy": "haproxy",
		"docker-ce": "docker-engine", "containerd.io": "containerd",
	}
	for pkg, want := range cases {
		got := ""
		for _, p := range stackProducts {
			if p.pkg != nil && p.pkg.MatchString(pkg) {
				got = p.id
				break
			}
		}
		if got != want {
			t.Errorf("package %s is product %q, want %q", pkg, got, want)
		}
	}
}

func TestJavaVendor(t *testing.T) {
	cases := map[string]string{
		"Eclipse Adoptium": "eclipse-temurin", "17.0.9-tem": "eclipse-temurin", "temurin-17.0.9+9": "eclipse-temurin",
		"zulu-17.46.19": "azul-zulu", "Azul Systems, Inc.": "azul-zulu", "Amazon.com Inc.": "amazon-corretto",
		"11.0.22-amzn": "amazon-corretto", "21.0.2-oracle": "oracle-jdk", "21.0.2-open": "openjdk-builds-from-oracle",
		"Ubuntu": "openjdk", "Private Build": "openjdk",
	}
	for in, want := range cases {
		if got := javaVendor(in); got != want {
			t.Errorf("javaVendor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJudgeStack(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	entry := func(product, version, source string) *stackEntry {
		return &stackEntry{StackItem: model.StackItem{Product: product, Version: version, Source: source}}
	}
	cases := []struct {
		e             *stackEntry
		status, cycle string
	}{
		{entry("postgresql", "11.22", "upstream-repo"), "eol", "11"},
		{entry("postgresql", "11.22", "ubuntu"), "ubuntu", "11"},
		{entry("postgresql", "18.1", "container"), "supported", "18"},
		{entry("postgresql", "", "unpackaged"), "unknown", ""},
		{entry("postgresql", "99.1", "unpackaged"), "unknown", ""},
		{entry("openjdk", "17.0.9", "unpackaged"), "unknown", ""},
	}
	for _, c := range cases {
		judgeStack(c.e, now)
		if c.e.Status != c.status || c.e.Cycle != c.cycle {
			t.Errorf("%s %s from %s: status %q cycle %q, want %q %q", c.e.Product, c.e.Version, c.e.Source, c.e.Status, c.e.Cycle, c.status, c.cycle)
		}
	}
	ubuntu := entry("postgresql", "11.22", "ubuntu")
	judgeStack(ubuntu, now)
	if ubuntu.EOL != "" {
		t.Errorf("an Ubuntu package carries an upstream end of life date %q", ubuntu.EOL)
	}
}

func TestStackEOLFindings(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	mk := func(product, version, source string, exposed bool) *stackEntry {
		e := &stackEntry{StackItem: model.StackItem{Product: product, Name: stackByID[product].name, Version: version, Source: source, Exposed: exposed, Container: "c1", Image: "x"}}
		judgeStack(e, now)
		return e
	}
	entries := []*stackEntry{
		mk("nodejs", "16.20.2", "version-manager", false),
		mk("nodejs", "14.21.3", "version-manager", false),
		mk("postgresql", "11.22", "container", true),
		mk("postgresql", "11.22", "ubuntu", true),
		mk("php", "7.4.33", "unpackaged", true), // web.php reports PHP
		mk("redis", "8.10.1", "container", false),
	}
	byTitle := map[string]model.Finding{}
	for _, f := range stackEOLFindings(entries, now) {
		byTitle[f.Title] = f
	}
	node, ok := byTitle["Node.js 14 and 16 are past end of life"]
	if !ok || node.Severity != model.Medium || len(node.Evidence) != 2 {
		t.Errorf("Node.js finding: %+v (all: %v)", node, keys(byTitle))
	}
	pg, ok := byTitle["PostgreSQL 11 is past end of life"]
	if !ok || pg.Severity != model.High || len(pg.Evidence) != 1 || !strings.Contains(pg.Remediation, "image tag") {
		t.Errorf("PostgreSQL finding: %+v", pg)
	}
	for title := range byTitle {
		if strings.Contains(title, "PHP") || strings.Contains(title, "Redis") {
			t.Errorf("unexpected finding %q", title)
		}
	}
}

func keys(m map[string]model.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDirsUnder(t *testing.T) {
	home := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(home, ".nvm/versions/node/v16.20.2"), 0o755))
	must(os.MkdirAll(filepath.Join(home, ".nvm/versions/node/v20.11.1"), 0o755))
	must(os.WriteFile(filepath.Join(home, ".nvm/versions/node/notes.txt"), nil, 0o644))
	other := t.TempDir()
	must(os.MkdirAll(filepath.Join(other, "secret-dir"), 0o755))
	must(os.Symlink(filepath.Join(other, "secret-dir"), filepath.Join(home, ".nvm/versions/node/v99.0.0")))
	_, got := dirsUnder(home, ".nvm/versions/node")
	if want := []string{"v16.20.2", "v20.11.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("dirsUnder = %v, want %v", got, want)
	}
	// A symlinked component points the walk somewhere else, so it stops.
	must(os.MkdirAll(filepath.Join(home, "real/versions"), 0o755))
	must(os.Symlink(other, filepath.Join(home, "real/versions/node")))
	must(os.Symlink(filepath.Join(home, "real"), filepath.Join(home, ".pyenv")))
	if _, got := dirsUnder(home, ".pyenv/versions"); got != nil {
		t.Errorf("followed a symlinked component: %v", got)
	}
}

// TestStackScanPatterns uses the bytes around the version in the official
// builds of each product, as copied out of their Docker images.
func TestStackScanPatterns(t *testing.T) {
	cases := []struct {
		id, data, want string
	}{
		{"postgresql", "PostgreSQL 16.2 on x86_64-pc-linux-musl, compiled by gcc", "16.2"},
		{"mysql", "/export/home/pb2/build/sb_0-123/mysql-8.0.36/sql/sql_parse.cc", "8.0.36"},
		{"mariadb", "for example 10.1.1-MariaDB-mariadb1precise-log.\x00x\x001:11.2.3+maria~ubu2204\x0011.2.3-MariaDB\x00\x00", "11.2.3"},
		{"redis", "waiting-for-sync\x00\x00server\x00%llx\x00\x00\x007.2.4\x00\x00\x00# Server\r\nredis_version:%s", "7.2.4"},
		{"redis", "SDS_NOINIT\x00\x007.2.4buildkitsandbox-1715987884000000000\x00", "7.2.4"},
		{"valkey", "sync\x00valkey8.0.1buildkitsandbox-1727908583000000000\x00", "8.0.1"},
		// Debian's reproducible builds leave out the build host.
		{"redis", "UINT32_MAX\x00prevlen\x00\x006.0.161790840090000000000\x00jemalloc-5.2.1", "6.0.16"},
		{"valkey", "x\x00valkey9.0.41789450523000000000\x00", "9.0.4"},
		{"nodejs", "https://nodejs.org/download/release/v20.11.1/node-v20.11.1-headers.tar.gz", "20.11.1"},
		{"apache-http-server", "Apache/2.4.58 (Unix)", "2.4.58"},
		{"haproxy", "HAProxy version 2.9.4-4e071ad, released 2024/01/31", "2.9.4"},
	}
	for _, c := range cases {
		got := ""
		for _, re := range stackByID[c.id].scan {
			if m := re.FindStringSubmatch(c.data); m != nil {
				got = m[1]
				break
			}
		}
		if got != c.want {
			t.Errorf("%s: scan found %q, want %q", c.id, got, c.want)
		}
	}
	// Valkey keeps a Redis compatibility version before the INFO header,
	// which is why processVersion tries Valkey's pattern first.
	valkey := "valkey8.0.1buildkitsandbox-1727908583000000000\x00\x008.0.1\x00\x007.2.4\x00\x00# Server\r\nredis_version:%s"
	if m := stackByID["valkey"].scan[0].FindStringSubmatch(valkey); m == nil || m[1] != "8.0.1" {
		t.Errorf("Valkey's binary is not recognized: %v", m)
	}
}

func TestStackLine(t *testing.T) {
	e := &stackEntry{StackItem: model.StackItem{
		Name: "PostgreSQL", Version: "16.4", Source: "ubuntu", Package: "postgresql-16",
		Running: true, Listen: []string{"127.0.0.1:5432"}, Status: "ubuntu",
	}}
	want := "PostgreSQL 16.4  Ubuntu package postgresql-16, running, listening on 127.0.0.1:5432, judged by Ubuntu's security updates, not upstream dates"
	if got := e.line(); got != want {
		t.Errorf("line =\n%q\nwant\n%q", got, want)
	}
	c := &stackEntry{StackItem: model.StackItem{
		Name: "Redis", Source: "container", Container: "cache", Image: "redis:latest",
		Running: true, Exposed: true, Listen: []string{"0.0.0.0:6379"}, Status: "unknown",
	}}
	if got := c.line(); got != "Redis (version unknown)  container cache (redis:latest), running, published on 0.0.0.0:6379" {
		t.Errorf("container line = %q", got)
	}
}
