package dpkg

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// writeAptLists builds a lists directory like a jammy host with the deadsnakes
// PPA and PGDG added. The lz4 list is unreadable, as in Docker's images.
func writeAptLists(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("archive.ubuntu.com_ubuntu_dists_jammy-updates_InRelease", "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Ubuntu\nLabel: Ubuntu\nSuite: jammy-updates\n")
	write("archive.ubuntu.com_ubuntu_dists_jammy-updates_main_binary-amd64_Packages",
		"Package: python3.10\nVersion: 3.10.12-1~22.04.18\n\nPackage: redis-server\nVersion: 5:6.0.16-1ubuntu1.2\n\nPackage: unwanted\nVersion: 1.0\n")
	write("ppa.launchpadcontent.net_deadsnakes_ppa_ubuntu_dists_jammy_InRelease", "Origin: LP-PPA-deadsnakes\nLabel: New Python Versions\n")
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte("Package: python3.11\nVersion: 3.11.9-1+jammy1\n"))
	_ = w.Close()
	write("ppa.launchpadcontent.net_deadsnakes_ppa_ubuntu_dists_jammy_main_binary-amd64_Packages.gz", gz.String())
	write("apt.postgresql.org_pub_repos_apt_dists_jammy-pgdg_InRelease", "Origin: apt.postgresql.org\n")
	write("apt.postgresql.org_pub_repos_apt_dists_jammy-pgdg_main_binary-amd64_Packages", "Package: postgresql-16\nVersion: 16.4-1.pgdg22.04+1\n")
	write("archive.ubuntu.com_ubuntu_dists_jammy_universe_binary-amd64_Packages.lz4", "not readable here")
	return dir
}

func TestAptIndexOrigin(t *testing.T) {
	old := AptListsDir
	AptListsDir = writeAptLists(t)
	defer func() { AptListsDir = old }()
	want := map[string]bool{"python3.10": true, "python3.11": true, "postgresql-16": true, "redis-server": true, "nginx": true}
	idx := LoadAptIndex(context.Background(), want)
	if idx.Lists != 3 {
		t.Errorf("read %d lists, want 3 (the lz4 one is skipped)", idx.Lists)
	}
	cases := []struct {
		pkg, version  string
		ubuntu, known bool
	}{
		{"python3.10", "3.10.12-1~22.04.18", true, true},
		{"python3.10", "3.10.12-1~22.04.3", true, true}, // behind on updates, but only Ubuntu offers it
		{"redis-server", "5:6.0.16-1ubuntu1.2", true, true},
		{"python3.11", "3.11.9-1+jammy1", false, true},
		{"postgresql-16", "16.4-1.pgdg22.04+1", false, true},
		{"nginx", "1.18.0-6ubuntu14", false, false}, // no list offers it
		{"unwanted", "1.0", false, false},           // not asked for, so not recorded
	}
	for _, c := range cases {
		ubuntu, known := idx.Origin(c.pkg, c.version)
		if ubuntu != c.ubuntu || known != c.known {
			t.Errorf("Origin(%s, %s) = %v, %v; want %v, %v", c.pkg, c.version, ubuntu, known, c.ubuntu, c.known)
		}
	}
	var none *AptIndex
	if u, k := none.Origin("python3.10", "x"); u || k {
		t.Error("a nil index claimed to know an origin")
	}
}

func TestReleaseFor(t *testing.T) {
	dir := writeAptLists(t)
	list := filepath.Join(dir, "archive.ubuntu.com_ubuntu_dists_jammy-updates_main_binary-amd64_Packages")
	if got, want := releaseFor(list), filepath.Join(dir, "archive.ubuntu.com_ubuntu_dists_jammy-updates_InRelease"); got != want {
		t.Errorf("releaseFor = %q, want %q", got, want)
	}
	if got := releaseOrigin(releaseFor(list)); got != "Ubuntu" {
		t.Errorf("origin %q, want Ubuntu (the PGP header comes first)", got)
	}
	if got := releaseFor(filepath.Join(dir, "nowhere_main_Packages")); got != "" {
		t.Errorf("releaseFor found %q for a list with no Release file", got)
	}
}
