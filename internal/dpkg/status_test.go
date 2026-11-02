package dpkg

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

const statusSample = `Package: nginx-core
Status: install ok installed
Priority: optional
Architecture: amd64
Source: nginx (1.18.0-6ubuntu14.4)
Version: 1.18.0-6ubuntu14.4
Description: x
 continuation line Status: deinstall ok config-files

Package: oldthing
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0-1

Package: heldpkg
Status: hold ok installed
Architecture: all
Version: 2.0-1

Package: half
Status: install ok half-configured
Architecture: all
Version: 3.0-1
`

func TestParseStatus(t *testing.T) {
	got := ParseStatus([]byte(statusSample))
	if len(got) != 2 {
		t.Fatalf("want 2 installed packages, got %d: %+v", len(got), got)
	}
	if got[0].Name != "nginx-core" || got[0].Source != "nginx" || got[0].Version != "1.18.0-6ubuntu14.4" || got[0].Held {
		t.Errorf("nginx-core parsed wrong: %+v", got[0])
	}
	if got[1].Name != "heldpkg" || !got[1].Held || got[1].Source != "heldpkg" {
		t.Errorf("heldpkg parsed wrong: %+v", got[1])
	}
}

func TestOrigin(t *testing.T) {
	cases := map[string]string{
		"1.18.0-6ubuntu14.4":                    "ubuntu",
		"8.3.6-0ubuntu0.24.04.3":                "ubuntu",
		"8.3.12-1+ubuntu24.04.1+deb.sury.org+1": "ondrej-ppa",
		"1.26.2-1~jammy":                        "upstream-repo",
		"1.2.3-4":                               "third-party",
		"2.0.0-0build1":                         "ubuntu",
		"1.24.0-1ubuntu1~ppa1":                  "third-party",
	}
	for in, want := range cases {
		if got := Origin(in); got != want {
			t.Errorf("Origin(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"/bin/ls":              "/usr/bin/ls",
		"/sbin/init":           "/usr/sbin/init",
		"/lib/systemd/systemd": "/usr/lib/systemd/systemd",
		"/usr/bin/ls":          "/usr/bin/ls",
		"/opt/x/bin/y":         "/opt/x/bin/y",
		"/binary":              "/binary",
	}
	for in, want := range cases {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeSystem builds a filesystem and dpkg database for Verify. Every file in
// files is listed in md5sums with its current content, so tests then change the
// disk to simulate tampering.
func fakeSystem(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	oldRoot, oldInfo := fsRoot, infoDir
	fsRoot, infoDir = root, filepath.Join(root, "info")
	t.Cleanup(func() { fsRoot, infoDir = oldRoot, oldInfo })
	if err := os.MkdirAll(infoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var sums []byte
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
		h := md5.Sum([]byte(content))
		sums = append(sums, []byte(hex.EncodeToString(h[:])+"  "+rel+"\n")...)
	}
	if err := os.WriteFile(filepath.Join(infoDir, "pkg.md5sums"), sums, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func verifyAll(t *testing.T) VerifyResult {
	t.Helper()
	res, err := Verify(context.Background(), nil, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestVerifyCleanSystem(t *testing.T) {
	fakeSystem(t, map[string]string{"usr/bin/a": "a", "usr/bin/b": "b"})
	res := verifyAll(t)
	if res.Checked != 2 || len(res.Mismatches)+len(res.Missing)+res.Unreadable != 0 {
		t.Errorf("%+v", res)
	}
}

func TestVerifyFindsModifiedFileOnUnmergedUsr(t *testing.T) {
	root := fakeSystem(t, map[string]string{"bin/login": "login", "usr/bin/who": "who"})
	if err := os.WriteFile(filepath.Join(root, "bin/login"), []byte("trojan"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := verifyAll(t)
	if res.Checked != 2 || len(res.Mismatches) != 1 || res.Mismatches[0].Path != "/bin/login" {
		t.Errorf("/bin/login must be hashed where it really is: %+v", res)
	}
}

func TestVerifyFindsFileRecordedUnderBinOnMergedUsr(t *testing.T) {
	root := fakeSystem(t, map[string]string{"usr/bin/ps": "ps"})
	sums := filepath.Join(infoDir, "pkg.md5sums")
	b, _ := os.ReadFile(sums)
	moved := []byte(string(b[:34]) + "bin/ps\n")
	if err := os.WriteFile(sums, moved, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/bin/ps"), []byte("trojan"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := verifyAll(t)
	if len(res.Mismatches) != 1 {
		t.Errorf("a package recording /bin/ps with only /usr/bin/ps on disk: %+v", res)
	}
}

func TestVerifyFindsFileReplacedBySymlink(t *testing.T) {
	root := fakeSystem(t, map[string]string{"usr/bin/sudo": "sudo"})
	target := filepath.Join(root, "evil")
	if err := os.WriteFile(target, []byte("evil"), 0o755); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(root, "usr/bin/sudo")
	if err := os.Remove(full); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, full); err != nil {
		t.Fatal(err)
	}
	res := verifyAll(t)
	if len(res.Mismatches) != 1 || res.Mismatches[0].LinkTarget != target {
		t.Errorf("symlink replacement missed: %+v", res)
	}
}

func TestVerifyReportsMissingFile(t *testing.T) {
	root := fakeSystem(t, map[string]string{"usr/bin/gone": "x", "usr/bin/here": "y"})
	if err := os.Remove(filepath.Join(root, "usr/bin/gone")); err != nil {
		t.Fatal(err)
	}
	res := verifyAll(t)
	if res.Checked != 1 || len(res.Missing) != 1 || res.Missing[0].Path != "/usr/bin/gone" {
		t.Errorf("%+v", res)
	}
}

func TestVerifyDedupesMergedPaths(t *testing.T) {
	root := fakeSystem(t, map[string]string{"usr/bin/x": "x"})
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	sums := filepath.Join(infoDir, "pkg.md5sums")
	b, _ := os.ReadFile(sums)
	both := append(append([]byte{}, b...), []byte(string(b[:34])+"bin/x\n")...)
	if err := os.WriteFile(sums, both, 0o644); err != nil {
		t.Fatal(err)
	}
	if res := verifyAll(t); res.Checked != 1 {
		t.Errorf("one file listed under two paths must be checked once: %+v", res)
	}
}

func TestFileMatches(t *testing.T) {
	root := fakeSystem(t, map[string]string{"usr/bin/caddy": "packaged", "usr/bin/other": "o"})
	bin := filepath.Join(root, "usr/bin/caddy")
	if match, listed, err := FileMatches("pkg", "/usr/bin/caddy", bin); !match || !listed || err != nil {
		t.Errorf("unchanged file: match=%v listed=%v err=%v", match, listed, err)
	}
	// /bin/caddy is the same file on a merged /usr.
	if match, listed, _ := FileMatches("pkg", "/bin/caddy", bin); !match || !listed {
		t.Errorf("merged path: match=%v listed=%v", match, listed)
	}
	if _, listed, _ := FileMatches("pkg", "/usr/bin/caddy.custom", bin); listed {
		t.Error("a path the package does not ship is not listed")
	}
	if _, listed, _ := FileMatches("nope", "/usr/bin/caddy", bin); listed {
		t.Error("a package without md5sums lists nothing")
	}
	if err := os.WriteFile(bin, []byte("xcaddy build"), 0o755); err != nil {
		t.Fatal(err)
	}
	if match, listed, err := FileMatches("pkg", "/usr/bin/caddy", bin); match || !listed || err != nil {
		t.Errorf("replaced file: match=%v listed=%v err=%v", match, listed, err)
	}
	// Multi-arch packages keep their md5sums under pkg:arch.
	if err := os.Rename(filepath.Join(infoDir, "pkg.md5sums"), filepath.Join(infoDir, "pkg:amd64.md5sums")); err != nil {
		t.Fatal(err)
	}
	if match, listed, _ := FileMatches("pkg", "/usr/bin/other", filepath.Join(root, "usr/bin/other")); !match || !listed {
		t.Errorf("pkg:arch md5sums: match=%v listed=%v", match, listed)
	}
}
