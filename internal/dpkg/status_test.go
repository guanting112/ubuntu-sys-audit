package dpkg

import "testing"

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
