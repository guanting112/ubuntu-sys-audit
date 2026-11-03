package dpkg

import (
	"os/exec"
	"testing"
)

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

var versionSeeds = []string{
	"1.0", "1.0-1", "1:1.0-1", "1.0~rc1-1", "1.0~~", "1.0~", "1.18.0-0ubuntu1.4",
	"1.18.0-6ubuntu14.6+esm1", "2:8.2.3995-1ubuntu2.24", "0.0~git20240101.abc-1",
	"1.0+dfsg-1", "1.0a", "1.0.a", "10", "9", "010", "", "~", "1:", "-", "1.0-", "a:b-c",
}

// FuzzCompareOrder checks what any version order needs: a version equals
// itself, swapping the arguments reverses the result, and the order is
// transitive. A fixed-in threshold must not depend on argument order.
func FuzzCompareOrder(f *testing.F) {
	for i, a := range versionSeeds {
		f.Add(a, versionSeeds[(i+1)%len(versionSeeds)], versionSeeds[(i+5)%len(versionSeeds)])
	}
	f.Fuzz(func(t *testing.T, a, b, c string) {
		if got := Compare(a, a); got != 0 {
			t.Fatalf("Compare(%q, %q) = %d, want 0", a, a, got)
		}
		ab, ba := sign(Compare(a, b)), sign(Compare(b, a))
		if ab != -ba {
			t.Fatalf("Compare(%q, %q) = %d but Compare(%q, %q) = %d", a, b, ab, b, a, ba)
		}
		bc, ac := sign(Compare(b, c)), sign(Compare(a, c))
		if (ab <= 0 && bc <= 0 && ac > 0) || (ab >= 0 && bc >= 0 && ac < 0) {
			t.Fatalf("not transitive: %q vs %q = %d, %q vs %q = %d, %q vs %q = %d", a, b, ab, b, c, bc, a, c, ac)
		}
	})
}

// FuzzCompareMatchesDpkg compares the result with dpkg itself, for versions
// dpkg accepts without a warning. It needs dpkg in PATH, as in the golang
// image make test uses and on GitHub's Ubuntu runners, and skips elsewhere.
func FuzzCompareMatchesDpkg(f *testing.F) {
	dpkg, err := exec.LookPath("dpkg")
	if err != nil {
		f.Skip("dpkg is not installed")
	}
	for i, a := range versionSeeds {
		f.Add(a, versionSeeds[(i+3)%len(versionSeeds)])
	}
	// A valid version starts with a digit, which also keeps dpkg from reading
	// the input as an option.
	valid := func(v string) bool {
		return v != "" && isDigit(v[0]) && exec.Command(dpkg, "--validate-version", v).Run() == nil
	}
	holds := func(a, op, b string) bool {
		return exec.Command(dpkg, "--compare-versions", a, op, b).Run() == nil
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		if !valid(a) || !valid(b) {
			return
		}
		want := 1
		switch {
		case holds(a, "lt", b):
			want = -1
		case holds(a, "eq", b):
			want = 0
		}
		if got := sign(Compare(a, b)); got != want {
			t.Fatalf("Compare(%q, %q) = %d, dpkg says %d", a, b, got, want)
		}
	})
}

// FuzzParseStatus feeds the status parser arbitrary bytes.
func FuzzParseStatus(f *testing.F) {
	f.Add([]byte("Package: nginx-core\nStatus: install ok installed\nArchitecture: amd64\nSource: nginx (1.18.0-6ubuntu14.4)\nVersion: 1.18.0-6ubuntu14.4\n\n"))
	f.Add([]byte("Package: a\n continuation\nStatus:\nVersion\n\n\nPackage:\n"))
	f.Add([]byte("Source: (\nSource: x (\nSource: x ()\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseStatus(data)
	})
}
