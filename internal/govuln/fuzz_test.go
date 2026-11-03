package govuln

import "testing"

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// FuzzCompareOrder checks that Compare is a consistent order: a version
// equals itself, swapping the arguments reverses the result, and the order
// is transitive. OSV ranges and the versions read from binaries depend on it.
func FuzzCompareOrder(f *testing.F) {
	seeds := []string{
		"0", "1.2.3", "1.2", "1", "1.2.3-rc.1", "1.2.3-rc.10", "1.2.3-rc", "1.2.3-beta.2",
		"0.0.0-20261030153154-30a33513ff6d", "1.2.4-0.20261030153154-30a33513ff6d",
		"2.0.0+incompatible", "1.0.0-alpha.beta", "1.0.0-x.7.z.92", "", "x", "1.x",
	}
	for i, a := range seeds {
		f.Add(a, seeds[(i+1)%len(seeds)], seeds[(i+4)%len(seeds)])
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
