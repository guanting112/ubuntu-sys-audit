package dpkg

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-1", 0},
		{"1.0", "1.1", -1},
		{"1.10", "1.9", 1},
		{"1:1.0", "2.0", 1},
		{"0:1.0", "1.0", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0~", "1.0", -1},
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0+", -1},
		{"1.0-1", "1.0-2", -1},
		{"1.0-1", "1.0", 1},
		{"1.18.0-0ubuntu1.4", "1.18.0-0ubuntu1.5", -1},
		{"1.18.0-6ubuntu14.4", "1.18.0-6ubuntu14.10", -1},
		{"8.1.2-1ubuntu2.14", "8.1.2-1ubuntu2.14~esm1", 1},
		{"1.13.1+dfsg-1ubuntu0.1~esm1", "1.13.1+dfsg-1ubuntu0.1", -1},
		{"1:2.34.1-1ubuntu1.1", "1:2.34.1-1ubuntu1.11", -1},
		{"1:2.34.1-1ubuntu1.1", "2.34.1-1ubuntu1.11", 1},
		{"8.3.6-0ubuntu0.24.04.3", "8.3.6-0ubuntu0.24.04.10", -1},
		{"5.15.0-27", "5.15.0-101", -1},
		{"0:5.15.0-27", "5.15.0-27", 0},
		{"1.2.3-1+ubuntu22.04.1+deb.sury.org+1", "1.2.3-1+ubuntu22.04.1+deb.sury.org+2", -1},
		{"1.0-0ubuntu0.1", "1.0-0ubuntu0.1+esm1", -1},
		{"001.0", "1.0", 0},
		{"1.0.0", "1.0", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q,%q) = %d, want %d (reversed)", c.b, c.a, got, -c.want)
		}
	}
}
