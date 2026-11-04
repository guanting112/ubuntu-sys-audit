package eol

import (
	"testing"
	"time"
)

func TestDataLoads(t *testing.T) {
	if Generated() == "" {
		t.Fatal("embedded data has no generation date")
	}
	if _, err := time.Parse("2006-01-02", Generated()); err != nil {
		t.Fatalf("generation date %q: %v", Generated(), err)
	}
	if !Known("postgresql") || Known("no-such-product") {
		t.Fatal("Known gives the wrong answer")
	}
}

func TestLookup(t *testing.T) {
	cases := []struct{ product, version, cycle string }{
		{"postgresql", "16.4", "16"},
		{"postgresql", "9.6.24", "9.6"},
		{"mariadb", "10.11.6", "10.11"}, // not 10.1
		{"mariadb", "10.1.48", "10.1"},
		{"mysql", "8.0.36", "8.0"},
		{"nodejs", "20.11.1", "20"},
		{"redis", "6.0.16", "6.0"},
		{"postgresql", "11", "11"},
		{"postgresql", "99.1", ""},
		{"postgresql", "", ""},
		{"no-such-product", "1.0", ""},
	}
	for _, c := range cases {
		r, ok := Lookup(c.product, c.version)
		if got := r.Cycle; ok != (c.cycle != "") || got != c.cycle {
			t.Errorf("Lookup(%q, %q) = %q, %v; want %q", c.product, c.version, got, ok, c.cycle)
		}
	}
}

func TestAt(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	window := 90 * 24 * time.Hour
	cases := []struct {
		r    Release
		want Status
	}{
		{Release{EOL: "2023-11-09"}, Ended},
		{Release{EOL: "2026-11-04"}, Ended}, // the end day itself is unsupported
		{Release{EOL: "2026-12-01"}, Ending},
		{Release{EOL: "2030-11-14"}, Supported},
		{Release{Ended: true}, Ended},
		{Release{}, Supported},
		{Release{EOL: "not a date"}, Supported},
	}
	for _, c := range cases {
		if got := c.r.At(now, window); got != c.want {
			t.Errorf("%+v.At = %d, want %d", c.r, got, c.want)
		}
	}
}

func TestMaintained(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	m := Maintained("postgresql", now)
	if len(m) == 0 {
		t.Fatal("no maintained PostgreSQL releases")
	}
	for _, c := range m {
		if c == "11" || c == "9.6" {
			t.Errorf("ended release %s listed as maintained", c)
		}
	}
}
