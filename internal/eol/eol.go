// Package eol tells whether a release of a product is past its end of life.
// The data comes from endoflife.date and is embedded at build time; the tool
// never fetches it while scanning. Refresh it before a release with
//
//	go run ./internal/eol/gen
package eol

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

//go:embed data.json
var raw []byte

// Release is one release cycle of a product, such as PostgreSQL 16.
type Release struct {
	Cycle string `json:"cycle"`
	// EOL is the date support ends, as YYYY-MM-DD. Empty means no date is set.
	EOL string `json:"eol,omitempty"`
	// Ended is set for a cycle past its end of life whose date is not known.
	Ended  bool   `json:"ended,omitempty"`
	Latest string `json:"latest,omitempty"`
}

type data struct {
	Source    string               `json:"source"`
	Generated string               `json:"generated"`
	Products  map[string][]Release `json:"products"`
}

var (
	once   sync.Once
	loaded data
)

func get() *data {
	once.Do(func() { _ = json.Unmarshal(raw, &loaded) })
	return &loaded
}

// Generated returns the day the embedded data was fetched.
func Generated() string { return get().Generated }

// Known reports whether there is data for a product.
func Known(product string) bool { return len(get().Products[product]) > 0 }

// Lookup finds the cycle a version belongs to: the longest cycle that equals
// the version or prefixes it at a dot, so 10.11.6 is MariaDB 10.11, not 10.1.
func Lookup(product, version string) (Release, bool) {
	var best Release
	found := false
	for _, r := range get().Products[product] {
		if version != r.Cycle && !strings.HasPrefix(version, r.Cycle+".") {
			continue
		}
		if !found || len(r.Cycle) > len(best.Cycle) {
			best, found = r, true
		}
	}
	return best, found
}

// Status is where a release stands on a given day.
type Status int

const (
	Supported Status = iota
	Ending           // support ends within the warning window
	Ended
)

// At reports the status of r on day now, warning `window` ahead of the end.
func (r Release) At(now time.Time, window time.Duration) Status {
	if r.Ended {
		return Ended
	}
	end, err := time.Parse("2006-01-02", r.EOL)
	if err != nil {
		return Supported
	}
	switch {
	case !now.Before(end):
		return Ended
	case now.Add(window).After(end):
		return Ending
	}
	return Supported
}

// Maintained lists the cycles of a product still supported on day now, in
// the order endoflife.date lists them, newest first.
func Maintained(product string, now time.Time) []string {
	var out []string
	for _, r := range get().Products[product] {
		if r.At(now, 0) != Ended {
			out = append(out, r.Cycle)
		}
	}
	return out
}
