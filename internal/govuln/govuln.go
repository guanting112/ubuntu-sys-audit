// Package govuln matches the modules and Go version recorded in a Go binary
// against Go's vulnerability database at vuln.go.dev. It reads the database's
// zip, which holds every entry in OSV form with an index of modules.
package govuln

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// The platform the binaries being checked run on: this one. An entry limited to
// Windows or macOS does not apply.
var (
	targetOS   = "linux"
	targetArch = runtime.GOARCH
)

// DBURL is the whole database as one zip, a few megabytes.
const DBURL = "https://vuln.go.dev/vulndb.zip"

// Stdlib is the module name the database uses for Go's standard library.
const Stdlib = "stdlib"

// Entry is one database entry that applies to a module version.
type Entry struct {
	ID      string
	Aliases []string // CVE and GHSA IDs
	Summary string
	Module  string
	Version string // the version found
	Fixed   string // the first fixed version above it, empty if none exists yet
}

// DB is an opened database.
type DB struct {
	// Modified is when the database last changed.
	Modified string
	files    map[string]*zip.File
	index    map[string][]string // module -> entry IDs
}

// maxEntrySize bounds one entry. Real ones are a few kilobytes.
const maxEntrySize = 4 << 20

// Open reads the database zip.
func Open(b []byte) (*DB, error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, fmt.Errorf("govuln: %w", err)
	}
	db := &DB{files: map[string]*zip.File{}, index: map[string][]string{}}
	for _, f := range zr.File {
		db.files[f.Name] = f
	}
	var meta struct {
		Modified string `json:"modified"`
	}
	if err := db.decode("index/db.json", &meta); err != nil {
		return nil, err
	}
	db.Modified = meta.Modified
	var modules []struct {
		Path  string `json:"path"`
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}
	if err := db.decode("index/modules.json", &modules); err != nil {
		return nil, err
	}
	for _, m := range modules {
		for _, v := range m.Vulns {
			db.index[m.Path] = append(db.index[m.Path], v.ID)
		}
	}
	if len(db.index) == 0 {
		return nil, fmt.Errorf("govuln: the database lists no modules")
	}
	return db, nil
}

func (db *DB) decode(name string, v any) error {
	f, ok := db.files[name]
	if !ok {
		return fmt.Errorf("govuln: %s missing from the database", name)
	}
	r, err := f.Open()
	if err != nil {
		return fmt.Errorf("govuln: %s: %w", name, err)
	}
	defer r.Close()
	if err := json.NewDecoder(io.LimitReader(r, maxEntrySize)).Decode(v); err != nil {
		return fmt.Errorf("govuln: %s: %w", name, err)
	}
	return nil
}

type osvEntry struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Withdrawn string   `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			Imports []struct {
				GOOS   []string `json:"goos"`
				GOARCH []string `json:"goarch"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// Match returns the entries that apply to a module at a version. version has
// no leading "v", and for the standard library it is a Go version such as
// 1.26.8. Withdrawn entries are skipped.
func (db *DB) Match(module, version string) ([]Entry, error) {
	var out []Entry
	seen := map[string]bool{}
	for _, id := range db.index[module] {
		// The index lists an entry once per affected package it names.
		if seen[id] {
			continue
		}
		seen[id] = true
		var e osvEntry
		if err := db.decode("ID/"+id+".json", &e); err != nil {
			return nil, err
		}
		if e.Withdrawn != "" {
			continue
		}
		for _, a := range e.Affected {
			if a.Package.Name != module {
				continue
			}
			// Without a package that builds for this platform, the entry
			// does not apply. No imports at all means every platform.
			imports := a.EcosystemSpecific.Imports
			if len(imports) > 0 && !slices.ContainsFunc(imports, func(i struct {
				GOOS   []string `json:"goos"`
				GOARCH []string `json:"goarch"`
			}) bool {
				return (len(i.GOOS) == 0 || slices.Contains(i.GOOS, targetOS)) && (len(i.GOARCH) == 0 || slices.Contains(i.GOARCH, targetArch))
			}) {
				continue
			}
			if affected, fixed := inRanges(version, a.Ranges); affected {
				out = append(out, Entry{ID: e.ID, Aliases: e.Aliases, Summary: e.Summary, Module: module, Version: version, Fixed: fixed})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// inRanges applies OSV SEMVER events: each introduced opens a vulnerable span
// and the next fixed closes it. It returns the fixed version of the span that
// holds version.
func inRanges(version string, ranges []struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}) (bool, string) {
	for _, r := range ranges {
		if r.Type != "SEMVER" {
			continue
		}
		open := false
		for _, ev := range r.Events {
			if v, ok := ev["introduced"]; ok {
				if Compare(version, v) >= 0 {
					open = true
				}
			}
			if v, ok := ev["fixed"]; ok && open {
				if Compare(version, v) < 0 {
					return true, v
				}
				open = false
			}
		}
		if open {
			return true, ""
		}
	}
	return false, ""
}

// GoVersion turns a Go toolchain version such as go1.26.8, go1.22rc1 or
// go1.21 into the form the database uses: 1.26.8, 1.22.0-rc.1, 1.21.0. It
// returns "" for development builds.
func GoVersion(v string) string {
	fields := strings.Fields(v) // drop suffixes such as " X:boringcrypto"
	if len(fields) == 0 {
		return ""
	}
	v, ok := strings.CutPrefix(fields[0], "go")
	if !ok || v == "" || !strings.ContainsAny(v[:1], "0123456789") {
		return ""
	}
	pre := ""
	for _, tag := range []string{"rc", "beta"} {
		if i := strings.Index(v, tag); i > 0 {
			pre = "-" + tag + "." + v[i+len(tag):]
			v = v[:i]
		}
	}
	parts := strings.Split(v, ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	return strings.Join(parts[:3], ".") + pre
}

// ModuleVersion strips the "v" and any "+incompatible" from a module version.
// It returns "" for "(devel)" and other versions that are not semver.
func ModuleVersion(v string) string {
	v, ok := strings.CutPrefix(v, "v")
	if !ok {
		return ""
	}
	v, _, _ = strings.Cut(v, "+")
	if _, _, ok := split(v); !ok {
		return ""
	}
	return v
}

// split separates a semver version into its numbers and prerelease.
func split(v string) ([3]int, string, bool) {
	var nums [3]int
	core, pre, _ := strings.Cut(v, "-")
	core, _, _ = strings.Cut(core, "+")
	parts := strings.Split(core, ".")
	if len(parts) > 3 || parts[0] == "" {
		return nums, "", false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nums, "", false
		}
		nums[i] = n
	}
	return nums, pre, true
}

// Compare orders two semver versions without a leading "v", following semver
// precedence: a prerelease comes before its release, and prerelease fields
// compare numerically when both are numbers. "0" is what OSV writes for "from
// the first version", so it sorts before everything, pseudo-versions included.
func Compare(a, b string) int {
	switch {
	case a == "0" && b == "0":
		return 0
	case a == "0":
		return -1
	case b == "0":
		return 1
	}
	an, ap, _ := split(a)
	bn, bp, _ := split(b)
	for i := range an {
		if an[i] != bn[i] {
			if an[i] < bn[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case ap == bp:
		return 0
	case ap == "":
		return 1
	case bp == "":
		return -1
	}
	af, bf := strings.Split(ap, "."), strings.Split(bp, ".")
	for i := 0; i < len(af) && i < len(bf); i++ {
		if af[i] == bf[i] {
			continue
		}
		ai, aErr := strconv.Atoi(af[i])
		bi, bErr := strconv.Atoi(bf[i])
		switch {
		case aErr == nil && bErr == nil && ai != bi:
			if ai < bi {
				return -1
			}
			return 1
		case aErr == nil && bErr == nil:
			// Equal numbers written differently, such as "1" and "01", which
			// semver does not allow. Ordering them by text keeps the result
			// independent of argument order.
			if af[i] < bf[i] {
				return -1
			}
			return 1
		case aErr == nil:
			return -1 // numbers sort before words
		case bErr == nil:
			return 1
		case af[i] < bf[i]:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(af) < len(bf):
		return -1
	case len(af) > len(bf):
		return 1
	}
	return 0
}
