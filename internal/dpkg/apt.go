package dpkg

import (
	"bufio"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"ubuntu-sys-audit/internal/fsx"
)

// AptListsDir is where apt keeps the package lists it downloaded. Tests
// point it at a fake directory.
var AptListsDir = "/var/lib/apt/lists"

// AptIndex records which package versions apt's lists offer from Ubuntu's
// own archives and which packages other repositories offer. dpkg does not
// record where an installed package came from, and a version string alone
// can mislead: Ubuntu's python3.10 on 22.04 is 3.10.12-1~22.04.18, with no
// "ubuntu" in it.
type AptIndex struct {
	ubuntu map[string]map[string]bool
	other  map[string]bool
	// Lists counts the package lists that could be read. Lists stored lz4,
	// xz or zstd compressed, as Docker's Ubuntu images do, are not.
	Lists int
}

// LoadAptIndex reads the lists for the packages in want only.
func LoadAptIndex(ctx context.Context, want map[string]bool) *AptIndex {
	idx := &AptIndex{ubuntu: map[string]map[string]bool{}, other: map[string]bool{}}
	var lists []string
	for _, pat := range []string{"*_Packages", "*_Packages.gz"} {
		m, _ := filepath.Glob(filepath.Join(AptListsDir, pat))
		lists = append(lists, m...)
	}
	origins := map[string]string{}
	for _, list := range lists {
		if ctx.Err() != nil {
			break
		}
		release := releaseFor(list)
		origin, seen := origins[release]
		if !seen {
			origin = releaseOrigin(release)
			origins[release] = origin
		}
		if idx.readList(list, strings.HasPrefix(origin, "Ubuntu"), want) {
			idx.Lists++
		}
	}
	return idx
}

// releaseFor finds the Release file of a list: the list's name with its
// trailing fields replaced, as in
// archive.ubuntu.com_ubuntu_dists_jammy-updates_main_binary-amd64_Packages ->
// archive.ubuntu.com_ubuntu_dists_jammy-updates_InRelease.
func releaseFor(list string) string {
	dir, base := filepath.Split(list)
	parts := strings.Split(base, "_")
	for i := len(parts) - 1; i > 0; i-- {
		prefix := filepath.Join(dir, strings.Join(parts[:i], "_"))
		for _, name := range []string{prefix + "_InRelease", prefix + "_Release"} {
			if st, err := os.Stat(name); err == nil && st.Mode().IsRegular() {
				return name
			}
		}
	}
	return ""
}

// releaseOrigin reads the Origin field: Ubuntu, UbuntuESM and UbuntuESMApps
// for Canonical's archives, LP-PPA-<name> for PPAs.
func releaseOrigin(path string) string {
	if path == "" {
		return ""
	}
	b, err := fsx.Read(path, 1<<20)
	if err != nil {
		return ""
	}
	// InRelease is clearsigned, so a PGP header and a blank line come
	// before the fields.
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Origin:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (idx *AptIndex) readList(path string, fromUbuntu bool, want map[string]bool) bool {
	f, err := fsx.OpenRegular(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return false
		}
		defer gz.Close()
		r = gz
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	name := ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			name = ""
		case strings.HasPrefix(line, "Package: "):
			name = strings.TrimSpace(line[len("Package: "):])
		case strings.HasPrefix(line, "Version: ") && want[name]:
			if !fromUbuntu {
				idx.other[name] = true
				continue
			}
			if idx.ubuntu[name] == nil {
				idx.ubuntu[name] = map[string]bool{}
			}
			idx.ubuntu[name][strings.TrimSpace(line[len("Version: "):])] = true
		}
	}
	return sc.Err() == nil
}

// Origin reports whether an installed version came from Ubuntu, and whether
// the lists can tell at all. A package only Ubuntu offers counts as Ubuntu's
// even when the installed version is no longer listed, as on a host that is
// behind on updates.
func (idx *AptIndex) Origin(pkg, version string) (ubuntu, known bool) {
	if idx == nil || idx.Lists == 0 {
		return false, false
	}
	switch {
	case idx.ubuntu[pkg][version]:
		return true, true
	case len(idx.ubuntu[pkg]) > 0 && !idx.other[pkg]:
		return true, true
	case idx.other[pkg]:
		return false, true
	}
	return false, false
}
