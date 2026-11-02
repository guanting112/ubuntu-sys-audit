package dpkg

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ubuntu-sys-audit/internal/fsx"
)

// InfoDir and StatusFile locate the dpkg database.
const (
	InfoDir        = "/var/lib/dpkg/info"
	StatusFile     = "/var/lib/dpkg/status"
	DiversionsFile = "/var/lib/dpkg/diversions"
)

// Package is an installed package.
type Package struct {
	Name    string
	Version string
	Arch    string
	Source  string // source package name, without version
	Held    bool
}

// ParseStatus parses dpkg's status file and returns packages that are actually
// installed. Packages removed but with config files left ("rc") are excluded;
// they carry no executable code to patch.
func ParseStatus(data []byte) []Package {
	var out []Package
	for _, para := range bytes.Split(data, []byte("\n\n")) {
		var p Package
		installed := false
		for _, line := range bytes.Split(para, []byte("\n")) {
			if len(line) == 0 || line[0] == ' ' {
				continue
			}
			i := bytes.IndexByte(line, ':')
			if i < 0 {
				continue
			}
			val := strings.TrimSpace(string(line[i+1:]))
			switch string(line[:i]) {
			case "Package":
				p.Name = val
			case "Version":
				p.Version = val
			case "Architecture":
				p.Arch = val
			case "Source":
				p.Source = strings.Fields(val + " x")[0]
			case "Status":
				f := strings.Fields(val)
				if len(f) == 3 && f[2] == "installed" {
					installed = true
					p.Held = f[0] == "hold"
				}
			}
		}
		if installed && p.Name != "" && p.Version != "" {
			if p.Source == "" {
				p.Source = p.Name
			}
			out = append(out, p)
		}
	}
	return out
}

// Origin classifies a package version string by who built it. This decides
// whether Ubuntu's advisories apply or upstream's do.
func Origin(version string) string {
	v := strings.ToLower(version)
	switch {
	case strings.Contains(v, "deb.sury.org"):
		return "ondrej-ppa"
	case strings.Contains(v, "ppa"):
		// Other PPAs often have "ubuntu" in the version too, as in
		// 1.2-1ubuntu1~ppa1, but USNs do not cover what they ship.
		return "third-party"
	case strings.Contains(v, "ubuntu"), strings.Contains(v, "build"):
		return "ubuntu"
	case nginxOrgVersion.MatchString(v):
		return "upstream-repo"
	}
	return "third-party"
}

var nginxOrgVersion = regexp.MustCompile(`-\d+~[a-z]+\d*$`)

// NormalizePath folds the usrmerge symlinks so /bin/ls and /usr/bin/ls compare
// equal; dpkg records whichever path the package shipped.
func NormalizePath(p string) string {
	for _, pre := range []string{"/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/"} {
		if strings.HasPrefix(p, pre) {
			return "/usr" + p
		}
	}
	return p
}

// Owners answers whether a path belongs to an installed package.
type Owners struct {
	paths map[string]struct{}
	// Diverted holds paths moved aside by dpkg-divert: their content is not
	// the one recorded in the original package's md5sums.
	Diverted map[string]struct{}
}

var skipOwnerPrefixes = []string{
	"/usr/share/doc/", "/usr/share/man/", "/usr/share/locale/", "/usr/share/icons/",
	"/usr/share/zoneinfo/", "/usr/share/info/", "/usr/share/help/", "/usr/share/lintian/",
	"/usr/share/perl/", "/usr/share/vim/", "/usr/src/", "/usr/include/",
}

// LoadOwners reads every package's file list. Documentation paths are dropped
// to keep memory proportional to what the checks ask about.
func LoadOwners(ctx context.Context) (*Owners, error) {
	o := &Owners{paths: make(map[string]struct{}, 1<<16), Diverted: map[string]struct{}{}}
	lists, err := filepath.Glob(InfoDir + "/*.list")
	if err != nil {
		return nil, err
	}
	if len(lists) == 0 {
		return nil, os.ErrNotExist
	}
	for _, path := range lists {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
	lines:
		for sc.Scan() {
			line := sc.Text()
			for _, pre := range skipOwnerPrefixes {
				if strings.HasPrefix(line, pre) {
					continue lines
				}
			}
			o.paths[NormalizePath(line)] = struct{}{}
		}
		f.Close()
	}
	if b, err := fsx.Read(DiversionsFile, fsx.DefaultLimit); err == nil {
		lines := strings.Split(string(b), "\n")
		for i := 0; i+2 < len(lines); i += 3 {
			// The moved copy keeps the package's content; the original path now
			// holds a replacement that was installed on purpose (Docker base
			// images divert man and initctl this way).
			o.Diverted[NormalizePath(lines[i])] = struct{}{}
			o.paths[NormalizePath(lines[i])] = struct{}{}
			o.paths[NormalizePath(lines[i+1])] = struct{}{}
		}
	}
	return o, nil
}

// Owned reports whether a path belongs to an installed package.
func (o *Owners) Owned(path string) bool {
	if o == nil {
		return false
	}
	_, ok := o.paths[NormalizePath(path)]
	return ok
}

// Mismatch is a package file that is no longer what the package installed.
type Mismatch struct {
	Path    string
	Package string
	// LinkTarget is set when a regular file was replaced by a symlink.
	LinkTarget string
}

// VerifyResult summarizes an integrity run.
type VerifyResult struct {
	Checked    int
	Mismatches []Mismatch
	Missing    []Mismatch
	Unreadable int
	Incomplete bool
}

// fsRoot and infoDir let tests point verification at a fake filesystem.
var (
	fsRoot  = ""
	infoDir = InfoDir
)

// Verify hashes package files accepted by want and compares them against the
// package's md5sums file. This catches binaries swapped on disk, the classic way
// to hide from ps, ss and friends.
//
// md5sums only lists regular files, so a symlink at that path means the file was
// replaced. Missing files are reported separately: an admin may have removed a
// tool on purpose, but it is also how a file ends up replaced and hidden.
//
// The recorded path is tried first. /usr is not merged on 18.04 and some upgraded
// hosts, so /bin/ps exists there while /usr/bin/ps does not.
func Verify(ctx context.Context, owners *Owners, want func(path string) bool) (VerifyResult, error) {
	var res VerifyResult
	sums, err := filepath.Glob(infoDir + "/*.md5sums")
	if err != nil {
		return res, err
	}
	if len(sums) == 0 {
		return res, os.ErrNotExist
	}
	seen := map[string]struct{}{}
	realDirs := map[string]string{}
	for _, sumFile := range sums {
		pkg := strings.TrimSuffix(filepath.Base(sumFile), ".md5sums")
		b, err := os.ReadFile(sumFile)
		if err != nil {
			continue
		}
		for _, line := range bytes.Split(b, []byte("\n")) {
			if len(line) < 34 {
				continue
			}
			sum, rel := string(line[:32]), strings.TrimSpace(string(line[33:]))
			recorded := "/" + rel
			norm := NormalizePath(recorded)
			if !want(norm) {
				continue
			}
			if owners != nil {
				if _, diverted := owners.Diverted[norm]; diverted {
					continue
				}
			}
			path, info, statErr := locate(recorded, norm)
			key := realPath(path, realDirs)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			if ctx.Err() != nil {
				res.Incomplete = true
				return res, nil
			}
			switch {
			case errors.Is(statErr, fs.ErrNotExist):
				res.Missing = append(res.Missing, Mismatch{Path: path, Package: pkg})
			case statErr != nil:
				res.Unreadable++
			case info.Mode()&fs.ModeSymlink != 0:
				target, _ := os.Readlink(fsRoot + path)
				res.Mismatches = append(res.Mismatches, Mismatch{Path: path, Package: pkg, LinkTarget: target})
			case !info.Mode().IsRegular():
				res.Mismatches = append(res.Mismatches, Mismatch{Path: path, Package: pkg, LinkTarget: "a " + info.Mode().Type().String() + " special file"})
			default:
				got, err := md5File(fsRoot + path)
				if err != nil {
					res.Unreadable++
					continue
				}
				res.Checked++
				if got != sum {
					res.Mismatches = append(res.Mismatches, Mismatch{Path: path, Package: pkg})
				}
			}
		}
	}
	return res, nil
}

// locate finds a package file at its recorded path, or at the merged /usr path.
func locate(recorded, norm string) (string, fs.FileInfo, error) {
	info, err := os.Lstat(fsRoot + recorded)
	if err == nil || recorded == norm || !errors.Is(err, fs.ErrNotExist) {
		return recorded, info, err
	}
	if info, err := os.Lstat(fsRoot + norm); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return norm, info, err
	}
	return recorded, nil, err
}

// realPath resolves the directory part only, so /bin/ps and /usr/bin/ps count as
// one file on merged systems while a symlink at the path itself stays visible.
func realPath(path string, cache map[string]string) string {
	dir, name := filepath.Split(path)
	real, ok := cache[dir]
	if !ok {
		var err error
		if real, err = filepath.EvalSymlinks(fsRoot + dir); err != nil {
			real = fsRoot + dir
		}
		cache[dir] = real
	}
	return filepath.Join(real, name)
}

// FileMatches hashes content and compares it with the md5sum package pkg
// recorded for path. content is usually path itself, but a running binary is
// read through /proc/pid/exe. listed is false when pkg's md5sums does not name
// path, so there is nothing to compare against.
func FileMatches(pkg, path, content string) (match, listed bool, err error) {
	sumFiles, _ := filepath.Glob(infoDir + "/" + pkg + ":*.md5sums")
	sumFiles = append([]string{infoDir + "/" + pkg + ".md5sums"}, sumFiles...)
	want := NormalizePath(path)
	for _, sumFile := range sumFiles {
		b, err := os.ReadFile(sumFile)
		if err != nil {
			continue
		}
		for _, line := range bytes.Split(b, []byte("\n")) {
			if len(line) < 34 || NormalizePath("/"+strings.TrimSpace(string(line[33:]))) != want {
				continue
			}
			got, err := md5File(content)
			if err != nil {
				return false, true, err
			}
			return got == string(line[:32]), true, nil
		}
	}
	return false, false, nil
}

func md5File(path string) (string, error) {
	f, err := fsx.OpenRegular(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
