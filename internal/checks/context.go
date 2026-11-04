// Package checks implements the audit. Checks only read state. They never run
// binaries from the host, and the only outbound traffic is the download of
// public advisory data, which sends nothing about the host.
package checks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"ubuntu-sys-audit/internal/dpkg"
	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/procinfo"
)

// Options configures a scan.
type Options struct {
	Version   string
	Offline   bool
	OVALFile  string
	Proxy     string
	SkipFS    bool
	NoNetlink bool
	FSTimeout time.Duration
	// CVEs, when set, replaces the scan with a lookup of these CVE IDs.
	CVEs []string
}

// User is an /etc/passwd entry.
type User struct {
	Name string
	// Password is the state of the /etc/passwd password field: "shadow", "empty",
	// "locked" or "inline". A hash stored there is never kept.
	Password string
	UID      int
	GID      int
	Home     string
	Shell    string
}

// ShadowEntry is a parsed /etc/shadow row. The password hash is reduced to its
// status and algorithm immediately and never stored.
type ShadowEntry struct {
	Status     string // "empty", "locked" or "password"
	Algo       string
	LastChange int
}

// Context is what a check receives. Ctx carries that check's deadline; the
// embedded shared state lazily loads expensive host data once for all checks.
type Context struct {
	Ctx  context.Context
	Opts Options
	Host model.Host
	*shared
}

type shared struct {
	root context.Context

	mu        sync.Mutex
	inventory []model.InventoryItem
	stack     []model.StackItem

	procsOnce sync.Once
	procs     []*procinfo.Process
	procsErr  error

	netOnce sync.Once
	net     *procinfo.NetView

	pkgOnce sync.Once
	pkgs    []dpkg.Package
	pkgErr  error

	ownOnce sync.Once
	owners  *dpkg.Owners
	ownErr  error

	usersOnce sync.Once
	users     []User
	usersErr  error

	shadowOnce sync.Once
	shadow     map[string]ShadowEntry
	shadowErr  error

	groupsOnce sync.Once
	groups     map[string][]string

	selfExe string
}

// NewContext gathers basic host facts.
func NewContext(ctx context.Context, opts Options) *Context {
	c := &Context{Ctx: ctx, Opts: opts, shared: &shared{root: ctx}}
	c.Host = model.Host{
		Hostname:    fsx.ProcString("/proc/sys/kernel/hostname"),
		Kernel:      fsx.ProcString("/proc/sys/kernel/osrelease"),
		Arch:        runtime.GOARCH,
		IsRoot:      os.Geteuid() == 0,
		InContainer: detectContainer(),
	}
	if f := strings.Fields(fsx.ProcString("/proc/uptime")); len(f) > 0 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil {
			c.Host.UptimeSec = int64(v)
		}
	}
	rel := readOSRelease()
	c.Host.OSName = rel["NAME"]
	c.Host.OSVersion = rel["VERSION_ID"]
	c.Host.Codename = rel["VERSION_CODENAME"]
	if c.Host.Codename == "" {
		c.Host.Codename = rel["UBUNTU_CODENAME"]
	}
	if c.Host.Hostname == "" {
		c.Host.Hostname, _ = os.Hostname()
	}
	// These reach the terminal, and a compromised host controls all of them.
	c.Host.Hostname = model.Clean(c.Host.Hostname)
	c.Host.OSName = model.Clean(c.Host.OSName)
	c.Host.OSVersion = model.Clean(c.Host.OSVersion)
	c.Host.Codename = model.Clean(c.Host.Codename)
	c.Host.Kernel = model.Clean(c.Host.Kernel)
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		c.selfExe = exe
	}
	return c
}

func readOSRelease() map[string]string {
	out := map[string]string{}
	b, err := fsx.Read("/etc/os-release", 1<<16)
	if err != nil {
		b, err = fsx.Read("/usr/lib/os-release", 1<<16)
		if err != nil {
			return out
		}
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out
}

func detectContainer() bool {
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	if s := fsx.ProcString("/run/systemd/container"); s != "" {
		return true
	}
	cg := fsx.ProcString("/proc/1/cgroup")
	for _, m := range []string{"docker", "kubepods", "containerd", "lxc"} {
		if strings.Contains(cg, m) {
			return true
		}
	}
	return false
}

// Procs returns the process snapshot.
func (c *Context) Procs() ([]*procinfo.Process, error) {
	// Bound to the scan rather than the calling check: the snapshot is shared,
	// so one check's deadline must not leave the rest with a partial list.
	c.procsOnce.Do(func() { c.procs, c.procsErr = procinfo.Snapshot(c.root) })
	return c.procs, c.procsErr
}

// Net returns sockets across every network namespace.
func (c *Context) Net() *procinfo.NetView {
	c.netOnce.Do(func() {
		procs, _ := c.Procs()
		c.net = procinfo.CollectNet(procs)
	})
	return c.net
}

// Packages returns the installed dpkg packages.
func (c *Context) Packages() ([]dpkg.Package, error) {
	c.pkgOnce.Do(func() {
		b, err := fsx.Read(dpkg.StatusFile, 256<<20)
		if err != nil {
			c.pkgErr = err
			return
		}
		c.pkgs = dpkg.ParseStatus(b)
	})
	return c.pkgs, c.pkgErr
}

// PackageVersions maps binary package names to installed versions.
func (c *Context) PackageVersions() map[string][]string {
	pkgs, _ := c.Packages()
	out := make(map[string][]string, len(pkgs))
	for _, p := range pkgs {
		out[p.Name] = append(out[p.Name], p.Version)
	}
	return out
}

// Owners returns the path to package index.
func (c *Context) Owners() (*dpkg.Owners, error) {
	c.ownOnce.Do(func() { c.owners, c.ownErr = dpkg.LoadOwners(c.root) })
	return c.owners, c.ownErr
}

// Owned reports whether a path belongs to a package. Snap content is treated as
// owned because snapd verifies it and it lives on a read only mount.
func (c *Context) Owned(path string) bool {
	if strings.HasPrefix(path, "/snap/") || strings.HasPrefix(path, "/var/lib/snapd/") {
		return true
	}
	o, err := c.Owners()
	if err != nil {
		return false
	}
	return o.Owned(path)
}

// Users returns /etc/passwd entries.
func (c *Context) Users() ([]User, error) {
	c.usersOnce.Do(func() {
		b, err := fsx.Read("/etc/passwd", fsx.DefaultLimit)
		if err != nil {
			c.usersErr = err
			return
		}
		c.users = parsePasswd(string(b))
	})
	return c.users, c.usersErr
}

func parsePasswd(s string) []User {
	var out []User
	for _, line := range strings.Split(s, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || strings.HasPrefix(line, "#") {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, User{Name: f[0], Password: passwdField(f[1]), UID: uid, GID: gid, Home: f[5], Shell: f[6]})
	}
	return out
}

func passwdField(v string) string {
	switch {
	case v == "x":
		return "shadow"
	case v == "":
		return "empty"
	case strings.HasPrefix(v, "*") || strings.HasPrefix(v, "!"):
		return "locked"
	}
	return "inline"
}

// Shadow returns password status per user.
func (c *Context) Shadow() (map[string]ShadowEntry, error) {
	c.shadowOnce.Do(func() {
		b, err := fsx.Read("/etc/shadow", fsx.DefaultLimit)
		if err != nil {
			c.shadowErr = err
			return
		}
		c.shadow = parseShadow(string(b))
	})
	return c.shadow, c.shadowErr
}

func parseShadow(s string) map[string]ShadowEntry {
	out := map[string]ShadowEntry{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 || f[0] == "" {
			continue
		}
		e := ShadowEntry{}
		e.LastChange, _ = strconv.Atoi(f[2])
		pw := f[1]
		switch {
		case pw == "":
			e.Status = "empty"
		case strings.HasPrefix(pw, "!") || strings.HasPrefix(pw, "*"):
			e.Status = "locked"
		default:
			e.Status = "password"
			e.Algo = hashAlgo(pw)
		}
		out[f[0]] = e
	}
	return out
}

func hashAlgo(pw string) string {
	switch {
	case strings.HasPrefix(pw, "$1$"):
		return "md5"
	case strings.HasPrefix(pw, "$2"):
		return "bcrypt"
	case strings.HasPrefix(pw, "$5$"):
		return "sha256"
	case strings.HasPrefix(pw, "$6$"):
		return "sha512"
	case strings.HasPrefix(pw, "$y$"), strings.HasPrefix(pw, "$gy$"):
		return "yescrypt"
	case !strings.HasPrefix(pw, "$"):
		return "des"
	}
	return "other"
}

// Groups returns the members of each group from /etc/group.
func (c *Context) Groups() map[string][]string {
	c.groupsOnce.Do(func() {
		c.groups = map[string][]string{}
		b, err := fsx.Read("/etc/group", fsx.DefaultLimit)
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Split(line, ":")
			if len(f) < 4 {
				continue
			}
			var members []string
			for _, m := range strings.Split(f[3], ",") {
				if m != "" {
					members = append(members, m)
				}
			}
			c.groups[f[0]] = members
		}
	})
	return c.groups
}

// Homes returns unique, real home directories with their user.
func (c *Context) Homes() []User {
	users, _ := c.Users()
	seen := map[string]bool{}
	var out []User
	for _, u := range users {
		h := filepath.Clean(u.Home)
		if h == "" || h == "/" || h == "." || seen[h] || strings.HasPrefix(h, "/nonexistent") ||
			h == "/bin" || h == "/usr/sbin" || h == "/sbin" || h == "/dev" || h == "/usr/games" ||
			h == "/proc" || h == "/run" || strings.HasPrefix(h, "/run/") {
			continue
		}
		// Stat, not Lstat: /home/x -> /data/x is a normal setup, and root set it.
		if st, err := os.Stat(h); err != nil || !st.IsDir() {
			continue
		}
		seen[h] = true
		out = append(out, u)
	}
	return out
}

// AddInventory records software versions for the report.
func (c *Context) AddInventory(items ...model.InventoryItem) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inventory = append(c.inventory, items...)
}

// AddStack records the databases, runtimes and servers for the report.
func (c *Context) AddStack(items ...model.StackItem) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stack = append(c.stack, items...)
}

// isLoginShell reports whether an account can get an interactive shell. An
// empty field in /etc/passwd means /bin/sh, so it counts.
func isLoginShell(shell string) bool {
	switch filepath.Base(shell) {
	case "nologin", "false", "sync", "halt", "shutdown", "git-shell", "true":
		return false
	}
	return true
}

func finding(id string, cat model.Category, sev model.Severity, title string) model.Finding {
	return model.Finding{ID: id, Category: cat, Severity: sev, Title: title}
}

func skipped(id string, cat model.Category, title, reason string) model.Finding {
	return model.Finding{ID: id, Category: cat, Severity: model.Skipped, Title: title, Detail: reason}
}

// requested reports a check the operator turned off with a flag. It is still
// listed, but does not count against the scan being complete.
func requested(id string, cat model.Category, title, reason string) model.Finding {
	f := skipped(id, cat, title, reason)
	f.Requested = true
	return f
}

func needRoot(id string, cat model.Category, title string) model.Finding {
	return skipped(id, cat, title, "Requires root. Run with sudo.")
}

// inDirs reports whether path is inside one of the directories.
func inDirs(path string, dirs ...string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}

var tempDirs = []string{"/tmp", "/var/tmp", "/dev/shm", "/run/shm"}

func inTemp(path string) bool { return inDirs(path, tempDirs...) }
