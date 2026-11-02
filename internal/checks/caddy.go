package checks

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"ubuntu-sys-audit/internal/dpkg"
	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/govuln"
	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/procinfo"
)

const caddyModule = "github.com/caddyserver/caddy/v2"

// caddyStandardModules ship in every Caddy build, so they are not plugins.
var caddyStandardModules = map[string]bool{
	caddyModule: true, "github.com/caddyserver/certmagic": true, "github.com/caddyserver/zerossl": true,
}

// caddyPaths are where Caddy is installed by hand. Caddy's guide for custom
// builds keeps a packaged binary and points /usr/bin/caddy at caddy.custom with
// update-alternatives, so the link is resolved before anything is read.
var caddyPaths = []string{
	"/usr/bin/caddy", "/usr/bin/caddy.*", "/usr/local/bin/caddy", "/usr/local/bin/caddy.*",
	"/usr/sbin/caddy", "/opt/caddy/caddy", "/opt/caddy/bin/caddy", "/opt/*/caddy",
}

// caddyPackageOrigin tells Ubuntu's caddy package from the one in Caddy's own
// apt repository. Ubuntu's version always has a Debian revision, such as
// 2.6.2-14 synced from Debian unchanged, while Caddy's is a plain 2.11.7.
func caddyPackageOrigin(version string) string {
	if strings.Contains(version, "-") {
		return "ubuntu"
	}
	return "upstream-repo"
}

// caddyInstance is one Caddy binary found on the host.
type caddyInstance struct {
	Where   string
	Origin  string // ubuntu, upstream-repo, compiled, container
	Version string // without "v", empty when unknown
	Go      string // the toolchain it was built with, such as go1.26.8
	Plugins []string
	// Modules maps every module in the build to its version without "v".
	// Replaced modules whose version cannot be known are left out.
	Modules map[string]string
}

// readBuildInfo parses the build information Go records in every binary. The
// file is read, never run, and anything but a regular file is refused.
func readBuildInfo(path string) (*debug.BuildInfo, error) {
	f, err := fsx.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return buildinfo.Read(f)
}

// caddyFromBuild returns what a build says about Caddy, and false when the
// binary is not Caddy.
func caddyFromBuild(info *debug.BuildInfo) (caddyInstance, bool) {
	inst := caddyInstance{Go: info.GoVersion, Modules: map[string]string{}}
	// Distribution builds record only the main package, such as
	// github.com/caddyserver/caddy/v2/cmd/caddy, and no modules.
	isCaddy := strings.HasPrefix(info.Main.Path, caddyModule) || strings.HasPrefix(info.Path, caddyModule)
	if isCaddy {
		inst.Version = govuln.ModuleVersion(info.Main.Version)
	}
	for _, d := range info.Deps {
		version := d.Version
		if d.Replace != nil {
			// A module swapped for a fork or a local copy is no longer the
			// version the database knows about.
			version = ""
			if d.Replace.Path == d.Path {
				version = d.Replace.Version
			}
		}
		v := govuln.ModuleVersion(version)
		if v != "" {
			inst.Modules[d.Path] = v
		}
		if d.Path == caddyModule {
			isCaddy = true
			if v != "" {
				inst.Version = v
			}
		}
		if !caddyStandardModules[d.Path] && strings.Contains(strings.ToLower(d.Path), "caddy") {
			label := d.Path + " " + d.Version
			if d.Replace != nil {
				label = d.Path + " replaced by " + strings.TrimSpace(d.Replace.Path+" "+d.Replace.Version)
			}
			inst.Plugins = append(inst.Plugins, label)
		}
	}
	sort.Strings(inst.Plugins)
	return inst, isCaddy
}

func caddyInstances(c *Context) []caddyInstance {
	var out []caddyInstance
	seen := map[string]bool{}
	var pkgVersion string
	if vs := c.PackageVersions()["caddy"]; len(vs) > 0 {
		pkgVersion = vs[0]
	}
	diverted := map[string]struct{}{}
	if o, err := c.Owners(); err == nil {
		diverted = o.Diverted
	}
	add := func(read, real, where string, inContainer bool) {
		info, err := readBuildInfo(read)
		if err != nil {
			return
		}
		inst, ok := caddyFromBuild(info)
		if !ok {
			return
		}
		inst.Where = where
		_, isDiverted := diverted[dpkg.NormalizePath(real)]
		switch {
		case inContainer:
			inst.Origin = "container"
		case c.Owned(real) && !isDiverted && pkgVersion != "":
			inst.Origin = caddyPackageOrigin(pkgVersion)
			if inst.Version == "" {
				inst.Version = upstreamOf(pkgVersion)
			}
		default:
			inst.Origin = "compiled"
		}
		out = append(out, inst)
	}
	if procs, err := c.Procs(); err == nil {
		for _, p := range procs {
			if p.KernelTh || p.Exe == "" || (base(p.Exe) != "caddy" && p.Comm != "caddy") {
				continue
			}
			key := p.Exe + "|" + strconv.FormatBool(p.InContainer)
			if seen[key] {
				continue
			}
			seen[key] = true
			where := "running pid " + strconv.Itoa(p.PID) + ", " + p.Exe
			if p.InContainer {
				where += " (in a container)"
			}
			// /proc/pid/exe opens the running binary, even inside a container.
			add("/proc/"+strconv.Itoa(p.PID)+"/exe", p.Exe, where, p.InContainer)
		}
	}
	for _, pat := range caddyPaths {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			real, err := filepath.EvalSymlinks(m)
			if err != nil || seen[real+"|false"] {
				continue
			}
			seen[real+"|false"] = true
			where := real
			if real != m {
				where = m + " -> " + real
			}
			add(real, real, where, false)
		}
	}
	return out
}

// caddyConfig is what the audit needs from one Caddy configuration.
type caddyConfig struct {
	Path   string
	Roots  []string
	Admin  []string // admin API addresses, including "off"
	Browse bool
}

// caddyTokens splits a Caddyfile line into tokens, keeping quoted text whole
// and dropping a comment.
func caddyTokens(line string) []string {
	var out []string
	var b strings.Builder
	var quote byte
	inToken := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case quote != 0:
			if ch == '\\' && quote == '"' && i+1 < len(line) {
				i++
				b.WriteByte(line[i])
			} else if ch == quote {
				quote = 0
			} else {
				b.WriteByte(ch)
			}
		case ch == '"' || ch == '`':
			quote, inToken = ch, true
		case ch == ' ' || ch == '\t':
			if inToken {
				out = append(out, b.String())
				b.Reset()
				inToken = false
			}
		case ch == '#' && !inToken:
			return out
		default:
			b.WriteByte(ch)
			inToken = true
		}
	}
	if inToken {
		out = append(out, b.String())
	}
	return out
}

// parseCaddyfile reads the directives that matter here. Snippets are scanned
// where they are defined, which covers what importing them would add. imports
// returns the files the Caddyfile imports.
func parseCaddyfile(src string) (cfg caddyConfig, imports []string) {
	var stack []string
	seenDirective := false
	heredocEnd := ""
	for _, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		if heredocEnd != "" {
			if strings.TrimSpace(raw) == heredocEnd {
				heredocEnd = ""
			}
			continue
		}
		tokens := caddyTokens(strings.TrimSpace(raw))
		for len(tokens) > 0 && tokens[0] == "}" {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			tokens = tokens[1:]
		}
		if len(tokens) == 0 {
			continue
		}
		// A heredoc's lines are text, not directives.
		if last := tokens[len(tokens)-1]; strings.HasPrefix(last, "<<") && len(last) > 2 {
			heredocEnd = last[2:]
		}
		opens := tokens[len(tokens)-1] == "{"
		args := tokens[1:]
		if opens && len(args) > 0 {
			args = args[:len(args)-1]
		}
		parent := ""
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		switch first := tokens[0]; {
		case first == "{" && len(stack) == 0 && !seenDirective:
			stack = append(stack, "global options")
			continue
		case first == "root" && len(args) > 0:
			cfg.Roots = append(cfg.Roots, args[len(args)-1])
		case first == "file_server":
			for _, a := range args {
				cfg.Browse = cfg.Browse || a == "browse"
			}
		case first == "browse" && parent == "file_server":
			cfg.Browse = true
		case first == "admin" && parent == "global options" && len(stack) == 1:
			if len(args) > 0 {
				cfg.Admin = append(cfg.Admin, args[0])
			}
		case first == "import" && len(args) > 0:
			imports = append(imports, args[0])
		}
		seenDirective = true
		if opens {
			stack = append(stack, tokens[0])
		}
	}
	return cfg, imports
}

// parseCaddyJSON reads Caddy's native configuration, which is also the form
// Caddy saves as autosave.json after adapting a Caddyfile.
func parseCaddyJSON(b []byte) (caddyConfig, error) {
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return caddyConfig{}, err
	}
	var cfg caddyConfig
	if admin, ok := doc["admin"].(map[string]any); ok {
		if off, _ := admin["disabled"].(bool); off {
			cfg.Admin = append(cfg.Admin, "off")
		} else if listen, ok := admin["listen"].(string); ok {
			cfg.Admin = append(cfg.Admin, listen)
		}
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if h, _ := x["handler"].(string); h == "file_server" {
				if _, ok := x["browse"]; ok {
					cfg.Browse = true
				}
			}
			for k, val := range x {
				if s, ok := val.(string); ok && k == "root" {
					cfg.Roots = append(cfg.Roots, s)
				}
				walk(val)
			}
		case []any:
			for _, val := range x {
				walk(val)
			}
		}
	}
	walk(doc)
	sort.Strings(cfg.Roots)
	return cfg, nil
}

// adminExposed reports an admin address reachable from other hosts. Caddy's
// default is localhost:2019.
func adminExposed(addr string) bool {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "tcp/")
	if addr == "" || addr == "off" || strings.HasPrefix(addr, "unix/") || strings.Contains(addr, "{") {
		return false
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if host == "localhost" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback()
	}
	return true // all interfaces when empty, or a name that resolves elsewhere
}

func isCaddyfile(path string) bool {
	name := filepath.Base(path)
	return strings.HasPrefix(name, "Caddyfile") || strings.HasSuffix(name, ".caddyfile")
}

// caddyConfigs finds the configurations Caddy runs with: what a running Caddy
// was given with --config, the autosave.json it keeps in its home, and the
// default /etc/caddy files. Files in a home directory belong to the account
// Caddy runs as, so links there are refused.
func caddyConfigs(c *Context) []caddyConfig {
	type source struct {
		path    string
		trusted bool
	}
	var sources []source
	homes := map[int]string{}
	if users, err := c.Users(); err == nil {
		for _, u := range users {
			homes[u.UID] = u.Home
		}
	}
	if procs, err := c.Procs(); err == nil {
		for _, p := range procs {
			if p.KernelTh || p.InContainer || (base(p.Exe) != "caddy" && p.Comm != "caddy") {
				continue
			}
			// A configuration outside /etc may sit where its owner can swap
			// in a link, so only those in /etc are followed through links.
			for i, a := range p.Cmdline {
				if v, ok := strings.CutPrefix(a, "--config="); ok {
					sources = append(sources, source{v, strings.HasPrefix(v, "/etc/")})
				} else if (a == "--config" || a == "-config") && i+1 < len(p.Cmdline) {
					v := p.Cmdline[i+1]
					sources = append(sources, source{v, strings.HasPrefix(v, "/etc/")})
				}
			}
			dirs := []string{}
			if v, ok := procinfo.Environ(p.PID, "XDG_CONFIG_HOME"); ok && v != "" {
				dirs = append(dirs, v)
			}
			if v, ok := procinfo.Environ(p.PID, "HOME"); ok && v != "" {
				dirs = append(dirs, filepath.Join(v, ".config"))
			}
			if h := homes[p.UID]; h != "" {
				dirs = append(dirs, filepath.Join(h, ".config"))
			}
			for _, d := range dirs {
				sources = append(sources, source{filepath.Join(d, "caddy", "autosave.json"), false})
			}
		}
	}
	sources = append(sources,
		source{"/etc/caddy/Caddyfile", true}, source{"/etc/caddy/caddy.json", true},
		source{"/var/lib/caddy/.config/caddy/autosave.json", false}, source{"/root/.config/caddy/autosave.json", true})

	var out []caddyConfig
	seen := map[string]bool{}
	var load func(path string, trusted bool, depth int)
	load = func(path string, trusted bool, depth int) {
		if !filepath.IsAbs(path) || seen[path] || depth > 8 || len(seen) > 256 {
			return
		}
		seen[path] = true
		var b []byte
		var err error
		if trusted {
			b, err = fsx.Read(path, 1<<20)
		} else {
			b, err = fsx.ReadNoFollow(path, 1<<20)
		}
		if err != nil {
			return
		}
		if !isCaddyfile(path) {
			if cfg, err := parseCaddyJSON(b); err == nil {
				cfg.Path = path
				out = append(out, cfg)
				return
			}
		}
		cfg, imports := parseCaddyfile(string(b))
		cfg.Path = path
		out = append(out, cfg)
		if !trusted {
			return
		}
		for _, imp := range imports {
			if !filepath.IsAbs(imp) {
				imp = filepath.Join(filepath.Dir(path), imp)
			}
			matches, _ := filepath.Glob(imp)
			for _, m := range matches {
				load(m, true, depth+1)
			}
		}
	}
	for _, s := range sources {
		load(filepath.Clean(s.path), s.trusted, 0)
	}
	return out
}

// caddyRoots returns the site roots of every Caddy configuration, for the
// webshell scan.
func caddyRoots(c *Context) []string {
	var roots []string
	for _, cfg := range caddyConfigs(c) {
		roots = append(roots, cfg.Roots...)
	}
	return roots
}

func caddyLabel(i caddyInstance) string {
	ver := i.Version
	if ver == "" {
		ver = "version unknown"
	}
	origin := originLabel(i.Origin)
	if i.Origin == "upstream-repo" {
		origin = "Caddy's apt repository"
	}
	if n := len(i.Plugins); n > 0 {
		origin += ", " + plural(n, "plugin")
	}
	line := fmt.Sprintf("caddy %s  [%s]  %s", ver, origin, i.Where)
	if i.Go != "" {
		line += "  built with " + i.Go
	}
	return line
}

func checkCaddy(c *Context) []model.Finding {
	const cat = model.CatWeb
	instances := caddyInstances(c)
	for _, i := range instances {
		c.AddInventory(model.InventoryItem{Name: "caddy", Version: i.Version, Source: i.Origin})
	}
	configs := caddyConfigs(c)
	var out []model.Finding
	if len(instances) == 0 {
		// A configuration with no binary still says what Caddy would expose.
		out = append(out, finding("web.caddy", cat, model.OK, "Caddy not found"))
	} else {
		var inv []string
		var external []caddyInstance
		for _, i := range instances {
			inv = append(inv, caddyLabel(i))
			for _, p := range i.Plugins {
				inv = append(inv, "    plugin "+p)
			}
			if i.Origin != "ubuntu" {
				external = append(external, i)
			}
		}
		summary := finding("web.caddy", cat, model.Info, fmt.Sprintf("Caddy copies found (%d)", len(instances)))
		summary.Detail = "Ubuntu's caddy package is judged by USN under the CVE category. Other builds, including those made with xcaddy, are compared against Go's vulnerability database. The version, Go toolchain and plugins come from the build information in the binary, which is read and never run."
		summary.Evidence = inv
		summary.Focus = true
		out = append(out, summary)
		if len(external) > 0 {
			out = append(out, caddyUpstreamFindings(c, external)...)
		}
	}
	return append(out, caddyConfigFindings(configs)...)
}

func caddyConfigFindings(configs []caddyConfig) []model.Finding {
	const cat = model.CatWeb
	var admin, browse []string
	for _, cfg := range configs {
		for _, a := range cfg.Admin {
			if adminExposed(a) {
				admin = append(admin, cfg.Path+": admin "+a)
			}
		}
		if cfg.Browse {
			browse = append(browse, cfg.Path)
		}
	}
	var out []model.Finding
	if len(admin) > 0 {
		f := finding("web.caddy.admin", cat, model.High, "Caddy's admin API is set to listen beyond localhost")
		f.Detail = "The admin API has no password. Anyone who reaches it can replace Caddy's whole configuration, for example to serve any file Caddy can read or to send traffic elsewhere."
		f.Evidence = uniqueStrings(admin)
		f.Remediation = "Remove the admin address or set admin localhost:2019, and block port 2019 at the firewall."
		out = append(out, f)
	}
	if len(browse) > 0 {
		f := finding("web.caddy.browse", cat, model.Medium, "Caddy has directory listing enabled (file_server browse)")
		f.Evidence = uniqueStrings(browse)
		f.Remediation = "Remove browse from file_server unless the listing is meant to be public."
		out = append(out, f)
	}
	return out
}

func caddyUpstreamFindings(c *Context, instances []caddyInstance) []model.Finding {
	const cat = model.CatWeb
	title := "Caddy vulnerability check"
	if c.Opts.Offline {
		return []model.Finding{requested("web.caddy.upstream", cat, title, "Offline mode, so Go's vulnerability database was not checked.")}
	}
	var buf bytes.Buffer
	err := fetch(c.Ctx, newHTTPClient(c.Opts.Proxy), govuln.DBURL, 64<<20, func(r io.Reader) error {
		buf.Reset()
		_, err := io.Copy(&buf, r)
		return err
	})
	if err != nil {
		return []model.Finding{skipped("web.caddy.upstream", cat, title, "Cannot get Go's vulnerability database: "+err.Error())}
	}
	db, err := govuln.Open(buf.Bytes())
	if err != nil {
		return []model.Finding{skipped("web.caddy.upstream", cat, title, "Cannot read Go's vulnerability database: "+err.Error())}
	}
	var out []model.Finding
	seen := map[string]bool{}
	for _, inst := range instances {
		key := caddyLabel(caddyInstance{Version: inst.Version, Go: inst.Go, Origin: inst.Origin}) + strings.Join(inst.Plugins, ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		goVersion := govuln.GoVersion(inst.Go)
		if inst.Version == "" && goVersion == "" {
			out = append(out, skipped("web.caddy.upstream", cat, "caddy ("+inst.Where+")", "Could not read the build information from the binary."))
			continue
		}
		var caddyHits, otherHits, stdHits []govuln.Entry
		var modules []string
		for m := range inst.Modules {
			modules = append(modules, m)
		}
		sort.Strings(modules)
		if inst.Version != "" {
			hits, err := db.Match(caddyModule, inst.Version)
			if err != nil {
				return append(out, skipped("web.caddy.upstream", cat, title, err.Error()))
			}
			caddyHits = append(caddyHits, hits...)
		}
		for _, m := range modules {
			if m == caddyModule {
				continue
			}
			hits, err := db.Match(m, inst.Modules[m])
			if err != nil {
				return append(out, skipped("web.caddy.upstream", cat, title, err.Error()))
			}
			if strings.Contains(strings.ToLower(m), "caddy") {
				caddyHits = append(caddyHits, hits...)
			} else {
				otherHits = append(otherHits, hits...)
			}
		}
		if goVersion != "" {
			hits, err := db.Match(govuln.Stdlib, goVersion)
			if err != nil {
				return append(out, skipped("web.caddy.upstream", cat, title, err.Error()))
			}
			stdHits = hits
		}
		out = append(out, caddyVulnFinding(inst, caddyHits, otherHits, stdHits, db.Modified))
	}
	return out
}

// caddyVulnFinding rates one build. Go's database does not rate severity, so
// Caddy and its plugins count as high and the rest as medium.
func caddyVulnFinding(inst caddyInstance, caddyHits, otherHits, stdHits []govuln.Entry, dbDate string) model.Finding {
	const cat = model.CatWeb
	ver := inst.Version
	if ver == "" {
		ver = "version unknown"
	}
	label := fmt.Sprintf("caddy %s (%s)", ver, originLabel(inst.Origin))
	if inst.Origin == "upstream-repo" {
		label = fmt.Sprintf("caddy %s (Caddy's apt repository)", ver)
	}
	total := len(caddyHits) + len(otherHits) + len(stdHits)
	if total == 0 {
		f := finding("web.caddy.upstream", cat, model.OK, label+" has no known vulnerabilities in Go's vulnerability database")
		f.Detail = "Checked Caddy, its modules and " + inst.Go + " against the database dated " + dbDate + "."
		return f
	}
	sev := model.Medium
	if len(caddyHits) > 0 {
		sev = model.High
	}
	var parts []string
	if n := len(caddyHits); n > 0 {
		parts = append(parts, fmt.Sprintf("%d in Caddy and its plugins", n))
	}
	if n := len(stdHits); n > 0 {
		parts = append(parts, fmt.Sprintf("%d in %s", n, inst.Go))
	}
	if n := len(otherHits); n > 0 {
		parts = append(parts, fmt.Sprintf("%d in other modules", n))
	}
	f := finding("web.caddy.upstream", cat, sev, fmt.Sprintf("%s has known vulnerabilities: %s", label, strings.Join(parts, ", ")))
	f.Detail = "Go's vulnerability database dated " + dbDate + " matches by version range and does not rate severity, so entries for Caddy and its plugins count as high and the rest as medium. Whether the vulnerable code is reachable depends on the configuration. Entries for Go and other modules go away only when Caddy is rebuilt with newer ones, so even the latest Caddy release can show them until the next one; xcaddy can rebuild with a newer Go now. This build gets no fixes through Ubuntu USNs."
	describe := func(e govuln.Entry, what string) string {
		id := e.ID
		for _, a := range e.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				id += " (" + a + ")"
				break
			}
		}
		fixed := "no fix yet"
		if e.Fixed != "" {
			fixed = "fixed in " + e.Fixed
		}
		return fmt.Sprintf("%s  %s %s, %s: %s", id, what, e.Version, fixed, e.Summary)
	}
	for _, e := range caddyHits {
		f.Evidence = append(f.Evidence, describe(e, e.Module))
	}
	for _, e := range stdHits {
		f.Evidence = append(f.Evidence, describe(e, "Go standard library"))
	}
	for _, e := range otherHits {
		f.Evidence = append(f.Evidence, describe(e, e.Module))
	}
	for _, list := range [][]govuln.Entry{caddyHits, stdHits, otherHits} {
		for _, e := range list {
			if len(f.Refs) < 5 {
				f.Refs = append(f.Refs, "https://pkg.go.dev/vuln/"+e.ID)
			}
		}
	}
	switch inst.Origin {
	case "upstream-repo":
		f.Remediation = "sudo apt update && sudo apt install --only-upgrade caddy, then restart Caddy."
	case "container":
		f.Remediation = "Pull a newer Caddy image and recreate the container."
	default:
		if len(inst.Plugins) > 0 {
			var with []string
			for _, p := range inst.Plugins {
				if name := strings.Fields(p)[0]; !strings.Contains(p, " replaced by ") {
					with = append(with, "--with "+name)
				}
			}
			f.Remediation = "Rebuild with the latest Caddy and Go: xcaddy build " + strings.Join(with, " ") + ", then replace the binary and restart Caddy."
		} else {
			f.Remediation = "Install the latest Caddy from caddyserver.com or GitHub, then restart Caddy."
		}
	}
	f.Focus = true
	return f
}
