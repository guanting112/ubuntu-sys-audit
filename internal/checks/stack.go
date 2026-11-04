package checks

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"ubuntu-sys-audit/internal/dpkg"
	"ubuntu-sys-audit/internal/eol"
	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/procinfo"
)

// The stack check lists the databases, language runtimes and servers on the
// host, with their versions and whether their release is past its end of
// life. It never runs them or connects to them: versions come from the dpkg
// database, install directories, container metadata and the bytes of the
// running binaries.

// stackProduct describes how to find one product.
type stackProduct struct {
	id   string // endoflife.date ID, also the product in JSON
	name string
	pkg  *regexp.Regexp // dpkg packages that hold the product itself
	exe  *regexp.Regexp // base names of its executables or process names
	env  []string       // variables official images set to its version
	// images are repositories without a registry, as in "postgres".
	images []string
	scan   []*regexp.Regexp // patterns that find the version in its binary
	// judgedBy names the check that already reports its end of life, so this
	// one only lists it.
	judgedBy string
}

func rx(s string) *regexp.Regexp { return regexp.MustCompile(s) }

// redisBuildID matches the build ID Redis and Valkey embed, which starts
// with prefix and the version. The patch number is matched lazily because the
// time that follows is digits too.
func redisBuildID(prefix string) string {
	lead := `\x00`
	if prefix != "" {
		lead = prefix
	}
	return lead + `(\d+\.\d+\.\d+?)(?:[A-Za-z0-9._-]{0,64}-)?\d{10}[01][0-9a-f]{8}\x00`
}

// stackProducts is in the order a process name is tried: MariaDB before
// MySQL, because older MariaDB also names its server mysqld.
var stackProducts = []*stackProduct{
	{id: "postgresql", name: "PostgreSQL", pkg: rx(`^postgresql-\d+(\.\d+)?$`), exe: rx(`^(postgres|postmaster)$`),
		env: []string{"PG_VERSION", "PG_MAJOR"}, images: []string{"postgres", "bitnami/postgresql", "postgis/postgis", "timescale/timescaledb"},
		scan: []*regexp.Regexp{rx(`PostgreSQL (\d+(?:\.\d+)+) on `)}},
	{id: "mariadb", name: "MariaDB", pkg: rx(`^mariadb-server(-core)?(-\d+\.\d+)?$`), exe: rx(`^(mariadbd|mysqld)$`),
		env: []string{"MARIADB_VERSION", "MARIADB_MAJOR"}, images: []string{"mariadb", "bitnami/mariadb"},
		// The NUL skips the example in the help text, 10.1.1-MariaDB-mariadb1precise-log.
		scan: []*regexp.Regexp{rx(`(\d+\.\d+\.\d+)-MariaDB\x00`)}},
	{id: "mysql", name: "MySQL", pkg: rx(`^(mysql-server-core-\d+\.\d+|mysql-server-\d+\.\d+|mysql-(community|commercial)-server-core)$`), exe: rx(`^mysqld$`),
		env: []string{"MYSQL_VERSION", "MYSQL_MAJOR"}, images: []string{"mysql", "mysql/mysql-server", "bitnami/mysql"},
		// Oracle's builds keep their source paths, as in mysql-8.0.36/sql/sql_parse.cc.
		scan: []*regexp.Regexp{rx(`mysql-(\d+\.\d+\.\d+)[/-]`)}},
	{id: "redis", name: "Redis", pkg: rx(`^redis-server$`), exe: rx(`^redis-server$`),
		env: []string{"REDIS_VERSION"}, images: []string{"redis", "bitnami/redis", "redis/redis-stack-server"},
		// The version sits before the INFO header, or starts the build ID:
		// the version, then the build host and a dash unless the build is
		// reproducible, as Debian's are, then a 10 digit time, a dirty flag
		// and 8 hex digits of git hash. 7.2.4buildkitsandbox-1715987884000000000
		// and 6.0.161790840090000000000 are both 7.2.4 and 6.0.16. Valkey keeps a
		// Redis version too, so processVersion tries Valkey's pattern first.
		scan: []*regexp.Regexp{rx(`(\d+\.\d+\.\d+)\x00+# Server\r\nredis_version`), rx(redisBuildID(""))}},
	{id: "valkey", name: "Valkey", pkg: rx(`^valkey-server$`), exe: rx(`^valkey-server$`),
		env: []string{"VALKEY_VERSION"}, images: []string{"valkey/valkey", "bitnami/valkey"},
		scan: []*regexp.Regexp{rx(redisBuildID("valkey"))}},
	{id: "mongodb", name: "MongoDB", pkg: rx(`^(mongodb-org-server|mongodb-enterprise-server|mongodb-server(-core)?)$`), exe: rx(`^mongod$`),
		// mongod holds its version once, between unrelated strings, so an
		// unpackaged one is listed with its version unknown.
		env: []string{"MONGO_VERSION"}, images: []string{"mongo", "bitnami/mongodb", "mongodb/mongodb-community-server"}},
	{id: "sqlite", name: "SQLite", pkg: rx(`^(libsqlite3-0|sqlite3)$`)},
	{id: "nodejs", name: "Node.js", pkg: rx(`^nodejs$`), exe: rx(`^(node|nodejs)$`),
		env: []string{"NODE_VERSION"}, images: []string{"node", "bitnami/node"},
		scan: []*regexp.Regexp{rx(`node-v(\d+\.\d+\.\d+)-headers`), rx(`release/v(\d+\.\d+\.\d+)/`)}},
	{id: "python", name: "Python", pkg: rx(`^python[23]\.\d+(-minimal)?$`), exe: rx(`^python[23](\.\d+)?$`),
		env: []string{"PYTHON_VERSION"}, images: []string{"python"}},
	{id: "ruby", name: "Ruby", pkg: rx(`^ruby\d\.\d+$`), exe: rx(`^ruby(\d+(\.\d+)*)?$`),
		env: []string{"RUBY_VERSION"}, images: []string{"ruby"}},
	{id: "php", name: "PHP", pkg: rx(`^php\d+\.\d+-(fpm|cli|cgi)$|^libapache2-mod-php\d+\.\d+$`), exe: rx(`^php(-fpm)?\d*(\.\d+)?$`),
		env: []string{"PHP_VERSION"}, images: []string{"php"}, scan: []*regexp.Regexp{phpScan, phpVerFall}, judgedBy: "web.php"},
	{id: "go", name: "Go", pkg: rx(`^golang-\d+\.\d+-go$`), env: []string{"GOLANG_VERSION"}, images: []string{"golang"}},
	{id: "eclipse-temurin", name: "Java (Eclipse Temurin)", pkg: rx(`^temurin-\d+-(jdk|jre)$`), images: []string{"eclipse-temurin"}},
	{id: "azul-zulu", name: "Java (Azul Zulu)", pkg: rx(`^zulu\d+(-ca)?-(jdk|jre)(-headless)?$`), images: []string{"azul/zulu-openjdk"}},
	{id: "amazon-corretto", name: "Java (Amazon Corretto)", pkg: rx(`^java-\d+-amazon-corretto-(jdk|jre)$`), images: []string{"amazoncorretto"}},
	{id: "oracle-jdk", name: "Java (Oracle JDK)", pkg: rx(`^jdk-\d+$`)},
	{id: "openjdk-builds-from-oracle", name: "Java (OpenJDK from Oracle)", images: []string{"openjdk"}},
	{id: "openjdk", name: "Java (OpenJDK)", pkg: rx(`^openjdk-\d+-(jre|jdk)(-headless)?$`), exe: rx(`^java$`)},
	{id: "nginx", name: "nginx", pkg: rx(`^(nginx|nginx-core|nginx-full|nginx-light|nginx-extras)$`), exe: rx(`^nginx$`),
		env: []string{"NGINX_VERSION"}, images: []string{"nginx", "bitnami/nginx"}, scan: []*regexp.Regexp{nginxScan}},
	{id: "apache-http-server", name: "Apache httpd", pkg: rx(`^apache2(-bin)?$`), exe: rx(`^(apache2|httpd)$`),
		env: []string{"HTTPD_VERSION"}, images: []string{"httpd", "bitnami/apache"}, scan: []*regexp.Regexp{rx(`Apache/(\d+\.\d+\.\d+)`)}},
	{id: "haproxy", name: "HAProxy", pkg: rx(`^haproxy$`), exe: rx(`^haproxy$`),
		env: []string{"HAPROXY_VERSION"}, images: []string{"haproxy", "bitnami/haproxy"},
		scan: []*regexp.Regexp{rx(`(\d+\.\d+\.\d+)[^ ,]*, released 20\d\d/\d\d/\d\d`)}},
	{id: "docker-engine", name: "Docker Engine", pkg: rx(`^(docker-ce|docker\.io|moby-engine)$`), exe: rx(`^dockerd$`)},
	{id: "containerd", name: "containerd", pkg: rx(`^(containerd\.io|containerd)$`), exe: rx(`^containerd$`)},
}

var stackByID = func() map[string]*stackProduct {
	m := map[string]*stackProduct{}
	for _, p := range stackProducts {
		m[p.id] = p
	}
	return m
}()

// bitnamiApps maps BITNAMI_APP_NAME to a product.
var bitnamiApps = map[string]string{
	"redis": "redis", "valkey": "valkey", "mysql": "mysql", "mariadb": "mariadb", "postgresql": "postgresql",
	"mongodb": "mongodb", "node": "nodejs", "python": "python", "ruby": "ruby", "php-fpm": "php", "php": "php",
	"nginx": "nginx", "apache": "apache-http-server", "haproxy": "haproxy",
}

// stackEntry is a StackItem plus what only the evidence lines need.
type stackEntry struct {
	model.StackItem
	tool string // the version manager that installed it
	// unconfirmed marks a package whose source neither apt's lists nor its
	// version can confirm. It is listed but not judged.
	unconfirmed bool
}

var (
	upstreamRepoPkg  = rx(`^(mysql-community-|mysql-commercial-|mongodb-org|mongodb-enterprise|docker-ce$|containerd\.io$|temurin-|zulu|java-\d+-amazon-corretto|jdk-\d+$)`)
	redisRepoVersion = rx(`\drl\d+~`)
	leadingVersion   = rx(`^\d+(?:\.\d+){0,3}`)
	containerIDRe    = rx(`[0-9a-f]{64}`)
)

// stackOrigin says where a package came from. The version alone misleads for
// some upstream repositories: Docker's and MySQL's write "ubuntu" into theirs.
func stackOrigin(pkg, version string) string {
	v := strings.ToLower(version)
	if upstreamRepoPkg.MatchString(pkg) || strings.Contains(v, "pgdg") || strings.Contains(v, "+maria~") ||
		strings.Contains(v, "nodesource") || redisRepoVersion.MatchString(v) {
		return "upstream-repo"
	}
	return dpkg.Origin(version)
}

// stackVersion reduces a package version, image tag or variable to the
// release version: 1:10.11.6+maria~ubu2204 is 10.11.6, jdk-21.0.2+13 is
// 21.0.2, and Java's 1.8.0_392 is 8.0.392.
func stackVersion(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i > 0 && i < 4 && allDigits(s[:i]) {
		s = s[i+1:]
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "jdk-"), "jdk")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "go"), "v")
	if rest, ok := strings.CutPrefix(s, "1.8.0"); ok {
		s = "8.0" + strings.Replace(rest, "_", ".", 1)
	}
	return leadingVersion.FindString(s)
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// imageRef splits an image reference into its repository, without a registry
// or the library/ prefix, and its tag.
func imageRef(image string) (repo, tag string) {
	image, _, _ = strings.Cut(image, "@")
	name := image
	if i := strings.LastIndexByte(image, ':'); i > strings.LastIndexByte(image, '/') {
		name, tag = image[:i], image[i+1:]
	}
	parts := strings.Split(name, "/")
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		parts = parts[1:]
	}
	if len(parts) == 2 && parts[0] == "library" {
		parts = parts[1:]
	}
	return strings.Join(parts, "/"), tag
}

// containerProducts finds what an image runs, from the variables official
// images set (PG_VERSION=16.1-1.pgdg120+1) or else from the image's tag.
func containerProducts(image string, env []string) map[string]string {
	vars := map[string]string{}
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			vars[k] = v
		}
	}
	found := map[string]string{}
	for _, p := range stackProducts {
		for _, k := range p.env {
			if v := stackVersion(vars[k]); v != "" {
				found[p.id] = v
				break
			}
		}
	}
	if id, ok := bitnamiApps[vars["BITNAMI_APP_NAME"]]; ok {
		if v := stackVersion(vars["APP_VERSION"]); v != "" {
			found[id] = v
		}
	}
	repo, tag := imageRef(image)
	for _, p := range stackProducts {
		for _, img := range p.images {
			if img == repo {
				if _, ok := found[p.id]; !ok {
					found[p.id] = stackVersion(tag)
				}
			}
		}
	}
	// Temurin images set JAVA_VERSION too; it is not a product variable
	// because other images use it for other builds.
	if v := vars["JAVA_VERSION"]; v != "" && strings.HasPrefix(v, "jdk") {
		found["eclipse-temurin"] = stackVersion(v)
	}
	return found
}

// javaVendor maps a JDK's IMPLEMENTOR or a version manager's name for it to a
// product.
func javaVendor(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "adoptium"), strings.Contains(l, "temurin"), strings.HasSuffix(l, "-tem"), strings.HasPrefix(l, "adoptopenjdk"):
		return "eclipse-temurin"
	case strings.Contains(l, "zulu"), strings.Contains(l, "azul"):
		return "azul-zulu"
	case strings.Contains(l, "corretto"), strings.Contains(l, "amazon"), strings.HasSuffix(l, "-amzn"):
		return "amazon-corretto"
	case strings.Contains(l, "oracle"):
		return "oracle-jdk"
	case strings.HasSuffix(l, "-open"), strings.HasPrefix(l, "openjdk"):
		return "openjdk-builds-from-oracle"
	}
	return "openjdk"
}

// dirsUnder lists the directories at rel below base. A symlink in any
// component of rel ends the walk, so a user cannot point it at someone else's
// files, and entries that are symlinks are skipped.
func dirsUnder(base, rel string) (string, []string) {
	p := base
	for _, part := range strings.Split(rel, "/") {
		p = filepath.Join(p, part)
		if st, err := os.Lstat(p); err != nil || !st.IsDir() {
			return p, nil
		}
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return p, nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && len(out) < 200 {
			out = append(out, e.Name())
		}
	}
	return p, out
}

// vmLayout is where a version manager keeps its installs.
type vmLayout struct {
	rel     string // below each home directory, or absolute
	product string // "java" is resolved per install
	tool    string
	prefix  string         // stripped from each entry
	only    *regexp.Regexp // entries that are releases, when the directory holds more
}

var vmLayouts = []vmLayout{
	{".nvm/versions/node", "nodejs", "nvm", "v", nil},
	{".local/share/fnm/node-versions", "nodejs", "fnm", "v", nil},
	{".volta/tools/image/node", "nodejs", "Volta", "", nil},
	{".asdf/installs/nodejs", "nodejs", "asdf", "", nil},
	{".pyenv/versions", "python", "pyenv", "", rx(`^\d+\.\d+\.\d+$`)},
	{".asdf/installs/python", "python", "asdf", "", rx(`^\d+\.\d+\.\d+$`)},
	{".rbenv/versions", "ruby", "rbenv", "", rx(`^\d+\.\d+\.\d+`)},
	{".rvm/rubies", "ruby", "RVM", "ruby-", rx(`^ruby-\d`)},
	{".asdf/installs/ruby", "ruby", "asdf", "", rx(`^\d`)},
	{".asdf/installs/golang", "go", "asdf", "", rx(`^\d`)},
	{"sdk", "go", "golang.org/dl", "go", rx(`^go\d`)},
	{".sdkman/candidates/java", "java", "SDKMAN!", "", rx(`^\d`)},
	{".asdf/installs/java", "java", "asdf", "", nil},
	{"/usr/local/n/versions/node", "nodejs", "n", "", nil},
	{"/usr/local/rvm/rubies", "ruby", "RVM", "ruby-", rx(`^ruby-\d`)},
}

// stackCollector gathers entries and merges what different sources say about
// the same installation.
type stackCollector struct {
	c       *Context
	entries []*stackEntry
	byKey   map[string]*stackEntry
	byPkg   map[string]*stackEntry // dpkg package name -> entry
	byID    map[string][]*stackEntry
	owners  *dpkg.Owners
	apt     *dpkg.AptIndex
	listen  map[uint64][]procinfo.Socket
}

// origin says where a package came from and whether that is confirmed. A
// marker in the name or version names the repository; otherwise apt's lists
// decide, and without them only a version that says "ubuntu" counts.
func (s *stackCollector) origin(pkg, version string) (string, bool) {
	heur := stackOrigin(pkg, version)
	if heur == "upstream-repo" || heur == "ondrej-ppa" {
		return heur, true
	}
	if ubuntu, known := s.apt.Origin(pkg, version); known {
		if ubuntu {
			return "ubuntu", true
		}
		if heur == "ubuntu" {
			heur = "third-party" // a PPA build can carry "ubuntu" in its version
		}
		return heur, true
	}
	return heur, heur != "third-party"
}

func (s *stackCollector) add(e stackEntry) *stackEntry {
	key := strings.Join([]string{e.Product, e.Version, e.Source, e.Path, e.Container}, "|")
	if old, ok := s.byKey[key]; ok {
		return old
	}
	n := e
	s.entries = append(s.entries, &n)
	s.byKey[key] = &n
	return &n
}

// stackCompanions are packages that own a product's running executable
// without being the product package: Ubuntu's redis-server runs
// redis-check-rdb from redis-tools.
var stackCompanions = map[string]bool{"redis-tools": true, "valkey-tools": true}

func (s *stackCollector) fromPackages() {
	pkgs, err := s.c.Packages()
	if err != nil {
		return
	}
	type match struct {
		pkg  dpkg.Package
		prod *stackProduct
	}
	var found []match
	want := map[string]bool{}
	for name := range stackCompanions {
		want[name] = true
	}
	for _, p := range pkgs {
		for _, prod := range stackProducts {
			if prod.pkg != nil && prod.pkg.MatchString(p.Name) {
				found = append(found, match{p, prod})
				want[p.Name] = true
				break
			}
		}
	}
	if len(found) > 0 {
		s.apt = dpkg.LoadAptIndex(s.c.Ctx, want)
	}
	for _, m := range found {
		source, confirmed := s.origin(m.pkg.Name, m.pkg.Version)
		e := s.add(stackEntry{StackItem: model.StackItem{
			Product: m.prod.id, Name: m.prod.name, Version: stackVersion(m.pkg.Version),
			Source: source, Package: m.pkg.Name,
		}, unconfirmed: !confirmed})
		s.byPkg[m.pkg.Name] = e
	}
}

func (s *stackCollector) fromVersionManagers() {
	var bases []string
	for _, u := range s.c.Homes() {
		bases = append(bases, u.Home)
	}
	if !contains(bases, "/root") {
		bases = append(bases, "/root")
	}
	for _, l := range vmLayouts {
		roots := bases
		rel := l.rel
		if filepath.IsAbs(l.rel) {
			roots, rel = []string{"/"}, strings.TrimPrefix(l.rel, "/")
		}
		for _, base := range roots {
			dir, names := dirsUnder(base, rel)
			for _, name := range names {
				if l.only != nil && !l.only.MatchString(name) {
					continue
				}
				id := l.product
				if id == "java" {
					id = javaVendor(name)
				}
				prod := stackByID[id]
				s.add(stackEntry{StackItem: model.StackItem{
					Product: id, Name: prod.name, Version: stackVersion(strings.TrimPrefix(name, l.prefix)),
					Source: "version-manager", Path: filepath.Join(dir, name),
				}, tool: l.tool})
			}
		}
	}
}

// fromSystemInstalls finds JDKs and Go toolchains unpacked by hand. Ubuntu's
// own JDKs and Go are packages and are skipped here.
func (s *stackCollector) fromSystemInstalls() {
	for _, pat := range []string{"/usr/lib/jvm/*/release", "/opt/*/release", "/usr/local/*/release"} {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			// /usr/lib/jvm/default-java links to a packaged JDK, which would
			// otherwise be listed again as unpackaged under the link's name.
			if st, err := os.Lstat(filepath.Dir(m)); err != nil || st.Mode()&os.ModeSymlink != 0 || s.c.Owned(m) {
				continue
			}
			if v, vendor := javaRelease(m); v != "" {
				prod := stackByID[javaVendor(vendor)]
				s.add(stackEntry{StackItem: model.StackItem{
					Product: prod.id, Name: prod.name, Version: v, Source: "unpackaged", Path: filepath.Dir(m),
				}})
			}
		}
	}
	for _, m := range []string{"/usr/local/go/VERSION"} {
		if s.c.Owned(m) {
			continue
		}
		if b, err := fsx.ReadNoFollow(m, 4096); err == nil {
			line, _, _ := strings.Cut(string(b), "\n")
			if v := stackVersion(line); v != "" {
				s.add(stackEntry{StackItem: model.StackItem{
					Product: "go", Name: "Go", Version: v, Source: "unpackaged", Path: filepath.Dir(m),
				}})
			}
		}
	}
}

var (
	javaVersionRe     = rx(`(?m)^JAVA_VERSION="([^"]+)"`)
	javaImplementorRe = rx(`(?m)^IMPLEMENTOR="([^"]+)"`)
)

// javaRelease reads a JDK's release file.
func javaRelease(path string) (version, implementor string) {
	b, err := fsx.ReadNoFollow(path, 64<<10)
	if err != nil {
		return "", ""
	}
	if m := javaVersionRe.FindSubmatch(b); m != nil {
		version = stackVersion(string(m[1]))
	}
	if m := javaImplementorRe.FindSubmatch(b); m != nil {
		implementor = string(m[1])
	}
	return version, implementor
}

// containerIDs maps Docker container IDs to their entries, for processes.
func (s *stackCollector) fromDocker() map[string][]*stackEntry {
	byContainer := map[string][]*stackEntry{}
	dirs, _ := filepath.Glob("/var/lib/docker/containers/*")
	for _, d := range dirs {
		if s.c.Ctx.Err() != nil {
			break
		}
		b, err := fsx.Read(filepath.Join(d, "config.v2.json"), 8<<20)
		if err != nil {
			continue
		}
		var cfg dockerConfig
		if json.Unmarshal(b, &cfg) != nil {
			continue
		}
		var hc dockerHostConfig
		if hb, err := fsx.Read(filepath.Join(d, "hostconfig.json"), 8<<20); err == nil {
			_ = json.Unmarshal(hb, &hc)
		}
		var published []string
		if cfg.State.Running && hc.NetworkMode != "host" {
			published = publishedPorts(cfg.NetworkSettings.Ports, hc.PortBindings)
		}
		name := strings.TrimPrefix(cfg.Name, "/")
		found := containerProducts(cfg.Config.Image, cfg.Config.Env)
		ids := make([]string, 0, len(found))
		for id := range found {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			e := s.add(stackEntry{StackItem: model.StackItem{
				Product: id, Name: stackByID[id].name, Version: found[id], Source: "container",
				Container: name, Image: cfg.Config.Image, Running: cfg.State.Running,
				Exposed: len(published) > 0, Listen: published,
			}})
			byContainer[filepath.Base(d)] = append(byContainer[filepath.Base(d)], e)
		}
	}
	return byContainer
}

// procGroup is the processes running one executable.
type procGroup struct {
	exe       string
	first     *procinfo.Process
	listen    []string
	exposed   bool
	container string // Docker container ID, from the cgroup
}

func (s *stackCollector) groupProcesses() []*procGroup {
	procs, err := s.c.Procs()
	if err != nil {
		return nil
	}
	byExe := map[string]*procGroup{}
	var out []*procGroup
	for _, p := range procs {
		if p.KernelTh || p.Exe == "" || s.productForProcess(p) == nil {
			continue
		}
		key := p.Exe + "|" + strconv.FormatBool(p.InContainer)
		cid := ""
		if p.InContainer {
			cid = containerIDOf(p.PID)
			key += "|" + cid + "|" + p.NetNS
		}
		g := byExe[key]
		if g == nil {
			g = &procGroup{exe: p.Exe, first: p, container: cid}
			byExe[key] = g
			out = append(out, g)
		}
		for _, ino := range p.Sockets {
			for _, sock := range s.listen[ino] {
				addr := netip.AddrPortFrom(sock.LocalIP, sock.LocalPort).String()
				if !contains(g.listen, addr) {
					g.listen = append(g.listen, addr)
				}
				if sock.HostNS && !sock.LocalIP.IsLoopback() {
					g.exposed = true
				}
			}
		}
	}
	return out
}

// productForProcess matches the executable's name, then the process name:
// Ubuntu's redis-server is a link to redis-check-rdb, and Redis renames its
// process, so the executable alone does not say Redis.
func (s *stackCollector) productForProcess(p *procinfo.Process) *stackProduct {
	names := []string{filepath.Base(p.Exe), p.Comm}
	if len(p.Cmdline) > 0 {
		first, _, _ := strings.Cut(p.Cmdline[0], " ")
		names = append(names, filepath.Base(first))
	}
	for _, n := range names {
		for _, prod := range stackProducts {
			if prod.exe != nil && prod.exe.MatchString(n) {
				return prod
			}
		}
	}
	return nil
}

func containerIDOf(pid int) string {
	b, err := fsx.ReadProc("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return ""
	}
	return containerIDRe.FindString(string(b))
}

func (s *stackCollector) fromProcesses(containers map[string][]*stackEntry) {
	for _, g := range s.groupProcesses() {
		if s.c.Ctx.Err() != nil {
			return
		}
		mark := func(e *stackEntry) {
			e.Running = true
			for _, a := range g.listen {
				if !contains(e.Listen, a) {
					e.Listen = append(e.Listen, a)
				}
			}
			e.Exposed = e.Exposed || g.exposed
		}
		p := g.first
		if es, ok := containers[g.container]; ok && g.container != "" {
			// What the container's metadata says is the better source; the
			// process adds only what it listens on, which matters for
			// containers on the host network.
			for _, e := range es {
				mark(e)
			}
			continue
		}
		if !p.InContainer {
			if e := s.underVersionManager(g.exe); e != nil {
				mark(e)
				continue
			}
			if pkg := s.owners.Package(g.exe); pkg != "" {
				mark(s.entryForPackage(pkg, s.productForProcess(p)))
				continue
			}
			if s.owners == nil || s.c.Owned(g.exe) {
				// Without the dpkg file lists, an executable cannot be told
				// apart from a self-installed one, so it is not listed.
				continue
			}
		}
		prod := s.productForProcess(p)
		version, id := processVersion(p, prod)
		e := stackEntry{StackItem: model.StackItem{
			Product: id, Name: stackByID[id].name, Version: version, Source: "unpackaged", Path: g.exe,
		}}
		if p.InContainer {
			e.Source = "container"
			e.Container = "pid " + strconv.Itoa(p.PID)
		}
		mark(s.add(e))
	}
}

// entryForPackage finds the entry for a package that owns a running
// executable, adding one when the package is not itself a product package:
// Ubuntu's Redis runs from redis-tools.
func (s *stackCollector) entryForPackage(pkg string, prod *stackProduct) *stackEntry {
	if e, ok := s.byPkg[pkg]; ok {
		return e
	}
	// mysqld is MariaDB's name too, so the owning package decides.
	if prod.id == "mariadb" && !strings.Contains(pkg, "mariadb") {
		prod = stackByID["mysql"]
	}
	version := ""
	for _, p := range s.pkgs() {
		if p.Name == pkg {
			version = p.Version
		}
	}
	source, confirmed := s.origin(pkg, version)
	e := s.add(stackEntry{StackItem: model.StackItem{
		Product: prod.id, Name: prod.name, Version: stackVersion(version), Source: source, Package: pkg,
	}, unconfirmed: !confirmed})
	s.byPkg[pkg] = e
	return e
}

func (s *stackCollector) pkgs() []dpkg.Package {
	p, _ := s.c.Packages()
	return p
}

func (s *stackCollector) underVersionManager(exe string) *stackEntry {
	for _, e := range s.entries {
		if e.Source == "version-manager" && strings.HasPrefix(exe, e.Path+"/") {
			return e
		}
	}
	return nil
}

var (
	pyVersionRe   = rx(`#define\s+PY_VERSION\s+"(\d+\.\d+\.\d+)`)
	rubyVersionRe = rx(`CONFIG\["RUBY_PROGRAM_VERSION"\] = "(\d+\.\d+\.\d+)"`)
	nodeMajorRe   = rx(`#define\s+NODE_MAJOR_VERSION\s+(\d+)`)
	nodeMinorRe   = rx(`#define\s+NODE_MINOR_VERSION\s+(\d+)`)
	nodePatchRe   = rx(`#define\s+NODE_PATCH_VERSION\s+(\d+)`)
)

// processVersion finds the version of a running executable that no package
// owns, and the product, which the binary can change: an unpackaged mysqld
// may be MariaDB, and a JDK says its vendor.
func processVersion(p *procinfo.Process, prod *stackProduct) (version, id string) {
	id = prod.id
	root := ""
	if p.InContainer {
		root = "/proc/" + strconv.Itoa(p.PID) + "/root"
	}
	exe := "/proc/" + strconv.Itoa(p.PID) + "/exe"
	switch prod.id {
	case "mariadb":
		if v := binaryVersion(exe, stackByID["mariadb"].scan[0]); v != "" {
			return v, "mariadb"
		}
		prod, id = stackByID["mysql"], "mysql"
	case "redis":
		if v := binaryVersion(exe, stackByID["valkey"].scan[0]); v != "" {
			return v, "valkey"
		}
	}
	prefix := root + filepath.Dir(filepath.Dir(p.Exe))
	readMatch := func(path string, re *regexp.Regexp) string {
		b, err := fsx.ReadNoFollow(path, 256<<10)
		if err != nil {
			return ""
		}
		if m := re.FindSubmatch(b); m != nil {
			return string(m[1])
		}
		return ""
	}
	switch id {
	case "postgresql":
		if dir := pgDataDir(p); dir != "" {
			if b, err := fsx.ReadNoFollow(filepath.Join(root+dir, "PG_VERSION"), 64); err == nil {
				version = stackVersion(string(b))
			}
		}
	case "python":
		heads, _ := filepath.Glob(prefix + "/include/python[23].*/patchlevel.h")
		for _, h := range heads {
			if v := readMatch(h, pyVersionRe); v != "" {
				version = v
				break
			}
		}
	case "ruby":
		confs, _ := filepath.Glob(prefix + "/lib/ruby/[0-9]*/*/rbconfig.rb")
		for _, c := range confs {
			if v := readMatch(c, rubyVersionRe); v != "" {
				version = v
				break
			}
		}
	case "nodejs":
		if b, err := fsx.ReadNoFollow(prefix+"/include/node/node_version.h", 64<<10); err == nil {
			ma, mi, pa := nodeMajorRe.FindSubmatch(b), nodeMinorRe.FindSubmatch(b), nodePatchRe.FindSubmatch(b)
			if ma != nil && mi != nil && pa != nil {
				version = string(ma[1]) + "." + string(mi[1]) + "." + string(pa[1])
			}
		}
	case "openjdk":
		for _, rel := range []string{prefix + "/release", filepath.Dir(prefix) + "/release"} {
			if v, vendor := javaRelease(rel); v != "" {
				return v, javaVendor(vendor)
			}
		}
	}
	if version != "" {
		return version, id
	}
	for _, re := range prod.scan {
		if v := binaryVersion(exe, re); v != "" {
			return v, id
		}
	}
	return "", id
}

// pgDataDir is the data directory a postgres process was started with.
func pgDataDir(p *procinfo.Process) string {
	for i, a := range p.Cmdline {
		switch {
		case a == "-D" && i+1 < len(p.Cmdline):
			return p.Cmdline[i+1]
		case strings.HasPrefix(a, "-D") && len(a) > 2:
			return a[2:]
		}
	}
	if v, ok := procinfo.Environ(p.PID, "PGDATA"); ok {
		return v
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func collectStack(c *Context) []*stackEntry {
	s := &stackCollector{
		c: c, byKey: map[string]*stackEntry{}, byPkg: map[string]*stackEntry{}, listen: map[uint64][]procinfo.Socket{},
	}
	if o, err := c.Owners(); err == nil {
		s.owners = o
	}
	if view := c.Net(); view != nil {
		for _, sock := range view.Sockets {
			if (sock.Proto == "tcp" || sock.Proto == "tcp6") && sock.State == procinfo.StateListen {
				s.listen[sock.Inode] = append(s.listen[sock.Inode], sock)
			}
		}
	}
	s.fromPackages()
	s.fromVersionManagers()
	s.fromSystemInstalls()
	containers := s.fromDocker()
	s.fromProcesses(containers)
	return s.entries
}

// stackWindow is how far ahead an end of life is announced.
const stackWindow = 90 * 24 * time.Hour

// judgeStack sets the cycle, end of life and status of an entry. Ubuntu's
// own packages are not judged by upstream dates: Ubuntu backports security
// fixes into them, which the CVE check and system.os cover.
func judgeStack(e *stackEntry, now time.Time) {
	rel, ok := eol.Lookup(e.Product, e.Version)
	if ok {
		e.Cycle = rel.Cycle
	}
	switch {
	case e.Source == "ubuntu":
		e.Status = "ubuntu"
	case e.Version == "" || !ok || e.unconfirmed:
		e.Status = "unknown"
	default:
		e.EOL = rel.EOL
		switch rel.At(now, stackWindow) {
		case eol.Ended:
			e.Status = "eol"
		case eol.Ending:
			e.Status = "eol-soon"
		default:
			e.Status = "supported"
		}
	}
}

func stackSourceLabel(e *stackEntry) string {
	switch e.Source {
	case "version-manager":
		return e.tool
	case "unpackaged":
		return "not packaged"
	case "container":
		return "container"
	}
	if e.unconfirmed {
		return "package of unconfirmed origin"
	}
	return originLabel(e.Source)
}

// line is one evidence line, as in
// "PostgreSQL 16.4  Ubuntu package postgresql-16, running, listening on 127.0.0.1:5432".
func (e *stackEntry) line() string {
	version := e.Version
	if version == "" {
		version = "(version unknown)"
	}
	var parts []string
	label := stackSourceLabel(e)
	switch {
	case e.Package != "":
		parts = append(parts, label+" "+e.Package)
	case e.Container != "" && e.Image != "":
		parts = append(parts, "container "+e.Container+" ("+e.Image+")")
	case e.Container != "":
		parts = append(parts, "in a container, "+e.Container+", "+e.Path)
	default:
		parts = append(parts, label+", "+e.Path)
	}
	if e.Running {
		parts = append(parts, "running")
	}
	if len(e.Listen) > 0 {
		verb := "listening on "
		if e.Source == "container" && e.Image != "" {
			verb = "published on "
		}
		parts = append(parts, verb+strings.Join(e.Listen, ", "))
	}
	switch e.Status {
	case "eol":
		if e.EOL != "" {
			parts = append(parts, "end of life since "+e.EOL)
		} else {
			parts = append(parts, "past end of life")
		}
	case "eol-soon":
		parts = append(parts, "end of life on "+e.EOL)
	case "supported":
		if e.EOL != "" {
			parts = append(parts, "supported until "+e.EOL)
		} else {
			parts = append(parts, "supported")
		}
	case "ubuntu":
		parts = append(parts, "judged by Ubuntu's security updates, not upstream dates")
	}
	return e.Name + " " + version + "  " + strings.Join(parts, ", ")
}

func checkStack(c *Context) []model.Finding {
	const cat = model.CatStack
	entries := collectStack(c)
	now := time.Now()
	for _, e := range entries {
		judgeStack(e, now)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if a, b := strings.ToLower(entries[i].Name), strings.ToLower(entries[j].Name); a != b {
			return a < b
		}
		return dpkg.Compare(entries[i].Version, entries[j].Version) < 0
	})
	items := make([]model.StackItem, len(entries))
	for i, e := range entries {
		items[i] = e.StackItem
	}
	c.AddStack(items...)

	if len(entries) == 0 {
		f := finding("stack.inventory", cat, model.Info, "No databases, language runtimes or servers found")
		if !c.Host.IsRoot {
			f.Detail = "Run with sudo to see other users' installs and every process."
		}
		return []model.Finding{f}
	}
	inv := finding("stack.inventory", cat, model.Info, fmt.Sprintf("Tech stack (%d components)", len(entries)))
	inv.Detail = "Databases, language runtimes and servers, from packages, install directories, containers and running processes. " +
		"End of life dates are from endoflife.date, as of " + eol.Generated() + ". " +
		"Ubuntu's own packages are not judged by them: Ubuntu backports security fixes into its packages, which the CVE check covers."
	if !c.Host.IsRoot {
		inv.Detail += " Run with sudo to see other users' installs and every process."
	}
	for _, e := range entries {
		inv.Evidence = append(inv.Evidence, e.line())
	}
	inv.Focus = true
	return append([]model.Finding{inv}, stackEOLFindings(entries, now)...)
}

func stackEOLFindings(entries []*stackEntry, now time.Time) []model.Finding {
	const cat = model.CatStack
	ended, ending := map[string][]*stackEntry{}, map[string][]*stackEntry{}
	for _, e := range entries {
		if stackByID[e.Product] == nil || stackByID[e.Product].judgedBy != "" {
			continue
		}
		switch e.Status {
		case "eol":
			ended[e.Product] = append(ended[e.Product], e)
		case "eol-soon":
			ending[e.Product] = append(ending[e.Product], e)
		}
	}
	var out []model.Finding
	for _, id := range sortedKeys(ended) {
		es := ended[id]
		prod := stackByID[id]
		sev := model.Medium
		inContainer := false
		eolOf := map[string]string{}
		var cycles []string
		for _, e := range es {
			if e.Exposed {
				sev = model.High
			}
			if e.Source == "container" {
				inContainer = true
			}
			if _, seen := eolOf[e.Cycle]; !seen {
				cycles = append(cycles, e.Cycle)
				eolOf[e.Cycle] = e.EOL
			}
		}
		sort.Slice(cycles, func(i, j int) bool { return dpkg.Compare(cycles[i], cycles[j]) < 0 })
		var dates []string
		for _, c := range cycles {
			when := "an unknown date"
			if eolOf[c] != "" {
				when = eolOf[c]
			}
			dates = append(dates, c+" on "+when)
		}
		verb := "is"
		if len(cycles) > 1 {
			verb = "are"
		}
		f := finding("stack.eol", cat, sev, fmt.Sprintf("%s %s %s past end of life", prod.name, joinAnd(cycles), verb))
		f.Detail = fmt.Sprintf("Upstream stopped security fixes for %s %s, so new vulnerabilities in it stay open.", prod.name, joinAnd(dates))
		if sev == model.High {
			f.Detail += " At least one accepts connections from beyond this host, which makes such a flaw reachable over the network."
		}
		f.Remediation = "Upgrade to a maintained release"
		if m := eol.Maintained(id, now); len(m) > 0 {
			if len(m) > 3 {
				m = m[:3]
			}
			f.Remediation += " (" + joinOr(m) + ")"
		}
		f.Remediation += "."
		if inContainer {
			f.Remediation += " For a container, move it to a maintained image tag."
		}
		for _, e := range es {
			f.Evidence = append(f.Evidence, e.line())
		}
		f.Focus = true
		out = append(out, f)
	}
	for _, id := range sortedKeys(ending) {
		es := ending[id]
		prod := stackByID[id]
		f := finding("stack.eol_soon", cat, model.Info, fmt.Sprintf("%s %s reaches end of life on %s", prod.name, es[0].Cycle, es[0].EOL))
		f.Detail = "Plan the upgrade: after this date upstream ships no more security fixes for it."
		for _, e := range es {
			f.Evidence = append(f.Evidence, e.line())
		}
		out = append(out, f)
	}
	return out
}

func sortedKeys(m map[string][]*stackEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func joinWith(list []string, word string) string {
	switch len(list) {
	case 0:
		return ""
	case 1:
		return list[0]
	}
	return strings.Join(list[:len(list)-1], ", ") + " " + word + " " + list[len(list)-1]
}

func joinAnd(list []string) string { return joinWith(list, "and") }
func joinOr(list []string) string  { return joinWith(list, "or") }
