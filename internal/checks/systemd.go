package checks

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
)

// unitLineEnds lists what systemd's line reader ends a line on. A bare CR or NUL
// counts, so splitting on LF alone would let "# note\rExecStart=/tmp/x" pass as a
// comment.
var unitLineEnds = strings.NewReplacer("\r\n", "\n", "\r", "\n", "\x00", "\n")

// logicalLines returns a file's lines the way systemd reads a unit: a trailing
// backslash joins the next line, and comment lines inside a continuation are
// skipped without ending it. An escaped backslash does not continue, and neither
// does a backslash followed by a space.
func logicalLines(src string) []string {
	var out []string
	var cur strings.Builder
	for _, raw := range strings.Split(unitLineEnds.Replace(src), "\n") {
		line := strings.TrimLeft(raw, " \t")
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		slashes := len(line) - len(strings.TrimRight(line, `\`))
		if slashes%2 == 1 {
			cur.WriteString(line[:len(line)-1])
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(line)
		out = append(out, strings.TrimSpace(cur.String()))
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// execPrefixes are the characters systemd accepts before a command's path.
const execPrefixes = "-@:+!|"

type unitExec struct {
	key string
	raw string // as written, including prefixes
	cmd string // for display, with prefixes removed
}

type parsedUnit struct {
	execs       []unitExec
	environment []string
	envFiles    []string
}

var envKeyRe = regexp.MustCompile(`^(Environment|EnvironmentFile)\s*=\s*(.*)$`)

// parseUnit keeps the keys this check needs. Sections are ignored on purpose: a
// command in the wrong section does not run, but it is still worth reading.
// "ExecStart=" with no value only clears earlier lines, so it is dropped.
func parseUnit(src string) parsedUnit {
	var u parsedUnit
	for _, line := range logicalLines(src) {
		if m := execKeyRe.FindStringSubmatch(line); m != nil {
			if m[2] != "" {
				u.execs = append(u.execs, unitExec{key: m[1], raw: m[2], cmd: strings.TrimLeft(m[2], execPrefixes)})
			}
		} else if m := envKeyRe.FindStringSubmatch(line); m != nil && m[2] != "" {
			if m[1] == "Environment" {
				u.environment = append(u.environment, m[2])
			} else {
				u.envFiles = append(u.envFiles, m[2])
			}
		}
	}
	return u
}

type unitWord struct {
	text   string
	quoted bool
}

// unitWords splits a value the way systemd does: whitespace separates words,
// quotes group them and C-style escapes are decoded, so "/\x74mp/x" is /tmp/x.
func unitWords(s string) []unitWord {
	var out []unitWord
	var b strings.Builder
	var quote byte
	inWord, quoted := false, false
	flush := func() {
		if inWord {
			out = append(out, unitWord{b.String(), quoted})
		}
		b.Reset()
		inWord, quoted = false, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			text, n := unitEscape(s[i+1:])
			b.WriteString(text)
			i += n
			inWord, quoted = true, true
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				b.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote = c
			inWord, quoted = true, true
		case c == ' ' || c == '\t' || c == '\n':
			flush()
		default:
			b.WriteByte(c)
			inWord = true
		}
	}
	flush()
	return out
}

var unitEscapes = map[byte]string{'a': "\a", 'b': "\b", 'f': "\f", 'n': "\n", 'r': "\r", 's': " ", 't': "\t", 'v': "\v"}

// unitEscape decodes the escape that follows a backslash and returns its text
// and how many bytes it used. Anything unknown stands for itself.
func unitEscape(s string) (string, int) {
	if text, ok := unitEscapes[s[0]]; ok {
		return text, 1
	}
	number := func(digits, base int) (string, int, bool) {
		start := 1
		if base == 8 {
			start = 0
		}
		if len(s) < start+digits {
			return "", 0, false
		}
		v, err := strconv.ParseUint(s[start:start+digits], base, 32)
		if err != nil {
			return "", 0, false
		}
		if digits > 3 {
			return string(rune(v)), start + digits, true
		}
		return string([]byte{byte(v)}), start + digits, true
	}
	var text string
	var n int
	var ok bool
	switch {
	case s[0] == 'x':
		text, n, ok = number(2, 16)
	case s[0] == 'u':
		text, n, ok = number(4, 16)
	case s[0] == 'U':
		text, n, ok = number(8, 16)
	case s[0] >= '0' && s[0] <= '7':
		text, n, ok = number(3, 8)
	}
	if ok {
		return text, n
	}
	return s[:1], 1
}

// execCommand is one command from an Exec value, with its prefixes removed and a
// separate argv[0] dropped. words[0] is the program.
type execCommand struct{ words []string }

// text rejoins the words with the quoting the signature patterns expect, because
// transient units write every argument in quotes: "bash" "-i".
func (c execCommand) text() string {
	parts := make([]string, len(c.words))
	for i, w := range c.words {
		parts[i] = w
		if strings.ContainsAny(w, " \t") {
			parts[i] = "'" + w + "'"
		}
	}
	return strings.Join(parts, " ")
}

// parseExecValue splits an Exec value into commands. A lone unquoted semicolon
// separates them, and only the first would run if a check read one program.
func parseExecValue(value string) []execCommand {
	var out []execCommand
	var cur []string
	flush := func() {
		if len(cur) == 0 {
			return
		}
		program := strings.TrimLeft(cur[0], execPrefixes)
		prefixes := cur[0][:len(cur[0])-len(program)]
		rest := cur[1:]
		if strings.Contains(prefixes, "@") && len(rest) > 0 {
			rest = rest[1:]
		}
		if program != "" {
			out = append(out, execCommand{append([]string{program}, rest...)})
		}
		cur = nil
	}
	for _, w := range unitWords(value) {
		if w.text == ";" && !w.quoted {
			flush()
			continue
		}
		cur = append(cur, w.text)
	}
	flush()
	return out
}

var (
	shellProgram = regexp.MustCompile(`^(sh|bash|dash|ash|ksh|zsh|fish)$`)
	interpreter  = regexp.MustCompile(`^(sh|bash|dash|ash|ksh|zsh|fish|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|node|nodejs|lua[0-9.]*)$`)
	// These run the program named in their arguments. flock is not one: its first
	// argument is a lock file, and /tmp is a usual place for those.
	wrapperProgram = regexp.MustCompile(`^(env|nohup|setsid|nice|ionice|chrt|taskset|timeout|stdbuf|sudo|runuser|exec|command|\.|source)$`)
	// A priority, CPU mask or duration given to a wrapper, not a program.
	wrapperNumber  = regexp.MustCompile(`^[0-9][0-9a-fx.,smhd-]*$`)
	shellSeparator = regexp.MustCompile("[;&|\n()`{}]")
	shellKeyword   = regexp.MustCompile(`^(then|do|else|if|elif|while|until|!)$`)
	shellAssign    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

const maxExecNesting = 8

// execTargets lists the programs a command ends up running: its own, a script
// given to an interpreter, and what a wrapper or "sh -c" launches. Arguments are
// not targets, so "foo --pidfile /tmp/foo.pid" does not count as running /tmp.
func execTargets(words []string, depth int) []string {
	if len(words) == 0 || depth > maxExecNesting {
		return nil
	}
	out := []string{words[0]}
	name := filepath.Base(words[0])
	rest := words[1:]
	switch {
	case wrapperProgram.MatchString(name):
		for i := 0; i < len(rest); i++ {
			w := rest[i]
			switch {
			case w == "-u" || w == "-g" || w == "-a":
				i++ // these take a value: sudo -u bob, env -u NAME, exec -a name
			case strings.HasPrefix(w, "-"), shellAssign.MatchString(w), wrapperNumber.MatchString(w):
			default:
				return append(out, execTargets(rest[i:], depth+1)...)
			}
		}
	case interpreter.MatchString(name):
		for i, w := range rest {
			if !strings.HasPrefix(w, "-") {
				// The script. Later words are its arguments, so only this one counts.
				return append(out, w)
			}
			if shellProgram.MatchString(name) && !strings.HasPrefix(w, "--") && strings.Contains(w, "c") {
				if i+1 < len(rest) {
					for _, cmd := range shellCommands(rest[i+1]) {
						out = append(out, execTargets(cmd, depth+1)...)
					}
				}
				return out
			}
		}
	}
	return out
}

// shellCommands finds the words at command position in a shell script. It is a
// rough split, good enough to see which programs a one-liner starts.
func shellCommands(script string) [][]string {
	var out [][]string
	for _, segment := range shellSeparator.Split(script, -1) {
		f := strings.Fields(segment)
		for i := range f {
			f[i] = strings.Trim(f[i], `'"`)
		}
		for len(f) > 0 && (shellKeyword.MatchString(f[0]) || shellAssign.MatchString(f[0])) {
			f = f[1:]
		}
		if len(f) > 0 {
			out = append(out, f)
		}
	}
	return out
}

// matchExec applies the signature patterns to the value as written and to its
// decoded commands, so quoting or escapes cannot hide a pattern.
func matchExec(raw string) string {
	if name := matchMalicious(raw); name != "" {
		return name
	}
	for _, c := range parseExecValue(raw) {
		if name := matchMalicious(c.text()); name != "" {
			return name
		}
	}
	return ""
}

// expandSpecifiers resolves the unit specifiers that decide where a path is. %T
// and %V are the temp directories, so they can hide a temp path as well as any
// shell variable could. home is empty for units outside a home directory.
func expandSpecifiers(s, home string) string {
	pairs := []string{"%%", "%", "%T", "/tmp", "%V", "/var/tmp"}
	if home != "" {
		pairs = append(pairs, "%h", home)
	}
	return strings.NewReplacer(pairs...).Replace(s)
}

// execSearchPath is where systemd looks for a program given without a path.
var execSearchPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// unitSearchDirs lists system unit directories from highest priority to lowest.
var unitSearchDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}

// homeUnitDirs are where systemd looks for a user's own units.
var homeUnitDirs = []string{".config/systemd/user", ".local/share/systemd/user"}

const lingerDir = "/var/lib/systemd/linger"

// netplanWaitOnline is written by "netplan generate" on every host that uses it,
// and overrides the ExecStart of systemd-networkd-wait-online with the same
// program. Reporting it would add one Medium to nearly every Ubuntu server.
const netplanWaitOnline = "/run/systemd/system/systemd-networkd-wait-online.service.d/10-netplan.conf"

func generatorDirs() []string {
	var dirs []string
	for _, prefix := range []string{"/etc/systemd", "/run/systemd", "/usr/local/lib/systemd", "/usr/lib/systemd", "/lib/systemd"} {
		for _, kind := range []string{"system-generators", "user-generators", "system-environment-generators", "user-environment-generators"} {
			dirs = append(dirs, prefix+"/"+kind)
		}
	}
	return dirs
}

func wantedUnit(name string) bool {
	return strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".conf") ||
		strings.HasSuffix(name, ".timer") || strings.HasSuffix(name, ".path") || strings.HasSuffix(name, ".socket")
}

func wantedTransient(name string) bool {
	return strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".timer")
}

type unitKind int

const (
	unitInstalled unitKind = iota // in a unit directory on the host
	unitGenerated                 // written by a generator at boot
	unitTransient                 // created through the API
	unitHome                      // in a user's home directory
)

// systemdScan holds the state of one systemd check. Paths are as the host sees
// them, and root is prepended only to touch the filesystem, which lets tests use
// a fake tree while paths such as /tmp still classify correctly.
type systemdScan struct {
	ctx       context.Context
	root      string
	owned     func(string) bool
	ownersErr error
	users     []User
	homes     []User
	cutoff    time.Time

	seen      map[string]bool
	walked    map[string]bool
	originals map[string]string
	scanned   int

	malicious, tempExec, unowned, transient []string
	generatorCritical, generatorUnowned     []string
	envInject, envTemp, envLinks            []string
	dropinCritical, dropinUnowned           []string
	dropinPackage                           []string
	links, truncated, linger, lingerUnits   []string
	// homeUnits maps a cleaned home directory to its units outside any package.
	homeUnits map[string][]string
}

func newSystemdScan(ctx context.Context, owned func(string) bool, users, homes []User) *systemdScan {
	return &systemdScan{
		ctx:       ctx,
		owned:     owned,
		users:     users,
		homes:     homes,
		cutoff:    time.Now().Add(-7 * 24 * time.Hour),
		seen:      map[string]bool{},
		walked:    map[string]bool{},
		originals: map[string]string{},
		homeUnits: map[string][]string{},
	}
}

func (s *systemdScan) run() []model.Finding {
	for _, dir := range systemdDirs {
		s.walkUnits(dir, unitInstalled, wantedUnit)
	}
	for _, dir := range generatedUnitDirs {
		s.walkUnits(dir, unitGenerated, wantedUnit)
	}
	s.walkUnits(transientUnitDir, unitTransient, wantedTransient)
	for _, u := range s.homes {
		s.scanHome(u)
	}
	s.scanGenerators()
	s.scanLinger()
	return s.findings()
}

// logical turns a real path back into the host's view of it.
func (s *systemdScan) logical(full string) string {
	if s.root != "" && strings.HasPrefix(full, s.root+"/") {
		return strings.TrimPrefix(full, s.root)
	}
	return full
}

// linkTarget resolves a path without opening it. A target that does not exist
// yet still matters: anyone can create a file in /tmp, so a dangling link there
// is as dangerous as a live one. The bool reports that nothing exists to read.
func (s *systemdScan) linkTarget(p string) (string, bool) {
	if real, err := filepath.EvalSymlinks(s.root + p); err == nil {
		return s.logical(real), false
	}
	cur := p
	for range 40 {
		target, err := os.Readlink(s.root + cur)
		if err != nil {
			break
		}
		if filepath.IsAbs(target) {
			cur = filepath.Clean(target)
		} else {
			cur = filepath.Join(filepath.Dir(cur), target)
		}
	}
	return cur, true
}

// walkUnits scans one unit directory. Resolving it first means a merged /usr or
// /etc/xdg/systemd/user, a link to /etc/systemd/user, is walked once. WalkDir
// alone would not enter a directory that is a symlink.
func (s *systemdScan) walkUnits(dir string, kind unitKind, want func(string) bool) {
	real, _ := s.linkTarget(dir)
	if s.walked[real] {
		return
	}
	s.walked[real] = true
	if inTemp(real + "/") {
		s.tempExec = append(s.tempExec, dir+" is a unit directory linked to a temp directory: "+real)
	}
	_ = filepath.WalkDir(s.root+real, func(full string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if s.ctx.Err() != nil {
			return filepath.SkipAll
		}
		p := s.logical(full)
		switch {
		case !want(d.Name()):
		case d.Type().IsRegular():
			s.readUnit(p, p, kind)
		case d.Type()&fs.ModeSymlink != 0:
			s.scanLinked(p, kind)
		}
		return nil
	})
}

// scanLinked handles a unit that is a symlink. Enablement links point at units
// scanned at their real path anyway. systemctl link can point anywhere, so a
// target outside the unit directories gets scanned here, or it would be missed.
func (s *systemdScan) scanLinked(p string, kind unitKind) {
	real, dangling := s.linkTarget(p)
	if real == "/dev/null" {
		return
	}
	if inTemp(real) {
		s.tempExec = append(s.tempExec, p+" is a unit file in a temp directory: "+real)
	}
	if dangling {
		return
	}
	// A drop-in takes effect where the link is, whatever it points at.
	_, isDropin := dropinUnit(p)
	switch {
	case isDropin:
		s.readUnit(p, real, kind)
	case !isSystemdPath(real):
		s.readUnit(real, real, kind)
	}
}

// readUnit reads a unit at a path that was already resolved or seen to be a
// regular file, so refusing a symlink here only closes a swap in between.
func (s *systemdScan) readUnit(display, path string, kind unitKind) {
	if s.seen[display] {
		return
	}
	s.seen[display] = true
	if b, err := fsx.ReadNoFollow(s.root+path, persistLimit); err == nil {
		s.checkUnit(display, b, kind, "")
	}
}

func (s *systemdScan) checkUnit(path string, b []byte, kind unitKind, home string) {
	s.scanned++
	if len(b) >= persistLimit {
		s.truncated = append(s.truncated, path)
	}
	u := parseUnit(string(b))
	// No package can own what only exists at run time.
	runtimeOnly := kind == unitGenerated || kind == unitTransient
	owned := !runtimeOnly && s.owned(path)
	unit, base, isDropin := "", "", false
	if kind == unitInstalled && !owned && s.ownersErr == nil {
		unit, base, isDropin = s.packageUnitOf(path)
	}
	var listed, replaced []string
	for _, e := range u.execs {
		if isDropin && e.key == "ExecStart" {
			replaced = append(replaced, e.raw)
			continue
		}
		listed = append(listed, e.cmd)
		s.judgeExec(path, e, home)
	}
	if len(replaced) > 0 {
		s.judgeDropin(path, unit, base, replaced)
	}
	if kind == unitGenerated {
		return
	}
	s.judgeEnvironment(path, u, owned, home)
	if kind == unitTransient {
		for _, cmd := range listed {
			s.transient = append(s.transient, path+": "+cmd)
		}
		return
	}
	if owned {
		return
	}
	first := ""
	if len(listed) > 0 {
		first = listed[0]
	}
	if kind == unitHome {
		entry := path
		if first != "" {
			entry += " -> " + first
		}
		s.homeUnits[home] = append(s.homeUnits[home], entry)
	}
	if first != "" && s.ownersErr == nil {
		s.unowned = append(s.unowned, s.recent(path)+path+" -> "+first)
	}
}

func (s *systemdScan) recent(path string) string {
	if st, err := os.Lstat(s.root + path); err == nil && st.ModTime().After(s.cutoff) {
		return "(modified in the last 7 days) "
	}
	return ""
}

func (s *systemdScan) judgeExec(path string, e unitExec, home string) {
	if name := matchExec(e.raw); name != "" {
		s.malicious = append(s.malicious, fmt.Sprintf("%s (%s): %s", path, name, e.cmd))
		return
	}
	if s.tempTarget(e.raw, home) != "" {
		s.tempExec = append(s.tempExec, path+": "+e.cmd)
	}
}

// tempTarget returns the first program an Exec value runs out of a temp
// directory, directly or through a link.
func (s *systemdScan) tempTarget(raw, home string) string {
	for _, c := range parseExecValue(expandSpecifiers(raw, home)) {
		for _, t := range execTargets(c.words, 0) {
			if !filepath.IsAbs(t) {
				continue
			}
			t = filepath.Clean(t)
			if inTemp(t) {
				return t
			}
			if real, _ := s.linkTarget(t); inTemp(real) {
				return real
			}
		}
	}
	return ""
}

// ownedProgram reports whether a program or library is package content. The file
// it resolves to decides, as that is what runs: /usr/bin/awk is an alternatives
// link no package lists, and a package's path can be repointed at something else.
func (s *systemdScan) ownedProgram(p string) bool {
	if !filepath.IsAbs(p) {
		found := false
		for _, dir := range execSearchPath {
			if _, err := os.Lstat(s.root + dir + "/" + p); err == nil {
				p, found = dir+"/"+p, true
				break
			}
		}
		if !found {
			return false
		}
	}
	real, _ := s.linkTarget(filepath.Clean(p))
	return s.owned(real)
}

// programsOwned reports whether everything an Exec value runs is package content.
// Past the program itself only absolute paths count, because a bare word inside a
// shell one-liner may be a builtin.
func (s *systemdScan) programsOwned(raw string) bool {
	for _, c := range parseExecValue(expandSpecifiers(raw, "")) {
		for i, t := range execTargets(c.words, 0) {
			if (i == 0 || filepath.IsAbs(t)) && !s.ownedProgram(t) {
				return false
			}
		}
	}
	return true
}

// dropinUnit names the unit a drop-in applies to, for the two locations an
// administrator or an attacker would use.
func dropinUnit(path string) (string, bool) {
	dir, file := filepath.Split(path)
	parent, name := filepath.Split(strings.TrimSuffix(dir, "/"))
	if parent != "/etc/systemd/system/" && parent != "/run/systemd/system/" {
		return "", false
	}
	unit, isDropinDir := strings.CutSuffix(name, ".d")
	if !isDropinDir || !strings.HasSuffix(file, ".conf") || !strings.Contains(unit, ".") {
		return "", false
	}
	return unit, true
}

// templateOf maps an instance such as getty@tty1.service to getty@.service.
func templateOf(unit string) string {
	at := strings.Index(unit, "@")
	dot := strings.LastIndex(unit, ".")
	if at < 0 || dot < at+2 {
		return ""
	}
	return unit[:at+1] + unit[dot:]
}

// packageUnitOf finds the unit a drop-in changes, if a package provides it. The
// first file found in priority order is what systemd loads, so a full copy in
// /etc means this is no longer the package's unit. Following links covers aliases
// such as sshd.service.
func (s *systemdScan) packageUnitOf(dropin string) (unit, base string, ok bool) {
	unit, ok = dropinUnit(dropin)
	if !ok {
		return "", "", false
	}
	for _, name := range []string{unit, templateOf(unit)} {
		if name == "" {
			continue
		}
		for _, dir := range unitSearchDirs {
			p := dir + "/" + name
			if _, err := os.Lstat(s.root + p); err != nil {
				continue
			}
			real, dangling := s.linkTarget(p)
			if dangling || real == "/dev/null" || !s.owned(real) {
				return "", "", false
			}
			return unit, real, true
		}
	}
	return "", "", false
}

func (s *systemdScan) originalExecStart(base string) string {
	if got, ok := s.originals[base]; ok {
		return got
	}
	got := "(unreadable)"
	if b, err := fsx.ReadNoFollow(s.root+base, persistLimit); err == nil {
		var cmds []string
		for _, e := range parseUnit(string(b)).execs {
			if e.key == "ExecStart" {
				cmds = append(cmds, e.cmd)
			}
		}
		got = strings.Join(cmds, " ; ")
		if got == "" {
			got = "(none)"
		}
	}
	s.originals[base] = got
	return got
}

// judgeDropin rates a drop-in that replaces the ExecStart of a package's unit.
func (s *systemdScan) judgeDropin(path, unit, base string, replaced []string) {
	var cmds []string
	sign := ""
	allOwned := true
	netplan := path == netplanWaitOnline
	for _, raw := range replaced {
		cmds = append(cmds, strings.TrimLeft(raw, execPrefixes))
		if sign == "" {
			if name := matchExec(raw); name != "" {
				sign = name
			} else if t := s.tempTarget(raw, ""); t != "" {
				sign = "runs a program from a temp directory: " + t
			}
		}
		allOwned = allOwned && s.programsOwned(raw)
		for _, c := range parseExecValue(raw) {
			netplan = netplan && filepath.Base(c.words[0]) == "systemd-networkd-wait-online"
		}
	}
	line := fmt.Sprintf("%s changes %s. Original ExecStart: %s. New ExecStart: %s", path, unit, s.originalExecStart(base), strings.Join(cmds, " ; "))
	switch {
	case sign != "":
		s.dropinCritical = append(s.dropinCritical, line+" ("+sign+")")
	case !allOwned:
		s.dropinUnowned = append(s.dropinUnowned, line)
	case !netplan:
		s.dropinPackage = append(s.dropinPackage, line)
	}
}

var loaderEnvLine = regexp.MustCompile(`^(?:export\s+)?(LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT)\s*=\s*(.*)$`)

// loaderValueOwned reports whether every path in a loader variable is package
// content. An empty entry means the current directory, so it does not count.
func (s *systemdScan) loaderValueOwned(value string) bool {
	for _, p := range strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ':' || r == ';' }) {
		if !filepath.IsAbs(p) || !s.ownedProgram(p) {
			return false
		}
	}
	return !strings.HasPrefix(value, ":") && !strings.HasSuffix(value, ":") && !strings.Contains(value, "::")
}

// judgeEnvironment looks for loader variables. Only the variable itself reaches
// the report: an Environment= line or an environment file can hold credentials.
func (s *systemdScan) judgeEnvironment(path string, u parsedUnit, owned bool, home string) {
	for _, value := range u.environment {
		for _, w := range unitWords(expandSpecifiers(value, home)) {
			if m := loaderEnvLine.FindStringSubmatch(w.text); m != nil && m[2] != "" && !(owned && s.loaderValueOwned(m[2])) {
				s.envInject = append(s.envInject, path+": "+m[1]+"="+m[2])
			}
		}
	}
	for _, raw := range u.envFiles {
		s.judgeEnvFile(path, raw, owned, home)
	}
}

func (s *systemdScan) judgeEnvFile(unit, raw string, owned bool, home string) {
	file := expandSpecifiers(strings.TrimPrefix(raw, "-"), home)
	if !filepath.IsAbs(file) {
		return
	}
	file = filepath.Clean(file)
	if inTemp(file) {
		s.envTemp = append(s.envTemp, unit+": EnvironmentFile="+file)
		return
	}
	if strings.Contains(file, "%") {
		return
	}
	files := []string{file}
	if strings.ContainsAny(file, "*?[") {
		files = nil
		matches, _ := filepath.Glob(s.root + file)
		for _, m := range matches {
			files = append(files, s.logical(m))
		}
	}
	for _, p := range files {
		st, err := os.Lstat(s.root + p)
		if err != nil {
			if target, _ := s.linkTarget(p); inTemp(target) {
				s.envTemp = append(s.envTemp, unit+": EnvironmentFile="+p+" -> "+target)
			}
			continue
		}
		if st.Mode()&os.ModeSymlink != 0 {
			target, _ := s.linkTarget(p)
			if inTemp(target) {
				s.envTemp = append(s.envTemp, unit+": EnvironmentFile="+p+" -> "+target)
			} else {
				s.envLinks = append(s.envLinks, unit+": EnvironmentFile="+p+" -> "+target)
			}
			continue
		}
		b, err := fsx.ReadNoFollow(s.root+p, persistLimit)
		if err != nil {
			continue
		}
		if len(b) >= persistLimit {
			s.truncated = append(s.truncated, p)
		}
		for _, entry := range envFileLoaderLines(string(b)) {
			if !(owned && s.loaderValueOwned(entry[1])) {
				s.envInject = append(s.envInject, unit+": EnvironmentFile="+p+": "+entry[0]+"="+entry[1])
			}
		}
	}
}

// envFileLoaderLines returns the key and value of each loader variable with a
// value. Nothing else from the file leaves this function.
func envFileLoaderLines(src string) [][2]string {
	var out [][2]string
	for _, line := range logicalLines(src) {
		m := loaderEnvLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if value := strings.Trim(m[2], `"' `); value != "" {
			out = append(out, [2]string{m[1], value})
		}
	}
	return out
}

// scanHome covers a user's own units. The user controls everything here and the
// scan runs as root, so reads refuse a symlink in any component and a link is
// reported rather than followed.
func (s *systemdScan) scanHome(u User) {
	home := filepath.Clean(u.Home)
	for _, rel := range homeUnitDirs {
		dir := filepath.Join(home, rel)
		if st, err := os.Stat(s.root + dir); err != nil || !st.IsDir() {
			continue
		}
		if hasSymlink(s.root+home, rel) {
			target, _ := s.linkTarget(dir)
			s.noteHomeLink(home, dir, target)
			continue
		}
		_ = filepath.WalkDir(s.root+dir, func(full string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if s.ctx.Err() != nil {
				return filepath.SkipAll
			}
			p := s.logical(full)
			switch {
			case !wantedUnit(d.Name()):
			case d.Type().IsRegular():
				if s.seen[p] {
					return nil
				}
				s.seen[p] = true
				rel := strings.TrimPrefix(full, s.root+home+"/")
				if b, err := fsx.ReadUnder(s.root+home, rel, persistLimit); err == nil {
					s.checkUnit(p, b, unitHome, home)
				}
			case d.Type()&fs.ModeSymlink != 0:
				s.scanHomeLink(home, p)
			}
			return nil
		})
	}
}

// hasSymlink reports a symlink in any component of rel below base.
func hasSymlink(base, rel string) bool {
	cur := base
	for _, part := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, part)
		if st, err := os.Lstat(cur); err != nil || st.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

func (s *systemdScan) scanHomeLink(home, p string) {
	target, _ := s.linkTarget(p)
	if target == "/dev/null" || isSystemdPath(target) {
		return
	}
	// An enablement link to a unit scanned in its own right. A dangling target
	// keeps the home's spelling, as it could not be resolved.
	realHome, _ := s.linkTarget(home)
	for _, rel := range homeUnitDirs {
		if inDirs(target, filepath.Join(realHome, rel), filepath.Join(home, rel)) {
			return
		}
	}
	s.noteHomeLink(home, p, target)
}

func (s *systemdScan) noteHomeLink(home, p, target string) {
	line := p + " -> " + target
	s.homeUnits[home] = append(s.homeUnits[home], line)
	if inTemp(target + "/") {
		s.tempExec = append(s.tempExec, p+" is a unit file in a temp directory: "+target)
	} else {
		s.links = append(s.links, line)
	}
}

// scanGenerators looks only at the top level of each directory, the same as
// systemd, which does not run anything further down.
func (s *systemdScan) scanGenerators() {
	visited := map[string]bool{}
	for _, dir := range generatorDirs() {
		real, _ := s.linkTarget(dir)
		if visited[real] {
			continue
		}
		visited[real] = true
		entries, err := os.ReadDir(s.root + real)
		if err != nil {
			continue
		}
		for _, d := range entries {
			if s.ctx.Err() != nil {
				return
			}
			s.scanGenerator(real+"/"+d.Name(), d)
		}
	}
}

func (s *systemdScan) scanGenerator(p string, d fs.DirEntry) {
	isLink := d.Type()&fs.ModeSymlink != 0
	if !isLink && !d.Type().IsRegular() {
		return
	}
	target, dangling, label := p, false, p
	if isLink {
		target, dangling = s.linkTarget(p)
		if target == "/dev/null" {
			return // masked, which is how an administrator turns a generator off
		}
		label = p + " -> " + target
	}
	s.scanned++
	if inTemp(target) {
		s.generatorCritical = append(s.generatorCritical, label+" (in a temp directory)")
		return
	}
	note := ""
	if dangling {
		note = " (target does not exist)"
	} else if b, err := fsx.ReadNoFollow(s.root+target, persistLimit); err == nil {
		if len(b) >= persistLimit {
			s.truncated = append(s.truncated, p)
		}
		for _, line := range logicalLines(string(b)) {
			if name := matchMalicious(line); name != "" {
				s.generatorCritical = append(s.generatorCritical, fmt.Sprintf("%s (%s): %s", label, name, line))
				return
			}
		}
		if st, err := os.Stat(s.root + target); err == nil && st.Mode().Perm()&0o111 == 0 {
			note = " (not executable, so systemd skips it for now)"
		}
	}
	if s.ownersErr != nil {
		return
	}
	// Both must be package content. A packaged link can be repointed.
	if s.owned(p) && (dangling || !isLink || s.owned(target)) {
		return
	}
	s.generatorUnowned = append(s.generatorUnowned, s.recent(p)+label+note)
}

func (s *systemdScan) scanLinger() {
	entries, err := os.ReadDir(s.root + lingerDir)
	if err != nil {
		return
	}
	byName := make(map[string]User, len(s.users))
	for _, u := range s.users {
		byName[u.Name] = u
	}
	for _, d := range entries {
		if d.IsDir() {
			continue
		}
		u, ok := byName[d.Name()]
		if !ok {
			s.linger = append(s.linger, d.Name()+" (no such account)")
			continue
		}
		s.linger = append(s.linger, fmt.Sprintf("%s (uid %d, home %s)", u.Name, u.UID, u.Home))
		for _, unit := range s.homeUnits[filepath.Clean(u.Home)] {
			s.lingerUnits = append(s.lingerUnits, u.Name+": "+unit)
		}
	}
}

func sortedUnique(list []string) []string {
	out := slices.Clone(list)
	slices.Sort(out)
	return slices.Compact(out)
}

func (s *systemdScan) findings() []model.Finding {
	const cat = model.CatPersistence
	var out []model.Finding
	add := func(list []string, counted bool, id string, sev model.Severity, title, detail, remediation string) {
		if len(list) == 0 {
			return
		}
		list = sortedUnique(list)
		if counted {
			title = fmt.Sprintf("%s (%d)", title, len(list))
		}
		f := finding(id, cat, sev, title)
		f.Detail = detail
		f.Evidence = list
		f.Remediation = remediation
		out = append(out, f)
	}
	add(s.malicious, false, "persistence.systemd_malicious", model.Critical, "systemd services with malicious signs", "",
		"Back up the unit file as evidence, stop it with systemctl disable --now and investigate how the attacker got in.")
	add(s.tempExec, false, "persistence.systemd_temp", model.Critical, "systemd services run programs from temp directories",
		"Nothing in a temp directory should run as a systemd service.", "")
	add(s.generatorCritical, false, "persistence.systemd_generator_malicious", model.Critical, "systemd generators with malicious signs or in temp directories",
		"Generators run as root at every boot and daemon-reload, before any service starts, and never appear as a service.",
		"Back up the file as evidence, remove it, run systemctl daemon-reload and investigate how the attacker got in.")
	add(s.dropinCritical, false, "persistence.systemd_dropin_malicious", model.Critical, "Drop-ins replace a package service's command with a malicious one",
		"The service keeps its name and package, while systemd runs this command instead.",
		"Back up the drop-in as evidence, remove it, run systemctl daemon-reload, restart the service and investigate how the attacker got in.")
	add(s.generatorUnowned, true, "persistence.systemd_generator_unowned", model.High, "systemd generators that belong to no package",
		"Generators run as root at every boot and daemon-reload, before any service starts, and never appear as a service. Administrators rarely add them.",
		"Find out who installed each one. If nobody did, back it up, remove it and investigate.")
	add(s.dropinUnowned, true, "persistence.systemd_dropin_unowned", model.High, "Drop-ins replace a package service's command with a program from no package",
		"The service keeps its name and package, while systemd runs this command instead.",
		"Confirm who added it. If nobody did, back it up, remove it and run systemctl daemon-reload.")
	add(s.envInject, true, "persistence.systemd_env_inject", model.High, "systemd units set dynamic linker variables",
		"LD_PRELOAD, LD_LIBRARY_PATH and LD_AUDIT load a chosen library into the service, which can then see and change everything it does. Only these variables are shown, as the rest of the line or file may hold credentials.",
		"Confirm who set this and what the library is. If nobody did, back up the unit and the library, and investigate.")
	add(s.envTemp, true, "persistence.systemd_env_temp", model.High, "systemd units load environment files from temp directories",
		"Anyone can write to temp directories, so anyone could set this service's environment, including LD_PRELOAD.",
		"Move the file somewhere only root can write, or remove the setting.")
	add(s.dropinPackage, true, "persistence.systemd_dropin_package", model.Medium, "Drop-ins replace a package service's command",
		"Administrators often do this to change a service's options, and the new program does belong to a package. Confirm the change is yours.", "")
	add(s.lingerUnits, true, "persistence.systemd_linger_units", model.Medium, "Lingering users have user units that belong to no package",
		"These start at boot under that account, with nobody logged in. Confirm you recognize them all.", "")
	add(s.links, true, "persistence.systemd_links", model.Medium, "User units that link outside their directories",
		"systemd still loads these, but this scan does not read what they point to, because the target could be a secret file. Check them by hand.", "")
	add(s.truncated, true, "persistence.systemd_truncated", model.Medium, "systemd files too large to scan completely",
		"Only the first 1 MiB of each was scanned. Padding can hide a malicious line from this check.", "")
	add(s.transient, true, "persistence.systemd_transient", model.Info, "Transient systemd units with commands",
		"These were created with systemd-run or through the systemd API, and disappear at reboot along with this evidence. Confirm you recognize them all.", "")
	add(s.linger, true, "persistence.systemd_linger", model.Info, "Users with lingering enabled",
		"These users' services start at boot and keep running, with no need to log in.", "")
	add(s.envLinks, true, "persistence.systemd_env_links", model.Info, "Environment files that are symlinks",
		"These were not read, so they were not checked for dynamic linker variables.", "")
	add(s.unowned, true, "persistence.systemd_unowned", model.Info, "systemd services that belong to no package",
		"Services you deployed yourself appear here. Confirm you recognize them all.", "")
	if s.ownersErr != nil {
		out = append(out, skipped("persistence.systemd_owners", cat, "systemd files against packages",
			"Cannot read the dpkg database, so generators and drop-ins were not compared with packages: "+s.ownersErr.Error()))
	}
	alarming := slices.ContainsFunc(out, func(f model.Finding) bool { return f.Severity == model.Critical || f.Severity == model.High })
	if !alarming {
		out = append(out, finding("persistence.systemd_clean", cat, model.OK, fmt.Sprintf("Scanned %d systemd units and generators, no malicious signs", s.scanned)))
	}
	return out
}
