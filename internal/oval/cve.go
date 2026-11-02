package oval

import (
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"ubuntu-sys-audit/internal/dpkg"
)

// CVEFeedURL returns the download URL of Canonical's CVE OVAL feed for a
// release. Unlike the USN feed, it lists every CVE Ubuntu tracks there,
// including the ones with no fix released yet.
func CVEFeedURL(codename string) string {
	return fmt.Sprintf("https://security-metadata.canonical.com/oval/com.ubuntu.%s.cve.oval.xml.bz2", codename)
}

// Status is what a CVE means for one package or kernel on this host.
type Status string

const (
	// Unfixed means Ubuntu lists the package as possibly affected with no fix
	// released. The feed does not tell a fix in progress from an untriaged CVE.
	Unfixed Status = "no fix released"
	// FixAvailable means a fixed version exists and the installed one is older.
	FixAvailable Status = "fix available"
	// Fixed means the installed version already has the fix.
	Fixed Status = "fixed"
)

// Component is one source package or kernel flavour a CVE concerns, as found on
// this host. Packages that are not installed and kernels that are not running
// are left out.
type Component struct {
	Source string `json:"source"`
	Kernel bool   `json:"kernel,omitempty"`
	Status Status `json:"status"`
	// Installed lists "binary version" for packages, or the running kernel.
	Installed []string `json:"installed"`
	Fixed     string   `json:"fixed,omitempty"`
	// Pro means the fix ships only through Ubuntu Pro (ESM).
	Pro bool `json:"pro,omitempty"`
}

// CVEResult is the answer for one CVE.
type CVEResult struct {
	ID       string  `json:"id"`
	Known    bool    `json:"known"`
	Priority string  `json:"priority,omitempty"`
	CVSS     float64 `json:"cvss,omitempty"`
	Public   string  `json:"public,omitempty"`
	// Sources names every source package the CVE concerns in this release,
	// installed or not.
	Sources    []string    `json:"sources,omitempty"`
	Components []Component `json:"components,omitempty"`
	// KernelUnknown means the CVE concerns Ubuntu kernels, but the running
	// kernel matches none of the flavours, as in a container or with a mainline
	// kernel, so the kernel was not checked.
	KernelUnknown bool `json:"kernel_unknown,omitempty"`
}

type cveFilter struct {
	want                         map[string]bool
	tests, objects, states, vars map[string]bool
}

type cveDefinition struct {
	ID       string
	Priority string
	CVSS     float64
	Public   string
	Criteria *criteria
}

// ParseCVEs reads a CVE OVAL feed and keeps only the given CVEs, with the tests,
// objects, states and variables they use. The feed is hundreds of megabytes
// once decompressed, so keeping all of it would cost memory on a production host.
func ParseCVEs(r io.Reader, bz2 bool, ids []string) (*Feed, error) {
	filter := &cveFilter{
		want:    map[string]bool{},
		tests:   map[string]bool{},
		objects: map[string]bool{},
		states:  map[string]bool{},
		vars:    map[string]bool{},
	}
	for _, id := range ids {
		filter.want[strings.ToUpper(id)] = true
	}
	return parse(r, bz2, filter)
}

// VulnerabilityCount returns how many CVE definitions the feed holds, kept or not.
// Zero means the file is not a CVE feed.
func (f *Feed) VulnerabilityCount() int { return f.vulnerabilities }

var cveTitle = regexp.MustCompile(`^(CVE-[0-9]+-[0-9]+) on `)

func (f *Feed) readCVEDefinition(dec *xml.Decoder, start *xml.StartElement) error {
	var x xmlDefinition
	if err := dec.DecodeElement(&x, start); err != nil {
		return err
	}
	if f.Release == "" {
		if m := releaseInID.FindStringSubmatch(attr(start.Attr, "id")); m != nil {
			f.Release = m[1]
		}
	}
	if x.Class != "vulnerability" || x.Criteria == nil {
		return nil
	}
	f.vulnerabilities++
	m := cveTitle.FindStringSubmatch(x.Metadata.Title)
	if m == nil || !f.filter.want[m[1]] {
		return nil
	}
	d := cveDefinition{ID: m[1]}
	for _, c := range x.Metadata.Advisory.CVEs {
		if strings.TrimSpace(c.ID) == m[1] {
			d.Priority = c.Priority
			d.CVSS, _ = strconv.ParseFloat(c.CVSS, 64)
			d.Public = c.Public
		}
	}
	crit, err := convertCriteria(x.Criteria)
	if err != nil {
		return err
	}
	d.Criteria = crit
	f.collectTests(crit)
	f.cveDefs = append(f.cveDefs, d)
	return nil
}

func (f *Feed) collectTests(c *criteria) {
	for _, item := range c.Items {
		if item.Sub != nil {
			f.collectTests(item.Sub)
		} else if item.TestRef != "" {
			f.filter.tests[item.TestRef] = true
		}
	}
}

// hostArch is the architecture this binary runs on.
var hostArch = runtime.GOARCH

var (
	unfixedSource = regexp.MustCompile(`^(\S+) source package in (\S+), might be affected and may need fixing\.$`)
	fixedSource   = regexp.MustCompile(`^(\S+) source package in (\S+), is affected and has been fixed \(note: '([^']+)'\)\.$`)
	kernelRunning = regexp.MustCompile(`^Is kernel '([^']+)' running\?$`)
	kernelFixed   = regexp.MustCompile(`^'([^']+)' kernel in \S+ was vulnerable but has been fixed \(note: '([^']+)'\)\.$`)
)

// LookupCVEs answers each CVE for the installed packages and running kernel, in
// the order given. Pass an empty release to leave the kernel out, as inside a
// container, where the kernel belongs to another host.
func (f *Feed) LookupCVEs(ids []string, packages map[string][]string, release string) []CVEResult {
	e := &evaluator{feed: f, packages: packages, release: release, patCache: map[string]bool{}}
	e.evr, e.evrOK = f.kernelEVR(release)
	byID := map[string]*cveDefinition{}
	for i := range f.cveDefs {
		byID[f.cveDefs[i].ID] = &f.cveDefs[i]
	}
	var out []CVEResult
	for _, id := range ids {
		id = strings.ToUpper(id)
		d, ok := byID[id]
		if !ok {
			out = append(out, CVEResult{ID: id})
			continue
		}
		r := CVEResult{ID: id, Known: true, Priority: d.Priority, CVSS: d.CVSS, Public: d.Public}
		l := &lookup{e: e, sources: map[string]bool{}, comps: map[string]*Component{}}
		l.walk(d.Criteria)
		r.KernelUnknown = l.kernels && !l.kernelMatched
		for s := range l.sources {
			r.Sources = append(r.Sources, s)
		}
		sort.Strings(r.Sources)
		for _, key := range l.order {
			r.Components = append(r.Components, *l.comps[key])
		}
		out = append(out, r)
	}
	return out
}

type lookup struct {
	e             *evaluator
	sources       map[string]bool
	comps         map[string]*Component
	order         []string
	kernels       bool // the CVE concerns at least one kernel flavour
	kernelMatched bool // and one of them is running
}

func (l *lookup) walk(c *criteria) {
	for _, item := range c.Items {
		switch {
		case item.Skip:
		case item.Sub != nil:
			l.walk(item.Sub)
		default:
			l.criterion(c, item)
		}
	}
}

func (l *lookup) criterion(c *criteria, item criterionItem) {
	t, ok := l.e.feed.tests[item.TestRef]
	if !ok {
		return
	}
	if m := unfixedSource.FindStringSubmatch(item.Comment); m != nil {
		l.sources[m[1]] = true
		if installed := l.installed(t); len(installed) > 0 {
			l.add(Component{Source: m[1], Status: Unfixed, Installed: installed})
		}
		return
	}
	if m := fixedSource.FindStringSubmatch(item.Comment); m != nil {
		l.sources[m[1]] = true
		fixed := l.e.feed.stateEVR[t.state]
		if fixed == "" {
			return
		}
		var old, current []string
		for _, line := range l.installed(t) {
			if version := line[strings.IndexByte(line, ' ')+1:]; dpkg.Compare(version, fixed) < 0 {
				old = append(old, line)
			} else {
				current = append(current, line)
			}
		}
		pro := strings.Contains(m[2], "esm") || strings.Contains(m[3], "esm")
		switch {
		case len(old) > 0:
			l.add(Component{Source: m[1], Status: FixAvailable, Installed: old, Fixed: m[3], Pro: pro})
		case len(current) > 0:
			l.add(Component{Source: m[1], Status: Fixed, Installed: current, Fixed: m[3]})
		}
		return
	}
	m := kernelRunning.FindStringSubmatch(item.Comment)
	if m == nil {
		return
	}
	flavour := m[1]
	// RISC-V kernels end in -generic too, so the release cannot tell them
	// apart from the amd64 and arm64 kernels this binary runs on.
	if strings.Contains(flavour, "riscv") && hostArch != "riscv64" {
		return
	}
	l.kernels = true
	l.sources[flavour] = true
	if !l.e.matchRelease(l.e.feed.statePat[t.state]) {
		return
	}
	l.kernelMatched = true
	// A fixed kernel pairs this test with a version test in the same AND.
	// Without one, no fix has been released for this flavour.
	note, state := "", ""
	if c.Operator == "AND" {
		for _, other := range c.Items {
			if km := kernelFixed.FindStringSubmatch(other.Comment); km != nil && km[1] == flavour {
				note = km[2]
				state = l.e.feed.stateEVR[l.e.feed.tests[other.TestRef].state]
			}
		}
	}
	comp := Component{Source: flavour, Kernel: true, Installed: []string{l.e.release}}
	switch {
	case state == "":
		comp.Status = Unfixed
	case !l.e.evrOK:
		return
	case dpkg.Compare(l.e.evr, state) < 0:
		comp.Status, comp.Fixed = FixAvailable, note
	default:
		comp.Status, comp.Fixed = Fixed, note
	}
	l.add(comp)
}

// installed returns "binary version" for each installed binary a test names.
func (l *lookup) installed(t test) []string {
	var out []string
	for _, binary := range l.e.feed.vars[l.e.feed.objectVar[t.object]] {
		for _, version := range l.e.packages[binary] {
			out = append(out, binary+" "+version)
		}
	}
	return out
}

// statusRank orders statuses by how much they ask of the operator.
var statusRank = map[Status]int{FixAvailable: 0, Unfixed: 1, Fixed: 2}

// add merges a component into the one for its source, keeping the most
// pressing status. A feed can list one source twice, for two sets of binaries.
func (l *lookup) add(c Component) {
	key := c.Source
	prev, ok := l.comps[key]
	if !ok {
		l.comps[key] = &c
		l.order = append(l.order, key)
		return
	}
	if statusRank[c.Status] < statusRank[prev.Status] {
		c.Installed = mergeLines(c.Installed, nil)
		l.comps[key] = &c
		return
	}
	if c.Status == prev.Status {
		prev.Installed = mergeLines(prev.Installed, c.Installed)
	}
}

func mergeLines(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range append(append([]string(nil), a...), b...) {
		if !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	return out
}
