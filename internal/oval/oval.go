// Package oval parses Canonical's OVAL feeds and evaluates them against the
// installed dpkg packages and the running kernel: the USN feed for fixes a host
// is missing, and the CVE feed to look up single CVEs, including unfixed ones.
//
// This is the correct way to answer "is this host missing a fix" on Ubuntu:
// Canonical backports patches, so comparing upstream version numbers against
// CVE ranges reports hosts that are already fixed. Each USN definition states
// the exact package version carrying the fix.
package oval

import (
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"ubuntu-sys-audit/internal/dpkg"
)

// FeedURL returns the Canonical USN OVAL download URL for a release codename.
func FeedURL(codename string) string {
	return fmt.Sprintf("https://security-metadata.canonical.com/oval/com.ubuntu.%s.usn.oval.xml.bz2", codename)
}

// CVE is one CVE referenced by a USN.
type CVE struct {
	ID       string  `json:"id"`
	Priority string  `json:"priority"`
	CVSS     float64 `json:"cvss,omitempty"`
}

// PkgHit is a package that is older than the fixed version.
type PkgHit struct {
	Source    string `json:"source"`
	Binary    string `json:"binary"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
	Kernel    bool   `json:"kernel,omitempty"`
}

// Hit is a USN that applies to this host.
type Hit struct {
	USN      string   `json:"usn"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Issued   string   `json:"issued"`
	CVEs     []CVE    `json:"cves"`
	Packages []PkgHit `json:"packages"`
}

// RequiresPro reports whether the fix ships only through Ubuntu Pro (ESM).
func (p PkgHit) RequiresPro() bool { return strings.Contains(p.Fixed, "esm") }

type definition struct {
	Title    string
	Severity string
	Issued   string
	USN      string
	CVEs     []CVE
	Criteria *criteria
}

type criteria struct {
	Operator string
	Negate   bool
	Items    []criterionItem
}

type criterionItem struct {
	Sub     *criteria
	TestRef string
	Comment string
	Negate  bool
	Skip    bool // extend_definition pointing at the release inventory check
}

type test struct {
	kind   string
	object string
	state  string
}

// Feed is a parsed OVAL document, reduced to what evaluation needs.
type Feed struct {
	Timestamp string
	// Release is the Ubuntu codename the feed's definitions are for.
	Release   string
	defs      []definition
	tests     map[string]test
	objectVar map[string]string
	stateEVR  map[string]string
	statePat  map[string]string
	vars      map[string][]string
	kernelRe  *regexp.Regexp

	// Set when parsing the CVE feed: only the wanted CVEs are kept.
	filter          *cveFilter
	cveDefs         []cveDefinition
	vulnerabilities int
}

// KernelRecognized reports whether any USN applies to this kind of kernel. Mainline
// and custom kernels match nothing, so having no kernel hits says nothing about
// them and must not be read as a clean result.
func (f *Feed) KernelRecognized(release string) bool {
	for _, pattern := range f.statePat {
		if re, err := regexp.Compile(pattern); err == nil && re.MatchString(release) {
			return true
		}
	}
	return false
}

// DefinitionCount returns how many USN definitions were loaded.
func (f *Feed) DefinitionCount() int { return len(f.defs) }

// Parse reads an OVAL document. When bz2 is true the stream is decompressed.
func Parse(r io.Reader, bz2 bool) (*Feed, error) {
	return parse(r, bz2, nil)
}

// sectionsBefore lists what must already have been read when a section starts.
// A filtered parse keeps only the tests, objects, states and variables the
// wanted definitions reach, which works only in the order Canonical writes them.
var sectionsBefore = map[string][]string{
	"tests":     {"definitions"},
	"objects":   {"definitions", "tests"},
	"states":    {"definitions", "tests"},
	"variables": {"definitions", "tests", "objects"},
}

func parse(r io.Reader, bz2 bool, filter *cveFilter) (*Feed, error) {
	if bz2 {
		r = bzip2.NewReader(r)
	}
	feed := &Feed{
		tests:     map[string]test{},
		objectVar: map[string]string{},
		stateEVR:  map[string]string{},
		statePat:  map[string]string{},
		vars:      map[string][]string{},
		filter:    filter,
	}
	read := map[string]bool{}
	dec := xml.NewDecoder(r)
	dec.Strict = false
	section := ""
	sawRoot := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("oval: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			if end, isEnd := tok.(xml.EndElement); isEnd {
				switch end.Name.Local {
				case "definitions", "tests", "objects", "states", "variables":
					section = ""
				}
			}
			continue
		}
		name := start.Name.Local
		if !sawRoot {
			if name != "oval_definitions" {
				return nil, fmt.Errorf("oval: unexpected root element %q", name)
			}
			sawRoot = true
			continue
		}
		switch name {
		case "definitions", "tests", "objects", "states", "variables":
			if filter != nil {
				for _, need := range sectionsBefore[name] {
					if !read[need] {
						return nil, fmt.Errorf("oval: %s come before %s, which this reader cannot filter", name, need)
					}
				}
			}
			section = name
			read[name] = true
			continue
		case "timestamp":
			if section == "" {
				var s string
				if err := dec.DecodeElement(&s, &start); err == nil {
					feed.Timestamp = strings.TrimSpace(s)
				}
				continue
			}
		}
		var err2 error
		switch section {
		case "definitions":
			err2 = feed.readDefinition(dec, &start)
		case "tests":
			err2 = feed.readTest(dec, &start)
		case "objects":
			err2 = feed.readObject(dec, &start)
		case "states":
			err2 = feed.readState(dec, &start)
		case "variables":
			err2 = feed.readVariable(dec, &start)
		}
		if err2 != nil {
			return nil, fmt.Errorf("oval: %s: %w", section, err2)
		}
	}
	if !sawRoot {
		return nil, fmt.Errorf("oval: empty document")
	}
	return feed, nil
}

type xmlDefinition struct {
	Class    string `xml:"class,attr"`
	Metadata struct {
		Title    string `xml:"title"`
		Advisory struct {
			Severity string `xml:"severity"`
			Issued   struct {
				Date string `xml:"date,attr"`
			} `xml:"issued"`
			CVEs []struct {
				Priority string `xml:"priority,attr"`
				CVSS     string `xml:"cvss_score,attr"`
				Public   string `xml:"public,attr"`
				ID       string `xml:",chardata"`
			} `xml:"cve"`
		} `xml:"advisory"`
	} `xml:"metadata"`
	Criteria *xmlCriteria `xml:"criteria"`
}

type xmlCriteria struct {
	Operator string `xml:"operator,attr"`
	Negate   string `xml:"negate,attr"`
	Children []struct {
		XMLName xml.Name
		Attrs   []xml.Attr `xml:",any,attr"`
		Inner   []byte     `xml:",innerxml"`
	} `xml:",any"`
}

var releaseInID = regexp.MustCompile(`^oval:com\.ubuntu\.([a-z]+):def:`)

var usnTitle = regexp.MustCompile(`^(USN-[0-9]+-[0-9]+)\b`)

func (f *Feed) readDefinition(dec *xml.Decoder, start *xml.StartElement) error {
	if start.Name.Local != "definition" {
		return dec.Skip()
	}
	if f.filter != nil {
		return f.readCVEDefinition(dec, start)
	}
	var x xmlDefinition
	if err := dec.DecodeElement(&x, start); err != nil {
		return err
	}
	if f.Release == "" {
		if m := releaseInID.FindStringSubmatch(attr(start.Attr, "id")); m != nil {
			f.Release = m[1]
		}
	}
	// Only patch class USNs. LSN entries describe livepatches and the
	// inventory definition only asserts the release.
	if x.Class != "patch" || x.Criteria == nil {
		return nil
	}
	m := usnTitle.FindStringSubmatch(x.Metadata.Title)
	if m == nil {
		return nil
	}
	d := definition{
		Title:    x.Metadata.Title,
		USN:      m[1],
		Severity: strings.ToLower(strings.TrimSpace(x.Metadata.Advisory.Severity)),
		Issued:   x.Metadata.Advisory.Issued.Date,
	}
	for _, c := range x.Metadata.Advisory.CVEs {
		score, _ := strconv.ParseFloat(c.CVSS, 64)
		d.CVEs = append(d.CVEs, CVE{ID: strings.TrimSpace(c.ID), Priority: c.Priority, CVSS: score})
	}
	crit, err := convertCriteria(x.Criteria)
	if err != nil {
		return err
	}
	d.Criteria = crit
	f.defs = append(f.defs, d)
	return nil
}

func attr(attrs []xml.Attr, name string) string {
	for _, a := range attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func convertCriteria(x *xmlCriteria) (*criteria, error) {
	c := &criteria{Operator: strings.ToUpper(x.Operator), Negate: x.Negate == "true"}
	if c.Operator == "" {
		c.Operator = "AND"
	}
	for _, ch := range x.Children {
		switch ch.XMLName.Local {
		case "criterion":
			c.Items = append(c.Items, criterionItem{
				TestRef: attr(ch.Attrs, "test_ref"),
				Comment: attr(ch.Attrs, "comment"),
				Negate:  attr(ch.Attrs, "negate") == "true",
			})
		case "extend_definition":
			c.Items = append(c.Items, criterionItem{Skip: true})
		case "criteria":
			var sub xmlCriteria
			sub.Operator = attr(ch.Attrs, "operator")
			sub.Negate = attr(ch.Attrs, "negate")
			wrapped := append(append([]byte("<x>"), ch.Inner...), "</x>"...)
			if err := xml.Unmarshal(wrapped, &sub); err != nil {
				return nil, err
			}
			sub.Operator = attr(ch.Attrs, "operator")
			sub.Negate = attr(ch.Attrs, "negate")
			conv, err := convertCriteria(&sub)
			if err != nil {
				return nil, err
			}
			c.Items = append(c.Items, criterionItem{Sub: conv})
		}
	}
	return c, nil
}

func (f *Feed) readTest(dec *xml.Decoder, start *xml.StartElement) error {
	id := attr(start.Attr, "id")
	if f.filter != nil && !f.filter.tests[id] {
		return dec.Skip()
	}
	var x struct {
		Object struct {
			Ref string `xml:"object_ref,attr"`
		} `xml:"object"`
		State struct {
			Ref string `xml:"state_ref,attr"`
		} `xml:"state"`
	}
	if err := dec.DecodeElement(&x, start); err != nil {
		return err
	}
	f.tests[id] = test{kind: start.Name.Local, object: x.Object.Ref, state: x.State.Ref}
	if f.filter != nil {
		f.filter.objects[x.Object.Ref] = true
		f.filter.states[x.State.Ref] = true
	}
	return nil
}

func (f *Feed) readObject(dec *xml.Decoder, start *xml.StartElement) error {
	id := attr(start.Attr, "id")
	if start.Name.Local != "dpkginfo_object" || f.filter != nil && !f.filter.objects[id] {
		return dec.Skip()
	}
	var x struct {
		Name struct {
			VarRef string `xml:"var_ref,attr"`
		} `xml:"name"`
	}
	if err := dec.DecodeElement(&x, start); err != nil {
		return err
	}
	f.objectVar[id] = x.Name.VarRef
	if f.filter != nil {
		f.filter.vars[x.Name.VarRef] = true
	}
	return nil
}

func (f *Feed) readState(dec *xml.Decoder, start *xml.StartElement) error {
	id := attr(start.Attr, "id")
	if f.filter != nil && !f.filter.states[id] {
		return dec.Skip()
	}
	switch start.Name.Local {
	case "dpkginfo_state":
		var x struct {
			EVR string `xml:"evr"`
		}
		if err := dec.DecodeElement(&x, start); err != nil {
			return err
		}
		f.stateEVR[id] = strings.TrimSpace(x.EVR)
	case "variable_state":
		var x struct {
			Value string `xml:"value"`
		}
		if err := dec.DecodeElement(&x, start); err != nil {
			return err
		}
		f.stateEVR[id] = strings.TrimSpace(x.Value)
	case "uname_state":
		var x struct {
			Release string `xml:"os_release"`
		}
		if err := dec.DecodeElement(&x, start); err != nil {
			return err
		}
		f.statePat[id] = strings.TrimSpace(x.Release)
	default:
		return dec.Skip()
	}
	return nil
}

func (f *Feed) readVariable(dec *xml.Decoder, start *xml.StartElement) error {
	switch start.Name.Local {
	case "constant_variable":
		if f.filter != nil && !f.filter.vars[attr(start.Attr, "id")] {
			return dec.Skip()
		}
		var x struct {
			Values []string `xml:"value"`
		}
		if err := dec.DecodeElement(&x, start); err != nil {
			return err
		}
		f.vars[attr(start.Attr, "id")] = x.Values
	case "local_variable":
		var x struct {
			Concat struct {
				Capture struct {
					Pattern string `xml:"pattern,attr"`
				} `xml:"regex_capture"`
			} `xml:"concat"`
		}
		if err := dec.DecodeElement(&x, start); err != nil {
			return err
		}
		if p := x.Concat.Capture.Pattern; p != "" && f.kernelRe == nil {
			if re, err := regexp.Compile(p); err == nil {
				f.kernelRe = re
			}
		}
	default:
		return dec.Skip()
	}
	return nil
}

var defaultKernelRe = regexp.MustCompile(`^([\d.]+-\d+)[-\w]+$`)

// kernelEVR converts a uname release such as 5.15.0-91-generic to the epoch
// version form OVAL compares against, 0:5.15.0-91.
func (f *Feed) kernelEVR(release string) (string, bool) {
	re := f.kernelRe
	if re == nil {
		re = defaultKernelRe
	}
	m := re.FindStringSubmatch(release)
	if m == nil || len(m) < 2 {
		return "", false
	}
	return "0:" + m[1], true
}

var (
	sourceFromComment  = regexp.MustCompile(`^(\S+) source package in`)
	kernelFromComment  = regexp.MustCompile(`^'([^']+)' kernel in`)
	fixedInComment     = regexp.MustCompile(`note: '([^']+)'`)
	isKernelRunningMsg = regexp.MustCompile(`^Is kernel '`)
)

type evaluator struct {
	feed     *Feed
	packages map[string][]string
	release  string
	evr      string
	evrOK    bool
	patCache map[string]bool
}

// Evaluate returns every USN whose fix is newer than what the host runs.
// packages maps a binary package name to its installed versions; release is
// the uname -r string of the running kernel.
func (f *Feed) Evaluate(packages map[string][]string, release string) []Hit {
	e := &evaluator{feed: f, packages: packages, release: release, patCache: map[string]bool{}}
	e.evr, e.evrOK = f.kernelEVR(release)
	var hits []Hit
	for i := range f.defs {
		d := &f.defs[i]
		var pkgs []PkgHit
		if !e.evalCriteria(d.Criteria, &pkgs) || len(pkgs) == 0 {
			continue
		}
		hits = append(hits, Hit{
			USN:      d.USN,
			Title:    d.Title,
			Severity: d.Severity,
			Issued:   d.Issued,
			CVEs:     d.CVEs,
			Packages: dedupePkgs(pkgs),
		})
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Issued > hits[j].Issued })
	return hits
}

func dedupePkgs(in []PkgHit) []PkgHit {
	seen := map[PkgHit]bool{}
	out := in[:0]
	for _, p := range in {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// evalCriteria returns whether the criteria hold and appends the packages that
// made them hold. Nothing is recorded for branches that end up false, so a
// kernel flavour test that matched cannot leak into a USN that does not apply.
func (e *evaluator) evalCriteria(c *criteria, out *[]PkgHit) bool {
	or := c.Operator == "OR"
	result := !or
	var collected []PkgHit
	for i := range c.Items {
		item := &c.Items[i]
		if item.Skip {
			continue
		}
		var local []PkgHit
		var v bool
		if item.Sub != nil {
			v = e.evalCriteria(item.Sub, &local)
		} else {
			v = e.evalTest(item, &local)
		}
		if item.Negate {
			v = !v
		}
		if or {
			if v {
				result = true
				collected = append(collected, local...)
			}
		} else {
			if !v {
				return c.Negate
			}
			collected = append(collected, local...)
		}
	}
	if c.Negate {
		return !result
	}
	if result {
		*out = append(*out, collected...)
	}
	return result
}

func (e *evaluator) evalTest(item *criterionItem, out *[]PkgHit) bool {
	t, ok := e.feed.tests[item.TestRef]
	if !ok {
		return false
	}
	switch t.kind {
	case "dpkginfo_test":
		return e.evalDpkg(t, item.Comment, out)
	case "uname_test":
		return e.matchRelease(e.feed.statePat[t.state])
	case "variable_test":
		return e.evalKernel(t, item.Comment, out)
	}
	return false
}

func (e *evaluator) evalDpkg(t test, comment string, out *[]PkgHit) bool {
	varID, ok := e.feed.objectVar[t.object]
	if !ok {
		return false
	}
	fixed := e.feed.stateEVR[t.state]
	if fixed == "" {
		return false
	}
	source := ""
	if m := sourceFromComment.FindStringSubmatch(comment); m != nil {
		source = m[1]
	}
	vuln := false
	for _, binary := range e.feed.vars[varID] {
		for _, installed := range e.packages[binary] {
			if dpkg.Compare(installed, fixed) < 0 {
				vuln = true
				*out = append(*out, PkgHit{Source: source, Binary: binary, Installed: installed, Fixed: fixed})
			}
		}
	}
	return vuln
}

func (e *evaluator) matchRelease(pattern string) bool {
	if pattern == "" {
		return false
	}
	if v, ok := e.patCache[pattern]; ok {
		return v
	}
	v := false
	if re, err := regexp.Compile(pattern); err == nil {
		v = re.MatchString(e.release)
	}
	e.patCache[pattern] = v
	return v
}

func (e *evaluator) evalKernel(t test, comment string, out *[]PkgHit) bool {
	if !e.evrOK {
		return false
	}
	state := e.feed.stateEVR[t.state]
	if state == "" || dpkg.Compare(e.evr, state) >= 0 {
		return false
	}
	source := "linux"
	if m := kernelFromComment.FindStringSubmatch(comment); m != nil {
		source = m[1]
	}
	fixed := strings.TrimPrefix(state, "0:")
	if m := fixedInComment.FindStringSubmatch(comment); m != nil {
		fixed = m[1]
	}
	*out = append(*out, PkgHit{
		Source: source, Binary: "kernel " + source, Installed: e.release, Fixed: fixed, Kernel: true,
	})
	return true
}
