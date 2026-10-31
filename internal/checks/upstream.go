package checks

import (
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"
)

// nginxAdvisory is one entry of nginx.org's security advisories page.
type nginxAdvisory struct {
	Title         string
	Severity      string
	CVEs          []string
	Vulnerable    string
	NotVulnerable string
}

var (
	nginxEntryRe = regexp.MustCompile(`(?s)<li><p>(.*?)</p></li>`)
	nginxCVERe   = regexp.MustCompile(`CVE-\d{4}-\d+`)
	htmlTagRe    = regexp.MustCompile(`<[^>]+>`)
	versionRe    = regexp.MustCompile(`^\d+(\.\d+)*$`)
)

// parseNginxAdvisories parses the advisories page. Entries lacking a Vulnerable
// field are not advisories and are ignored.
func parseNginxAdvisories(page string) []nginxAdvisory {
	var out []nginxAdvisory
	for _, m := range nginxEntryRe.FindAllStringSubmatch(page, -1) {
		parts := strings.Split(m[1], "<br>")
		if len(parts) == 0 {
			continue
		}
		a := nginxAdvisory{Title: html.UnescapeString(strings.TrimSpace(htmlTagRe.ReplaceAllString(parts[0], "")))}
		for _, part := range parts[1:] {
			text := html.UnescapeString(strings.TrimSpace(htmlTagRe.ReplaceAllString(part, "")))
			switch {
			case strings.HasPrefix(text, "Severity:"):
				a.Severity = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(text, "Severity:")))
			case strings.HasPrefix(text, "Not vulnerable:"):
				a.NotVulnerable = strings.TrimSpace(strings.TrimPrefix(text, "Not vulnerable:"))
			case strings.HasPrefix(text, "Vulnerable:"):
				a.Vulnerable = strings.TrimSpace(strings.TrimPrefix(text, "Vulnerable:"))
			default:
				a.CVEs = append(a.CVEs, nginxCVERe.FindAllString(text, -1)...)
			}
		}
		if a.Vulnerable != "" {
			out = append(out, a)
		}
	}
	return out
}

func compareDotted(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func minorOf(v string) string {
	p := strings.Split(v, ".")
	if len(p) >= 2 {
		return p[0] + "." + p[1]
	}
	return v
}

// Affects reports whether a version is in the vulnerable range. nginx writes
// ranges that span stable branches, such as Vulnerable: 0.1.29-1.31.6 with Not
// vulnerable: 1.31.7+, 1.30.6+, so 1.30.6 lies inside the range yet is fixed.
// A "x.y.z+" entry therefore clears versions on its own x.y branch at or above it.
func (a nginxAdvisory) Affects(version string) bool {
	if !versionRe.MatchString(version) {
		return false
	}
	inRange := false
	for _, tok := range strings.Split(a.Vulnerable, ",") {
		tok = strings.TrimSpace(tok)
		switch {
		case tok == "all":
			inRange = true
		case strings.Contains(tok, " "):
			// Platform specific ranges, such as "nginx/Windows 1.2.3-1.2.4".
		default:
			lo, hi, isRange := strings.Cut(tok, "-")
			if !isRange {
				hi = lo
			}
			if versionRe.MatchString(lo) && versionRe.MatchString(hi) &&
				compareDotted(version, lo) >= 0 && compareDotted(version, hi) <= 0 {
				inRange = true
			}
		}
	}
	if !inRange {
		return false
	}
	for _, tok := range strings.Split(a.NotVulnerable, ",") {
		tok = strings.TrimSpace(tok)
		fixed, hasPlus := strings.CutSuffix(tok, "+")
		if !versionRe.MatchString(fixed) {
			continue
		}
		if hasPlus && minorOf(fixed) == minorOf(version) && compareDotted(version, fixed) >= 0 {
			return false
		}
		if !hasPlus && compareDotted(version, fixed) == 0 {
			return false
		}
	}
	return true
}

type phpRelease struct {
	Version string   `json:"version"`
	Tags    []string `json:"tags"`
}

// parsePHPActive parses php.net/releases/active.php into branch -> latest
// release, for example "8.3" -> 8.3.36.
func parsePHPActive(data []byte) (map[string]phpRelease, error) {
	var raw map[string]map[string]phpRelease
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := map[string]phpRelease{}
	for _, branches := range raw {
		for branch, rel := range branches {
			if rel.Version != "" {
				out[branch] = rel
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no active PHP branches in response")
	}
	return out, nil
}

// assessPHP compares a PHP version with php.net's active branches. It returns
// how far behind the version is, or an empty status when it is current.
func assessPHP(version string, active map[string]phpRelease) (status string, latest phpRelease) {
	branch := minorOf(version)
	rel, ok := active[branch]
	if !ok {
		return "eol", phpRelease{}
	}
	if compareDotted(version, rel.Version) < 0 {
		return "behind", rel
	}
	return "", rel
}
