package checks

import (
	"reflect"
	"strings"
	"testing"

	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/oval"
)

func TestParseCVEList(t *testing.T) {
	got, err := ParseCVEList(" cve-2026-98432, CVE-2024-6387\tcve-2026-98432,,CVE-2021-44228 ")
	want := []string{"CVE-2026-98432", "CVE-2024-6387", "CVE-2021-44228"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", " , ", "CVE-2026-1", "2026-98432", "CVE-2026-98432;rm", "CVE-26-12345"} {
		if _, err := ParseCVEList(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestChecksFor(t *testing.T) {
	lookup := ChecksFor(Options{CVEs: []string{"CVE-2026-98432"}})
	if len(lookup) != 1 || lookup[0].ID != "cve.lookup" || containsHan(lookup[0].Name) {
		t.Errorf("a lookup runs only the lookup: %+v", lookup)
	}
	if got := ChecksFor(Options{}); len(got) != len(All()) {
		t.Errorf("a normal scan runs every check: %d of %d", len(got), len(All()))
	}
}

func TestLookupFinding(t *testing.T) {
	host := model.Host{OSVersion: "24.04", Codename: "noble"}
	meta := oval.CVEResult{ID: "CVE-2026-0001", Known: true, Priority: "high", CVSS: 9.8, Public: "20261015"}
	with := func(comps ...oval.Component) oval.CVEResult {
		r := meta
		r.Components = comps
		return r
	}
	ssl := oval.Component{Source: "openssl", Status: oval.FixAvailable, Installed: []string{"openssl 3.0.13-0ubuntu3.11", "libssl3t64 3.0.13-0ubuntu3.11"}, Fixed: "3.0.13-0ubuntu3.16"}
	kernel := oval.Component{Source: "linux", Kernel: true, Status: oval.FixAvailable, Installed: []string{"6.8.0-134-generic"}, Fixed: "6.8.0-147.147"}
	hwe := oval.Component{Source: "linux-hwe-7.0", Kernel: true, Status: oval.Unfixed, Installed: []string{"7.0.0-42-generic"}}
	shark := oval.Component{Source: "wireshark", Status: oval.Unfixed, Installed: []string{"tshark 4.2.2-1"}}
	magick := oval.Component{Source: "imagemagick", Status: oval.FixAvailable, Installed: []string{"imagemagick 8:6.9-5.2"}, Fixed: "8:6.9-5.2ubuntu0.1~esm1", Pro: true}
	curl := oval.Component{Source: "curl", Status: oval.Fixed, Installed: []string{"curl 8.5.0-2ubuntu10.16"}, Fixed: "8.5.0-2ubuntu10.16"}
	notInstalled := meta
	notInstalled.Sources = []string{"curl", "openssl"}
	kernelOnly := meta
	kernelOnly.KernelUnknown = true
	mixedUnknown := with(shark)
	mixedUnknown.KernelUnknown = true
	critical := with(hwe)
	critical.Priority = "critical"

	cases := []struct {
		name        string
		r           oval.CVEResult
		pro         bool
		sev         model.Severity
		title       string
		remediation string
		detail      string
		evidence    []string
	}{
		{"unknown", oval.CVEResult{ID: "CVE-2026-9999"}, false, model.Info, "CVE-2026-9999: not in Ubuntu's CVE data for 24.04 (noble)", "", "may be mistyped", nil},
		{"package fix", with(ssl), false, model.High, "CVE-2026-0001: affected, fix available", "sudo apt update && sudo apt install --only-upgrade libssl3t64 openssl", "older than the fixed version",
			[]string{"Priority high, CVSS 9.8, public 2026-10-15", "openssl 3.0.13-0ubuntu3.11 installed, fixed in 3.0.13-0ubuntu3.16", "libssl3t64 3.0.13-0ubuntu3.11 installed, fixed in 3.0.13-0ubuntu3.16"}},
		{"kernel fix", with(kernel), false, model.High, "CVE-2026-0001: affected, fix available", "sudo apt update && sudo apt full-upgrade, then reboot.", "only after a reboot",
			[]string{"Priority high, CVSS 9.8, public 2026-10-15", "kernel linux running 6.8.0-134-generic, fixed in 6.8.0-147.147"}},
		{"pro only", with(magick), false, model.High, "CVE-2026-0001: affected, fix available", "sudo pro attach <token>, then sudo pro fix CVE-2026-0001", "Ubuntu Pro", nil},
		{"pro enabled", with(magick), true, model.High, "CVE-2026-0001: affected, fix available", "sudo apt update && sudo apt install --only-upgrade imagemagick", "", nil},
		{"no fix", critical, false, model.Critical, "CVE-2026-0001: affected, no fix released yet", "No update exists yet. Follow https://ubuntu.com/security/CVE-2026-0001 for the fix and any mitigation.", "still being triaged",
			[]string{"Priority critical, CVSS 9.8, public 2026-10-15", "kernel linux-hwe-7.0 running 7.0.0-42-generic: no fix released"}},
		{"part fixed", with(ssl, shark, curl), false, model.High, "CVE-2026-0001: affected, a fix is available for part of it", "", "", []string{
			"Priority high, CVSS 9.8, public 2026-10-15", "openssl 3.0.13-0ubuntu3.11 installed, fixed in 3.0.13-0ubuntu3.16", "libssl3t64 3.0.13-0ubuntu3.11 installed, fixed in 3.0.13-0ubuntu3.16",
			"wireshark (tshark 4.2.2-1): no fix released", "curl 8.5.0-2ubuntu10.16: includes the fix from 8.5.0-2ubuntu10.16"}},
		{"kernel unknown", kernelOnly, false, model.Skipped, "CVE-2026-0001: kernel not checked", "", "running kernel was not checked", nil},
		{"package affected, kernel unknown", mixedUnknown, false, model.High, "CVE-2026-0001: affected, no fix released yet", "", "running kernel was not checked", nil},
		{"fixed", with(curl), false, model.OK, "CVE-2026-0001: fixed in the installed versions", "", "", nil},
		{"not installed", notInstalled, false, model.OK, "CVE-2026-0001: not affected, no affected package is installed", "", "",
			[]string{"Priority high, CVSS 9.8, public 2026-10-15", "Affected in Ubuntu: curl, openssl"}},
	}
	for _, c := range cases {
		f := lookupFinding(c.r, host, c.pro)
		if f.Severity != c.sev || f.Title != c.title || f.ID != "cve.lookup."+c.r.ID {
			t.Errorf("%s: got [%v] %s %s", c.name, f.Severity, f.ID, f.Title)
		}
		if c.remediation != "" && f.Remediation != c.remediation {
			t.Errorf("%s: remediation %q", c.name, f.Remediation)
		}
		if !strings.Contains(f.Detail, c.detail) {
			t.Errorf("%s: detail %q lacks %q", c.name, f.Detail, c.detail)
		}
		if c.evidence != nil && !reflect.DeepEqual(f.Evidence, c.evidence) {
			t.Errorf("%s: evidence\n got %q\nwant %q", c.name, f.Evidence, c.evidence)
		}
		if len(f.Refs) != 1 || f.Refs[0] != "https://ubuntu.com/security/"+c.r.ID {
			t.Errorf("%s: refs %q", c.name, f.Refs)
		}
		if containsHan(f.Title + f.Detail + f.Remediation + strings.Join(f.Evidence, "")) {
			t.Errorf("%s: text must be English", c.name)
		}
	}
	if f := lookupFinding(with(oval.Component{Source: "x", Status: oval.Unfixed, Installed: []string{"x 1"}}), host, false); f.Severity != model.High {
		t.Errorf("an affected host keeps the CVE's priority without a fix: %v", f.Severity)
	}
	low := with(shark)
	low.Priority = "low"
	if f := lookupFinding(low, host, false); f.Severity != model.Info {
		t.Errorf("a low priority CVE is informational: %v", f.Severity)
	}
}
