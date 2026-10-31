package oval

import (
	"os"
	"strings"
	"testing"
)

const sample = `<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:ind-def="i" xmlns:unix-def="u" xmlns:linux-def="l" xmlns:oval="c">
<generator><oval:timestamp>2026-10-30T13:03:53</oval:timestamp></generator>
<definitions>
 <definition id="d100" class="inventory" version="1">
  <metadata><title>Check that Ubuntu is installed.</title></metadata>
  <criteria><criterion test_ref="t100" comment="x"/></criteria>
 </definition>
 <definition id="d1" class="patch" version="1">
  <metadata><title>USN-1000-1 -- nginx vulnerabilities</title>
   <advisory><severity>High</severity><issued date="2024-01-02T00:00:00Z"/>
    <cve href="h" priority="high" cvss_score="7.5">CVE-2024-0001</cve>
    <cve href="h" priority="medium">CVE-2024-0002</cve>
   </advisory>
  </metadata>
  <criteria>
   <extend_definition applicability_check="true" definition_ref="d100" comment="installed"/>
   <criterion test_ref="t1" comment="nginx source package in jammy, is affected and has been fixed (note: '1.18.0-6ubuntu14.5')."/>
  </criteria>
 </definition>
 <definition id="d2" class="patch" version="1">
  <metadata><title>USN-2000-1 -- Linux kernel vulnerabilities</title>
   <advisory><severity>Critical</severity><issued date="2025-01-02T00:00:00Z"/>
    <cve href="h" priority="critical" cvss_score="9.8">CVE-2025-0001</cve>
   </advisory>
  </metadata>
  <criteria>
   <extend_definition applicability_check="true" definition_ref="d100" comment="installed"/>
   <criteria operator="OR">
    <criteria operator="AND">
     <criterion test_ref="k1" comment="Is kernel 'linux' running?"/>
     <criterion test_ref="k2" comment="'linux' kernel in jammy was vulnerable but has been fixed (note: '5.15.0-27.28')."/>
    </criteria>
    <criteria operator="AND">
     <criterion test_ref="k3" comment="Is kernel 'linux-aws' running?"/>
     <criterion test_ref="k4" comment="'linux-aws' kernel in jammy was vulnerable but has been fixed (note: '5.15.0-1005.7')."/>
    </criteria>
   </criteria>
  </criteria>
 </definition>
 <definition id="d3" class="patch" version="1">
  <metadata><title>LSN-0086-1 -- Kernel Live Patch Security Notice</title></metadata>
  <criteria><criterion test_ref="t1" comment="livepatch"/></criteria>
 </definition>
 <definition id="d4" class="patch" version="1">
  <metadata><title>USN-3000-1 -- jQuery UI vulnerability</title>
   <advisory><severity>Medium</severity><issued date="2022-01-02T00:00:00Z"/></advisory>
  </metadata>
  <criteria>
   <extend_definition applicability_check="true" definition_ref="d100" comment="installed"/>
   <criterion test_ref="t2" comment="jqueryui source package in esm-apps/jammy, is affected and has been fixed (note: '1.13.1-1~esm1')."/>
  </criteria>
 </definition>
</definitions>
<tests>
 <ind-def:textfilecontent54_test id="t100"><ind-def:object object_ref="o100"/><ind-def:state state_ref="s100"/></ind-def:textfilecontent54_test>
 <linux-def:dpkginfo_test id="t1"><linux-def:object object_ref="o1"/><linux-def:state state_ref="s1"/></linux-def:dpkginfo_test>
 <linux-def:dpkginfo_test id="t2"><linux-def:object object_ref="o2"/><linux-def:state state_ref="s2"/></linux-def:dpkginfo_test>
 <unix-def:uname_test id="k1"><unix-def:object object_ref="o200"/><unix-def:state state_ref="ks1"/></unix-def:uname_test>
 <ind-def:variable_test id="k2"><ind-def:object object_ref="o210"/><ind-def:state state_ref="ks2"/></ind-def:variable_test>
 <unix-def:uname_test id="k3"><unix-def:object object_ref="o200"/><unix-def:state state_ref="ks3"/></unix-def:uname_test>
 <ind-def:variable_test id="k4"><ind-def:object object_ref="o210"/><ind-def:state state_ref="ks4"/></ind-def:variable_test>
</tests>
<objects>
 <linux-def:dpkginfo_object id="o1"><linux-def:name var_ref="v1" var_check="at least one"/></linux-def:dpkginfo_object>
 <linux-def:dpkginfo_object id="o2"><linux-def:name var_ref="v2" var_check="at least one"/></linux-def:dpkginfo_object>
 <unix-def:uname_object id="o200"/>
 <ind-def:variable_object id="o210"><ind-def:var_ref>v200</ind-def:var_ref></ind-def:variable_object>
</objects>
<states>
 <linux-def:dpkginfo_state id="s1"><linux-def:evr datatype="debian_evr_string" operation="less than">1.18.0-6ubuntu14.5</linux-def:evr></linux-def:dpkginfo_state>
 <linux-def:dpkginfo_state id="s2"><linux-def:evr datatype="debian_evr_string" operation="less than">1.13.1-1~esm1</linux-def:evr></linux-def:dpkginfo_state>
 <unix-def:uname_state id="ks1"><unix-def:os_release operation="pattern match">5\.15\.0\-\d+(\-generic|\-generic\-64k)</unix-def:os_release></unix-def:uname_state>
 <ind-def:variable_state id="ks2"><ind-def:value datatype="debian_evr_string" operation="less than">0:5.15.0-27</ind-def:value></ind-def:variable_state>
 <unix-def:uname_state id="ks3"><unix-def:os_release operation="pattern match">5\.15\.0\-\d+(\-aws)</unix-def:os_release></unix-def:uname_state>
 <ind-def:variable_state id="ks4"><ind-def:value datatype="debian_evr_string" operation="less than">0:5.15.0-1005</ind-def:value></ind-def:variable_state>
</states>
<variables>
 <local_variable id="v200" datatype="debian_evr_string"><concat><literal_component>0:</literal_component><regex_capture pattern="^([\d|\.]+-\d+)[-|\w]+$"><object_component object_ref="o200" item_field="os_release"/></regex_capture></concat></local_variable>
 <constant_variable id="v1" datatype="string"><value>nginx</value><value>nginx-core</value></constant_variable>
 <constant_variable id="v2" datatype="string"><value>libjs-jquery-ui</value></constant_variable>
</variables>
</oval_definitions>`

func parseSample(t *testing.T) *Feed {
	t.Helper()
	f, err := Parse(strings.NewReader(sample), false)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func hitByUSN(hits []Hit, usn string) *Hit {
	for i := range hits {
		if hits[i].USN == usn {
			return &hits[i]
		}
	}
	return nil
}

func TestParseKeepsOnlyUSNPatchDefinitions(t *testing.T) {
	f := parseSample(t)
	if f.DefinitionCount() != 3 {
		t.Fatalf("want 3 USN definitions (LSN and inventory dropped), got %d", f.DefinitionCount())
	}
	if f.Timestamp != "2026-10-30T13:03:53" {
		t.Errorf("timestamp = %q", f.Timestamp)
	}
}

func TestVulnerablePackageIsReported(t *testing.T) {
	hits := parseSample(t).Evaluate(map[string][]string{"nginx-core": {"1.18.0-6ubuntu14.4"}}, "5.15.0-200-generic")
	h := hitByUSN(hits, "USN-1000-1")
	if h == nil {
		t.Fatalf("USN-1000-1 not reported: %+v", hits)
	}
	if h.Severity != "high" || len(h.CVEs) != 2 || h.CVEs[0].CVSS != 7.5 {
		t.Errorf("advisory metadata wrong: %+v", h)
	}
	p := h.Packages[0]
	if p.Source != "nginx" || p.Binary != "nginx-core" || p.Fixed != "1.18.0-6ubuntu14.5" {
		t.Errorf("package hit wrong: %+v", p)
	}
	if p.RequiresPro() {
		t.Error("regular fix must not be flagged as Pro only")
	}
}

func TestFixedOrAbsentPackageIsNotReported(t *testing.T) {
	f := parseSample(t)
	for name, pkgs := range map[string]map[string][]string{
		"backported fix": {"nginx": {"1.18.0-6ubuntu14.5"}},
		"newer":          {"nginx": {"1.18.0-6ubuntu14.10"}},
		"not installed":  {"curl": {"1.0"}},
	} {
		if h := hitByUSN(f.Evaluate(pkgs, "5.15.0-200-generic"), "USN-1000-1"); h != nil {
			t.Errorf("%s: unexpected hit %+v", name, h)
		}
	}
}

func TestKernelEvaluatesOnlyRunningFlavour(t *testing.T) {
	f := parseSample(t)
	h := hitByUSN(f.Evaluate(nil, "5.15.0-25-generic"), "USN-2000-1")
	if h == nil {
		t.Fatal("old generic kernel should match")
	}
	if len(h.Packages) != 1 || h.Packages[0].Source != "linux" || !h.Packages[0].Kernel || h.Packages[0].Fixed != "5.15.0-27.28" {
		t.Errorf("kernel hit wrong: %+v", h.Packages)
	}
	if hitByUSN(f.Evaluate(nil, "5.15.0-27-generic"), "USN-2000-1") != nil {
		t.Error("kernel at the fixed ABI must not match")
	}
	if hitByUSN(f.Evaluate(nil, "5.15.0-1006-aws"), "USN-2000-1") != nil {
		t.Error("newer aws kernel must not match")
	}
	h = hitByUSN(f.Evaluate(nil, "5.15.0-1004-aws"), "USN-2000-1")
	if h == nil || h.Packages[0].Source != "linux-aws" {
		t.Errorf("aws flavour should match with its own source: %+v", h)
	}
	if hitByUSN(f.Evaluate(nil, "6.8.0-1-orbstack"), "USN-2000-1") != nil {
		t.Error("foreign kernel must not match")
	}
}

func TestProOnlyFixIsFlagged(t *testing.T) {
	h := hitByUSN(parseSample(t).Evaluate(map[string][]string{"libjs-jquery-ui": {"1.13.0-1"}}, "x"), "USN-3000-1")
	if h == nil || !h.Packages[0].RequiresPro() {
		t.Fatalf("expected Pro only fix: %+v", h)
	}
}

func TestParseRejectsWrongDocument(t *testing.T) {
	if _, err := Parse(strings.NewReader("<html><body>blocked by proxy</body></html>"), false); err == nil {
		t.Error("a captive portal page must not parse as an empty feed")
	}
	if _, err := Parse(strings.NewReader(""), false); err == nil {
		t.Error("empty input must fail")
	}
}

// TestRealFeed runs against a downloaded feed when OVAL_FILE is set.
func TestRealFeed(t *testing.T) {
	path := os.Getenv("OVAL_FILE")
	if path == "" {
		t.Skip("OVAL_FILE not set")
	}
	r, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	f, err := Parse(r, strings.HasSuffix(path, ".bz2"))
	if err != nil {
		t.Fatal(err)
	}
	if f.DefinitionCount() < 100 {
		t.Fatalf("only %d definitions", f.DefinitionCount())
	}
	hits := f.Evaluate(map[string][]string{"nginx": {"0.1-1"}, "openssl": {"0.1-1"}, "sudo": {"0.1-1"}}, "1.0.0-1-generic")
	t.Logf("feed %s: %d definitions, %d hits for ancient packages", f.Timestamp, f.DefinitionCount(), len(hits))
	if len(hits) == 0 {
		t.Error("ancient packages should match real USNs")
	}
	// OVAL_KERNEL names an old kernel for this release, such as
	// 5.15.0-25-generic on jammy. It must match real kernel USNs, and the same
	// flavour with a far newer ABI must not.
	release := os.Getenv("OVAL_KERNEL")
	if release == "" {
		return
	}
	countKernel := func(rel string) (kernel, foreign int) {
		for _, h := range f.Evaluate(nil, rel) {
			for _, p := range h.Packages {
				if p.Kernel {
					kernel++
				} else {
					foreign++
				}
			}
		}
		return
	}
	old, foreign := countKernel(release)
	t.Logf("kernel %s: %d kernel hits", release, old)
	if old == 0 {
		t.Errorf("old kernel %s should match kernel USNs", release)
	}
	if foreign != 0 {
		t.Errorf("no packages installed, yet %d package hits", foreign)
	}
	parts := strings.SplitN(release, "-", 3)
	newest := parts[0] + "-99999-" + parts[2]
	if n, _ := countKernel(newest); n != 0 {
		t.Errorf("kernel %s should match nothing, got %d", newest, n)
	}
}
