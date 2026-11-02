package oval

import (
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// cveSample follows the shape of com.ubuntu.<codename>.cve.oval.xml: one
// definition per CVE, unfixed packages tested for existence only, fixed ones
// against a version, and kernels by flavour.
const cveSample = `<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:ind-def="i" xmlns:unix-def="u" xmlns:linux-def="l" xmlns:oval="c">
<generator><oval:timestamp>2026-11-02T10:00:00</oval:timestamp></generator>
<definitions>
 <definition id="oval:com.ubuntu.noble:def:100" class="inventory" version="1">
  <metadata><title>Check that Ubuntu 24.04 LTS (noble) is installed.</title></metadata>
  <criteria><criterion test_ref="t100" comment="x"/></criteria>
 </definition>
 <definition id="oval:com.ubuntu.noble:def:1" class="vulnerability" version="1">
  <metadata><title>CVE-2026-0001 on Ubuntu 24.04 LTS (noble) - high</title>
   <advisory><severity>High</severity>
    <cve href="h" priority="high" public="20261015" cvss_score="9.8">CVE-2026-0001</cve>
   </advisory>
  </metadata>
  <criteria>
   <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="installed"/>
   <criteria operator="OR">
    <criterion test_ref="u1" comment="wireshark source package in noble, might be affected and may need fixing."/>
    <criterion test_ref="u2" comment="absent source package in noble, might be affected and may need fixing."/>
    <criterion test_ref="f1" comment="openssl source package in noble, is affected and has been fixed (note: '3.0.13-0ubuntu3.16')."/>
    <criterion test_ref="f2" comment="curl source package in noble, is affected and has been fixed (note: '8.5.0-2ubuntu10.16')."/>
    <criterion test_ref="f3" comment="imagemagick source package in esm-apps/noble, is affected and has been fixed (note: '8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm1')."/>
    <criterion test_ref="k1" comment="Is kernel 'linux-hwe-7.0' running?"/>
    <criterion test_ref="k4" comment="Is kernel 'linux-riscv-7.0' running?"/>
    <criteria operator="AND">
     <criterion test_ref="k2" comment="Is kernel 'linux' running?"/>
     <criterion test_ref="k3" comment="'linux' kernel in noble was vulnerable but has been fixed (note: '6.8.0-147.147')."/>
    </criteria>
   </criteria>
  </criteria>
 </definition>
 <definition id="oval:com.ubuntu.noble:def:2" class="vulnerability" version="1">
  <metadata><title>CVE-2026-0002 on Ubuntu 24.04 LTS (noble) - medium</title>
   <advisory><severity>Medium</severity><cve href="h" priority="medium" public="20260101">CVE-2026-0002</cve></advisory>
  </metadata>
  <criteria>
   <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="installed"/>
   <criterion test_ref="u9" comment="unwanted source package in noble, might be affected and may need fixing."/>
  </criteria>
 </definition>
</definitions>
<tests>
 <linux-def:dpkginfo_test id="u1" check_existence="at_least_one_exists"><linux-def:object object_ref="ou1"/></linux-def:dpkginfo_test>
 <linux-def:dpkginfo_test id="u2" check_existence="at_least_one_exists"><linux-def:object object_ref="ou2"/></linux-def:dpkginfo_test>
 <linux-def:dpkginfo_test id="u9" check_existence="at_least_one_exists"><linux-def:object object_ref="ou9"/></linux-def:dpkginfo_test>
 <linux-def:dpkginfo_test id="f1"><linux-def:object object_ref="of1"/><linux-def:state state_ref="sf1"/></linux-def:dpkginfo_test>
 <linux-def:dpkginfo_test id="f2"><linux-def:object object_ref="of2"/><linux-def:state state_ref="sf2"/></linux-def:dpkginfo_test>
 <linux-def:dpkginfo_test id="f3"><linux-def:object object_ref="of3"/><linux-def:state state_ref="sf3"/></linux-def:dpkginfo_test>
 <unix-def:uname_test id="k1"><unix-def:object object_ref="ok"/><unix-def:state state_ref="sk1"/></unix-def:uname_test>
 <unix-def:uname_test id="k2"><unix-def:object object_ref="ok"/><unix-def:state state_ref="sk2"/></unix-def:uname_test>
 <unix-def:uname_test id="k4"><unix-def:object object_ref="ok"/><unix-def:state state_ref="sk1"/></unix-def:uname_test>
 <ind-def:variable_test id="k3"><ind-def:object object_ref="okv"/><ind-def:state state_ref="sk3"/></ind-def:variable_test>
</tests>
<objects>
 <linux-def:dpkginfo_object id="ou1"><linux-def:name var_ref="vu1"/></linux-def:dpkginfo_object>
 <linux-def:dpkginfo_object id="ou2"><linux-def:name var_ref="vu2"/></linux-def:dpkginfo_object>
 <linux-def:dpkginfo_object id="ou9"><linux-def:name var_ref="vu9"/></linux-def:dpkginfo_object>
 <linux-def:dpkginfo_object id="of1"><linux-def:name var_ref="vf1"/></linux-def:dpkginfo_object>
 <linux-def:dpkginfo_object id="of2"><linux-def:name var_ref="vf2"/></linux-def:dpkginfo_object>
 <linux-def:dpkginfo_object id="of3"><linux-def:name var_ref="vf3"/></linux-def:dpkginfo_object>
 <unix-def:uname_object id="ok"/>
 <ind-def:variable_object id="okv"><ind-def:var_ref>vk</ind-def:var_ref></ind-def:variable_object>
</objects>
<states>
 <linux-def:dpkginfo_state id="sf1"><linux-def:evr operation="less than">0:3.0.13-0ubuntu3.16</linux-def:evr></linux-def:dpkginfo_state>
 <linux-def:dpkginfo_state id="sf2"><linux-def:evr operation="less than">0:8.5.0-2ubuntu10.16</linux-def:evr></linux-def:dpkginfo_state>
 <linux-def:dpkginfo_state id="sf3"><linux-def:evr operation="less than">8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm1</linux-def:evr></linux-def:dpkginfo_state>
 <unix-def:uname_state id="sk1"><unix-def:os_release operation="pattern match">7\.0\.0\-\d+(\-generic|\-generic\-64k)</unix-def:os_release></unix-def:uname_state>
 <unix-def:uname_state id="sk2"><unix-def:os_release operation="pattern match">6\.8\.0\-\d+(\-generic|\-generic\-64k)</unix-def:os_release></unix-def:uname_state>
 <ind-def:variable_state id="sk3"><ind-def:value operation="less than" datatype="debian_evr_string">0:6.8.0-147</ind-def:value></ind-def:variable_state>
</states>
<variables>
 <constant_variable id="vu1" datatype="string"><value>wireshark</value><value>tshark</value></constant_variable>
 <constant_variable id="vu2" datatype="string"><value>absent</value></constant_variable>
 <constant_variable id="vu9" datatype="string"><value>unwanted</value></constant_variable>
 <constant_variable id="vf1" datatype="string"><value>openssl</value><value>libssl3t64</value></constant_variable>
 <constant_variable id="vf2" datatype="string"><value>curl</value></constant_variable>
 <constant_variable id="vf3" datatype="string"><value>imagemagick</value></constant_variable>
 <local_variable id="vk" datatype="debian_evr_string"><concat><literal_component>0:</literal_component><regex_capture pattern="^([\d|\.]+-\d+)[-\w]+$"><object_component object_ref="ok" item_field="os_release"/></regex_capture></concat></local_variable>
</variables>
</oval_definitions>`

func parseCVESample(t *testing.T, ids ...string) *Feed {
	t.Helper()
	f, err := ParseCVEs(strings.NewReader(cveSample), false, ids)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

var hostPackages = map[string][]string{
	"tshark":      {"4.2.2-1"},
	"openssl":     {"3.0.13-0ubuntu3.11"},
	"libssl3t64":  {"3.0.13-0ubuntu3.11"},
	"curl":        {"8.5.0-2ubuntu10.16"},
	"imagemagick": {"8:6.9.12.98+dfsg1-5.2"},
}

func TestParseCVEsKeepsOnlyWantedDefinitions(t *testing.T) {
	f := parseCVESample(t, "cve-2026-0001")
	if f.Release != "noble" || f.VulnerabilityCount() != 2 || len(f.cveDefs) != 1 {
		t.Fatalf("release %q, %d vulnerabilities, %d kept", f.Release, f.VulnerabilityCount(), len(f.cveDefs))
	}
	if _, kept := f.tests["u9"]; kept {
		t.Error("a test only an unwanted CVE uses was kept")
	}
	if _, kept := f.vars["vu9"]; kept {
		t.Error("a variable only an unwanted CVE uses was kept")
	}
	if len(f.vars["vu1"]) != 2 || f.stateEVR["sf1"] == "" || f.statePat["sk1"] == "" {
		t.Error("what the wanted CVE uses must be kept")
	}
}

func TestLookupPackages(t *testing.T) {
	f := parseCVESample(t, "CVE-2026-0001")
	r := f.LookupCVEs([]string{"cve-2026-0001"}, hostPackages, "")[0]
	if !r.Known || r.ID != "CVE-2026-0001" || r.Priority != "high" || r.CVSS != 9.8 || r.Public != "20261015" {
		t.Fatalf("metadata: %+v", r)
	}
	want := []Component{
		{Source: "wireshark", Status: Unfixed, Installed: []string{"tshark 4.2.2-1"}},
		{Source: "openssl", Status: FixAvailable, Installed: []string{"openssl 3.0.13-0ubuntu3.11", "libssl3t64 3.0.13-0ubuntu3.11"}, Fixed: "3.0.13-0ubuntu3.16"},
		{Source: "curl", Status: Fixed, Installed: []string{"curl 8.5.0-2ubuntu10.16"}, Fixed: "8.5.0-2ubuntu10.16"},
		{Source: "imagemagick", Status: FixAvailable, Installed: []string{"imagemagick 8:6.9.12.98+dfsg1-5.2"}, Fixed: "8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm1", Pro: true},
	}
	if !reflect.DeepEqual(r.Components, want) {
		t.Errorf("components:\n got %+v\nwant %+v", r.Components, want)
	}
	wantSources := []string{"absent", "curl", "imagemagick", "linux", "linux-hwe-7.0", "openssl", "wireshark"}
	if !reflect.DeepEqual(r.Sources, wantSources) {
		t.Errorf("sources: %q", r.Sources)
	}
	if !r.KernelUnknown {
		t.Error("with no release given, the kernel must be reported as not checked")
	}
}

func TestLookupKernels(t *testing.T) {
	f := parseCVESample(t, "CVE-2026-0001")
	cases := []struct {
		release string
		want    *Component
	}{
		{"7.0.0-42-generic", &Component{Source: "linux-hwe-7.0", Kernel: true, Status: Unfixed, Installed: []string{"7.0.0-42-generic"}}},
		{"6.8.0-134-generic", &Component{Source: "linux", Kernel: true, Status: FixAvailable, Installed: []string{"6.8.0-134-generic"}, Fixed: "6.8.0-147.147"}},
		{"6.8.0-147-generic", &Component{Source: "linux", Kernel: true, Status: Fixed, Installed: []string{"6.8.0-147-generic"}, Fixed: "6.8.0-147.147"}},
		{"6.8.0-150-generic", &Component{Source: "linux", Kernel: true, Status: Fixed, Installed: []string{"6.8.0-150-generic"}, Fixed: "6.8.0-147.147"}},
		{"6.8.0-134-aws", nil},
		{"6.12.0-1-custom", nil},
	}
	for _, c := range cases {
		r := f.LookupCVEs([]string{"CVE-2026-0001"}, nil, c.release)[0]
		var got *Component
		for i := range r.Components {
			if r.Components[i].Kernel {
				got = &r.Components[i]
			}
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v, want %+v", c.release, got, c.want)
		}
		if unknown := c.want == nil; r.KernelUnknown != unknown {
			t.Errorf("%s: kernel unknown %v, want %v", c.release, r.KernelUnknown, unknown)
		}
		for _, comp := range r.Components {
			if !comp.Kernel {
				t.Errorf("%s: no packages given, yet %+v", c.release, comp)
			}
		}
	}
}

func TestLookupRISCVKernelOnlyOnRISCV(t *testing.T) {
	f := parseCVESample(t, "CVE-2026-0001")
	defer func(arch string) { hostArch = arch }(hostArch)
	for arch, want := range map[string]int{"amd64": 1, "arm64": 1, "riscv64": 2} {
		hostArch = arch
		r := f.LookupCVEs([]string{"CVE-2026-0001"}, nil, "7.0.0-42-generic")[0]
		if len(r.Components) != want {
			t.Errorf("%s: %d kernels match 7.0.0-42-generic, want %d: %+v", arch, len(r.Components), want, r.Components)
		}
	}
}

func TestLookupUnknownCVE(t *testing.T) {
	f := parseCVESample(t, "CVE-2026-9999", "CVE-2026-0002")
	got := f.LookupCVEs([]string{"CVE-2026-9999", "CVE-2026-0002"}, hostPackages, "6.8.0-1-generic")
	if got[0].Known || got[0].ID != "CVE-2026-9999" {
		t.Errorf("a CVE missing from the feed: %+v", got[0])
	}
	if !got[1].Known || len(got[1].Components) != 0 || got[1].KernelUnknown || !reflect.DeepEqual(got[1].Sources, []string{"unwanted"}) {
		t.Errorf("a known CVE whose package is not installed: %+v", got[1])
	}
}

func TestParseCVEsRejectsAnOrderItCannotFilter(t *testing.T) {
	doc := `<oval_definitions><tests><linux-def:dpkginfo_test id="t"/></tests><definitions/></oval_definitions>`
	if _, err := ParseCVEs(strings.NewReader(doc), false, []string{"CVE-1-1"}); err == nil {
		t.Error("tests before definitions would drop every test, so parsing must fail")
	}
}

func TestUSNFeedHasNoCVEDefinitions(t *testing.T) {
	f, err := ParseCVEs(strings.NewReader(sample), false, []string{"CVE-2024-0001"})
	if err != nil {
		t.Fatal(err)
	}
	if f.VulnerabilityCount() != 0 {
		t.Errorf("a USN feed passed as the CVE feed must be recognizable: %d", f.VulnerabilityCount())
	}
}

// TestRealCVEFeed runs against a downloaded CVE feed when CVE_OVAL_FILE is set.
// CVE_OVAL_IDS lists CVEs to look up, and CVE_OVAL_KERNEL a uname release.
func TestRealCVEFeed(t *testing.T) {
	path := os.Getenv("CVE_OVAL_FILE")
	if path == "" {
		t.Skip("CVE_OVAL_FILE not set")
	}
	ids := strings.Split(os.Getenv("CVE_OVAL_IDS"), ",")
	r, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	start := time.Now()
	f, err := ParseCVEs(r, strings.HasSuffix(path, ".bz2"), ids)
	if err != nil {
		t.Fatal(err)
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	t.Logf("parsed in %s, heap in use %d MiB, peak from the OS %d MiB", time.Since(start).Round(time.Millisecond), mem.HeapInuse>>20, mem.Sys>>20)
	t.Logf("feed %s for %s: %d CVE definitions, %d kept, %d tests kept", f.Timestamp, f.Release, f.VulnerabilityCount(), len(f.cveDefs), len(f.tests))
	if f.VulnerabilityCount() < 1000 {
		t.Fatalf("only %d CVE definitions", f.VulnerabilityCount())
	}
	for _, res := range f.LookupCVEs(ids, nil, os.Getenv("CVE_OVAL_KERNEL")) {
		t.Logf("%s known=%v priority=%s kernel_unknown=%v sources=%d", res.ID, res.Known, res.Priority, res.KernelUnknown, len(res.Sources))
		for _, c := range res.Components {
			t.Logf("    %s: %s %v fixed=%q", c.Source, c.Status, c.Installed, c.Fixed)
		}
	}
}
