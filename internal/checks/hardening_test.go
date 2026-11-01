package checks

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/procinfo"
)

func TestParseUfwDefaults(t *testing.T) {
	for _, c := range []struct{ src, policy, ipv6 string }{
		{"# comment\nIPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n", "DROP", "yes"},
		{"DEFAULT_INPUT_POLICY='accept' # opened for testing\nIPV6=NO\n", "ACCEPT", "no"},
		{"#IPV6=no\n#DEFAULT_INPUT_POLICY=\"ACCEPT\"\n", "", ""},
		{"DEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n", "", ""},
		{"", "", ""},
	} {
		policy, ipv6 := parseUfwDefaults(c.src)
		if policy != c.policy || ipv6 != c.ipv6 {
			t.Errorf("parseUfwDefaults(%q) = %q, %q, want %q, %q", c.src, policy, ipv6, c.policy, c.ipv6)
		}
	}
}

func TestPublicIPv6Addrs(t *testing.T) {
	got := publicIPv6Addrs(strings.Join([]string{
		"20010db8000000000000000000000001 02 40 00 80 eth0",
		"fd000000000000000000000000000001 03 40 00 80 docker0", // unique local
		"fe800000000000000000000000000001 02 40 20 80 eth0",    // link local
		"00000000000000000000000000000001 01 80 10 80 lo",      // loopback
		"20010db8000000000000000000000002 01 80 00 80 lo",      // public, but not reachable on lo
		"not-hex 02 40 00 80 eth1",
		"short line",
	}, "\n"))
	want := []string{"2001:db8::1 on eth0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestIPv6Listeners(t *testing.T) {
	sock := func(proto, ip string, port uint16, state int, hostNS bool) procinfo.Socket {
		return procinfo.Socket{Proto: proto, LocalIP: netip.MustParseAddr(ip), LocalPort: port, State: state, HostNS: hostNS}
	}
	view := &procinfo.NetView{Sockets: []procinfo.Socket{
		sock("tcp6", "::", 22, procinfo.StateListen, true),
		sock("tcp6", "2001:db8::1", 443, procinfo.StateListen, true),
		sock("udp6", "::", 500, procinfo.StateClose, true),
		sock("tcp6", "::1", 25, procinfo.StateListen, true),              // loopback
		sock("tcp6", "fe80::1", 26, procinfo.StateListen, true),          // link local
		sock("tcp6", "fd00::1", 27, procinfo.StateListen, true),          // unique local
		sock("tcp6", "::ffff:192.0.2.1", 28, procinfo.StateListen, true), // really IPv4
		sock("tcp", "0.0.0.0", 29, procinfo.StateListen, true),           // IPv4
		sock("tcp6", "::", 30, procinfo.StateListen, false),              // another namespace
		sock("tcp6", "::", 31, 1, true),                                  // not listening
	}}
	got := strings.Join(ipv6Listeners(view), "\n")
	for _, want := range []string{"[::]:22", "[2001:db8::1]:443", "[::]:500"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in:\n%s", want, got)
		}
	}
	for _, port := range []string{":25", ":26", ":27", ":28", ":29", ":30", ":31"} {
		if strings.Contains(got, port+" ") {
			t.Errorf("%s should not be listed:\n%s", port, got)
		}
	}
}

func TestPublishedPorts(t *testing.T) {
	type ports = map[string][]dockerPortBinding
	for _, c := range []struct {
		name              string
		actual, requested ports
		want              []string
	}{
		{"all interfaces", ports{"80/tcp": {{"0.0.0.0", "8080"}, {"::", "8080"}}}, nil, []string{"0.0.0.0:8080 -> 80/tcp", "[::]:8080 -> 80/tcp"}},
		{"a specific address still bypasses ufw", ports{"80/tcp": {{"192.0.2.5", "80"}}}, nil, []string{"192.0.2.5:80 -> 80/tcp"}},
		{"loopback is not exposed", ports{"80/tcp": {{"127.0.0.1", "80"}, {"::1", "80"}}}, nil, nil},
		{"exposed but not published", ports{"80/tcp": nil}, nil, nil},
		{"actual wins over requested", ports{"80/tcp": {{"127.0.0.1", "80"}}}, ports{"80/tcp": {{"", "80"}}}, nil},
		{"requested is the fallback, and empty means all interfaces", nil, ports{"80/tcp": {{"", "80"}}}, []string{"0.0.0.0:80 -> 80/tcp"}},
		{"Docker chooses the port", nil, ports{"80/tcp": {{"", ""}}}, []string{"0.0.0.0:any -> 80/tcp"}},
		{"no ports", nil, nil, nil},
	} {
		if got := publishedPorts(c.actual, c.requested); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDockerManagesIptables(t *testing.T) {
	for src, want := range map[string]bool{
		`{"iptables": false}`:         false,
		`{"iptables": true}`:          true,
		`{"log-driver": "json-file"}`: true,
		`not json`:                    true,
		``:                            true,
	} {
		if got := dockerManagesIptables([]byte(src)); got != want {
			t.Errorf("%q: got %v, want %v", src, got, want)
		}
	}
}

func TestDockerUfwFinding(t *testing.T) {
	published := []string{"web  0.0.0.0:80 -> 80/tcp"}
	f := dockerUfwFinding(published, false)
	if f.Severity != model.Medium || !strings.Contains(f.Title, "bypass ufw") || f.Remediation == "" {
		t.Errorf("unfiltered: %+v", f)
	}
	f = dockerUfwFinding(published, true)
	if f.Severity != model.Info || !strings.Contains(f.Detail, "DOCKER-USER") {
		t.Errorf("rules in DOCKER-USER should lower the severity, not hide the ports: %+v", f)
	}
	if !reflect.DeepEqual(f.Evidence, published) {
		t.Errorf("the ports should still be listed: %v", f.Evidence)
	}
}

func TestParseModuleBlocks(t *testing.T) {
	blocked := map[string]bool{}
	parseModuleBlocks(strings.Join([]string{
		"# blacklist commented",
		"blacklist dccp",
		"install rds /bin/false",
		"install tipc /usr/bin/true",
		"install sctp /sbin/modprobe --ignore-install sctp", // still loads it
		"options other x=1",
	}, "\n"), blocked)
	want := map[string]bool{"dccp": true, "rds": true, "tipc": true}
	if !reflect.DeepEqual(blocked, want) {
		t.Errorf("got %v, want %v", blocked, want)
	}
}

func TestParseCmdlineBlocks(t *testing.T) {
	blocked := map[string]bool{}
	parseCmdlineBlocks("BOOT_IMAGE=/vmlinuz ro modprobe.blacklist=dccp,sctp module_blacklist=rds quiet", blocked)
	want := map[string]bool{"dccp": true, "sctp": true, "rds": true}
	if !reflect.DeepEqual(blocked, want) {
		t.Errorf("got %v, want %v", blocked, want)
	}
}

func TestAssessRareProtocols(t *testing.T) {
	const dep = "kernel/net/ipv4/tcp_bbr.ko.zst:\nkernel/net/dccp/dccp.ko.zst:\nkernel/net/sctp/sctp.ko.zst: kernel/lib/libcrc32c.ko\nkernel/net/rds/rds.ko:\nkernel/net/tipc/tipc.ko.xz:\n"
	for _, c := range []struct {
		name, modules, dep, builtin string
		blocked                     map[string]bool
		disabled                    bool
		loaded, loadable            []string
	}{
		{name: "all available", dep: dep, loadable: []string{"dccp", "sctp", "rds", "tipc"}},
		{name: "extra modules not installed", dep: "kernel/net/ipv4/tcp_bbr.ko.zst:\n"},
		{name: "blocked", dep: dep, blocked: map[string]bool{"dccp": true, "rds": true}, loadable: []string{"sctp", "tipc"}},
		{name: "loaded", modules: "rds 57344 0 - Live 0x0\nnf_tables 300000 1 - Live 0x0\n", dep: dep, blocked: map[string]bool{"rds": true}, loaded: []string{"rds"}, loadable: []string{"dccp", "sctp", "tipc"}},
		{name: "built in", dep: dep, builtin: "kernel/net/sctp/sctp.ko\n", loaded: []string{"sctp"}, loadable: []string{"dccp", "rds", "tipc"}},
		{name: "module loading disabled", dep: dep, disabled: true},
		{name: "a related module is not the protocol", modules: "rds_tcp 1 0 - Live 0x0\n", dep: "kernel/net/rds/rds_tcp.ko:\n"},
	} {
		loaded, loadable := assessRareProtocols(c.modules, c.dep, c.builtin, c.blocked, c.disabled)
		if !reflect.DeepEqual(loaded, c.loaded) || !reflect.DeepEqual(loadable, c.loadable) {
			t.Errorf("%s: got loaded %v, loadable %v, want %v, %v", c.name, loaded, loadable, c.loaded, c.loadable)
		}
	}
}

func TestRareProtocolsFinding(t *testing.T) {
	f := rareProtocolsFinding([]string{"rds"}, []string{"sctp"}, true)
	if f.Severity != model.Medium || !strings.Contains(f.Title, "loaded: rds") || !strings.Contains(f.Remediation, "install rds /bin/false") || !strings.Contains(f.Remediation, "modprobe -r") {
		t.Errorf("loaded: %+v", f)
	}
	if evidence := strings.Join(f.Evidence, "\n"); !strings.Contains(evidence, "Loaded: rds") || !strings.Contains(evidence, "auto-loaded: sctp") {
		t.Errorf("evidence should separate both states: %s", evidence)
	}
	f = rareProtocolsFinding(nil, []string{"dccp", "tipc"}, true)
	if f.Severity != model.Info || !strings.Contains(f.Title, "auto-loaded: dccp, tipc") || strings.Contains(f.Remediation, "modprobe -r") {
		t.Errorf("loadable only: %+v", f)
	}
	if f = rareProtocolsFinding(nil, nil, true); f.Severity != model.OK {
		t.Errorf("nothing available should pass: %+v", f)
	}
	// An unknown module list must not read as a pass.
	if f = rareProtocolsFinding(nil, nil, false); f.Severity != model.Info || !strings.Contains(f.Detail, "not assessed") {
		t.Errorf("unknown module list: %+v", f)
	}
}

func TestUsernsFinding(t *testing.T) {
	for _, c := range []struct {
		name        string
		s           usernsSettings
		container   bool
		sev         model.Severity
		remediation string
	}{
		{name: "no user namespaces", s: usernsSettings{}, sev: model.OK},
		{name: "limit is zero", s: usernsSettings{MaxNamespaces: "0"}, sev: model.OK},
		{name: "clone off", s: usernsSettings{MaxNamespaces: "63000", Clone: "0"}, sev: model.OK},
		{name: "restricted by AppArmor", s: usernsSettings{MaxNamespaces: "63000", Clone: "1", AppArmorRestrict: "1", AppArmorEnabled: "Y"}, sev: model.OK},
		{name: "restriction without AppArmor does nothing", s: usernsSettings{MaxNamespaces: "63000", AppArmorRestrict: "1", AppArmorEnabled: "N"}, sev: model.Medium, remediation: "Enable AppArmor"},
		{name: "24.04 with the restriction off", s: usernsSettings{MaxNamespaces: "63000", Clone: "1", AppArmorRestrict: "0", AppArmorEnabled: "Y"}, sev: model.Medium, remediation: "kernel.apparmor_restrict_unprivileged_userns=1"},
		{name: "older Ubuntu", s: usernsSettings{MaxNamespaces: "63000", Clone: "1"}, sev: model.Medium, remediation: "kernel.unprivileged_userns_clone=0"},
		{name: "other kernels", s: usernsSettings{MaxNamespaces: "63000"}, sev: model.Medium, remediation: "user.max_user_namespaces=0"},
		{name: "container", s: usernsSettings{MaxNamespaces: "63000", Clone: "1"}, container: true, sev: model.Info, remediation: "kernel.unprivileged_userns_clone=0"},
	} {
		f := usernsFinding(c.s, c.container)
		if f.Severity != c.sev {
			t.Errorf("%s: severity %v, want %v", c.name, f.Severity, c.sev)
		}
		if !strings.Contains(f.Remediation, c.remediation) {
			t.Errorf("%s: remediation %q lacks %q", c.name, f.Remediation, c.remediation)
		}
	}
}
