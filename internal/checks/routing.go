package checks

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/procinfo"
)

// tunnelKind names a tunnel interface from what sysfs reports, or returns "" for
// any other interface. tunFlags comes from a file only tun and tap devices have.
func tunnelKind(devType, arpType, tunFlags string) string {
	if tunFlags != "" {
		v, err := strconv.ParseUint(strings.TrimPrefix(tunFlags, "0x"), 16, 64)
		if err == nil && v&0x2 != 0 {
			return "tap"
		}
		return "tun"
	}
	switch devType {
	case "wireguard", "vxlan", "geneve", "gre", "gretap", "ip6gre", "ip6gretap", "ipip", "sit", "vti", "vti6", "l2tp":
		return devType
	}
	switch arpType {
	case "768":
		return "ipip"
	case "769":
		return "ip6tnl"
	case "776":
		return "sit"
	case "778":
		return "gre"
	case "823":
		return "ip6gre"
	}
	return ""
}

type netInterface struct {
	Name   string
	Up     bool
	Bridge bool
	Tunnel string // empty when it is not a tunnel
}

func ueventValue(src, key string) string {
	for _, line := range strings.Split(src, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return v
		}
	}
	return ""
}

func readInterfaces() ([]netInterface, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var out []netInterface
	for _, e := range entries {
		dir := "/sys/class/net/" + e.Name()
		flags, err := strconv.ParseUint(strings.TrimPrefix(fsx.ProcString(dir+"/flags"), "0x"), 16, 64)
		if err != nil {
			continue
		}
		devType := ueventValue(fsx.ProcString(dir+"/uevent"), "DEVTYPE")
		out = append(out, netInterface{
			Name:   e.Name(),
			Up:     flags&0x1 != 0,
			Bridge: devType == "bridge",
			Tunnel: tunnelKind(devType, fsx.ProcString(dir+"/type"), fsx.ProcString(dir+"/tun_flags")),
		})
	}
	return out, nil
}

// tunInterfaceFromFdinfo returns the interface a /dev/net/tun descriptor is
// attached to, from its /proc/<pid>/fdinfo entry.
func tunInterfaceFromFdinfo(fdinfo string) string {
	for _, line := range strings.Split(fdinfo, "\n") {
		if v, ok := strings.CutPrefix(line, "iff:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// tunOwners maps tun and tap interfaces to the processes holding them.
func tunOwners(procs []*procinfo.Process) map[string]*procinfo.Process {
	out := map[string]*procinfo.Process{}
	for _, p := range procs {
		for _, fd := range p.TunFDs {
			name := tunInterfaceFromFdinfo(fsx.ProcString(fmt.Sprintf("/proc/%d/fdinfo/%d", p.PID, fd)))
			if name != "" && out[name] == nil {
				out[name] = p
			}
		}
	}
	return out
}

// forwardingDaemons are programs that need IP forwarding to do their job.
var forwardingDaemons = map[string]bool{
	"dockerd": true, "containerd": true, "podman": true, "kubelet": true, "k3s": true, "lxd": true,
	"libvirtd": true, "openvpn": true, "tailscaled": true, "zerotier-one": true, "charon": true,
	"pluto": true, "nebula": true, "pppd": true, "zebra": true, "bgpd": true, "ospfd": true,
	"bird": true, "bird6": true, "keepalived": true, "vtund": true,
}

// forwardingPaths exist on hosts set up as a container host or VPN server, even
// while the service is stopped.
var forwardingPaths = []string{
	"/var/run/docker.sock", "/run/docker.sock", "/etc/kubernetes", "/var/lib/kubelet",
	"/var/snap/lxd/common/lxd", "/var/lib/lxd", "/var/lib/libvirt", "/etc/wireguard", "/etc/openvpn",
}

// forwardingExplanation returns what justifies IP forwarding on this host, or ""
// when nothing does. A process name counts only when its binary is packaged, so
// an implant cannot explain itself away by choosing a name.
func forwardingExplanation(c *Context, ifaces []netInterface, procs []*procinfo.Process) string {
	for _, i := range ifaces {
		if i.Bridge || i.Tunnel != "" {
			return "interface " + i.Name
		}
	}
	for _, p := range forwardingPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	for _, p := range procs {
		if forwardingDaemons[base(p.Exe)] && trustedExe(c, p) {
			return "process " + base(p.Exe)
		}
	}
	return ""
}

func forwardingFinding(ipv4, ipv6 string) model.Finding {
	f := finding("network.forwarding", model.CatNetwork, model.Medium, "IP forwarding is on, but no router, VPN or container software was found")
	f.Detail = "A host with forwarding on can pass traffic between networks, which attackers use to reach internal systems through it. It may also simply be left over from an old setup."
	if ipv4 == "1" {
		f.Evidence = append(f.Evidence, "net.ipv4.ip_forward = 1")
	}
	if ipv6 == "1" {
		f.Evidence = append(f.Evidence, "net.ipv6.conf.all.forwarding = 1")
	}
	f.Remediation = "If this host should not route traffic, set the values above to 0 with sudo sysctl -w, and remove them from /etc/sysctl.conf and /etc/sysctl.d/."
	return f
}

type defaultRoute struct {
	Iface string
	Line  string
}

// littleEndianIPv4 decodes an address as printed in /proc/net/route.
func littleEndianIPv4(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return s
	}
	return netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]}).String()
}

// ipv4DefaultRoutes parses /proc/net/route.
func ipv4DefaultRoutes(src string) []defaultRoute {
	var out []defaultRoute
	for _, line := range strings.Split(src, "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x1 == 0 {
			continue
		}
		out = append(out, defaultRoute{f[0], fmt.Sprintf("IPv4 default via %s dev %s metric %s", littleEndianIPv4(f[2]), f[0], f[6])})
	}
	return out
}

// ipv6DefaultRoutes parses /proc/net/ipv6_route. The kernel lists a rejecting
// default route on lo, which is not a way out.
func ipv6DefaultRoutes(src string) []defaultRoute {
	var out []defaultRoute
	for _, line := range strings.Split(src, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || strings.Trim(f[0], "0") != "" || f[1] != "00" {
			continue
		}
		flags, err := strconv.ParseUint(f[8], 16, 32)
		if err != nil || flags&0x1 == 0 || flags&0x200 != 0 || f[9] == "lo" {
			continue
		}
		next := f[4]
		if raw, err := hex.DecodeString(next); err == nil && len(raw) == 16 {
			next = netip.AddrFrom16([16]byte(raw)).String()
		}
		out = append(out, defaultRoute{f[9], fmt.Sprintf("IPv6 default via %s dev %s", next, f[9])})
	}
	return out
}

// routesFinding reports default routes that change where the host's traffic goes.
// Hosts with several links can have this on purpose, so it is only informational.
func routesFinding(ipv4, ipv6 []defaultRoute, tunnels map[string]bool) (model.Finding, bool) {
	interfaces := func(routes []defaultRoute) int {
		seen := map[string]bool{}
		for _, r := range routes {
			seen[r.Iface] = true
		}
		return len(seen)
	}
	var lines []string
	viaTunnel := false
	for _, r := range append(append([]defaultRoute(nil), ipv4...), ipv6...) {
		lines = append(lines, r.Line)
		viaTunnel = viaTunnel || tunnels[r.Iface]
	}
	several := interfaces(ipv4) > 1 || interfaces(ipv6) > 1
	if !several && !viaTunnel {
		return model.Finding{}, false
	}
	f := finding("network.routes", model.CatNetwork, model.Info, "Several default routes on different interfaces")
	f.Detail = "Hosts with more than one link can have this on purpose. Confirm each route is expected, since an added route can send traffic through another network."
	if viaTunnel {
		f.Title = "A default route goes through a tunnel"
		f.Detail = "A VPN can do this on purpose. Confirm it is expected, since all traffic using this route leaves through the tunnel."
	}
	f.Evidence = lines
	return f, true
}

func tunnelFindings(c *Context, ifaces []netInterface, owners map[string]*procinfo.Process) []model.Finding {
	const cat = model.CatNetwork
	var all, unmanaged, suspicious []string
	for _, i := range ifaces {
		if i.Tunnel == "" || !i.Up {
			continue
		}
		line := fmt.Sprintf("%s (%s)", i.Name, i.Tunnel)
		p := owners[i.Name]
		if p != nil {
			line += " held by " + p.Label()
		}
		all = append(all, line)
		switch {
		case p == nil || trustedExe(c, p):
		case inTemp(p.Exe) || p.ExeDeleted:
			suspicious = append(suspicious, line)
		default:
			unmanaged = append(unmanaged, line)
		}
	}
	var out []model.Finding
	if len(suspicious) > 0 {
		f := finding("network.tunnel_suspicious", cat, model.High, "A tunnel is held by a binary in a temp directory or a deleted binary")
		f.Detail = "VPN software does not run this way. Attackers use tunnels like this to reach internal networks through a compromised host."
		f.Evidence = suspicious
		f.Remediation = "Preserve /proc/<pid>/exe and connection details, then isolate the host and investigate."
		out = append(out, f)
	}
	if len(unmanaged) > 0 {
		f := finding("network.tunnel_unmanaged", cat, model.Medium, "A tunnel is held by a program outside package management")
		f.Detail = "This may be VPN software installed by hand. Confirm you recognise it, since attackers also use tunnels to reach internal networks."
		f.Evidence = unmanaged
		out = append(out, f)
	}
	if len(all) > 0 {
		f := finding("network.tunnels", cat, model.Info, fmt.Sprintf("Tunnel interfaces are up (%d)", len(all)))
		f.Detail = "VPNs and container networks use these. Confirm you recognise each one."
		f.Evidence = all
		out = append(out, f)
	}
	return out
}

func checkTunnelsAndRouting(c *Context) []model.Finding {
	const id, cat, title = "network.routing", model.CatNetwork, "Tunnels and routing"
	ifaces, err := readInterfaces()
	if err != nil {
		return []model.Finding{skipped(id, cat, title, "Cannot read /sys/class/net: "+err.Error())}
	}
	sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].Name < ifaces[j].Name })
	procs, procErr := c.Procs()
	out := tunnelFindings(c, ifaces, tunOwners(procs))

	// Container engines turn this on for every container, so it says nothing there.
	ipv4 := fsx.ProcString("/proc/sys/net/ipv4/ip_forward")
	ipv6 := fsx.ProcString("/proc/sys/net/ipv6/conf/all/forwarding")
	if (ipv4 == "1" || ipv6 == "1") && !c.Host.InContainer && procErr == nil && forwardingExplanation(c, ifaces, procs) == "" {
		out = append(out, forwardingFinding(ipv4, ipv6))
	}

	tunnels := map[string]bool{}
	for _, i := range ifaces {
		tunnels[i.Name] = i.Tunnel != ""
	}
	route4, _ := fsx.ReadProc("/proc/net/route")
	route6, _ := fsx.ReadProc("/proc/net/ipv6_route")
	if f, ok := routesFinding(ipv4DefaultRoutes(string(route4)), ipv6DefaultRoutes(string(route6)), tunnels); ok {
		out = append(out, f)
	}
	if len(out) == 0 {
		out = append(out, finding(id, cat, model.OK, "No tunnels, unexplained IP forwarding or unusual default routes"))
	}
	return out
}
