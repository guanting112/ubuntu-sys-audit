package checks

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/procinfo"
)

func base(p string) string { return filepath.Base(p) }

func ownerLabel(view *procinfo.NetView, ino uint64) string {
	if p := view.ByInode[ino]; p != nil {
		return p.Label()
	}
	return "(no owner found)"
}

// trustedExe requires the binary to belong to a package or a container, since a
// process name alone is attacker controlled. A deleted binary at a package's path
// still counts: that is a service not restarted after an upgrade, which is
// reported on its own as a stale binary.
func trustedExe(c *Context, p *procinfo.Process) bool {
	if p == nil || p.Exe == "" {
		return false
	}
	return p.InContainer || c.Owned(p.Exe)
}

var dnsDaemons = map[string]bool{
	"systemd-resolved": true, "systemd-resolve": true, "named": true, "unbound": true,
	"dnsmasq": true, "pdns_server": true, "pdns_recursor": true, "nsd": true, "knotd": true,
	"coredns": true, "pihole-FTL": true, "dnscrypt-proxy": true, "AdGuardHome": true,
	"kube-dns": true, "stubby": true, "dnsdist": true, "maradns": true, "bind9": true, "lxd": true,
	"docker-proxy": true,
}

func isStubAddress(a netip.Addr) bool {
	return a == netip.MustParseAddr("127.0.0.53") || a == netip.MustParseAddr("127.0.0.54")
}

// classifyDNS decides how a socket bound to port 53 should be reported.
func classifyDNS(c *Context, s procinfo.Socket, p *procinfo.Process) (model.Severity, string) {
	if !c.Host.IsRoot && p == nil {
		return model.Skipped, "Cannot determine the owner without root"
	}
	if p == nil {
		if c.Host.InContainer {
			return model.Medium, "Running inside a container, which cannot see host processes, so the owner is unknown. Confirm on the host"
		}
		if !s.HostNS {
			return model.Medium, "In another network namespace with no owner found"
		}
		return model.Critical, "No process owns this socket, so it may be hidden"
	}
	name := base(p.Exe)
	known := dnsDaemons[name]
	switch {
	case !known:
		if p.InContainer || !s.HostNS {
			return model.High, "A non-DNS program inside a container holds port 53"
		}
		return model.Critical, "Listening on port 53 but not a known DNS service"
	case p.ExeDeleted && !trustedExe(c, p), inTemp(p.Exe):
		return model.Critical, "Named like a DNS service, but its binary was deleted or runs from a temp directory"
	case !trustedExe(c, p):
		// Pi-hole and AdGuard Home are usually installed this way, so this needs
		// a look rather than an alarm.
		return model.High, "Named like a DNS service, but its binary belongs to no package. Confirm you installed it"
	case isStubAddress(s.LocalIP) && (name == "systemd-resolved" || name == "systemd-resolve"):
		return model.OK, "The local stub of systemd-resolved, which is normal"
	case s.LocalIP.IsLoopback():
		return model.Info, "Local DNS service bound to loopback only"
	case p.InContainer || !s.HostNS:
		return model.Info, "DNS service inside a container"
	case s.LocalIP.IsUnspecified():
		return model.Medium, "DNS service bound to all interfaces. Confirm it is not an open resolver"
	}
	return model.Info, "DNS service bound to a specific interface"
}

func resolverAddrs() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	for _, p := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf", "/run/systemd/resolve/stub-resolv.conf"} {
		b, err := fsx.Read(p, 1<<16)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" {
				if a, err := netip.ParseAddr(f[1]); err == nil {
					out[a.Unmap()] = true
				}
			}
		}
	}
	// systemd-resolved's real upstreams come from DHCP or netplan and may only
	// be recorded in its link state files.
	links, _ := filepath.Glob("/run/systemd/resolve/netif/*")
	links2, _ := filepath.Glob("/run/systemd/netif/links/*")
	for _, p := range append(links, links2...) {
		b, err := fsx.Read(p, 1<<16)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok || (k != "SERVERS" && k != "DNS") {
				continue
			}
			for _, tok := range strings.Fields(v) {
				if a, err := netip.ParseAddr(tok); err == nil {
					out[a.Unmap()] = true
				}
			}
		}
	}
	return out
}

func checkDNS53(c *Context) []model.Finding {
	const cat = model.CatNetwork
	if _, err := c.Procs(); err != nil {
		return []model.Finding{skipped("network.dns53", cat, "Port 53 check", err.Error())}
	}
	view := c.Net()
	var out []model.Finding
	listeners := 0
	var okLines []string
	for _, s := range view.Sockets {
		if s.LocalPort != 53 || !s.Listening() {
			continue
		}
		listeners++
		p := view.ByInode[s.Inode]
		sev, why := classifyDNS(c, s, p)
		line := fmt.Sprintf("%s %s  %s", s.Proto, s.Local(), ownerLabel(view, s.Inode))
		if sev == model.OK {
			okLines = append(okLines, line)
			continue
		}
		f := finding("network.dns53.listener", cat, sev, "Port 53 listener: "+s.Proto+" "+s.Local())
		f.Detail = why
		f.Evidence = []string{line}
		if p != nil && len(p.Cmdline) > 0 {
			f.Evidence = append(f.Evidence, "Command: "+p.CmdlineString())
		}
		f.Focus = true
		if sev <= model.High {
			f.Remediation = "Find out where this process came from. If unexpected, preserve evidence (/proc/<pid>/exe, memory, outbound connections), then isolate the host."
		}
		out = append(out, f)
	}
	if len(okLines) > 0 {
		f := finding("network.dns53.stub", cat, model.OK, "systemd-resolved local stub on port 53 (normal)")
		f.Evidence = okLines
		out = append(out, f)
	} else if listeners == 0 {
		out = append(out, finding("network.dns53.none", cat, model.OK, "Nothing listens on port 53"))
	}

	// Traffic to port 53 from anything but the configured resolvers or a DNS
	// daemon is how DNS tunnels and implants with hardcoded resolvers look.
	resolvers := resolverAddrs()
	var odd []string
	for _, s := range view.Sockets {
		if s.RemotePort != 53 || s.State != procinfo.StateEstablished {
			continue
		}
		if resolvers[s.RemoteIP] || s.RemoteIP.IsLoopback() {
			continue
		}
		p := view.ByInode[s.Inode]
		if p != nil && dnsDaemons[base(p.Exe)] && trustedExe(c, p) {
			continue
		}
		odd = append(odd, fmt.Sprintf("%s %s -> %s  %s", s.Proto, s.Local(), s.Remote(), ownerLabel(view, s.Inode)))
	}
	if len(odd) > 0 {
		f := finding("network.dns53.outbound", cat, model.Medium, "Processes connect directly to DNS servers the system does not use")
		f.Detail = "This may just be a program with 8.8.8.8 hardcoded, or it may be a DNS tunnel or C2. Check the process and destination."
		f.Evidence = odd
		f.Focus = true
		out = append(out, f)
	}
	return out
}

type riskyPort struct {
	sev  model.Severity
	name string
}

var riskyPorts = map[uint16]riskyPort{
	21: {model.Medium, "FTP"}, 23: {model.High, "Telnet"}, 111: {model.Medium, "rpcbind"},
	139: {model.Medium, "SMB"}, 445: {model.Medium, "SMB"}, 2049: {model.Medium, "NFS"},
	2375: {model.Critical, "Docker API (unencrypted)"}, 3306: {model.Medium, "MySQL"},
	5432: {model.Medium, "PostgreSQL"}, 5900: {model.Medium, "VNC"}, 6379: {model.High, "Redis"},
	9200: {model.High, "Elasticsearch"}, 10250: {model.Medium, "kubelet"},
	11211: {model.High, "Memcached"}, 27017: {model.High, "MongoDB"},
	161: {model.Medium, "SNMP"}, 631: {model.Medium, "CUPS"}, 873: {model.Medium, "rsync"},
	2379: {model.High, "etcd"}, 3389: {model.Medium, "RDP"}, 5672: {model.Medium, "RabbitMQ"},
	6443: {model.Medium, "Kubernetes API"}, 9090: {model.Medium, "Prometheus"}, 15672: {model.Medium, "RabbitMQ"},
	// Caddy's admin API takes a new configuration from anyone, with no password.
	2019: {model.Critical, "Caddy admin API"},
}

// Kernel services hold sockets with no owning process.
var kernelPorts = map[uint16]bool{111: true, 2049: true, 4789: true, 6081: true, 8472: true, 51820: true}

func checkListeners(c *Context) []model.Finding {
	const cat = model.CatNetwork
	if _, err := c.Procs(); err != nil {
		return []model.Finding{skipped("network.listeners", cat, "Listening ports", err.Error())}
	}
	view := c.Net()
	type row struct {
		line string
		port uint16
	}
	var rows []row
	var out []model.Finding
	public := 0
	var badOwner, orphan, unmanaged []string
	exposed := map[riskyPort][]string{}
	for _, s := range view.Sockets {
		if !s.Listening() {
			continue
		}
		p := view.ByInode[s.Inode]
		scope := ""
		if !s.HostNS {
			scope = " [other network namespace]"
		}
		line := fmt.Sprintf("%-4s %-28s %s%s", s.Proto, s.Local(), ownerLabel(view, s.Inode), scope)
		rows = append(rows, row{line, s.LocalPort})
		isPublic := !s.LocalIP.IsLoopback() && s.HostNS
		if isPublic {
			public++
		}
		if p == nil {
			if c.Host.IsRoot && s.HostNS && !c.Host.InContainer && !kernelPorts[s.LocalPort] {
				orphan = append(orphan, line)
			}
		} else if inTemp(p.Exe) || (p.ExeDeleted && !trustedExe(c, p)) {
			badOwner = append(badOwner, line)
		} else if isPublic && c.Host.IsRoot && !trustedExe(c, p) && p.Exe != "" {
			unmanaged = append(unmanaged, line)
		}
		if r, ok := riskyPorts[s.LocalPort]; ok && isPublic {
			exposed[r] = append(exposed[r], line)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].port != rows[j].port {
			return rows[i].port < rows[j].port
		}
		return rows[i].line < rows[j].line
	})
	lines := make([]string, len(rows))
	for i, r := range rows {
		lines[i] = r.line
	}
	inv := finding("network.listeners", cat, model.Info, fmt.Sprintf("Listening ports (%d, %d non-loopback)", len(rows), public))
	inv.Evidence = lines
	inv.Focus = true
	out = append(out, inv)

	if len(badOwner) > 0 {
		f := finding("network.listener_bad_exe", cat, model.Critical, "Ports held by a binary in a temp directory or a deleted binary")
		f.Detail = "Normal services do not run this way. It looks like malware that deleted itself after starting."
		f.Evidence = badOwner
		f.Remediation = "Preserve /proc/<pid>/exe and connection details, then isolate the host and investigate."
		out = append(out, f)
	}
	if len(orphan) > 0 {
		f := finding("network.listener_orphan", cat, model.Medium, "Listening ports with no owner")
		f.Detail = "Kernel services such as NFS and WireGuard look like this, but so does a process hidden by a rootkit."
		f.Evidence = orphan
		out = append(out, f)
	}
	if len(unmanaged) > 0 {
		f := finding("network.listener_unmanaged", cat, model.Medium, "Non-loopback ports held by programs outside package management")
		f.Detail = "Self-compiled or manually installed services appear here. They get no security updates from apt."
		f.Evidence = unmanaged
		out = append(out, f)
	}
	var keys []riskyPort
	for r := range exposed {
		keys = append(keys, r)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].name < keys[j].name })
	for _, r := range keys {
		f := finding("network.exposed."+strings.ToLower(strings.Fields(r.name)[0]), cat, r.sev, r.name+" is bound to a non-loopback address")
		f.Detail = "Services like this should not be exposed directly. This tool cannot see external firewalls such as cloud security groups, so check those too."
		f.Evidence = exposed[r]
		f.Remediation = "Bind to 127.0.0.1 or a private address, and restrict sources with a firewall."
		out = append(out, f)
	}
	return out
}

// Binaries with a legitimate reason to open AF_PACKET sockets.
var packetAllow = map[string]bool{
	"dhclient": true, "dhcpcd": true, "NetworkManager": true, "systemd-networkd": true,
	"wpa_supplicant": true, "hostapd": true, "tcpdump": true, "dumpcap": true, "tshark": true,
	"wireshark": true, "lldpd": true, "keepalived": true, "suricata": true, "snort": true,
	"zeek": true, "arping": true, "dnsmasq": true, "kea-dhcp4": true, "dhcpd": true,
	"dhcrelay": true, "pppd": true, "iftop": true, "nethogs": true, "vnstatd": true,
	"ntopng": true, "packetbeat": true, "falcon-sensor": true, "udhcpc": true, "rdisc": true,
	"ndppd": true, "radvd": true, "openvswitch-switch": true, "ovs-vswitchd": true,
}

// Binaries with a legitimate reason to open raw IP sockets.
var rawAllow = map[string]bool{
	"ping": true, "ping4": true, "ping6": true, "traceroute": true, "mtr-packet": true,
	"keepalived": true, "bird": true, "bird6": true, "ospfd": true, "ospf6d": true, "isisd": true,
	"pimd": true, "zebra": true, "fping": true, "smokeping": true, "nmap": true,
	"systemd-networkd": true, "NetworkManager": true, "radvd": true, "tcptraceroute": true,
	"dhclient": true, "chronyd": true, "ntpd": true, "iperf3": true,
}

func checkRawSockets(c *Context) []model.Finding {
	const cat = model.CatNetwork
	if !c.Host.IsRoot {
		return []model.Finding{needRoot("network.raw", cat, "Raw and packet sockets")}
	}
	if _, err := c.Procs(); err != nil {
		return []model.Finding{skipped("network.raw", cat, "Raw and packet sockets", err.Error())}
	}
	view := c.Net()
	var out []model.Finding

	filters, filterErr, moduleLoaded := loadPacketFilters(c)
	var allowed []string
	for _, s := range view.Packet {
		p := view.ByInode[s.Inode]
		label := ownerLabel(view, s.Inode)
		line := fmt.Sprintf("packet proto=%#04x iface=%d  %s", s.Proto, s.Iface, label)
		prog := filters[s.Inode]
		magic, dnsPort := procinfo.BPFIndicators(prog)
		if len(prog) > 0 {
			line += "  [" + procinfo.DescribeBPF(prog) + "]"
		}
		switch {
		case len(magic) > 0:
			f := finding("network.bpfdoor", cat, model.Critical, "Packet socket BPF filter contains BPFDoor magic values")
			f.Detail = "Matched published BPFDoor magic numbers: " + strings.Join(magic, ", ") + ". BPFDoor opens no port and waits for a wake-up packet through a filter like this, so firewalls and ordinary port checks cannot see it."
			f.Evidence = []string{line}
			f.Remediation = "Treat the host as compromised. Isolate it, preserve memory and /proc/<pid>/exe, then perform forensics."
			f.Refs = []string{"https://www.trendmicro.com/en_us/research/25/d/bpfdoor-hidden-controller.html"}
			f.Focus = true
			out = append(out, f)
		case p == nil:
			if s.HostNS && !c.Host.InContainer {
				f := finding("network.packet_orphan", cat, model.High, "Packet socket has no owner")
				f.Detail = "This socket can see all packets, yet no visible process holds it, so the owner may be hidden."
				f.Evidence = []string{line}
				out = append(out, f)
			}
		case dnsPort && !(packetAllow[base(p.Exe)] && trustedExe(c, p)):
			f := finding("network.packet_dns", cat, model.Critical, "Unknown process filters port 53 packets with BPF")
			f.Detail = "It receives DNS traffic without opening a port, which is exactly how passive backdoors work."
			f.Evidence = []string{line}
			f.Focus = true
			out = append(out, f)
		case packetAllow[base(p.Exe)] && trustedExe(c, p):
			allowed = append(allowed, line)
		case trustedExe(c, p):
			f := finding("network.packet_review", cat, model.Medium, "Packaged program opened a packet socket: "+base(p.Exe))
			f.Detail = "This program comes from a package but is not on the list of known packet capture tools. Confirm its purpose."
			f.Evidence = []string{line}
			out = append(out, f)
		default:
			f := finding("network.packet_unknown", cat, model.High, "Unpackaged program opened a packet socket: "+p.Comm)
			f.Detail = "This socket sees packets before the firewall, which is often used for passive backdoors or sniffing."
			f.Evidence = []string{line}
			if len(p.Cmdline) > 0 {
				f.Evidence = append(f.Evidence, "Command: "+p.CmdlineString())
			}
			f.Focus = true
			out = append(out, f)
		}
	}
	if len(allowed) > 0 {
		f := finding("network.packet_known", cat, model.Info, fmt.Sprintf("Packet sockets held by known programs (%d)", len(allowed)))
		f.Evidence = allowed
		out = append(out, f)
	}
	if len(view.Packet) == 0 {
		out = append(out, finding("network.packet_none", cat, model.OK, "No packet sockets"))
	}
	if filterErr != "" {
		f := skipped("network.bpf_filters", cat, "BPF filter contents", filterErr+". Packet sockets and owners are still listed, but BPFDoor magic values were not checked.")
		f.Requested = c.Opts.NoNetlink
		out = append(out, f)
	} else if moduleLoaded {
		f := finding("network.packet_diag", cat, model.Info, "The kernel auto-loaded af_packet_diag while BPF filters were read")
		f.Detail = "Same effect as running ss -0. To avoid it, use --no-netlink."
		out = append(out, f)
	}

	for _, s := range view.Sockets {
		if s.Proto != "raw" && s.Proto != "raw6" {
			continue
		}
		p := view.ByInode[s.Inode]
		line := fmt.Sprintf("%s protocol=%d  %s", s.Proto, s.LocalPort, ownerLabel(view, s.Inode))
		switch {
		case p == nil && (!s.HostNS || c.Host.InContainer):
		case p == nil:
			f := finding("network.raw_orphan", cat, model.High, "Raw socket has no owner")
			f.Evidence = []string{line}
			out = append(out, f)
		case rawAllow[base(p.Exe)] && trustedExe(c, p):
		case trustedExe(c, p):
			f := finding("network.raw_review", cat, model.Medium, "Packaged program opened a raw socket: "+base(p.Exe))
			f.Evidence = []string{line}
			out = append(out, f)
		default:
			f := finding("network.raw_unknown", cat, model.High, "Unpackaged program opened a raw socket: "+p.Comm)
			f.Detail = "Raw sockets can send and receive arbitrary IP packets, which is how ICMP backdoors work."
			f.Evidence = []string{line}
			out = append(out, f)
		}
	}
	return out
}

func checkPromisc(c *Context) []model.Finding {
	const cat = model.CatNetwork
	ifaces, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return []model.Finding{skipped("network.iface", cat, "Promiscuous interfaces", err.Error())}
	}
	var promisc []string
	for _, e := range ifaces {
		name := e.Name()
		flags := fsx.ProcString("/sys/class/net/" + name + "/flags")
		v, err := strconv.ParseUint(strings.TrimPrefix(flags, "0x"), 16, 64)
		if err != nil || v&0x100 == 0 {
			continue
		}
		// Ports enslaved to a bridge are promiscuous by design.
		if _, err := os.Stat("/sys/class/net/" + name + "/brport"); err == nil {
			continue
		}
		promisc = append(promisc, name)
	}
	if len(promisc) == 0 {
		return []model.Finding{finding("network.iface", cat, model.OK, "No interfaces in promiscuous mode")}
	}
	f := finding("network.iface", cat, model.Medium, "Interfaces in promiscuous mode")
	f.Detail = "Promiscuous mode receives packets meant for other hosts. It may be tcpdump, or it may be a sniffer."
	f.Evidence = promisc
	return []model.Finding{f}
}

// mptcpSockets sums the MPTCP rows of /proc/net/protocols. The third column is
// the number of sockets in use in the reader's network namespace.
func mptcpSockets(protocols string) int {
	total := 0
	for _, line := range strings.Split(protocols, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || (f[0] != "MPTCP" && f[0] != "MPTCPv6") {
			continue
		}
		if n, err := strconv.Atoi(f[2]); err == nil {
			total += n
		}
	}
	return total
}

// mptcpFinding recommends turning MPTCP off. Few servers use it, it is on by
// default wherever the kernel supports it, and its code has had a steady run of
// CVEs, so disabling it removes attack surface at little cost. enabled is the
// sysctl value, empty when the kernel has no such setting.
func mptcpFinding(enabled string, sockets int) model.Finding {
	const id, cat = "network.mptcp", model.CatNetwork
	switch enabled {
	case "":
		return finding(id, cat, model.OK, "MPTCP is not available on this kernel")
	case "0":
		return finding(id, cat, model.OK, "MPTCP is disabled")
	}
	f := finding(id, cat, model.Medium, "MPTCP is enabled, recommend disabling it")
	f.Detail = "Multipath TCP is on by default on kernels that support it, but few servers need it. Its kernel code has had repeated CVEs, so turning it off reduces attack surface."
	f.Evidence = []string{"net.mptcp.enabled = " + enabled, fmt.Sprintf("MPTCP sockets in use: %d", sockets)}
	f.Remediation = "Run sudo sysctl -w net.mptcp.enabled=0 and add net.mptcp.enabled = 0 to /etc/sysctl.d/90-disable-mptcp.conf to keep it after a reboot. The setting is per network namespace, so containers keep their own value."
	f.Refs = []string{"https://docs.kernel.org/networking/mptcp-sysctl.html"}
	if sockets > 0 {
		f.Title = "MPTCP is enabled and in use, review before disabling"
		f.Detail += " Something on this host has MPTCP sockets open. Existing sockets keep working, but programs that create new ones without falling back to TCP will fail once it is off, so find out what uses it first (ss -M lists them)."
	}
	return f
}

func checkMPTCP(c *Context) []model.Finding {
	return []model.Finding{mptcpFinding(
		fsx.ProcString("/proc/sys/net/mptcp/enabled"),
		mptcpSockets(fsx.ProcString("/proc/net/protocols")),
	)}
}

func checkFirewall(c *Context) []model.Finding {
	const cat = model.CatNetwork
	ufw := ufwStatus()
	tables := strings.Fields(fsx.ProcString("/proc/net/ip_tables_names"))
	nft := false
	if st, err := os.Stat("/etc/nftables.conf"); err == nil && st.Size() > 0 {
		nft = true
	}
	f := finding("network.firewall", cat, model.Info, "Firewall: ufw "+ufw)
	f.Evidence = []string{
		"ufw: " + ufw,
		"Loaded iptables tables: " + strings.Join(tables, ", "),
		fmt.Sprintf("/etc/nftables.conf exists: %v", nft),
	}
	f.Detail = "This tool does not run iptables or nft. It reads ufw's default policy and IPv6 setting, but does not evaluate rules and cannot see cloud security groups."
	out := []model.Finding{f}
	if ufw == "enabled" {
		out = append(out, ufwFindings(c)...)
	}
	return out
}

type dockerConfig struct {
	Name   string `json:"Name"`
	Config struct {
		Image string   `json:"Image"`
		Env   []string `json:"Env"`
	} `json:"Config"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	NetworkSettings struct {
		Ports map[string][]dockerPortBinding `json:"Ports"`
	} `json:"NetworkSettings"`
}

type dockerHostConfig struct {
	Privileged   bool                           `json:"Privileged"`
	NetworkMode  string                         `json:"NetworkMode"`
	PidMode      string                         `json:"PidMode"`
	Binds        []string                       `json:"Binds"`
	PortBindings map[string][]dockerPortBinding `json:"PortBindings"`
}

func checkDocker(c *Context) []model.Finding {
	const cat = model.CatNetwork
	var out []model.Finding
	sock, err := os.Stat("/var/run/docker.sock")
	if err == nil && sock.Mode().Perm()&0o002 != 0 {
		f := finding("docker.socket_perm", cat, model.Critical, "docker.sock is world-writable")
		f.Detail = "Anyone who can write to docker.sock can get root. Its mode is " + fmt.Sprintf("%o", sock.Mode().Perm()) + "."
		f.Remediation = "chmod 660 /var/run/docker.sock"
		out = append(out, f)
	}
	dirs, _ := filepath.Glob("/var/lib/docker/containers/*")
	if len(dirs) == 0 {
		if err != nil {
			return out
		}
		return append(out, finding("docker.containers", cat, model.Info, "Docker is installed with no containers"))
	}
	var running, stopped, privileged, published []string
	for _, d := range dirs {
		if c.Ctx.Err() != nil {
			break
		}
		b, err := fsx.Read(filepath.Join(d, "config.v2.json"), 8<<20)
		if err != nil {
			continue
		}
		var cfg dockerConfig
		if json.Unmarshal(b, &cfg) != nil {
			continue
		}
		name := strings.TrimPrefix(cfg.Name, "/")
		line := name + "  image=" + cfg.Config.Image
		if cfg.State.Running {
			running = append(running, line)
		} else {
			stopped = append(stopped, line)
		}
		hb, err := fsx.Read(filepath.Join(d, "hostconfig.json"), 8<<20)
		if err != nil {
			continue
		}
		var hc dockerHostConfig
		if json.Unmarshal(hb, &hc) != nil {
			continue
		}
		// A container on the host network has no port rules to bypass ufw with.
		if cfg.State.Running && hc.NetworkMode != "host" {
			for _, port := range publishedPorts(cfg.NetworkSettings.Ports, hc.PortBindings) {
				published = append(published, name+"  "+port)
			}
		}
		var bad []string
		if hc.Privileged {
			bad = append(bad, "privileged")
		}
		if hc.PidMode == "host" {
			bad = append(bad, "pid=host")
		}
		for _, bind := range hc.Binds {
			if strings.HasPrefix(bind, "/:") || strings.HasPrefix(bind, "/var/run/docker.sock:") {
				bad = append(bad, "mounts "+strings.SplitN(bind, ":", 2)[0])
			}
		}
		if len(bad) > 0 && cfg.State.Running {
			privileged = append(privileged, name+": "+strings.Join(bad, ", "))
		}
	}
	f := finding("docker.containers", cat, model.Info, fmt.Sprintf("Containers: %d running, %d stopped", len(running), len(stopped)))
	f.Detail = "The CVE check covers the host's apt packages only, not packages inside container images. nginx and PHP versions from running containers appear under Web."
	f.Evidence = append(running, stopped...)
	out = append(out, f)
	if len(privileged) > 0 {
		g := finding("docker.privileged", cat, model.High, "Containers have privileges that allow escaping to the host")
		g.Detail = "If one of these containers is compromised, so is the host."
		g.Evidence = privileged
		out = append(out, g)
	}
	if len(published) > 0 && ufwStatus() == "enabled" {
		daemon, _ := fsx.Read("/etc/docker/daemon.json", 1<<20)
		if dockerManagesIptables(daemon) {
			out = append(out, dockerUfwFinding(published, dockerUserConfigured()))
		}
	}
	return out
}

func loadPacketFilters(c *Context) (map[uint64][]procinfo.BPFInstruction, string, bool) {
	if c.Opts.NoNetlink {
		return nil, "Disabled by --no-netlink", false
	}
	before := procinfo.PacketDiagModuleLoaded()
	filters, err := procinfo.PacketFilters(5 * time.Second)
	if err != nil {
		return nil, "Cannot read them: " + err.Error(), false
	}
	return filters, "", !before && procinfo.PacketDiagModuleLoaded()
}
