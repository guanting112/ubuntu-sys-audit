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
	return "（找不到擁有者）"
}

// trustedExe requires the binary to belong to a package or a container, since
// a process name alone is attacker controlled.
func trustedExe(c *Context, p *procinfo.Process) bool {
	if p == nil || p.Exe == "" || p.ExeDeleted {
		return false
	}
	return p.InContainer || c.Owned(p.Exe)
}

var dnsDaemons = map[string]bool{
	"systemd-resolved": true, "systemd-resolve": true, "named": true, "unbound": true,
	"dnsmasq": true, "pdns_server": true, "pdns_recursor": true, "nsd": true, "knotd": true,
	"coredns": true, "pihole-FTL": true, "dnscrypt-proxy": true, "AdGuardHome": true,
	"kube-dns": true, "stubby": true, "dnsdist": true, "maradns": true, "bind9": true, "lxd": true,
}

func isStubAddress(a netip.Addr) bool {
	return a == netip.MustParseAddr("127.0.0.53") || a == netip.MustParseAddr("127.0.0.54")
}

// classifyDNS decides how a socket bound to port 53 should be reported.
func classifyDNS(c *Context, s procinfo.Socket, p *procinfo.Process) (model.Severity, string) {
	if !c.Host.IsRoot && p == nil {
		return model.Skipped, "沒有 root 權限，無法判斷擁有者"
	}
	if p == nil {
		if c.Host.InContainer {
			return model.Medium, "在容器內執行，看不到宿主機的程序，無法判斷擁有者。請在宿主機上確認"
		}
		if !s.HostNS {
			return model.Medium, "位於其他網路命名空間，找不到擁有者"
		}
		return model.Critical, "找不到擁有這個 socket 的程序，可能被隱藏"
	}
	name := base(p.Exe)
	known := dnsDaemons[name]
	switch {
	case !known:
		if p.InContainer || !s.HostNS {
			return model.High, "容器內的非 DNS 程式佔用 53 Port"
		}
		return model.Critical, "不是已知的 DNS 服務，卻在監聽 53 Port"
	case !trustedExe(c, p):
		return model.Critical, "名稱像 DNS 服務，但執行檔不屬於任何套件（或已刪除）"
	case isStubAddress(s.LocalIP) && (name == "systemd-resolved" || name == "systemd-resolve"):
		return model.OK, "systemd-resolved 的本機 stub，屬正常行為"
	case s.LocalIP.IsLoopback():
		return model.Info, "本機 DNS 服務，只綁定 loopback"
	case p.InContainer || !s.HostNS:
		return model.Info, "容器內的 DNS 服務"
	case s.LocalIP.IsUnspecified():
		return model.Medium, "DNS 服務綁定所有網卡，請確認不是 open resolver"
	}
	return model.Info, "DNS 服務綁定特定網卡"
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
		return []model.Finding{skipped("network.dns53", cat, "53 Port 檢查", err.Error())}
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
		f := finding("network.dns53.listener", cat, sev, "53 Port 監聽："+s.Proto+" "+s.Local())
		f.Detail = why
		f.Evidence = []string{line}
		if p != nil && len(p.Cmdline) > 0 {
			f.Evidence = append(f.Evidence, "指令："+p.CmdlineString())
		}
		f.Focus = true
		if sev <= model.High {
			f.Remediation = "確認這個程序的來源。若非預期，先保留現場（/proc/<pid>/exe、記憶體、對外連線）再隔離主機。"
		}
		out = append(out, f)
	}
	if len(okLines) > 0 {
		f := finding("network.dns53.stub", cat, model.OK, "systemd-resolved 的本機 stub 監聽 53 Port（正常）")
		f.Evidence = okLines
		out = append(out, f)
	} else if listeners == 0 {
		out = append(out, finding("network.dns53.none", cat, model.OK, "沒有程序監聽 53 Port"))
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
		f := finding("network.dns53.outbound", cat, model.Medium, "有程序直接連到非系統設定的 DNS 伺服器")
		f.Detail = "可能只是寫死 8.8.8.8 的程式，也可能是 DNS tunnel 或 C2。請確認程序與目的地。"
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
	2375: {model.Critical, "Docker API（未加密）"}, 3306: {model.Medium, "MySQL"},
	5432: {model.Medium, "PostgreSQL"}, 5900: {model.Medium, "VNC"}, 6379: {model.High, "Redis"},
	9200: {model.High, "Elasticsearch"}, 10250: {model.Medium, "kubelet"},
	11211: {model.High, "Memcached"}, 27017: {model.High, "MongoDB"},
}

// Kernel services hold sockets with no owning process.
var kernelPorts = map[uint16]bool{111: true, 2049: true, 4789: true, 6081: true, 8472: true, 51820: true}

func checkListeners(c *Context) []model.Finding {
	const cat = model.CatNetwork
	if _, err := c.Procs(); err != nil {
		return []model.Finding{skipped("network.listeners", cat, "監聽中的 Port", err.Error())}
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
			scope = " [其他網路命名空間]"
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
		} else if p.ExeDeleted || inTemp(p.Exe) {
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
	inv := finding("network.listeners", cat, model.Info, fmt.Sprintf("%d 個監聽中的 Port，其中 %d 個對外", len(rows), public))
	inv.Evidence = lines
	inv.Focus = true
	out = append(out, inv)

	if len(badOwner) > 0 {
		f := finding("network.listener_bad_exe", cat, model.Critical, "有 Port 由暫存目錄或已刪除的執行檔監聽")
		f.Detail = "正常服務不會這樣跑。這很像惡意程式執行後刪除自身。"
		f.Evidence = badOwner
		f.Remediation = "先保留 /proc/<pid>/exe 與連線資訊，再隔離主機調查。"
		out = append(out, f)
	}
	if len(orphan) > 0 {
		f := finding("network.listener_orphan", cat, model.Medium, "有監聽中的 Port 找不到擁有者")
		f.Detail = "kernel 內建服務（NFS、WireGuard）會這樣顯示，但 rootkit 隱藏程序時也是如此。"
		f.Evidence = orphan
		out = append(out, f)
	}
	if len(unmanaged) > 0 {
		f := finding("network.listener_unmanaged", cat, model.Medium, "對外 Port 由非套件管理的程式監聽")
		f.Detail = "自行編譯或手動安裝的服務都會列在這裡，它們不會收到 apt 的安全更新。"
		f.Evidence = unmanaged
		out = append(out, f)
	}
	var keys []riskyPort
	for r := range exposed {
		keys = append(keys, r)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].name < keys[j].name })
	for _, r := range keys {
		f := finding("network.exposed."+strings.ToLower(strings.Fields(r.name)[0]), cat, r.sev, r.name+" 綁定在非 loopback 位址")
		f.Detail = "這類服務不該直接暴露。工具看不到雲端安全群組等外部防火牆，請一併確認。"
		f.Evidence = exposed[r]
		f.Remediation = "改綁 127.0.0.1 或內網位址，並用防火牆限制來源。"
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
		return []model.Finding{needRoot("network.raw", cat, "Raw／Packet Socket")}
	}
	if _, err := c.Procs(); err != nil {
		return []model.Finding{skipped("network.raw", cat, "Raw／Packet Socket", err.Error())}
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
			f := finding("network.bpfdoor", cat, model.Critical, "Packet socket 的 BPF 過濾器含 BPFDoor 特徵值")
			f.Detail = "比對到已公開的 BPFDoor magic number：" + strings.Join(magic, ", ") + "。BPFDoor 不開 Port，靠這種過濾器等待喚醒封包，所以防火牆和一般 Port 檢查都看不到它。"
			f.Evidence = []string{line}
			f.Remediation = "視為主機已遭入侵。先隔離主機並保留記憶體與 /proc/<pid>/exe，再做鑑識。"
			f.Refs = []string{"https://www.trendmicro.com/en_us/research/25/d/bpfdoor-hidden-controller.html"}
			f.Focus = true
			out = append(out, f)
		case p == nil:
			if s.HostNS && !c.Host.InContainer {
				f := finding("network.packet_orphan", cat, model.High, "Packet socket 找不到擁有者")
				f.Detail = "這個 socket 能看到所有封包，卻沒有可見的程序持有它，可能遭到隱藏。"
				f.Evidence = []string{line}
				out = append(out, f)
			}
		case dnsPort && !(packetAllow[base(p.Exe)] && trustedExe(c, p)):
			f := finding("network.packet_dns", cat, model.Critical, "未知程序用 BPF 過濾 53 Port 封包")
			f.Detail = "它不必開 Port 就能收到 DNS 流量，這正是被動後門的做法。"
			f.Evidence = []string{line}
			f.Focus = true
			out = append(out, f)
		case packetAllow[base(p.Exe)] && trustedExe(c, p):
			allowed = append(allowed, line)
		case trustedExe(c, p):
			f := finding("network.packet_review", cat, model.Medium, "套件程式開啟 Packet socket："+base(p.Exe))
			f.Detail = "這支程式來自套件，但不在已知會抓封包的清單內，請確認用途。"
			f.Evidence = []string{line}
			out = append(out, f)
		default:
			f := finding("network.packet_unknown", cat, model.High, "非套件程式開啟 Packet socket："+p.Comm)
			f.Detail = "這個 socket 能在防火牆之前看到封包，常被用來做被動後門或側錄。"
			f.Evidence = []string{line}
			if len(p.Cmdline) > 0 {
				f.Evidence = append(f.Evidence, "指令："+p.CmdlineString())
			}
			f.Focus = true
			out = append(out, f)
		}
	}
	if len(allowed) > 0 {
		f := finding("network.packet_known", cat, model.Info, fmt.Sprintf("%d 個由已知程式開啟的 Packet socket", len(allowed)))
		f.Evidence = allowed
		out = append(out, f)
	}
	if len(view.Packet) == 0 {
		out = append(out, finding("network.packet_none", cat, model.OK, "沒有 Packet socket"))
	}
	if filterErr != "" {
		out = append(out, skipped("network.bpf_filters", cat, "BPF 過濾器內容", filterErr+"。仍有列出 Packet socket 與擁有者，但沒有比對 BPFDoor 特徵值。"))
	} else if moduleLoaded {
		f := finding("network.packet_diag", cat, model.Info, "讀取 BPF 過濾器時，kernel 自動載入了 packet_diag 模組")
		f.Detail = "與執行 ss -0 的效果相同。若不希望載入，請加上 --no-netlink。"
		out = append(out, f)
	}

	for _, s := range view.Sockets {
		if s.Proto != "raw" && s.Proto != "raw6" {
			continue
		}
		p := view.ByInode[s.Inode]
		line := fmt.Sprintf("%s 協定=%d  %s", s.Proto, s.LocalPort, ownerLabel(view, s.Inode))
		switch {
		case p == nil && (!s.HostNS || c.Host.InContainer):
		case p == nil:
			f := finding("network.raw_orphan", cat, model.High, "Raw socket 找不到擁有者")
			f.Evidence = []string{line}
			out = append(out, f)
		case rawAllow[base(p.Exe)] && trustedExe(c, p):
		case trustedExe(c, p):
			f := finding("network.raw_review", cat, model.Medium, "套件程式開啟 Raw socket："+base(p.Exe))
			f.Evidence = []string{line}
			out = append(out, f)
		default:
			f := finding("network.raw_unknown", cat, model.High, "非套件程式開啟 Raw socket："+p.Comm)
			f.Detail = "Raw socket 可收發任意 IP 封包，ICMP 後門就靠它。"
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
		return []model.Finding{skipped("network.iface", cat, "網卡混雜模式", err.Error())}
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
		return []model.Finding{finding("network.iface", cat, model.OK, "沒有網卡處於混雜模式")}
	}
	f := finding("network.iface", cat, model.Medium, "網卡處於混雜模式")
	f.Detail = "混雜模式會收到不屬於本機的封包，可能是 tcpdump，也可能是側錄工具。"
	f.Evidence = promisc
	return []model.Finding{f}
}

func checkFirewall(c *Context) []model.Finding {
	const cat = model.CatNetwork
	ufw := "未安裝"
	if b, err := fsx.Read("/etc/ufw/ufw.conf", 1<<14); err == nil {
		ufw = "已停用"
		for _, line := range strings.Split(string(b), "\n") {
			if strings.EqualFold(strings.TrimSpace(line), "ENABLED=yes") {
				ufw = "已啟用"
			}
		}
	}
	tables := strings.Fields(fsx.ProcString("/proc/net/ip_tables_names"))
	nft := false
	if st, err := os.Stat("/etc/nftables.conf"); err == nil && st.Size() > 0 {
		nft = true
	}
	f := finding("network.firewall", cat, model.Info, "防火牆：ufw "+ufw)
	f.Evidence = []string{
		"ufw：" + ufw,
		"已載入的 iptables 表：" + strings.Join(tables, ", "),
		fmt.Sprintf("/etc/nftables.conf 存在：%v", nft),
	}
	f.Detail = "工具不會執行 iptables 或 nft，所以只回報狀態，不判斷規則內容，也看不到雲端安全群組。"
	return []model.Finding{f}
}

type dockerConfig struct {
	Name   string `json:"Name"`
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
}

type dockerHostConfig struct {
	Privileged  bool     `json:"Privileged"`
	NetworkMode string   `json:"NetworkMode"`
	PidMode     string   `json:"PidMode"`
	Binds       []string `json:"Binds"`
}

func checkDocker(c *Context) []model.Finding {
	const cat = model.CatNetwork
	var out []model.Finding
	sock, err := os.Stat("/var/run/docker.sock")
	if err == nil && sock.Mode().Perm()&0o002 != 0 {
		f := finding("docker.socket_perm", cat, model.Critical, "docker.sock 任何人都可寫入")
		f.Detail = "能寫入 docker.sock 就能取得 root。權限是 " + fmt.Sprintf("%o", sock.Mode().Perm()) + "。"
		f.Remediation = "chmod 660 /var/run/docker.sock"
		out = append(out, f)
	}
	dirs, _ := filepath.Glob("/var/lib/docker/containers/*")
	if len(dirs) == 0 {
		if err != nil {
			return out
		}
		return append(out, finding("docker.containers", cat, model.Info, "已安裝 Docker，目前沒有容器"))
	}
	var running, stopped, privileged []string
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
		line := name + "  映像=" + cfg.Config.Image
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
		var bad []string
		if hc.Privileged {
			bad = append(bad, "privileged")
		}
		if hc.PidMode == "host" {
			bad = append(bad, "pid=host")
		}
		for _, bind := range hc.Binds {
			if strings.HasPrefix(bind, "/:") || strings.HasPrefix(bind, "/var/run/docker.sock:") {
				bad = append(bad, "掛載 "+strings.SplitN(bind, ":", 2)[0])
			}
		}
		if len(bad) > 0 && cfg.State.Running {
			privileged = append(privileged, name+"："+strings.Join(bad, ", "))
		}
	}
	f := finding("docker.containers", cat, model.Info, fmt.Sprintf("%d 個執行中容器，%d 個已停止", len(running), len(stopped)))
	f.Detail = "CVE 類別只比對宿主機的 apt 套件，容器映像內的套件沒有掃描。執行中容器的 nginx／PHP 版本則會在 Web 類別列出。"
	f.Evidence = append(running, stopped...)
	out = append(out, f)
	if len(privileged) > 0 {
		g := finding("docker.privileged", cat, model.High, "容器具有逃逸到宿主機的權限")
		g.Detail = "這些容器一旦被入侵，等於宿主機被入侵。"
		g.Evidence = privileged
		out = append(out, g)
	}
	return out
}

func loadPacketFilters(c *Context) (map[uint64][]procinfo.BPFInstruction, string, bool) {
	if c.Opts.NoNetlink {
		return nil, "已用 --no-netlink 關閉", false
	}
	before := procinfo.PacketDiagModuleLoaded()
	filters, err := procinfo.PacketFilters(5 * time.Second)
	if err != nil {
		return nil, "無法讀取：" + err.Error(), false
	}
	return filters, "", !before && procinfo.PacketDiagModuleLoaded()
}
