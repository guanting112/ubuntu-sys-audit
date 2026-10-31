package procinfo

import (
	"encoding/hex"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"ubuntu-sys-audit/internal/fsx"
)

// Socket is one row of /proc/net/{tcp,tcp6,udp,udp6,raw,raw6}.
type Socket struct {
	Proto      string
	LocalIP    netip.Addr
	LocalPort  uint16
	RemoteIP   netip.Addr
	RemotePort uint16
	State      int
	Inode      uint64
	UID        int
	NetNS      string
	HostNS     bool
}

// TCP and UDP state values used by the kernel.
const (
	StateEstablished = 0x01
	StateClose       = 0x07
	StateListen      = 0x0A
)

// Listening reports whether a TCP socket listens or a UDP socket is unconnected
// and bound to a port.
func (s Socket) Listening() bool {
	switch s.Proto {
	case "tcp", "tcp6":
		return s.State == StateListen
	case "udp", "udp6":
		return s.State == StateClose && s.LocalPort != 0 && s.RemotePort == 0
	}
	return false
}

// Local formats the local endpoint.
func (s Socket) Local() string { return netip.AddrPortFrom(s.LocalIP, s.LocalPort).String() }

// Remote formats the remote endpoint.
func (s Socket) Remote() string { return netip.AddrPortFrom(s.RemoteIP, s.RemotePort).String() }

// PacketSocket is one row of /proc/net/packet, an AF_PACKET socket that sees
// frames before the firewall does. BPFDoor style implants receive their magic
// packets this way, which is why they never appear as a listening port.
type PacketSocket struct {
	Type   int
	Proto  uint16
	Iface  int
	UID    int
	Inode  uint64
	NetNS  string
	HostNS bool
}

// ParseAddr decodes the hex "ADDR:PORT" form used by /proc/net. IPv4 and each
// 32-bit word of IPv6 are stored in host byte order, which is little endian on
// amd64 and arm64.
func ParseAddr(s string) (netip.Addr, uint16, bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return netip.Addr{}, 0, false
	}
	raw, err := hex.DecodeString(s[:i])
	if err != nil {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	switch len(raw) {
	case 4:
		return netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]}), uint16(port), true
	case 16:
		var b [16]byte
		for w := 0; w < 4; w++ {
			for j := 0; j < 4; j++ {
				b[w*4+j] = raw[w*4+3-j]
			}
		}
		return netip.AddrFrom16(b).Unmap(), uint16(port), true
	}
	return netip.Addr{}, 0, false
}

// ParseSocketTable parses one /proc/net socket table.
func ParseSocketTable(proto string, data []byte) []Socket {
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return nil
	}
	var out []Socket
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		lip, lport, ok1 := ParseAddr(f[1])
		rip, rport, ok2 := ParseAddr(f[2])
		state, err := strconv.ParseInt(f[3], 16, 32)
		if !ok1 || !ok2 || err != nil {
			continue
		}
		uid, _ := strconv.Atoi(f[7])
		ino, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, Socket{
			Proto: proto, LocalIP: lip, LocalPort: lport, RemoteIP: rip, RemotePort: rport,
			State: int(state), UID: uid, Inode: ino,
		})
	}
	return out
}

// ParsePacketTable parses /proc/net/packet.
func ParsePacketTable(data []byte) []PacketSocket {
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return nil
	}
	var out []PacketSocket
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 9 {
			continue
		}
		typ, _ := strconv.Atoi(f[2])
		proto, _ := strconv.ParseUint(f[3], 16, 16)
		iface, _ := strconv.Atoi(f[4])
		uid, _ := strconv.Atoi(f[7])
		ino, _ := strconv.ParseUint(f[8], 10, 64)
		out = append(out, PacketSocket{Type: typ, Proto: uint16(proto), Iface: iface, UID: uid, Inode: ino})
	}
	return out
}

// NetView holds every socket on the host across network namespaces.
type NetView struct {
	Sockets []Socket
	Packet  []PacketSocket
	ByInode map[uint64]*Process
	NSCount int
}

// CollectNet walks each distinct network namespace through one of its member
// processes, so a backdoor inside a container netns is seen as well. The
// tool's own namespace is treated as the host's.
func CollectNet(procs []*Process) *NetView {
	view := &NetView{ByInode: map[uint64]*Process{}}
	hostNS, _ := os.Readlink("/proc/self/ns/net")
	nsPID := map[string]string{hostNS: "self"}
	for _, p := range procs {
		for _, ino := range p.Sockets {
			if _, dup := view.ByInode[ino]; !dup {
				view.ByInode[ino] = p
			}
		}
		if p.KernelTh || p.NetNS == "" {
			continue
		}
		if _, ok := nsPID[p.NetNS]; !ok {
			nsPID[p.NetNS] = strconv.Itoa(p.PID)
		}
	}
	view.NSCount = len(nsPID)
	seen := map[uint64]bool{}
	for ns, pid := range nsPID {
		base := "/proc/" + pid + "/net/"
		isHost := ns == hostNS
		for _, proto := range []string{"tcp", "tcp6", "udp", "udp6", "raw", "raw6"} {
			b, err := fsx.ReadProc(base + proto)
			if err != nil {
				continue
			}
			for _, s := range ParseSocketTable(proto, b) {
				// Connected sockets with inode 0 are in TIME_WAIT; they have
				// no owner and are not interesting here.
				if s.Inode == 0 || seen[s.Inode] {
					continue
				}
				seen[s.Inode] = true
				s.NetNS, s.HostNS = ns, isHost
				view.Sockets = append(view.Sockets, s)
			}
		}
		if b, err := fsx.ReadProc(base + "packet"); err == nil {
			for _, s := range ParsePacketTable(b) {
				if seen[s.Inode] {
					continue
				}
				seen[s.Inode] = true
				s.NetNS, s.HostNS = ns, isHost
				view.Packet = append(view.Packet, s)
			}
		}
	}
	return view
}
