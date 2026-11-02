//go:build linux

package procinfo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// BPFInstruction is one classic BPF instruction attached to a packet socket.
type BPFInstruction struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

const (
	netlinkSockDiag  = 4
	sockDiagByFamily = 20
	afPacket         = 17
	packetShowFilter = 0x20
	packetDiagFilter = 7
)

// packetDiagModule is where the kernel lists the module that answers packet_diag
// queries. The module is named af_packet_diag, so /sys/module/packet_diag never
// exists and checking it hid every auto load.
const packetDiagModule = "/sys/module/af_packet_diag"

// PacketDiagModuleLoaded reports whether the kernel's af_packet_diag module is
// already present. Querying filters makes the kernel auto load it, the same
// thing `ss -0` does, so the caller can disclose that.
func PacketDiagModuleLoaded() bool {
	_, err := os.Stat(packetDiagModule)
	return err == nil
}

// PacketFilters returns the classic BPF program attached to each AF_PACKET
// socket in this network namespace, keyed by socket inode. This is the data
// `ss -0pb` prints.
func PacketFilters(timeout time.Duration) (map[uint64][]BPFInstruction, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkSockDiag)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	defer syscall.Close(fd)
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("netlink bind: %w", err)
	}

	// nlmsghdr (16 bytes) followed by struct packet_diag_req (20 bytes).
	req := make([]byte, 36)
	le := binary.LittleEndian
	le.PutUint32(req[0:], uint32(len(req)))
	le.PutUint16(req[4:], sockDiagByFamily)
	le.PutUint16(req[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	le.PutUint32(req[8:], 1)
	req[16] = afPacket
	le.PutUint32(req[24:], packetShowFilter)
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("netlink send: %w", err)
	}

	out := map[uint64][]BPFInstruction{}
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return nil, fmt.Errorf("netlink recv: %w", err)
		}
		done, err := parseDiagMessages(buf[:n], out)
		if err != nil {
			return nil, err
		}
		if done {
			return out, nil
		}
	}
}

func parseDiagMessages(data []byte, out map[uint64][]BPFInstruction) (bool, error) {
	le := binary.LittleEndian
	for len(data) >= 16 {
		msgLen := int(le.Uint32(data[0:]))
		msgType := le.Uint16(data[4:])
		if msgLen < 16 || msgLen > len(data) {
			return false, errors.New("netlink: truncated message")
		}
		switch msgType {
		case syscall.NLMSG_DONE:
			return true, nil
		case syscall.NLMSG_ERROR:
			if msgLen >= 20 {
				if code := int32(le.Uint32(data[16:])); code != 0 {
					return false, fmt.Errorf("netlink: %w", syscall.Errno(-code))
				}
			}
			return true, nil
		case sockDiagByFamily:
			parseDiagPayload(data[16:msgLen], out)
		}
		next := (msgLen + 3) &^ 3
		if next >= len(data) {
			break
		}
		data = data[next:]
	}
	return false, nil
}

func parseDiagPayload(p []byte, out map[uint64][]BPFInstruction) {
	if len(p) < 16 {
		return
	}
	le := binary.LittleEndian
	ino := uint64(le.Uint32(p[4:]))
	attrs := p[16:]
	for len(attrs) >= 4 {
		attrLen := int(le.Uint16(attrs[0:]))
		attrType := le.Uint16(attrs[2:]) & 0x3fff
		if attrLen < 4 || attrLen > len(attrs) {
			return
		}
		if attrType == packetDiagFilter {
			out[ino] = decodeBPF(attrs[4:attrLen])
		}
		next := (attrLen + 3) &^ 3
		if next >= len(attrs) {
			return
		}
		attrs = attrs[next:]
	}
}

func decodeBPF(b []byte) []BPFInstruction {
	le := binary.LittleEndian
	prog := make([]BPFInstruction, 0, len(b)/8)
	for len(b) >= 8 {
		prog = append(prog, BPFInstruction{Code: le.Uint16(b[0:]), JT: b[2], JF: b[3], K: le.Uint32(b[4:])})
		b = b[8:]
	}
	return prog
}

// BPFDoorMagic lists the magic values published for BPFDoor's packet filter:
// 0x7255 (UDP), 0x5293 (TCP), 0x39393939 (ICMP), as documented by Trend Micro
// (research/25/d/bpfdoor-hidden-controller).
var BPFDoorMagic = map[uint32]string{0x7255: "0x7255", 0x5293: "0x5293", 0x39393939: "0x39393939"}

const bpfJmpJeq = 0x15 // BPF_JMP | BPF_JEQ | BPF_K

// BPFIndicators reports filter constants worth flagging: published BPFDoor
// magic values anywhere in the program, and comparisons against port 53.
func BPFIndicators(prog []BPFInstruction) (magic []string, matchesDNS bool) {
	seen := map[string]bool{}
	for _, in := range prog {
		if name, ok := BPFDoorMagic[in.K]; ok && !seen[name] {
			seen[name] = true
			magic = append(magic, name)
		}
		if in.Code == bpfJmpJeq && in.K == 53 {
			matchesDNS = true
		}
	}
	return magic, matchesDNS
}

// DescribeBPF renders a short summary of a filter.
func DescribeBPF(prog []BPFInstruction) string {
	if len(prog) == 0 {
		return "no filter"
	}
	var ks []string
	for _, in := range prog {
		if in.Code == bpfJmpJeq {
			ks = append(ks, fmt.Sprintf("%#x", in.K))
		}
		if len(ks) == 8 {
			break
		}
	}
	return fmt.Sprintf("%d BPF instructions, compares against %s", len(prog), strings.Join(ks, " "))
}
