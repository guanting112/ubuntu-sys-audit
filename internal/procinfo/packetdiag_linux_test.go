//go:build linux

package procinfo

import "testing"

func TestBPFIndicators(t *testing.T) {
	magic, dns := BPFIndicators([]BPFInstruction{
		{Code: 0x28, K: 12},
		{Code: bpfJmpJeq, K: 0x0800},
		{Code: bpfJmpJeq, K: 0x7255},
		{Code: bpfJmpJeq, K: 53},
		{Code: bpfJmpJeq, K: 0x39393939},
	})
	if len(magic) != 2 || !dns {
		t.Errorf("magic=%v dns=%v", magic, dns)
	}
	magic, dns = BPFIndicators([]BPFInstruction{{Code: bpfJmpJeq, K: 0x888e}, {Code: 0x06, K: 53}})
	if len(magic) != 0 || dns {
		t.Errorf("benign filter flagged: magic=%v dns=%v", magic, dns)
	}
}

func TestParseDiagMessages(t *testing.T) {
	// One SOCK_DIAG message: inode 4242, a PACKET_DIAG_FILTER attribute with
	// one instruction, followed by NLMSG_DONE.
	msg := []byte{
		44, 0, 0, 0, 20, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, // nlmsghdr, length 44
		17, 3, 0, 0, 0x92, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // packet_diag_msg
		12, 0, 7, 0, // rtattr, length 12, type 7
		0x15, 0, 1, 2, 0x55, 0x72, 0, 0, // jeq #0x7255
		20, 0, 0, 0, 3, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // NLMSG_DONE
	}
	out := map[uint64][]BPFInstruction{}
	done, err := parseDiagMessages(msg, out)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	prog := out[4242]
	if len(prog) != 1 || prog[0].Code != bpfJmpJeq || prog[0].K != 0x7255 || prog[0].JF != 2 {
		t.Fatalf("decoded wrong: %+v", out)
	}
}
