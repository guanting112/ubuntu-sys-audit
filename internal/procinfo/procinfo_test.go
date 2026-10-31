package procinfo

import "testing"

func TestParseAddr(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port uint16
	}{
		{"3500007F:0035", "127.0.0.53", 53},
		{"00000000:0016", "0.0.0.0", 22},
		{"00000000000000000000000000000000:0035", "::", 53},
		{"00000000000000000000000001000000:01BB", "::1", 443},
		{"0000000000000000FFFF00000100007F:0050", "127.0.0.1", 80},
		{"B80D01200000000000000000EFBEADDE:0035", "2001:db8::dead:beef", 53},
	}
	for _, c := range cases {
		ip, port, ok := ParseAddr(c.in)
		if !ok || ip.String() != c.ip || port != c.port {
			t.Errorf("ParseAddr(%q) = %v:%d ok=%v, want %s:%d", c.in, ip, port, ok, c.ip, c.port)
		}
	}
	for _, bad := range []string{"", "zz:0035", "3500007F", "3500007F:zzzz"} {
		if _, _, ok := ParseAddr(bad); ok {
			t.Errorf("ParseAddr(%q) should fail", bad)
		}
	}
}

func TestParseSocketTableAndListening(t *testing.T) {
	data := []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 25621 2 0
   1: 0100007F:E2B4 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 25622 2 0
`)
	got := ParseSocketTable("udp", data)
	if len(got) != 2 {
		t.Fatalf("want 2 rows, got %d", len(got))
	}
	if !got[0].Listening() || got[0].LocalPort != 53 || got[0].Inode != 25621 || got[0].UID != 101 {
		t.Errorf("row 0 wrong: %+v", got[0])
	}
	if got[1].Listening() || got[1].RemotePort != 53 || got[1].RemoteIP.String() != "8.8.8.8" {
		t.Errorf("connected UDP socket misread: %+v", got[1])
	}
	tcp := Socket{Proto: "tcp", State: StateListen, LocalPort: 22}
	if !tcp.Listening() {
		t.Error("TCP LISTEN should be listening")
	}
	if (Socket{Proto: "tcp", State: StateEstablished}).Listening() {
		t.Error("TCP ESTABLISHED should not be listening")
	}
}

func TestParsePacketTable(t *testing.T) {
	data := []byte(`sk               RefCnt Type Proto  Iface R Rmem   User   Inode
ffff9d5e4a7f5000 3      3    0003   2     1 0      0      44123
ffff9d5e4a7f6000 3      2    0800   0     1 0      1000   44124
`)
	got := ParsePacketTable(data)
	if len(got) != 2 {
		t.Fatalf("want 2 rows, got %d", len(got))
	}
	if got[0].Type != 3 || got[0].Proto != 3 || got[0].Iface != 2 || got[0].Inode != 44123 {
		t.Errorf("row 0 wrong: %+v", got[0])
	}
	if got[1].Proto != 0x0800 || got[1].UID != 1000 {
		t.Errorf("row 1 wrong: %+v", got[1])
	}
}

func TestParseStatHandlesHostileComm(t *testing.T) {
	line := "1234 (evil) (name) S 77 1234 1234 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 1 1 1"
	comm, ppid, flags := ParseStat(line)
	if comm != "evil) (name" || ppid != 77 || flags != 4194560 {
		t.Errorf("got comm=%q ppid=%d flags=%d", comm, ppid, flags)
	}
	if _, _, flags := ParseStat("2 (kthreadd) S 0 0 0 0 -1 2129984 0"); flags&pfKthread == 0 {
		t.Error("kernel thread flag not detected")
	}
}
