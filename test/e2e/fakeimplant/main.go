//go:build linux

// fakeimplant is a harmless test fixture for the end to end test. It reproduces
// the observable traits of a passive backdoor so the audit can be checked
// against them, and does nothing else: it never reads what it receives, never
// sends anything and has no command channel.
//
// It binds UDP 53, opens an AF_PACKET socket with a classic BPF filter holding
// the published BPFDoor magic values, deletes its own binary and sleeps.
package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

type sockFilter struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

type sockFprog struct {
	Len    uint16
	_      [6]byte
	Filter *sockFilter
}

const (
	bpfLdAbsH = 0x28
	bpfJeq    = 0x15
	bpfRetK   = 0x06
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "shell-target":
			reverseShellFixture()
			return
		case "idle":
			// Does nothing. The caller sets argv[0] to test name based checks.
			time.Sleep(24 * time.Hour)
			return
		}
	}
	// systemd-resolved holds 127.0.0.53:53, which makes a wildcard bind fail,
	// so bind the first non loopback address instead.
	if conn := bindDNS(); conn != nil {
		defer conn.Close()
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "packet socket:", err)
		os.Exit(1)
	}
	// Rejects everything: the filter exists to be observed, not to capture.
	prog := []sockFilter{
		{Code: bpfLdAbsH, K: 36},
		{Code: bpfJeq, JF: 1, K: 53},
		{Code: bpfJeq, JF: 0, K: 0x7255},
		{Code: bpfJeq, JF: 0, K: 0x39393939},
		{Code: bpfRetK, K: 0},
	}
	fprog := sockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if _, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER,
		uintptr(unsafe.Pointer(&fprog)), unsafe.Sizeof(fprog), 0); e != 0 {
		fmt.Fprintln(os.Stderr, "attach filter:", e)
		os.Exit(1)
	}
	if exe, err := os.Executable(); err == nil && len(os.Args) > 1 && os.Args[1] == "self-delete" {
		_ = os.Remove(exe)
	}
	time.Sleep(24 * time.Hour)
}

func bindDNS() net.PacketConn {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil {
			continue
		}
		conn, err := net.ListenPacket("udp4", net.JoinHostPort(ipn.IP.String(), "53"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "bind udp/53:", err)
			return nil
		}
		return conn
	}
	return nil
}

// reverseShellFixture connects a shell's stdio to a local TCP listener, which
// is the shape of a reverse shell. Nobody sends it commands: it only waits.
func reverseShellFixture() {
	ln, err := net.Listen("tcp4", "127.0.0.1:18443")
	if err != nil {
		os.Exit(1)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	c, err := net.Dial("tcp4", "127.0.0.1:18443")
	if err != nil {
		os.Exit(1)
	}
	f, err := c.(*net.TCPConn).File()
	if err != nil {
		os.Exit(1)
	}
	if _, err := syscall.ForkExec("/bin/sh", []string{"sh"}, &syscall.ProcAttr{
		Files: []uintptr{f.Fd(), f.Fd(), f.Fd()},
	}); err != nil {
		os.Exit(1)
	}
	time.Sleep(24 * time.Hour)
}
