package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"ubuntu-sys-audit/internal/procinfo"
)

func selfSigned(t *testing.T, cn string, dns ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve answers every connection on a loopback port with handle.
func serve(t *testing.T, handle func(net.Conn)) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				handle(conn)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

func serveTLS(t *testing.T, cfg *tls.Config) netip.AddrPort {
	return serve(t, func(conn net.Conn) {
		srv := tls.Server(conn, cfg)
		_ = srv.Handshake()
	})
}

func TestProbeTLS(t *testing.T) {
	ctx := context.Background()
	site := selfSigned(t, "shop.example.org", "shop.example.org", "www.example.org")
	sni := make(chan string, 1)
	leaky := serveTLS(t, &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		sni <- h.ServerName
		return &site, nil
	}})
	answer, cert, err := probeTLS(ctx, leaky)
	if answer != tlsCertificate || cert == nil {
		t.Fatalf("default certificate: answer %v, err %v", answer, err)
	}
	if got := <-sni; got != "" {
		t.Errorf("the probe must not send a server name, sent %q", got)
	}
	if got := certNames(cert); !reflect.DeepEqual(got, []string{"shop.example.org", "www.example.org"}) {
		t.Errorf("names: %q", got)
	}
	if got := certIssuer(cert); got != "self-signed" {
		t.Errorf("issuer: %q", got)
	}

	// nginx's ssl_reject_handshake and Caddy without default_sni answer with an alert.
	rejecting := serveTLS(t, &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.ServerName == "" {
			return nil, errors.New("no name")
		}
		return &site, nil
	}})
	if answer, _, err := probeTLS(ctx, rejecting); answer != tlsRefused {
		t.Errorf("rejecting server: answer %v, err %v", answer, err)
	}

	plain := serve(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	})
	if answer, _, err := probeTLS(ctx, plain); answer != tlsPlain {
		t.Errorf("plain HTTP: answer %v, err %v", answer, err)
	}

	// A plain HTTP server waiting for a request line says nothing at all.
	silent := serve(t, func(conn net.Conn) { time.Sleep(2 * time.Second) })
	short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if answer, _, err := probeTLS(short, silent); answer != tlsPlain {
		t.Errorf("silent server: answer %v, err %v", answer, err)
	}
	// A TLS answer that starts and then stalls is a real timeout.
	stalled := serve(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x40})
		time.Sleep(2 * time.Second)
	})
	short2, cancel2 := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel2()
	if answer, _, err := probeTLS(short2, stalled); answer != tlsTimeout {
		t.Errorf("stalled server: answer %v, err %v", answer, err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := netip.MustParseAddrPort(ln.Addr().String())
	ln.Close()
	if answer, _, err := probeTLS(ctx, closed); answer != tlsUnreachable {
		t.Errorf("closed port: answer %v, err %v", answer, err)
	}
}

func TestRevealingName(t *testing.T) {
	cases := map[string]bool{
		"shop.example.com":                true,
		"*.example.com":                   true,
		"origin.mycompany.com.tw":         true,
		"localhost":                       false,
		"localhost.localdomain":           false,
		"web01":                           false, // a bare host name, as Ubuntu's snakeoil certificate uses
		"203.0.113.5":                     false,
		"2001:db8::1":                     false,
		"ip-172-31-5-10.ec2.internal":     false,
		"printer.local":                   false,
		"nas.home.arpa":                   false,
		"site.test":                       false,
		"example":                         false,
		"app.example":                     false,
		"traefik.default.svc.cluster.lan": false,
	}
	for name, want := range cases {
		if got := revealingName(name); got != want {
			t.Errorf("revealingName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestTLSTargets(t *testing.T) {
	sock := func(proto, local string, inode uint64) procinfo.Socket {
		ap := netip.MustParseAddrPort(local)
		return procinfo.Socket{Proto: proto, LocalIP: ap.Addr(), LocalPort: ap.Port(), State: procinfo.StateListen, Inode: inode, HostNS: true}
	}
	programs := map[uint64]string{1: "nginx", 2: "nginx", 3: "sshd", 4: "docker-proxy", 5: "caddy", 6: "nginx", 7: "nginx", 8: "caddy"}
	owner := func(inode uint64) (string, string) { return "pid " + programs[inode], programs[inode] }
	sockets := []procinfo.Socket{
		sock("tcp", "0.0.0.0:443", 1),
		sock("tcp6", "[::]:443", 2),
		sock("tcp", "0.0.0.0:22", 3),     // not TLS
		sock("tcp", "0.0.0.0:8443", 4),   // a TLS port, whoever holds it
		sock("tcp", "127.0.0.1:2019", 5), // Caddy's admin API is plain HTTP
		sock("tcp", "0.0.0.0:80", 6),     // plain HTTP on a TLS server
		sock("tcp", "10.0.0.5:9001", 7),  // any other port of a TLS server
		sock("tcp", "127.0.0.1:7443", 8), // loopback only
		sock("udp", "0.0.0.0:443", 1),    // QUIC is not checked
		{Proto: "tcp", LocalIP: netip.MustParseAddr("0.0.0.0"), LocalPort: 443, State: procinfo.StateListen, Inode: 9}, // another namespace
	}
	local := []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("2001:db8::5")}
	var got []string
	for _, tg := range tlsTargets(sockets, owner, local) {
		got = append(got, tg.Addr.String()+" "+tg.Program+" "+map[bool]string{true: "exposed", false: "local"}[tg.Exposed])
	}
	want := []string{
		"10.0.0.5:443 nginx exposed",
		"127.0.0.1:443 nginx exposed",
		"203.0.113.5:443 nginx exposed",
		"[::1]:443 nginx exposed",
		"[2001:db8::5]:443 nginx exposed",
		"127.0.0.1:7443 caddy local",
		"10.0.0.5:8443 docker-proxy exposed",
		"127.0.0.1:8443 docker-proxy exposed",
		"203.0.113.5:8443 docker-proxy exposed",
		"10.0.0.5:9001 nginx exposed",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("targets:\n got %q\nwant %q", got, want)
	}
}

func TestTLSLinesAndRemediation(t *testing.T) {
	target := func(addr, program string) tlsTarget {
		return tlsTarget{Listen: "0.0.0.0:443", Addr: netip.MustParseAddrPort(addr), Owner: "pid=1 " + program, Program: program, Exposed: true}
	}
	leak := []tlsResult{
		{tlsTarget: target("127.0.0.1:443", "nginx"), Answer: tlsCertificate, Names: []string{"shop.example.com", "localhost"}, Issuer: "issued by Let's Encrypt R11"},
		{tlsTarget: target("203.0.113.5:443", "nginx"), Answer: tlsCertificate, Names: []string{"shop.example.com", "localhost"}, Issuer: "issued by Let's Encrypt R11"},
	}
	describe := func(r tlsResult) string { return strings.Join(r.revealing(), ", ") + " (" + r.Issuer + ")" }
	lines := tlsLines(leak, describe)
	if want := []string{"0.0.0.0:443 via 127.0.0.1, 203.0.113.5  pid=1 nginx  shop.example.com (issued by Let's Encrypt R11)"}; !reflect.DeepEqual(lines, want) {
		t.Errorf("lines:\n got %q\nwant %q", lines, want)
	}
	rem := tlsRemediation(leak)
	if !strings.HasPrefix(rem, "nginx: add a default server") || !strings.Contains(rem, "ssl_reject_handshake on;") || strings.Contains(rem, "Other services") {
		t.Errorf("nginx remediation: %s", rem)
	}
	other := tlsRemediation([]tlsResult{{tlsTarget: target("127.0.0.1:443", "docker-proxy")}})
	if !strings.HasPrefix(other, "Other services:") {
		t.Errorf("generic remediation: %s", other)
	}
	if containsHan(rem + other) {
		t.Error("text must be English")
	}
}
