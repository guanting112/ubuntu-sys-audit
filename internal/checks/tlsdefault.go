package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/procinfo"
)

// Censys and Shodan connect to every address on HTTPS ports without a server
// name (SNI) and index the certificate that comes back. That certificate comes
// from the default server, so if it names a real domain, the address is tied
// to the domain even when the site itself hides behind Cloudflare. This check
// makes the same handshake against the host's own TLS ports. It sends no
// request, so web servers log nothing for it.

const (
	tlsProbeTimeout = 3 * time.Second
	maxTLSProbes    = 64
	tlsProbeWorkers = 8
)

// tlsPorts usually carry TLS whoever holds them.
var tlsPorts = map[uint16]bool{443: true, 2083: true, 2087: true, 2096: true, 4443: true, 8443: true, 9443: true, 10443: true}

// tlsServers terminate TLS for others, so all their ports are tried except
// plainPorts.
var tlsServers = map[string]bool{
	"nginx": true, "openresty": true, "apache2": true, "httpd": true, "caddy": true, "haproxy": true,
	"traefik": true, "envoy": true, "lighttpd": true, "h2o": true, "hitch": true, "stunnel": true, "stunnel4": true,
}

// plainPorts carry plain HTTP even on those servers. A handshake there would
// only leave a 400 in the access log. 2019 is Caddy's admin API.
var plainPorts = map[uint16]bool{80: true, 81: true, 8000: true, 8008: true, 8080: true, 2019: true}

// localNameSuffixes are names that cannot tie a host to a public domain.
var localNameSuffixes = []string{".localhost", ".local", ".localdomain", ".internal", ".lan", ".home.arpa", ".test", ".invalid", ".example"}

// tlsTarget is one handshake to make: a listening socket, reached at one of
// the addresses it accepts.
type tlsTarget struct {
	Listen  string // the socket as the kernel lists it, such as 0.0.0.0:443
	Addr    netip.AddrPort
	Owner   string
	Program string
	Exposed bool // the socket accepts more than loopback connections
}

// tlsTargets picks the TLS sockets and the addresses to reach each one at. A
// socket on all addresses is tried at loopback and at every address of the
// host, because servers such as nginx choose the default server by the
// address a connection arrived on.
func tlsTargets(sockets []procinfo.Socket, owner func(inode uint64) (label, program string), local []netip.Addr) []tlsTarget {
	seen := map[netip.AddrPort]bool{}
	var out []tlsTarget
	add := func(t tlsTarget) {
		if !seen[t.Addr] {
			seen[t.Addr] = true
			out = append(out, t)
		}
	}
	for _, s := range sockets {
		if (s.Proto != "tcp" && s.Proto != "tcp6") || !s.Listening() || !s.HostNS {
			continue
		}
		label, program := owner(s.Inode)
		if !tlsPorts[s.LocalPort] && !(tlsServers[program] && !plainPorts[s.LocalPort]) {
			continue
		}
		t := tlsTarget{Listen: s.Local(), Owner: label, Program: program, Exposed: !s.LocalIP.IsLoopback()}
		ip := s.LocalIP.Unmap()
		if !ip.IsUnspecified() {
			t.Addr = netip.AddrPortFrom(ip, s.LocalPort)
			add(t)
			continue
		}
		// A socket on :: usually takes IPv4 too, so both families are tried.
		// An address another socket answers for, or that is refused, is
		// dropped later.
		addrs := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		if ip.Is6() {
			addrs = append(addrs, netip.IPv6Loopback())
		}
		for _, a := range local {
			if a.Is4() || ip.Is6() {
				addrs = append(addrs, a)
			}
		}
		for _, a := range addrs {
			t.Addr = netip.AddrPortFrom(a, s.LocalPort)
			add(t)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Addr.Port() != out[j].Addr.Port() {
			return out[i].Addr.Port() < out[j].Addr.Port()
		}
		return out[i].Addr.Addr().Less(out[j].Addr.Addr())
	})
	if len(out) > maxTLSProbes {
		out = out[:maxTLSProbes]
	}
	return out
}

// hostAddrs lists the host's own addresses other than loopback and link-local.
func hostAddrs() []netip.Addr {
	ifAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range ifAddrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// tlsAnswer is what a handshake without a server name got back.
type tlsAnswer int

const (
	tlsUnreachable tlsAnswer = iota // no TCP connection: refused, dropped or not yet usable
	tlsTimeout                      // a TLS answer started but stalled
	tlsPlain                        // not TLS, or no answer at all
	tlsRefused                      // the server declined with a TLS alert
	tlsCertificate                  // the server sent a certificate
)

// probeTLS makes a handshake without a server name and returns the leaf
// certificate. The certificate is only read, never trusted.
func probeTLS(ctx context.Context, addr netip.AddrPort) (tlsAnswer, *x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, tlsProbeTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		// A firewall that drops packets, or an IPv6 address still being
		// checked for duplicates, makes the connection time out. Either way
		// the address cannot be reached, which is not a TLS answer.
		return tlsUnreachable, nil, err
	}
	defer conn.Close()
	counted := &countingConn{Conn: conn}
	var leaf *x509.Certificate
	client := tls.Client(counted, &tls.Config{
		// No ServerName, so no SNI is sent: the point is to see what a
		// scanner that knows only the address gets.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) > 0 {
				leaf, _ = x509.ParseCertificate(raw[0])
			}
			return nil
		},
	})
	err = client.HandshakeContext(ctx)
	if leaf != nil {
		return tlsCertificate, leaf, nil
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "remote error" {
		return tlsRefused, nil, err
	}
	// A plain HTTP server waits for the end of a request line, which a
	// handshake may never contain, so silence means it is not TLS. Every TLS
	// server answers a handshake at once.
	if isTimeout(err) && counted.n > 0 {
		return tlsTimeout, nil, err
	}
	return tlsPlain, nil, err
}

// countingConn counts the bytes the server sent.
type countingConn struct {
	net.Conn
	n int
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.n += n
	return n, err
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// certNames returns the names a certificate is for: its DNS names and its
// common name, lowercased and without duplicates.
func certNames(c *x509.Certificate) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range append([]string{c.Subject.CommonName}, c.DNSNames...) {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// revealingName reports whether a certificate name ties the host to a domain.
// localhost, single labels such as a bare host name, addresses and reserved or
// private suffixes do not.
func revealingName(name string) bool {
	name = strings.TrimPrefix(name, "*.")
	if name == "localhost" || !strings.Contains(name, ".") {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, s := range localNameSuffixes {
		if strings.HasSuffix(name, s) {
			return false
		}
	}
	return true
}

func certIssuer(c *x509.Certificate) string {
	if c.Issuer.String() == c.Subject.String() {
		return "self-signed"
	}
	issuer := c.Issuer.CommonName
	if len(c.Issuer.Organization) > 0 {
		issuer = strings.TrimSpace(c.Issuer.Organization[0] + " " + issuer)
	}
	return "issued by " + issuer
}

// tlsResult is one handshake's outcome.
type tlsResult struct {
	tlsTarget
	Answer tlsAnswer
	Names  []string
	Issuer string
}

func (r tlsResult) revealing() []string {
	var out []string
	for _, n := range r.Names {
		if revealingName(n) {
			out = append(out, n)
		}
	}
	return out
}

func probeAll(ctx context.Context, targets []tlsTarget) []tlsResult {
	results := make([]tlsResult, len(targets))
	sem := make(chan struct{}, tlsProbeWorkers)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			answer, cert, _ := probeTLS(ctx, t.Addr)
			r := tlsResult{tlsTarget: t, Answer: answer}
			if cert != nil {
				r.Names, r.Issuer = certNames(cert), certIssuer(cert)
			}
			results[i] = r
		}()
	}
	wg.Wait()
	return results
}

// tlsLines groups results that differ only in the address used, so a socket
// on all addresses that answers the same everywhere takes one line.
func tlsLines(results []tlsResult, describe func(tlsResult) string) []string {
	type group struct {
		key   string
		addrs []string
	}
	var groups []*group
	index := map[string]*group{}
	for _, r := range results {
		key := r.Listen + "  " + r.Owner + "  " + describe(r)
		g := index[key]
		if g == nil {
			g = &group{key: key}
			index[key] = g
			groups = append(groups, g)
		}
		g.addrs = append(g.addrs, r.Addr.Addr().String())
	}
	var out []string
	for _, g := range groups {
		listen, rest, _ := strings.Cut(g.key, "  ")
		out = append(out, listen+" via "+strings.Join(g.addrs, ", ")+"  "+rest)
	}
	return out
}

func checkDefaultCert(c *Context) []model.Finding {
	const cat = model.CatWeb
	view := c.Net()
	owner := func(inode uint64) (string, string) {
		p := view.ByInode[inode]
		if p == nil {
			return "(no owner found)", ""
		}
		program := p.Comm
		if p.Exe != "" {
			program = base(p.Exe)
		}
		return p.Label(), program
	}
	targets := tlsTargets(view.Sockets, owner, hostAddrs())
	if len(targets) == 0 {
		return []model.Finding{finding("web.tls.default_cert", cat, model.OK, "No HTTPS or other TLS ports to check")}
	}
	var exposed, local, safe []tlsResult
	var timedOut []string
	for _, r := range probeAll(c.Ctx, targets) {
		switch {
		case r.Answer == tlsTimeout:
			timedOut = append(timedOut, r.Addr.String()+"  "+r.Owner)
		case r.Answer == tlsUnreachable || r.Answer == tlsPlain:
			// Refused on one family, or a plain service on a TLS-looking port.
		case len(r.revealing()) > 0 && r.Exposed:
			exposed = append(exposed, r)
		case len(r.revealing()) > 0:
			local = append(local, r)
		default:
			safe = append(safe, r)
		}
	}
	describe := func(r tlsResult) string {
		if r.Answer == tlsRefused {
			return "refuses the handshake"
		}
		names := r.Names
		if rv := r.revealing(); len(rv) > 0 {
			names = rv
		}
		if len(names) == 0 {
			names = []string{"no names"}
		}
		return strings.Join(names, ", ") + " (" + r.Issuer + ")"
	}
	var out []model.Finding
	if len(exposed) > 0 {
		f := finding("web.tls.default_cert", cat, model.High, fmt.Sprintf("HTTPS without a server name gets a certificate that names this host's domains (%d)", len(tlsLines(exposed, describe))))
		f.Detail = "Censys and Shodan connect to every address on common HTTPS ports without a server name and index the certificate they get back. A real domain in it ties this address to the domain, which undoes hiding the origin behind Cloudflare. The certificate comes from the default server for the port and address, so naming the sites correctly is not enough. If the firewall admits only Cloudflare's ranges on these ports, scanners cannot connect, but anyone allowed through still learns the domains."
		f.Evidence = tlsLines(exposed, describe)
		f.Remediation = tlsRemediation(exposed)
		f.Refs = []string{"https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_reject_handshake"}
		f.Focus = true
		out = append(out, f)
	}
	if len(local) > 0 {
		f := finding("web.tls.default_cert_local", cat, model.Info, "TLS ports reachable only from this host give a domain's certificate without a server name")
		f.Detail = "Scanners cannot reach these sockets, so nothing leaks. A self-signed certificate for localhost keeps it that way if the socket is later opened to the network."
		f.Evidence = tlsLines(local, describe)
		out = append(out, f)
	}
	if len(timedOut) > 0 {
		f := skipped("web.tls.default_cert_timeout", cat, "Default TLS certificate", fmt.Sprintf("%d of the %d addresses tried started a TLS answer but did not finish within %s, so their certificates were not checked.", len(timedOut), len(targets), tlsProbeTimeout))
		f.Evidence = timedOut
		out = append(out, f)
	}
	if len(exposed) == 0 && len(safe) > 0 {
		f := finding("web.tls.default_cert", cat, model.OK, "HTTPS without a server name gets no certificate that names a domain")
		f.Detail = "A handshake without a server name was made to each TLS port at each address it listens on, the way scanners connect."
		f.Evidence = tlsLines(safe, describe)
		out = append(out, f)
	}
	if len(out) == 0 {
		out = append(out, finding("web.tls.default_cert", cat, model.OK, "No TLS service answered on the ports tried"))
	}
	return out
}

// tlsRemediation gives the fix for each server that leaked.
func tlsRemediation(results []tlsResult) string {
	programs := map[string]bool{}
	for _, r := range results {
		programs[r.Program] = true
	}
	var parts []string
	if programs["nginx"] || programs["openresty"] {
		parts = append(parts, "nginx: add a default server on every TLS port so a connection without a name never reaches a real site: server { listen 443 ssl default_server; listen [::]:443 ssl default_server; ssl_reject_handshake on; }. ssl_reject_handshake needs nginx 1.19.4 or later, and Ubuntu 22.04 and older ship 1.18 or earlier; there, use ssl_certificate and ssl_certificate_key with a self-signed certificate for localhost and return 444. Make one with openssl req -x509 -nodes -newkey rsa:2048 -days 3650 -subj /CN=localhost -keyout /etc/nginx/ssl/default_server.key -out /etc/nginx/ssl/default_server.crt.")
	}
	if programs["apache2"] || programs["httpd"] {
		parts = append(parts, "Apache: make the first <VirtualHost *:443> a catch-all with a self-signed certificate for localhost, since Apache uses the first virtual host on a port for connections without a name.")
	}
	if programs["caddy"] {
		parts = append(parts, "Caddy: remove default_sni from the global options. Without it, Caddy refuses connections that name no site.")
	}
	if programs["haproxy"] {
		parts = append(parts, "HAProxy: load a self-signed certificate for localhost first on the bind line, since HAProxy uses the first certificate for connections without a name.")
	}
	known := map[string]bool{"nginx": true, "openresty": true, "apache2": true, "httpd": true, "caddy": true, "haproxy": true}
	for p := range programs {
		if !known[p] {
			parts = append(parts, "Other services: configure each so a connection without a server name gets a self-signed certificate for localhost or is refused.")
			break
		}
	}
	return strings.Join(parts, " ")
}
