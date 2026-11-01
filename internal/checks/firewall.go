package checks

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/procinfo"
)

// globalUnicast is the IPv6 range reachable from the internet. Unique local
// addresses report the same scope in /proc/net/if_inet6, but they are not.
var globalUnicast = netip.MustParsePrefix("2000::/3")

// ufwStatus reports whether ufw is configured to run.
func ufwStatus() string {
	b, err := fsx.Read("/etc/ufw/ufw.conf", 1<<14)
	if err != nil {
		return "not installed"
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "ENABLED=yes") {
			return "enabled"
		}
	}
	return "disabled"
}

// parseUfwDefaults reads the two settings in /etc/default/ufw that decide how
// much ufw filters. A setting that is absent comes back empty.
func parseUfwDefaults(src string) (policy, ipv6 string) {
	for _, line := range strings.Split(src, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		value, _, _ = strings.Cut(value, "#")
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch strings.TrimSpace(key) {
		case "DEFAULT_INPUT_POLICY":
			policy = strings.ToUpper(value)
		case "IPV6":
			ipv6 = strings.ToLower(value)
		}
	}
	return policy, ipv6
}

// publicIPv6Addrs returns the internet-reachable addresses in /proc/net/if_inet6.
func publicIPv6Addrs(ifInet6 string) []string {
	var out []string
	for _, line := range strings.Split(ifInet6, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || f[3] != "00" || f[5] == "lo" {
			continue
		}
		raw, err := hex.DecodeString(f[0])
		if err != nil || len(raw) != 16 {
			continue
		}
		addr := netip.AddrFrom16([16]byte(raw))
		if globalUnicast.Contains(addr) {
			out = append(out, addr.String()+" on "+f[5])
		}
	}
	return out
}

// ipv6Listeners lists sockets that accept connections on a public IPv6 address.
func ipv6Listeners(view *procinfo.NetView) []string {
	var out []string
	for _, s := range view.Sockets {
		if !s.Listening() || !s.HostNS || !s.LocalIP.Is6() || s.LocalIP.Is4In6() {
			continue
		}
		if s.LocalIP.IsUnspecified() || globalUnicast.Contains(s.LocalIP) {
			out = append(out, fmt.Sprintf("%-4s %-28s %s", s.Proto, s.Local(), ownerLabel(view, s.Inode)))
		}
	}
	sort.Strings(out)
	return out
}

func ufwPolicyFinding(policy string) model.Finding {
	f := finding("network.ufw_policy", model.CatNetwork, model.Medium, "ufw is enabled but allows incoming traffic by default")
	f.Detail = "With this policy ufw blocks only what a rule denies, so any other listening port stays reachable even though ufw reports that it is active."
	f.Evidence = []string{`DEFAULT_INPUT_POLICY="` + policy + `" in /etc/default/ufw`}
	f.Remediation = "Allow the services you need, starting with SSH so you do not lock yourself out, then run sudo ufw default deny incoming."
	return f
}

func ufwIPv6Finding(addrs, listeners []string) model.Finding {
	f := finding("network.ufw_ipv6", model.CatNetwork, model.Medium, "ufw does not filter IPv6, and services listen on a public IPv6 address")
	f.Detail = "IPV6=no in /etc/default/ufw means ufw adds no IPv6 rules. These services can be reached over IPv6 whatever the IPv4 rules say, unless another firewall filters that traffic."
	for _, a := range addrs {
		f.Evidence = append(f.Evidence, "Public address: "+a)
	}
	f.Evidence = append(f.Evidence, listeners...)
	f.Remediation = "Set IPV6=yes in /etc/default/ufw and run sudo ufw reload, then review the rules, or filter IPv6 another way."
	return f
}

// ufwFindings evaluates ufw's settings. It does not evaluate its rules.
func ufwFindings(c *Context) []model.Finding {
	const cat = model.CatNetwork
	b, err := fsx.Read("/etc/default/ufw", 1<<14)
	if err != nil {
		return []model.Finding{skipped("network.ufw_policy", cat, "ufw default policy and IPv6 setting", "Cannot read /etc/default/ufw: "+err.Error())}
	}
	policy, ipv6 := parseUfwDefaults(string(b))
	var out []model.Finding
	if policy == "ACCEPT" {
		out = append(out, ufwPolicyFinding(policy))
	}
	if ipv6 != "no" {
		return out
	}
	addrs := publicIPv6Addrs(fsx.ProcString("/proc/net/if_inet6"))
	if len(addrs) == 0 {
		return out
	}
	if _, err := c.Procs(); err != nil {
		return append(out, skipped("network.ufw_ipv6", cat, "IPv6 listeners not filtered by ufw", err.Error()))
	}
	if listeners := ipv6Listeners(c.Net()); len(listeners) > 0 {
		out = append(out, ufwIPv6Finding(addrs, listeners))
	}
	return out
}

type dockerPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

func hasBindings(ports map[string][]dockerPortBinding) bool {
	for _, bindings := range ports {
		if len(bindings) > 0 {
			return true
		}
	}
	return false
}

// publishedPorts lists the ports a container publishes beyond loopback. actual
// comes from NetworkSettings and includes ports Docker chose itself, so the
// requested PortBindings are only the fallback.
func publishedPorts(actual, requested map[string][]dockerPortBinding) []string {
	ports := actual
	if !hasBindings(ports) {
		ports = requested
	}
	var out []string
	for containerPort, bindings := range ports {
		for _, b := range bindings {
			ip, port := b.HostIP, b.HostPort
			if ip == "" {
				ip = "0.0.0.0"
			}
			if addr, err := netip.ParseAddr(ip); err == nil && addr.IsLoopback() {
				continue
			}
			if port == "" {
				port = "any"
			}
			out = append(out, net.JoinHostPort(ip, port)+" -> "+containerPort)
		}
	}
	sort.Strings(out)
	return out
}

// dockerManagesIptables reads /etc/docker/daemon.json. With "iptables": false
// Docker adds no rules, so published ports stay behind ufw.
func dockerManagesIptables(daemonJSON []byte) bool {
	var cfg struct {
		IPTables *bool `json:"iptables"`
	}
	if json.Unmarshal(daemonJSON, &cfg) != nil || cfg.IPTables == nil {
		return true
	}
	return *cfg.IPTables
}

// dockerUserConfigured reports whether a firewall file on the host mentions the
// DOCKER-USER chain, the supported place to filter published ports.
func dockerUserConfigured() bool {
	for _, p := range []string{"/etc/ufw/after.rules", "/etc/ufw/after6.rules", "/etc/iptables/rules.v4", "/etc/iptables/rules.v6", "/etc/nftables.conf"} {
		if b, err := fsx.Read(p, 1<<20); err == nil && strings.Contains(string(b), "DOCKER-USER") {
			return true
		}
	}
	return false
}

func dockerUfwFinding(published []string, filtered bool) model.Finding {
	f := finding("docker.ufw_bypass", model.CatNetwork, model.Medium, "Published container ports bypass ufw")
	f.Detail = "Docker diverts traffic to published ports through its own iptables rules before it goes through ufw. These ports can be reachable even where ufw denies them, and ufw status does not show it."
	f.Evidence = published
	f.Remediation = "Publish with 127.0.0.1:HOST:CONTAINER behind a reverse proxy, or filter these ports in the DOCKER-USER chain."
	f.Refs = []string{"https://docs.docker.com/engine/network/packet-filtering-firewalls/"}
	if filtered {
		f.Severity = model.Info
		f.Title = "Published container ports rely on DOCKER-USER rules"
		f.Detail = "Docker diverts traffic to published ports through its own iptables rules before it goes through ufw. This host's firewall files mention DOCKER-USER, the supported place to filter them. This tool does not evaluate rules, so confirm they cover these ports."
	}
	return f
}
