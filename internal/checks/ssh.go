package checks

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
)

// parseSSHDConfig returns the effective global settings. sshd uses the first
// value it sees for a keyword, and a Match line ends the global section. An
// Include is expanded in place, which is where Ubuntu's drop-in files come in.
func parseSSHDConfig(path string, depth int, out map[string]string, stop *bool) {
	if depth > 8 || *stop {
		return
	}
	b, err := fsx.Read(path, 1<<20)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		key := strings.ToLower(f[0])
		if key == "match" {
			*stop = true
			return
		}
		val := strings.Join(f[1:], " ")
		if key == "include" {
			for _, pat := range f[1:] {
				if !filepath.IsAbs(pat) {
					pat = filepath.Join("/etc/ssh", pat)
				}
				matches, _ := filepath.Glob(pat)
				for _, m := range matches {
					parseSSHDConfig(m, depth+1, out, stop)
					if *stop {
						return
					}
				}
			}
			continue
		}
		if _, exists := out[key]; !exists {
			out[key] = val
		}
	}
}

func checkSSHConfig(c *Context) []model.Finding {
	const cat = model.CatSSH
	if _, err := os.Stat("/etc/ssh/sshd_config"); err != nil {
		return []model.Finding{finding("ssh.config", cat, model.Info, "OpenSSH server is not installed (no sshd_config)")}
	}
	cfg := map[string]string{}
	stop := false
	parseSSHDConfig("/etc/ssh/sshd_config", 0, cfg, &stop)
	if len(cfg) == 0 && !c.Host.IsRoot {
		return []model.Finding{needRoot("ssh.config", cat, "sshd configuration")}
	}
	get := func(key, def string) string {
		if v, ok := cfg[key]; ok {
			return strings.ToLower(v)
		}
		return def
	}
	var out []model.Finding
	add := func(id string, sev model.Severity, title, detail, fix string) {
		f := finding("ssh."+id, cat, sev, title)
		f.Detail, f.Remediation = detail, fix
		out = append(out, f)
	}
	switch get("permitrootlogin", "prohibit-password") {
	case "yes":
		add("root_login", model.High, "Root can log in over SSH with a password", "PermitRootLogin yes.", "Set PermitRootLogin to no or prohibit-password, then reload sshd.")
	case "without-password", "prohibit-password", "forced-commands-only":
		add("root_login", model.Info, "Root can log in over SSH with keys only", "", "If direct root login is not needed, set PermitRootLogin no.")
	default:
		add("root_login", model.OK, "Root login over SSH is disabled", "", "")
	}
	if get("permitemptypasswords", "no") == "yes" {
		add("empty_passwords", model.Critical, "sshd allows empty passwords", "PermitEmptyPasswords yes.", "Set it to no and reload sshd.")
	}
	if get("passwordauthentication", "yes") == "yes" {
		add("password_auth", model.Medium, "SSH allows password login", "This is the default unless explicitly disabled, and it invites brute force attempts.", "Once keys work, set PasswordAuthentication no.")
	} else {
		add("password_auth", model.OK, "SSH password login is disabled", "", "")
	}
	if get("permituserenvironment", "no") != "no" {
		add("user_env", model.Medium, "sshd lets users set environment variables", "An attacker can use this to inject LD_PRELOAD and bypass restrictions.", "Set PermitUserEnvironment no.")
	}
	if v := get("authorizedkeyscommand", "none"); v != "none" {
		f := finding("ssh.keys_command", cat, model.Medium, "sshd uses AuthorizedKeysCommand")
		f.Detail = "Authorized keys come from an external program. Confirm this is intended, since it is also a common place for a backdoor."
		f.Evidence = []string{cfg["authorizedkeyscommand"]}
		out = append(out, f)
	}
	if v := cfg["authorizedkeysfile"]; v != "" && v != ".ssh/authorized_keys .ssh/authorized_keys2" && v != ".ssh/authorized_keys" {
		f := finding("ssh.keys_file", cat, model.Medium, "sshd uses a non-default AuthorizedKeysFile")
		f.Evidence = []string{v}
		out = append(out, f)
	}
	if v := cfg["port"]; v != "" {
		f := finding("ssh.port", cat, model.Info, "sshd uses custom port: "+v)
		out = append(out, f)
	}

	var badKeys []string
	keys, _ := filepath.Glob("/etc/ssh/ssh_host_*_key")
	for _, k := range keys {
		if st, err := os.Stat(k); err == nil && st.Mode().Perm()&0o077 != 0 {
			badKeys = append(badKeys, fmt.Sprintf("%s  mode %o", k, st.Mode().Perm()))
		}
	}
	if len(badKeys) > 0 {
		f := finding("ssh.host_keys", cat, model.High, "SSH host keys have overly broad permissions")
		f.Evidence = badKeys
		f.Remediation = "chmod 600 /etc/ssh/ssh_host_*_key"
		out = append(out, f)
	}
	if _, err := os.Stat("/etc/ssh/sshrc"); err == nil {
		f := finding("ssh.sshrc", cat, model.High, "/etc/ssh/sshrc exists")
		f.Detail = "This script runs on every SSH login. Ubuntu does not ship this file by default."
		out = append(out, f)
	}
	return out
}

// parseAuthorizedKey handles "[options] type base64 [comment]". Options may
// contain quoted spaces, so the key type is located by name.
func parseAuthorizedKey(line string) (options, keyType, blob, comment string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	inQuote := false
	var fields []string
	start := 0
	for i, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			if i > start {
				fields = append(fields, line[start:i])
			}
			start = i + 1
		}
	}
	if start < len(line) {
		fields = append(fields, line[start:])
	}
	for i, tok := range fields {
		if isKeyType(tok) && i+1 < len(fields) {
			return strings.Join(fields[:i], " "), tok, fields[i+1], strings.Join(fields[i+2:], " "), true
		}
	}
	return
}

func isKeyType(s string) bool {
	return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-sha2-") || strings.HasPrefix(s, "sk-")
}

func fingerprint(blob string) string {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(blob); err != nil {
			return "invalid key"
		}
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func checkAuthorizedKeys(c *Context) []model.Finding {
	const cat = model.CatSSH
	if !c.Host.IsRoot {
		return []model.Finding{needRoot("ssh.keys", cat, "SSH authorized keys")}
	}
	min := uidMin()
	var out []model.Finding
	var inventory, forced, serviceKeys, badPerms, deprecated []string
	total := 0
	for _, u := range c.Homes() {
		for _, name := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2"} {
			p := filepath.Join(u.Home, name)
			st, err := os.Lstat(p)
			if err != nil {
				continue
			}
			if st.Mode()&os.ModeSymlink != 0 {
				target, _ := os.Readlink(p)
				badPerms = append(badPerms, p+" is a symlink to "+target)
				continue
			}
			if st.Mode().Perm()&0o022 != 0 {
				badPerms = append(badPerms, fmt.Sprintf("%s  mode %o", p, st.Mode().Perm()))
			}
			b, err := fsx.ReadNoFollow(p, 1<<20)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				opts, typ, blob, comment, ok := parseAuthorizedKey(line)
				if !ok {
					continue
				}
				total++
				entry := fmt.Sprintf("%s  %s  %s  %s", u.Name, typ, fingerprint(blob), comment)
				inventory = append(inventory, entry)
				if strings.Contains(opts, "command=") {
					forced = append(forced, entry+"  options: "+opts)
				}
				if typ == "ssh-dss" {
					deprecated = append(deprecated, entry)
				}
				if u.UID > 0 && u.UID < min {
					serviceKeys = append(serviceKeys, entry)
				}
			}
		}
		if _, err := os.Lstat(filepath.Join(u.Home, ".ssh/rc")); err == nil {
			f := finding("ssh.user_rc", cat, model.High, u.Name+" has ~/.ssh/rc")
			f.Detail = "This script runs on each of this user's SSH logins, which makes it a common persistence trick."
			f.Evidence = []string{filepath.Join(u.Home, ".ssh/rc")}
			out = append(out, f)
		}
	}
	summary := finding("ssh.keys", cat, model.Info, fmt.Sprintf("SSH authorized keys (%d)", total))
	summary.Detail = "Confirm you recognize every key listed. Adding one more key is the most common backdoor."
	summary.Evidence = inventory
	out = append(out, summary)
	if len(serviceKeys) > 0 {
		f := finding("ssh.service_keys", cat, model.High, "System accounts have SSH authorized keys")
		f.Detail = "For example /var/www/.ssh/authorized_keys, which often appears after a website is compromised."
		f.Evidence = serviceKeys
		out = append(out, f)
	}
	if len(forced) > 0 {
		f := finding("ssh.forced_command", cat, model.Medium, "Authorized keys use the command= option")
		f.Detail = "Often used to restrict backup accounts, but it can also run commands silently at login. Check the content."
		f.Evidence = forced
		out = append(out, f)
	}
	if len(deprecated) > 0 {
		f := finding("ssh.dsa_keys", cat, model.Medium, "Authorized keys use deprecated DSA")
		f.Evidence = deprecated
		out = append(out, f)
	}
	if len(badPerms) > 0 {
		f := finding("ssh.key_perms", cat, model.Medium, "authorized_keys has unsafe permissions")
		f.Evidence = badPerms
		f.Remediation = "Use chmod 600 and avoid symlinks."
		out = append(out, f)
	}
	return out
}
