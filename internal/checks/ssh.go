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

// sshdTokens splits a config line the way sshd does: the keyword ends at
// whitespace or "=", one "=" may separate it from the arguments, double quotes
// group, and an unquoted # starts a comment. Reading these any other way makes
// PermitRootLogin = yes look unset, which would report a risky host as safe.
func sshdTokens(line string) (key string, args []string) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return "", nil
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), nil
	}
	key = strings.ToLower(line[:i])
	rest := strings.TrimLeft(line[i:], " \t")
	rest = strings.TrimLeft(strings.TrimPrefix(rest, "="), " \t")
	var cur strings.Builder
	inQuote, have := false, false
	flush := func() {
		if have {
			args = append(args, cur.String())
			cur.Reset()
			have = false
		}
	}
	for _, r := range rest {
		switch {
		case r == '"':
			inQuote = !inQuote
			have = true
		case inQuote:
			cur.WriteRune(r)
		case r == ' ' || r == '\t':
			flush()
		case r == '#' && !have:
			flush()
			return key, args
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	flush()
	return key, args
}

// sshdConfig holds the settings parsed from sshd_config and its includes.
type sshdConfig struct {
	global   map[string]string
	matchAll map[string]string
	// risky lists settings in conditional Match blocks that loosen access for
	// some connections. Whether they apply cannot be known here.
	risky []string
	// section is the Match block being read: "" for global, "all" for Match all,
	// otherwise the condition.
	section string
}

func newSSHDConfig() *sshdConfig {
	return &sshdConfig{global: map[string]string{}, matchAll: map[string]string{}}
}

// parseFile reads one config file. sshd keeps the first value it sees for a
// keyword. A Match block in an included file ends with that file, so reaching one
// there must not stop the file that included it.
func (cfg *sshdConfig) parseFile(path string, depth int) {
	if depth > 8 {
		return
	}
	b, err := fsx.Read(path, 1<<20)
	if err != nil {
		return
	}
	saved := cfg.section
	defer func() {
		if depth > 0 {
			cfg.section = saved
		}
	}()
	for _, line := range strings.Split(string(b), "\n") {
		key, args := sshdTokens(line)
		switch key {
		case "":
		case "match":
			cfg.section = strings.Join(args, " ")
			if strings.EqualFold(cfg.section, "all") {
				cfg.section = "all"
			}
		case "include":
			for _, pat := range args {
				if !filepath.IsAbs(pat) {
					pat = filepath.Join("/etc/ssh", pat)
				}
				matches, _ := filepath.Glob(pat)
				for _, m := range matches {
					cfg.parseFile(m, depth+1)
				}
			}
		default:
			cfg.set(key, strings.Join(args, " "))
		}
	}
}

func (cfg *sshdConfig) set(key, value string) {
	target := cfg.global
	switch cfg.section {
	case "":
	case "all":
		target = cfg.matchAll
	default:
		v := strings.ToLower(value)
		if (key == "permitrootlogin" || key == "passwordauthentication" || key == "permitemptypasswords") && v == "yes" {
			cfg.risky = append(cfg.risky, "Match "+cfg.section+": "+key+" "+value)
		}
		return
	}
	if _, exists := target[key]; !exists {
		target[key] = value
	}
}

// raw returns the effective value. Match all applies to every connection and
// overrides the global section.
func (cfg *sshdConfig) raw(key string) (string, bool) {
	if v, ok := cfg.matchAll[key]; ok {
		return v, true
	}
	v, ok := cfg.global[key]
	return v, ok
}

func (cfg *sshdConfig) get(key, def string) string {
	if v, ok := cfg.raw(key); ok {
		return strings.ToLower(v)
	}
	return def
}

func checkSSHConfig(c *Context) []model.Finding {
	const cat = model.CatSSH
	if _, err := os.Stat("/etc/ssh/sshd_config"); err != nil {
		return []model.Finding{finding("ssh.config", cat, model.Info, "OpenSSH server is not installed (no sshd_config)")}
	}
	cfg := newSSHDConfig()
	cfg.parseFile("/etc/ssh/sshd_config", 0)
	if len(cfg.global)+len(cfg.matchAll) == 0 && !c.Host.IsRoot {
		return []model.Finding{needRoot("ssh.config", cat, "sshd configuration")}
	}
	get := cfg.get
	var out []model.Finding
	add := func(id string, sev model.Severity, title, detail, fix string) {
		f := finding("ssh."+id, cat, sev, title)
		f.Detail, f.Remediation = detail, fix
		out = append(out, f)
	}
	// Each check passes only on a value known to be safe, so a setting this code
	// misreads shows up as a finding instead of a pass.
	switch v := get("permitrootlogin", "prohibit-password"); v {
	case "no":
		add("root_login", model.OK, "Root login over SSH is disabled", "", "")
	case "without-password", "prohibit-password", "forced-commands-only":
		add("root_login", model.Info, "Root can log in over SSH with keys only", "", "If direct root login is not needed, set PermitRootLogin no.")
	case "yes":
		add("root_login", model.High, "Root can log in over SSH with a password", "PermitRootLogin yes.", "Set PermitRootLogin to no or prohibit-password, then reload sshd.")
	default:
		add("root_login", model.Medium, "PermitRootLogin has an unrecognized value: "+v, "", "Set PermitRootLogin to no or prohibit-password, then reload sshd.")
	}
	if get("permitemptypasswords", "no") != "no" {
		add("empty_passwords", model.Critical, "sshd allows empty passwords", "PermitEmptyPasswords yes.", "Set it to no and reload sshd.")
	}
	passwordOff := get("passwordauthentication", "yes") == "no"
	// With PAM, keyboard-interactive prompts for the same password.
	kbd := get("kbdinteractiveauthentication", get("challengeresponseauthentication", "yes"))
	kbdOff := kbd == "no" || get("usepam", "no") != "yes"
	switch {
	case !passwordOff:
		add("password_auth", model.Medium, "SSH allows password login", "This is the default unless explicitly disabled, and it invites brute force attempts.", "Once keys work, set PasswordAuthentication no.")
	case !kbdOff:
		add("password_auth", model.Medium, "SSH allows password login through keyboard-interactive", "PasswordAuthentication is off, but keyboard-interactive with PAM still prompts for the password.", "Set KbdInteractiveAuthentication no.")
	default:
		add("password_auth", model.OK, "SSH password login is disabled", "", "")
	}
	if len(cfg.risky) > 0 {
		f := finding("ssh.match_override", cat, model.Medium, fmt.Sprintf("Match blocks loosen SSH access for some connections (%d)", len(cfg.risky)))
		f.Detail = "These settings apply only to connections matching the condition, so the results above may not hold for them."
		f.Evidence = cfg.risky
		out = append(out, f)
	}
	if get("permituserenvironment", "no") != "no" {
		add("user_env", model.Medium, "sshd lets users set environment variables", "An attacker can use this to inject LD_PRELOAD and bypass restrictions.", "Set PermitUserEnvironment no.")
	}
	if v, ok := cfg.raw("authorizedkeyscommand"); ok && !strings.EqualFold(v, "none") {
		f := finding("ssh.keys_command", cat, model.Medium, "sshd uses AuthorizedKeysCommand")
		f.Detail = "Authorized keys come from an external program. Confirm this is intended, since it is also a common place for a backdoor."
		f.Evidence = []string{v}
		out = append(out, f)
	}
	if v, _ := cfg.raw("authorizedkeysfile"); v != "" && v != ".ssh/authorized_keys .ssh/authorized_keys2" && v != ".ssh/authorized_keys" {
		f := finding("ssh.keys_file", cat, model.Medium, "sshd uses a non-default AuthorizedKeysFile")
		f.Evidence = []string{v}
		out = append(out, f)
	}
	if v, _ := cfg.raw("port"); v != "" {
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
	var ends []int
	start := 0
	for i, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			if i > start {
				fields = append(fields, line[start:i])
				ends = append(ends, i)
			}
			start = i + 1
		}
	}
	if start < len(line) {
		fields = append(fields, line[start:])
		ends = append(ends, len(line))
	}
	for i, tok := range fields {
		if !isKeyType(tok) || strings.ContainsAny(tok, " \t") {
			continue
		}
		// Quotes only group options. sshd splits the key and comment on
		// whitespace alone, so a quote there cannot pull spaces into the key.
		if rest := strings.Fields(line[ends[i]:]); len(rest) > 0 {
			return strings.Join(fields[:i], " "), tok, rest[0], strings.Join(rest[1:], " "), true
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
	const keysLimit = 1 << 20
	var inventory, forced, serviceKeys, badPerms, deprecated, tooLarge []string
	total := 0
	for _, u := range c.Homes() {
		if st, err := os.Lstat(filepath.Join(u.Home, ".ssh")); err == nil && st.Mode()&os.ModeSymlink != 0 {
			target, _ := os.Readlink(filepath.Join(u.Home, ".ssh"))
			badPerms = append(badPerms, filepath.Join(u.Home, ".ssh")+" is a symlink to "+target)
			continue
		}
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
			b, err := fsx.ReadUnder(u.Home, name, keysLimit)
			if err != nil {
				continue
			}
			if len(b) >= keysLimit {
				tooLarge = append(tooLarge, p)
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
	if len(tooLarge) > 0 {
		f := finding("ssh.keys_truncated", cat, model.Medium, fmt.Sprintf("authorized_keys files too large to read completely (%d)", len(tooLarge)))
		f.Detail = "Only the first 1 MiB was read. sshd reads the whole file, so padding can hide a key from this check."
		f.Evidence = tooLarge
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
