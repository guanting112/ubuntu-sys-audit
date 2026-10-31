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
		return []model.Finding{finding("ssh.config", cat, model.Info, "未安裝 OpenSSH server（找不到 sshd_config）")}
	}
	cfg := map[string]string{}
	stop := false
	parseSSHDConfig("/etc/ssh/sshd_config", 0, cfg, &stop)
	if len(cfg) == 0 && !c.Host.IsRoot {
		return []model.Finding{needRoot("ssh.config", cat, "sshd 設定")}
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
		add("root_login", model.High, "允許 root 用密碼登入 SSH", "PermitRootLogin yes。", "改成 PermitRootLogin no 或 prohibit-password，再重新載入 sshd。")
	case "without-password", "prohibit-password", "forced-commands-only":
		add("root_login", model.Info, "root 僅可用金鑰登入 SSH", "", "若不需要 root 直接登入，可改為 PermitRootLogin no。")
	default:
		add("root_login", model.OK, "已禁止 root 登入 SSH", "", "")
	}
	if get("permitemptypasswords", "no") == "yes" {
		add("empty_passwords", model.Critical, "sshd 允許空白密碼登入", "PermitEmptyPasswords yes。", "改為 no 並重新載入 sshd。")
	}
	if get("passwordauthentication", "yes") == "yes" {
		add("password_auth", model.Medium, "SSH 允許密碼登入", "未明確關閉時預設就是允許，容易遭到暴力嘗試。", "確認金鑰可用後設定 PasswordAuthentication no。")
	} else {
		add("password_auth", model.OK, "SSH 已關閉密碼登入", "", "")
	}
	if get("permituserenvironment", "no") != "no" {
		add("user_env", model.Medium, "sshd 允許使用者設定環境變數", "攻擊者可藉此注入 LD_PRELOAD 繞過限制。", "設定 PermitUserEnvironment no。")
	}
	if v := get("authorizedkeyscommand", "none"); v != "none" {
		f := finding("ssh.keys_command", cat, model.Medium, "sshd 設定了 AuthorizedKeysCommand")
		f.Detail = "授權金鑰來自外部程式。請確認這是預期設定，它也是常見的後門位置。"
		f.Evidence = []string{cfg["authorizedkeyscommand"]}
		out = append(out, f)
	}
	if v := cfg["authorizedkeysfile"]; v != "" && v != ".ssh/authorized_keys .ssh/authorized_keys2" && v != ".ssh/authorized_keys" {
		f := finding("ssh.keys_file", cat, model.Medium, "sshd 使用非預設的 AuthorizedKeysFile")
		f.Evidence = []string{v}
		out = append(out, f)
	}
	if v := cfg["port"]; v != "" {
		f := finding("ssh.port", cat, model.Info, "sshd 使用自訂 Port："+v)
		out = append(out, f)
	}

	var badKeys []string
	keys, _ := filepath.Glob("/etc/ssh/ssh_host_*_key")
	for _, k := range keys {
		if st, err := os.Stat(k); err == nil && st.Mode().Perm()&0o077 != 0 {
			badKeys = append(badKeys, fmt.Sprintf("%s  權限 %o", k, st.Mode().Perm()))
		}
	}
	if len(badKeys) > 0 {
		f := finding("ssh.host_keys", cat, model.High, "SSH host key 權限過寬")
		f.Evidence = badKeys
		f.Remediation = "chmod 600 /etc/ssh/ssh_host_*_key"
		out = append(out, f)
	}
	if _, err := os.Stat("/etc/ssh/sshrc"); err == nil {
		f := finding("ssh.sshrc", cat, model.High, "存在 /etc/ssh/sshrc")
		f.Detail = "每次 SSH 登入都會執行此腳本。Ubuntu 預設沒有這個檔案。"
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
			return "無效金鑰"
		}
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func checkAuthorizedKeys(c *Context) []model.Finding {
	const cat = model.CatSSH
	if !c.Host.IsRoot {
		return []model.Finding{needRoot("ssh.keys", cat, "SSH 授權金鑰")}
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
				badPerms = append(badPerms, p+" 是 symlink，指向 "+target)
				continue
			}
			if st.Mode().Perm()&0o022 != 0 {
				badPerms = append(badPerms, fmt.Sprintf("%s  權限 %o", p, st.Mode().Perm()))
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
					forced = append(forced, entry+"  選項："+opts)
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
			f := finding("ssh.user_rc", cat, model.High, u.Name+" 有 ~/.ssh/rc")
			f.Detail = "該使用者每次 SSH 登入都會執行此腳本，常被用來持久化。"
			f.Evidence = []string{filepath.Join(u.Home, ".ssh/rc")}
			out = append(out, f)
		}
	}
	summary := finding("ssh.keys", cat, model.Info, fmt.Sprintf("共 %d 把 SSH 授權金鑰", total))
	summary.Detail = "請逐一確認清單內都是認得的金鑰。攻擊者最常見的後門就是多塞一把。"
	summary.Evidence = inventory
	out = append(out, summary)
	if len(serviceKeys) > 0 {
		f := finding("ssh.service_keys", cat, model.High, "系統帳號有 SSH 授權金鑰")
		f.Detail = "例如 /var/www/.ssh/authorized_keys，常見於網站被入侵之後。"
		f.Evidence = serviceKeys
		out = append(out, f)
	}
	if len(forced) > 0 {
		f := finding("ssh.forced_command", cat, model.Medium, "授權金鑰帶有 command= 選項")
		f.Detail = "常用於限制備份帳號，也可能用來在登入時偷偷執行指令。請確認內容。"
		f.Evidence = forced
		out = append(out, f)
	}
	if len(deprecated) > 0 {
		f := finding("ssh.dsa_keys", cat, model.Medium, "授權金鑰使用已淘汰的 DSA")
		f.Evidence = deprecated
		out = append(out, f)
	}
	if len(badPerms) > 0 {
		f := finding("ssh.key_perms", cat, model.Medium, "authorized_keys 權限異常")
		f.Evidence = badPerms
		f.Remediation = "chmod 600，且不要用 symlink。"
		out = append(out, f)
	}
	return out
}
