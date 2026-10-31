package checks

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"ubuntu-sys-audit/internal/dpkg"
	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/procinfo"
)

// webInstance is one copy of nginx or PHP found on the host.
type webInstance struct {
	Name    string
	Version string
	Origin  string // ubuntu, ondrej-ppa, upstream-repo, third-party, compiled, container
	Where   string
}

// binaryVersion extracts a version from a binary by scanning its bytes. Running
// `nginx -v` as root would execute whatever sits at that path, which is exactly
// what a security scan must not do, so the file is only ever read. A chunk
// overlap keeps a match that straddles a buffer boundary intact.
func binaryVersion(path string, re *regexp.Regexp) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return ""
	}
	const chunk, overlap = 4 << 20, 128
	buf := make([]byte, chunk)
	carry := 0
	var total int64
	for total < 512<<20 {
		n, err := f.Read(buf[carry:])
		if n > 0 {
			total += int64(n)
			window := buf[:carry+n]
			if m := re.FindSubmatch(window); m != nil {
				return string(m[1])
			}
			if len(window) > overlap {
				copy(buf, window[len(window)-overlap:])
				carry = overlap
			} else {
				carry = len(window)
			}
		}
		if err != nil {
			if err != io.EOF {
				return ""
			}
			break
		}
	}
	return ""
}

var (
	nginxScan  = regexp.MustCompile(`(?:nginx version: (?:nginx|openresty)/|nginx/)(\d+\.\d+\.\d+)`)
	phpScan    = regexp.MustCompile(`X-Powered-By: PHP/(\d+\.\d+\.\d+)`)
	phpVerFall = regexp.MustCompile(`PHP/(\d+\.\d+\.\d+)`)
)

func upstreamOf(pkgVersion string) string {
	v := pkgVersion
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		v = v[:i]
	}
	if m := regexp.MustCompile(`^\d+\.\d+\.\d+`).FindString(v); m != "" {
		return m
	}
	return v
}

var nginxPackages = map[string]bool{"nginx": true, "nginx-core": true, "nginx-full": true, "nginx-light": true, "nginx-extras": true, "openresty": true}

var phpPackageRe = regexp.MustCompile(`^(php[0-9.]+-(fpm|cli|cgi)|libapache2-mod-php[0-9.]+)$`)

func collectInstances(c *Context, name string, isPkg func(string) bool, isProc func(*procinfo.Process) bool, paths []string, scan ...*regexp.Regexp) []webInstance {
	var out []webInstance
	if pkgs, err := c.Packages(); err == nil {
		for _, p := range pkgs {
			if isPkg(p.Name) {
				out = append(out, webInstance{Name: p.Name, Version: p.Version, Origin: dpkg.Origin(p.Version), Where: "apt 套件"})
			}
		}
	}
	readVersion := func(path string) string {
		for _, re := range scan {
			if v := binaryVersion(path, re); v != "" {
				return v
			}
		}
		return ""
	}
	seen := map[string]bool{}
	if procs, err := c.Procs(); err == nil {
		for _, p := range procs {
			if p.KernelTh || p.Exe == "" || !isProc(p) {
				continue
			}
			key := p.Exe + "|" + strconv.FormatBool(p.InContainer)
			if seen[key] {
				continue
			}
			seen[key] = true
			if !p.InContainer && c.Owned(p.Exe) {
				continue
			}
			// /proc/pid/exe opens the running binary directly, even when it
			// lives in a container's filesystem or has been deleted.
			v := readVersion("/proc/" + strconv.Itoa(p.PID) + "/exe")
			origin := "compiled"
			where := "執行中 pid " + strconv.Itoa(p.PID) + "，" + p.Exe
			if p.InContainer {
				origin = "container"
				where += "（容器內）"
			}
			out = append(out, webInstance{Name: name, Version: v, Origin: origin, Where: where})
		}
	}
	for _, pat := range paths {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			real, err := filepath.EvalSymlinks(m)
			if err != nil || seen[real+"|false"] || c.Owned(real) {
				continue
			}
			seen[real+"|false"] = true
			out = append(out, webInstance{Name: name, Version: readVersion(real), Origin: "compiled", Where: real})
		}
	}
	return out
}

func originLabel(o string) string {
	switch o {
	case "ubuntu":
		return "Ubuntu 套件"
	case "ondrej-ppa":
		return "ondrej PPA"
	case "upstream-repo":
		return "官方套件庫"
	case "third-party":
		return "第三方套件"
	case "compiled":
		return "自行編譯"
	case "container":
		return "容器"
	}
	return o
}

// parsedNginx is what the audit needs from an nginx configuration.
type parsedNginx struct {
	Roots        []string
	Includes     []string
	ServerTokens string
	Autoindex    bool
	WeakTLS      []string
}

// parseNginxTokens tokenizes one nginx configuration file. nginx has a simple
// grammar of directives ending in ';' and blocks in braces; quoting and
// comments are the only subtleties.
func parseNginxTokens(src string) *parsedNginx {
	p := &parsedNginx{}
	var tok strings.Builder
	var args []string
	flush := func() {
		if tok.Len() > 0 {
			args = append(args, tok.String())
			tok.Reset()
		}
	}
	var quote byte
	inComment := false
	for i := 0; i < len(src); i++ {
		ch := src[i]
		switch {
		case inComment:
			if ch == '\n' {
				inComment = false
			}
		case quote != 0:
			if ch == quote {
				quote = 0
			} else {
				tok.WriteByte(ch)
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '#' && tok.Len() == 0:
			inComment = true
		case ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r':
			flush()
		case ch == ';':
			flush()
			p.directive(args)
			args = nil
		case ch == '{' || ch == '}':
			flush()
			args = nil
		default:
			tok.WriteByte(ch)
		}
	}
	return p
}

func (p *parsedNginx) directive(args []string) {
	if len(args) < 2 {
		return
	}
	switch args[0] {
	case "root":
		p.Roots = append(p.Roots, args[1])
	case "include":
		p.Includes = append(p.Includes, args[1])
	case "server_tokens":
		p.ServerTokens = args[1]
	case "autoindex":
		if args[1] == "on" {
			p.Autoindex = true
		}
	case "ssl_protocols":
		for _, v := range args[1:] {
			if v == "TLSv1" || v == "TLSv1.1" || v == "SSLv3" || v == "SSLv2" {
				p.WeakTLS = append(p.WeakTLS, v)
			}
		}
	}
}

// loadNginxConfig follows include directives starting at one file.
func loadNginxConfig(path string) *parsedNginx {
	merged := &parsedNginx{}
	prefix := filepath.Dir(path)
	seen := map[string]bool{}
	var walk func(string, int)
	walk = func(p string, depth int) {
		if depth > 12 || seen[p] || len(seen) > 2000 {
			return
		}
		seen[p] = true
		b, err := fsx.Read(p, 4<<20)
		if err != nil {
			return
		}
		cfg := parseNginxTokens(string(b))
		merged.Roots = append(merged.Roots, cfg.Roots...)
		merged.WeakTLS = append(merged.WeakTLS, cfg.WeakTLS...)
		merged.Autoindex = merged.Autoindex || cfg.Autoindex
		if merged.ServerTokens == "" {
			merged.ServerTokens = cfg.ServerTokens
		}
		for _, inc := range cfg.Includes {
			if !filepath.IsAbs(inc) {
				inc = filepath.Join(prefix, inc)
			}
			matches, _ := filepath.Glob(inc)
			for _, m := range matches {
				walk(m, depth+1)
			}
		}
	}
	walk(path, 0)
	return merged
}

func nginxConfigPaths(c *Context) []string {
	var out []string
	if procs, err := c.Procs(); err == nil {
		for _, p := range procs {
			if p.Comm != "nginx" || p.InContainer {
				continue
			}
			for i, a := range p.Cmdline {
				if a == "-c" && i+1 < len(p.Cmdline) {
					out = append(out, p.Cmdline[i+1])
				}
			}
			fields := strings.Fields(p.CmdlineString())
			for i, a := range fields {
				if a == "-c" && i+1 < len(fields) {
					out = append(out, fields[i+1])
				}
			}
		}
	}
	out = append(out, "/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/usr/local/etc/nginx/nginx.conf", "/opt/nginx/conf/nginx.conf")
	return uniqueStrings(out)
}

func checkNginx(c *Context) []model.Finding {
	const cat = model.CatWeb
	instances := collectInstances(c, "nginx",
		func(n string) bool { return nginxPackages[n] },
		func(p *procinfo.Process) bool {
			return p.Comm == "nginx" || base(p.Exe) == "nginx" || base(p.Exe) == "openresty"
		},
		[]string{"/usr/local/nginx/sbin/nginx", "/usr/local/sbin/nginx", "/usr/local/bin/nginx", "/opt/nginx/sbin/nginx", "/opt/*/sbin/nginx", "/usr/local/openresty/nginx/sbin/nginx"},
		nginxScan)
	var out []model.Finding
	for _, i := range instances {
		c.AddInventory(model.InventoryItem{Name: i.Name, Version: i.Version, Source: i.Origin})
	}
	if len(instances) == 0 {
		return []model.Finding{finding("web.nginx", cat, model.OK, "沒有發現 nginx")}
	}
	var inv []string
	var external []webInstance
	for _, i := range instances {
		ver := i.Version
		if ver == "" {
			ver = "版本不明"
		}
		inv = append(inv, fmt.Sprintf("%s  %s  [%s]  %s", i.Name, ver, originLabel(i.Origin), i.Where))
		if i.Origin != "ubuntu" {
			external = append(external, i)
		}
	}
	summary := finding("web.nginx", cat, model.Info, fmt.Sprintf("發現 %d 份 nginx", len(instances)))
	summary.Evidence = inv
	summary.Focus = true
	summary.Detail = "Ubuntu 套件的漏洞由 CVE 類別依 USN 判斷。其他來源（自行編譯、官方套件庫、容器）的版本則比對 nginx.org 的公告。"
	out = append(out, summary)

	if len(external) > 0 {
		out = append(out, nginxUpstreamFindings(c, external)...)
	}
	out = append(out, nginxConfigFindings(c)...)
	return out
}

func nginxUpstreamFindings(c *Context, instances []webInstance) []model.Finding {
	const cat = model.CatWeb
	title := "nginx 官方公告比對"
	if c.Opts.Offline {
		return []model.Finding{skipped("web.nginx.upstream", cat, title, "離線模式，沒有比對 nginx.org 的公告。")}
	}
	var page []byte
	client := newHTTPClient(c.Opts.Proxy)
	err := fetch(c.Ctx, client, "https://nginx.org/en/security_advisories.html", 8<<20, func(r io.Reader) error {
		b, err := io.ReadAll(r)
		page = b
		return err
	})
	if err != nil {
		return []model.Finding{skipped("web.nginx.upstream", cat, title, "無法取得 nginx.org 公告："+err.Error())}
	}
	advisories := parseNginxAdvisories(string(page))
	if len(advisories) == 0 {
		return []model.Finding{skipped("web.nginx.upstream", cat, title, "nginx.org 頁面格式無法解析，沒有比對。")}
	}
	var out []model.Finding
	seen := map[string]bool{}
	for _, inst := range instances {
		ver := upstreamOf(inst.Version)
		if inst.Version == "" || !versionRe.MatchString(ver) {
			out = append(out, skipped("web.nginx.upstream", cat, inst.Name+"（"+inst.Where+"）", "無法從執行檔判斷版本。"))
			continue
		}
		key := ver + "|" + inst.Origin
		if seen[key] {
			continue
		}
		seen[key] = true
		worst := model.Info
		var ev []string
		for _, a := range advisories {
			if !a.Affects(ver) {
				continue
			}
			sev := nginxSeverity(a.Severity)
			if sev < worst {
				worst = sev
			}
			ev = append(ev, fmt.Sprintf("[%s] %s  %s  影響 %s，已修補 %s", a.Severity, a.Title, strings.Join(a.CVEs, " "), a.Vulnerable, a.NotVulnerable))
		}
		label := fmt.Sprintf("nginx %s（%s）", ver, originLabel(inst.Origin))
		if len(ev) == 0 {
			out = append(out, finding("web.nginx.upstream", cat, model.OK, label+"不受 nginx.org 已公告的漏洞影響"))
			continue
		}
		f := finding("web.nginx.upstream", cat, worst, fmt.Sprintf("%s受 %d 則 nginx.org 公告影響", label, len(ev)))
		f.Detail = "判斷依據是版本範圍。許多 nginx 漏洞只在啟用特定模組時才可利用（例如 HTTP/3），但版本落在範圍內就應該升級。這個來源不會收到 Ubuntu 的 USN 修補。"
		f.Evidence = ev
		f.Refs = []string{"https://nginx.org/en/security_advisories.html"}
		f.Remediation = "升級到 nginx.org 公告的修補版本。"
		f.Focus = true
		out = append(out, f)
	}
	return out
}

func nginxSeverity(s string) model.Severity {
	switch s {
	case "critical":
		return model.Critical
	case "high", "major":
		return model.High
	case "medium":
		return model.Medium
	}
	return model.Info
}

func nginxConfigFindings(c *Context) []model.Finding {
	const cat = model.CatWeb
	var out []model.Finding
	for _, path := range nginxConfigPaths(c) {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		cfg := loadNginxConfig(path)
		if len(cfg.WeakTLS) > 0 {
			// Ubuntu's stock nginx.conf lists these. From 20.04 on, OpenSSL's
			// default security level refuses them regardless, so on those
			// releases the line alone does not mean old TLS is reachable.
			sev := model.Info
			detail := "Ubuntu 預設的 nginx.conf 就是這樣寫。20.04 起 OpenSSL 的預設安全等級會拒絕這些協定，通常實際上連不上，但仍建議改掉。"
			if c.Host.Codename == "bionic" {
				sev = model.Medium
				detail = "18.04 的 OpenSSL 仍接受這些協定，所以舊版 TLS 確實可以連線。"
			}
			f := finding("web.nginx.tls", cat, sev, "nginx 設定列出舊版 TLS："+strings.Join(uniqueStrings(cfg.WeakTLS), ", "))
			f.Detail = detail
			f.Evidence = []string{path}
			f.Remediation = "設定 ssl_protocols TLSv1.2 TLSv1.3;"
			out = append(out, f)
		}
		if cfg.ServerTokens != "off" {
			f := finding("web.nginx.tokens", cat, model.Info, "nginx 會在回應中顯示版本號")
			f.Detail = "攻擊者掃描時能直接看到版本。這只是減少資訊外洩，不能取代修補。"
			f.Evidence = []string{path}
			f.Remediation = "在 http 區塊設定 server_tokens off;"
			out = append(out, f)
		}
		if cfg.Autoindex {
			f := finding("web.nginx.autoindex", cat, model.Medium, "nginx 啟用了目錄列表（autoindex on）")
			f.Evidence = []string{path}
			out = append(out, f)
		}
	}
	return out
}

func checkPHP(c *Context) []model.Finding {
	const cat = model.CatWeb
	instances := collectInstances(c, "php",
		phpPackageRe.MatchString,
		func(p *procinfo.Process) bool {
			b := base(p.Exe)
			return strings.HasPrefix(b, "php-fpm") || b == "php" || regexp.MustCompile(`^php\d`).MatchString(b)
		},
		[]string{"/usr/local/bin/php", "/usr/local/sbin/php-fpm", "/usr/local/php*/bin/php", "/usr/local/php*/sbin/php-fpm", "/opt/php*/bin/php", "/opt/php*/sbin/php-fpm"},
		phpScan, phpVerFall)
	for _, i := range instances {
		c.AddInventory(model.InventoryItem{Name: i.Name, Version: i.Version, Source: i.Origin})
	}
	if len(instances) == 0 {
		return []model.Finding{finding("web.php", cat, model.OK, "沒有發現 PHP")}
	}
	var out []model.Finding
	var inv []string
	var external []webInstance
	for _, i := range instances {
		ver := i.Version
		if ver == "" {
			ver = "版本不明"
		}
		inv = append(inv, fmt.Sprintf("%s  %s  [%s]  %s", i.Name, ver, originLabel(i.Origin), i.Where))
		if i.Origin != "ubuntu" {
			external = append(external, i)
		}
	}
	summary := finding("web.php", cat, model.Info, fmt.Sprintf("發現 %d 份 PHP", len(instances)))
	summary.Evidence = inv
	summary.Focus = true
	summary.Detail = "Ubuntu 套件的漏洞由 CVE 類別依 USN 判斷。其他來源則比對 php.net 目前維護的版本。"
	out = append(out, summary)
	if len(external) > 0 {
		out = append(out, phpUpstreamFindings(c, external)...)
	}
	return append(out, phpConfigFindings()...)
}

func phpUpstreamFindings(c *Context, instances []webInstance) []model.Finding {
	const cat = model.CatWeb
	title := "PHP 官方版本比對"
	if c.Opts.Offline {
		return []model.Finding{skipped("web.php.upstream", cat, title, "離線模式，沒有比對 php.net。")}
	}
	var data []byte
	client := newHTTPClient(c.Opts.Proxy)
	err := fetch(c.Ctx, client, "https://www.php.net/releases/active.php", 8<<20, func(r io.Reader) error {
		b, err := io.ReadAll(r)
		data = b
		return err
	})
	if err != nil {
		return []model.Finding{skipped("web.php.upstream", cat, title, "無法取得 php.net 資料："+err.Error())}
	}
	active, err := parsePHPActive(data)
	if err != nil {
		return []model.Finding{skipped("web.php.upstream", cat, title, "php.net 回應無法解析："+err.Error())}
	}
	var branches []string
	for b := range active {
		branches = append(branches, b)
	}
	sort.Strings(branches)
	var out []model.Finding
	seen := map[string]bool{}
	for _, inst := range instances {
		ver := upstreamOf(inst.Version)
		if inst.Version == "" || !versionRe.MatchString(ver) {
			out = append(out, skipped("web.php.upstream", cat, inst.Name+"（"+inst.Where+"）", "無法從執行檔判斷版本。"))
			continue
		}
		key := ver + "|" + inst.Origin
		if seen[key] {
			continue
		}
		seen[key] = true
		label := fmt.Sprintf("PHP %s（%s）", ver, originLabel(inst.Origin))
		status, rel := assessPHP(ver, active)
		switch status {
		case "":
			out = append(out, finding("web.php.upstream", cat, model.OK, label+"已是該分支最新版"))
		case "eol":
			sev := model.High
			detail := "這個分支已不在 php.net 的維護清單內（目前維護 " + strings.Join(branches, "、") + "），新的 PHP CVE 不會有官方修補。"
			if inst.Origin == "ondrej-ppa" {
				sev = model.Medium
				detail += " ondrej PPA 可能仍對舊分支提供 backport，版本號不一定代表未修補，但這不屬於官方支援。"
			}
			f := finding("web.php.upstream", cat, sev, label+"的分支已停止維護")
			f.Detail = detail
			f.Remediation = "升級到維護中的 PHP 分支。"
			f.Focus = true
			out = append(out, f)
		case "behind":
			sev := model.Medium
			for _, t := range rel.Tags {
				if t == "security" {
					sev = model.High
				}
			}
			f := finding("web.php.upstream", cat, sev, label+"落後該分支最新版 "+rel.Version)
			f.Detail = "這個來源不會收到 Ubuntu 的 USN 修補。"
			if sev == model.High {
				f.Detail += "最新版標記為安全性更新。"
			}
			f.Remediation = "升級到 " + rel.Version + "。"
			f.Refs = []string{"https://www.php.net/ChangeLog-8.php"}
			f.Focus = true
			out = append(out, f)
		}
	}
	return out
}

// parsePHPIni returns effective settings from ini text. Later values win, the
// same order PHP applies php.ini and then conf.d files.
func parsePHPIni(src string, into map[string]string) {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == ';' || line[0] == '[' || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if i := strings.IndexByte(v, ';'); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		into[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(v, `"'`)
	}
}

func iniTrue(v string) bool {
	switch strings.ToLower(v) {
	case "on", "1", "true", "yes":
		return true
	}
	return false
}

func phpConfigFindings() []model.Finding {
	const cat = model.CatWeb
	var out []model.Finding
	inis, _ := filepath.Glob("/etc/php/*/*/php.ini")
	for _, ini := range inis {
		sapi := base(filepath.Dir(ini))
		if sapi == "cli" {
			continue
		}
		settings := map[string]string{}
		if b, err := fsx.Read(ini, 1<<20); err == nil {
			parsePHPIni(string(b), settings)
		} else {
			continue
		}
		confs, _ := filepath.Glob(filepath.Join(filepath.Dir(ini), "conf.d", "*.ini"))
		sort.Strings(confs)
		for _, conf := range confs {
			if b, err := fsx.Read(conf, 1<<20); err == nil {
				parsePHPIni(string(b), settings)
			}
		}
		if iniTrue(settings["allow_url_include"]) {
			f := finding("web.php.url_include", cat, model.High, "PHP 啟用 allow_url_include："+ini)
			f.Detail = "LFI 漏洞會因此直接變成遠端程式碼執行。"
			f.Remediation = "設定 allow_url_include = Off"
			out = append(out, f)
		}
		if iniTrue(settings["display_errors"]) {
			f := finding("web.php.display_errors", cat, model.Medium, "PHP 啟用 display_errors："+ini)
			f.Detail = "錯誤訊息可能洩漏路徑、SQL 與設定。"
			f.Remediation = "設定 display_errors = Off"
			out = append(out, f)
		}
		if v, ok := settings["expose_php"]; !ok || iniTrue(v) {
			f := finding("web.php.expose", cat, model.Info, "PHP 會在回應中顯示版本號："+ini)
			f.Remediation = "設定 expose_php = Off"
			out = append(out, f)
		}
		if strings.TrimSpace(settings["disable_functions"]) == "" {
			f := finding("web.php.disable_functions", cat, model.Info, "PHP 未限制危險函式："+ini)
			f.Detail = "disable_functions 是空的，webshell 可以直接呼叫 system、exec 等函式。"
			f.Remediation = "若應用程式不需要，就加入 disable_functions = exec,passthru,shell_exec,system,proc_open,popen"
			out = append(out, f)
		}
	}
	return out
}

type shellRule struct {
	re   *regexp.Regexp
	sev  model.Severity
	name string
}

// Each rule targets behaviour that essentially never appears in application
// code: directly executing request input, or layered decoding fed into eval.
var shellRules = []shellRule{
	{regexp.MustCompile(`(?i)\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*@?\s*(?:(?:base64_decode|gzinflate|str_rot13|stripslashes)\s*\(\s*)*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b`), model.Critical, "直接執行 HTTP 請求內容"},
	{regexp.MustCompile(`(?i)\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{0,64}\]\s*\(`), model.Critical, "把 HTTP 參數當成函式呼叫"},
	{regexp.MustCompile(`(?i)\b(c99shell|r57shell|wso\s*shell|FilesMan|b374k|IndoXploit|phpspy|weevely)\b`), model.Critical, "已知 webshell 名稱"},
	{regexp.MustCompile(`e45e329feb5d925b`), model.Critical, "Behinder（冰蠍）預設金鑰"},
	{regexp.MustCompile(`3c6e0b8a9c15224a`), model.Critical, "Godzilla（哥斯拉）預設金鑰"},
	{regexp.MustCompile(`(?i)\beval\s*\(\s*(gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode|strrev|rawurldecode|hex2bin)\s*\(`), model.High, "混淆程式碼交給 eval"},
	{regexp.MustCompile(`(?i)\bpreg_replace\s*\(\s*['"].*?/[a-z]*e[a-z]*['"]\s*,`), model.High, "preg_replace /e 程式碼執行"},
	{regexp.MustCompile(`(?i)\bcreate_function\s*\(.*\$_(GET|POST|REQUEST|COOKIE)`), model.High, "create_function 搭配請求內容"},
	{regexp.MustCompile(`(?i)\b(fsockopen|pfsockopen)\b.*(/bin/(ba)?sh)`), model.High, "PHP reverse shell"},
}

func matchWebshell(src []byte) (model.Severity, string) {
	for _, r := range shellRules {
		if r.re.Match(src) {
			return r.sev, r.name
		}
	}
	return model.Info, ""
}

var phpExtRe = regexp.MustCompile(`(?i)\.(php[0-9]?|phtml|phar|pht|phps|inc)$`)
var doubleExtRe = regexp.MustCompile(`(?i)\.(php[0-9]?|phtml|phar)\.[a-z0-9]+$`)
var uploadDirRe = regexp.MustCompile(`(?i)/(uploads?|attachments?|avatars?)/`)

// Source trees use these directory names for code about uploads, which is not
// the same as a directory users upload into.
var codeDirRe = regexp.MustCompile(`(?i)/(vendor|plugins?|themes?|modules?|src|app|lib|libs|includes?|core|admin|classes|controllers?|components?)/`)

// isUploadedPHP reports a PHP file sitting in an upload directory. WordPress and
// others place a tiny index.php there to stop directory listing, so that is exempt.
func isUploadedPHP(path string, size int64) bool {
	if !uploadDirRe.MatchString(path) || codeDirRe.MatchString(path) {
		return false
	}
	name := strings.ToLower(filepath.Base(path))
	if strings.HasSuffix(name, ".inc") {
		return false
	}
	return !(name == "index.php" && size < 256)
}

func webRoots(c *Context) []string {
	roots := []string{"/var/www", "/srv/www", "/srv/http", "/usr/share/nginx/html", "/usr/local/nginx/html"}
	for _, path := range nginxConfigPaths(c) {
		if _, err := os.Stat(path); err == nil {
			roots = append(roots, loadNginxConfig(path).Roots...)
		}
	}
	apache, _ := filepath.Glob("/etc/apache2/sites-enabled/*")
	docRoot := regexp.MustCompile(`(?im)^\s*DocumentRoot\s+"?([^"\s]+)`)
	for _, conf := range apache {
		if b, err := fsx.Read(conf, 1<<20); err == nil {
			for _, m := range docRoot.FindAllStringSubmatch(string(b), -1) {
				roots = append(roots, m[1])
			}
		}
	}
	// Nested roots such as /var/www and /var/www/app would scan files twice.
	unique := uniqueStrings(roots)
	var out []string
	for _, r := range unique {
		r = filepath.Clean(r)
		if !filepath.IsAbs(r) || r == "/" || strings.ContainsAny(r, "$") {
			continue
		}
		nested := false
		for _, other := range out {
			if strings.HasPrefix(r, other+"/") || r == other {
				nested = true
			}
		}
		if st, err := os.Stat(r); !nested && err == nil && st.IsDir() {
			out = append(out, r)
		}
	}
	return out
}

func checkWebshells(c *Context) []model.Finding {
	const cat = model.CatWeb
	roots := webRoots(c)
	if len(roots) == 0 {
		return []model.Finding{finding("web.shell", cat, model.OK, "沒有發現網站根目錄")}
	}
	var critical, high, uploads, double, recent []string
	files := 0
	incomplete := false
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if c.Ctx.Err() != nil {
				incomplete = true
				return filepath.SkipAll
			}
			if d.IsDir() {
				if n := d.Name(); n == ".git" || n == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			name := d.Name()
			isPHP := phpExtRe.MatchString(name)
			if !isPHP {
				if doubleExtRe.MatchString(name) {
					double = append(double, path)
				}
				return nil
			}
			files++
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.ModTime().After(cutoff) {
				recent = append(recent, fmt.Sprintf("%s  %s", path, info.ModTime().Format("2006-01-02 15:04")))
			}
			if isUploadedPHP(path, info.Size()) {
				uploads = append(uploads, path)
			}
			if name == "eval-stdin.php" {
				high = append(high, path+"（PHPUnit CVE-2017-9841，可遠端執行程式碼）")
			}
			if info.Size() > 4<<20 {
				return nil
			}
			b, err := fsx.ReadNoFollow(path, 4<<20)
			if err != nil {
				return nil
			}
			sev, rule := matchWebshell(b)
			switch {
			case rule == "":
			case sev == model.Critical:
				critical = append(critical, path+"（"+rule+"）")
			default:
				high = append(high, path+"（"+rule+"）")
			}
			return nil
		})
	}
	var out []model.Finding
	add := func(id string, sev model.Severity, title, detail, fix string, ev []string) {
		if len(ev) == 0 {
			return
		}
		sort.Strings(ev)
		f := finding("web.shell."+id, cat, sev, fmt.Sprintf(title, len(ev)))
		f.Detail, f.Remediation, f.Evidence = detail, fix, ev
		f.Focus = sev <= model.High
		out = append(out, f)
	}
	keep := "先備份檔案與存取紀錄當證據，再移除，並找出上傳途徑。"
	add("critical", model.Critical, "%d 個 PHP 檔案符合 webshell 特徵", "這些特徵幾乎不會出現在正常程式碼中。", keep, critical)
	add("high", model.High, "%d 個 PHP 檔案含可疑程式碼", "商業軟體的授權保護偶爾也會這樣寫，請逐一確認。", keep, high)
	add("uploads", model.High, "上傳目錄內有 %d 個 PHP 檔案", "上傳目錄不該有可執行的 PHP，這是檔案上傳漏洞被利用後的典型痕跡。", "移除檔案，並在 nginx 禁止該目錄執行 PHP。", uploads)
	add("double_ext", model.Medium, "%d 個雙副檔名檔案（如 x.php.jpg）", "這是繞過上傳檢查的常見手法。", "檢查內容。", double)
	add("recent", model.Info, "最近 7 天內有 %d 個 PHP 檔案被修改", "如果最近沒有部署，這份清單就值得看一下。", "", recent)
	if len(critical)+len(high)+len(uploads) == 0 {
		out = append(out, finding("web.shell", cat, model.OK, fmt.Sprintf("已掃描 %d 個 PHP 檔案，沒有 webshell 特徵", files)))
	}
	if incomplete {
		out = append(out, skipped("web.shell.partial", cat, "Webshell 掃描未完成", fmt.Sprintf("達到時間上限，只掃描了 %d 個檔案。", files)))
	}
	f := finding("web.shell.roots", cat, model.Info, "已掃描的網站根目錄")
	f.Evidence = roots
	f.Detail = "特徵比對能抓到常見的 webshell，抓不到經過客製或混淆的版本。"
	return append(out, f)
}
