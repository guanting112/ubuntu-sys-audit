package checks

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"ubuntu-sys-audit/internal/dpkg"
	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/oval"
)

func loadFeed(c *Context) (*oval.Feed, error) {
	if path := c.Opts.OVALFile; path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return oval.Parse(f, strings.HasSuffix(path, ".bz2"))
	}
	var feed *oval.Feed
	client := newHTTPClient(c.Opts.Proxy)
	err := fetch(c.Ctx, client, oval.FeedURL(c.Host.Codename), 128<<20, func(r io.Reader) error {
		parsed, err := oval.Parse(r, true)
		if err != nil {
			return err
		}
		feed = parsed
		return nil
	})
	return feed, err
}

func priorityRank(p string) model.Severity {
	switch strings.ToLower(p) {
	case "critical":
		return model.Critical
	case "high":
		return model.High
	case "medium":
		return model.Medium
	}
	return model.Info
}

var focusSources = regexp.MustCompile(`^(linux.*|nginx|php.*|openssl.*|openssh|sudo|glibc|apache2|xz-utils|bash|curl|policykit-1|polkit|systemd|libapache2-mod.*)$`)

type sourceGroup struct {
	source   string
	kernel   bool
	hits     []oval.Hit
	binaries map[string]*oval.PkgHit
	worst    model.Severity
	cves     map[string]bool
	proOnly  bool
}

func groupHits(hits []oval.Hit) []*sourceGroup {
	groups := map[string]*sourceGroup{}
	for _, h := range hits {
		sources := map[string]bool{}
		for _, p := range h.Packages {
			src := p.Source
			if src == "" {
				src = p.Binary
			}
			g := groups[src]
			if g == nil {
				g = &sourceGroup{source: src, binaries: map[string]*oval.PkgHit{}, worst: model.Info, cves: map[string]bool{}, proOnly: true}
				groups[src] = g
			}
			if p.Kernel {
				g.kernel = true
			}
			pc := p
			if prev, ok := g.binaries[p.Binary]; !ok || dpkg.Compare(prev.Fixed, p.Fixed) < 0 {
				g.binaries[p.Binary] = &pc
			}
			if !p.RequiresPro() {
				g.proOnly = false
			}
			if !sources[src] {
				sources[src] = true
				g.hits = append(g.hits, h)
				if s := priorityRank(h.Severity); s < g.worst {
					g.worst = s
				}
				for _, cve := range h.CVEs {
					g.cves[cve.ID] = true
					if s := priorityRank(cve.Priority); s < g.worst {
						g.worst = s
					}
				}
			}
		}
	}
	out := make([]*sourceGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].worst != out[j].worst {
			return out[i].worst < out[j].worst
		}
		return out[i].source < out[j].source
	})
	return out
}

func describeHit(h oval.Hit) string {
	date := h.Issued
	if len(date) >= 10 {
		date = date[:10]
	}
	sev := h.Severity
	if sev == "" || sev == "none" {
		sev = "-"
	}
	title := h.Title
	if i := strings.Index(title, " -- "); i >= 0 {
		title = title[i+4:]
	}
	line := fmt.Sprintf("%s  %s  [%s]  %s", h.USN, date, sev, title)
	if len(h.CVEs) > 0 {
		ids := make([]string, 0, 6)
		sorted := append([]oval.CVE(nil), h.CVEs...)
		sort.SliceStable(sorted, func(i, j int) bool {
			return priorityRank(sorted[i].Priority) < priorityRank(sorted[j].Priority)
		})
		for i, cve := range sorted {
			if i == 6 {
				ids = append(ids, fmt.Sprintf("…等 %d 個", len(sorted)))
				break
			}
			ids = append(ids, cve.ID)
		}
		line += "  " + strings.Join(ids, " ")
	}
	return line
}

func checkCVE(c *Context) []model.Finding {
	const cat = model.CatCVE
	title := "CVE 比對（Ubuntu USN）"
	if _, known := releases[c.Host.Codename]; !known && c.Opts.OVALFile == "" {
		return []model.Finding{skipped("cve.usn", cat, title, "沒有這個發行版（"+c.Host.Codename+"）的 OVAL 資料。")}
	}
	if c.Opts.Offline && c.Opts.OVALFile == "" {
		f := skipped("cve.usn", cat, title, "離線模式且沒有指定 --oval-file，所以沒有比對 CVE。")
		f.Remediation = "在有網路的機器下載 " + oval.FeedURL(c.Host.Codename) + "，再用 --oval-file 指定。"
		return []model.Finding{f}
	}
	if _, err := c.Packages(); err != nil {
		return []model.Finding{skipped("cve.usn", cat, title, "無法讀取 dpkg 資料庫："+err.Error())}
	}
	feed, err := loadFeed(c)
	if err != nil {
		f := skipped("cve.usn", cat, title, "無法取得 OVAL 資料："+err.Error())
		f.Remediation = "確認主機可連線 security-metadata.canonical.com、使用 --proxy，或下載後用 --oval-file 指定。"
		return []model.Finding{f}
	}
	var out []model.Finding
	if ts, err := time.Parse("2006-01-02T15:04:05", feed.Timestamp); err == nil && time.Since(ts) > 14*24*time.Hour {
		f := finding("cve.feed_stale", cat, model.Medium, fmt.Sprintf("OVAL 資料已是 %d 天前的版本", int(time.Since(ts).Hours()/24)))
		f.Detail = "資料日期是 " + feed.Timestamp + "，之後公告的漏洞不在比對範圍內。"
		f.Remediation = "下載最新的 OVAL 檔案。"
		out = append(out, f)
	}
	hits := feed.Evaluate(c.PackageVersions(), c.Host.Kernel)
	if len(hits) == 0 {
		f := finding("cve.usn", cat, model.OK, fmt.Sprintf("已比對 %d 則 USN，沒有未套用的修補", feed.DefinitionCount()))
		f.Detail = "資料日期 " + feed.Timestamp + "。USN 只涵蓋 Ubuntu 已發布修補的漏洞與 apt 安裝的套件；自行編譯或第三方來源請看 Web 類別。"
		return append(out, f)
	}

	groups := groupHits(hits)
	counts := map[model.Severity]int{}
	allCVEs := map[string]bool{}
	for _, g := range groups {
		counts[g.worst]++
		for id := range g.cves {
			allCVEs[id] = true
		}
	}
	overview := finding("cve.overview", cat, model.Info,
		fmt.Sprintf("%d 個套件有未套用的修補：%d 則 USN、%d 個 CVE", len(groups), len(hits), len(allCVEs)))
	overview.Detail = fmt.Sprintf("OVAL 資料日期 %s，共比對 %d 則 USN。嚴重度取該套件所有 USN 與 CVE 的最高值。", feed.Timestamp, feed.DefinitionCount())
	overview.Evidence = []string{
		fmt.Sprintf("嚴重 %d 個套件，高 %d 個，中 %d 個，資訊 %d 個", counts[model.Critical], counts[model.High], counts[model.Medium], counts[model.Info]),
	}
	overview.Focus = true
	out = append(out, overview)

	pro := esmEnabled()
	for _, g := range groups {
		f := finding("cve.pkg."+g.source, cat, g.worst, fmt.Sprintf("%s：%d 則安全公告未修補，涉及 %d 個 CVE", g.source, len(g.hits), len(g.cves)))
		f.Focus = focusSources.MatchString(g.source)

		var names []string
		for name := range g.binaries {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			p := g.binaries[name]
			f.Evidence = append(f.Evidence, fmt.Sprintf("%s  已安裝 %s，修補版本 %s", p.Binary, p.Installed, p.Fixed))
		}
		for _, h := range g.hits {
			f.Evidence = append(f.Evidence, describeHit(h))
			if len(f.Refs) < 5 {
				f.Refs = append(f.Refs, "https://ubuntu.com/security/notices/"+h.USN)
			}
		}
		switch {
		case g.kernel:
			f.Detail = "比對的是執行中的 kernel。就算已經安裝新 kernel，重開機之前仍然受影響。"
			f.Remediation = "sudo apt update && sudo apt full-upgrade，然後重新開機。"
		case g.proOnly && !pro:
			f.Detail = "修補只透過 Ubuntu Pro（ESM）提供，這台主機尚未啟用。"
			f.Remediation = "sudo pro attach <token>，再執行 sudo pro fix " + g.hits[0].USN
		default:
			f.Remediation = "sudo apt update && sudo apt install --only-upgrade " + strings.Join(names, " ")
			if !pro {
				for _, name := range names {
					if g.binaries[name].RequiresPro() {
						f.Detail = "apt 能修補其中一部分，較新的修補只透過 Ubuntu Pro（ESM）提供，這台主機尚未啟用。"
						break
					}
				}
			}
		}
		out = append(out, f)
	}
	return out
}
