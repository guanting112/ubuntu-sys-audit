// Package output writes reports as JSON files or plain text.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ubuntu-sys-audit/internal/model"
)

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// SaveJSON writes the report to path, readable only by its owner: it lists
// accounts, keys and weaknesses. When the tool runs under sudo the file goes
// back to the invoking user, so the report is not stranded as root owned.
func SaveJSON(path string, r *model.Report) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if err := JSON(f, r); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
		gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
		if err1 == nil && err2 == nil && uid > 0 {
			_ = os.Chown(path, uid, gid)
		}
	}
	return nil
}

// DefaultFilename builds a report name from the host and scan time.
func DefaultFilename(r *model.Report) string {
	host := strings.Map(func(c rune) rune {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.':
			return c
		}
		return '_'
	}, r.Host.Hostname)
	if host == "" {
		host = "host"
	}
	return fmt.Sprintf("audit-%s-%s.json", host, r.ScannedAt.Local().Format("20060102-150405"))
}

// Text writes a plain text report. minSeverity hides findings below it.
func Text(w io.Writer, r *model.Report, minSeverity model.Severity) {
	h := r.Host
	fmt.Fprintf(w, "ubuntu-sys-audit %s  %s\n", r.Version, r.ScannedAt.Local().Format(time.DateTime))
	fmt.Fprintf(w, "主機 %s  %s %s  kernel %s  %s\n", h.Hostname, h.OSName, h.OSVersion, h.Kernel, h.Arch)
	if !h.IsRoot {
		fmt.Fprintln(w, "注意：沒有以 root 執行，部分項目未檢查。")
	}
	fmt.Fprintln(w, Summary(r))
	fmt.Fprintln(w)
	for _, f := range r.Findings {
		if f.Severity > minSeverity {
			continue
		}
		fmt.Fprintf(w, "[%s] %s  (%s)\n", f.Severity.Label(), f.Title, f.Category.Label())
		if f.Detail != "" {
			fmt.Fprintf(w, "    %s\n", f.Detail)
		}
		for _, e := range f.Evidence {
			fmt.Fprintf(w, "    - %s\n", e)
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "    處理：%s\n", f.Remediation)
		}
		for _, ref := range f.Refs {
			fmt.Fprintf(w, "    參考：%s\n", ref)
		}
		fmt.Fprintln(w)
	}
}

// Summary returns a one line count of findings.
func Summary(r *model.Report) string {
	s := r.Summary
	return fmt.Sprintf("嚴重 %d  高 %d  中 %d  資訊 %d  通過 %d  未檢查 %d  （耗時 %.1f 秒）",
		s.Critical, s.High, s.Medium, s.Info, s.OK, s.Skipped, float64(r.DurationMS)/1000)
}
