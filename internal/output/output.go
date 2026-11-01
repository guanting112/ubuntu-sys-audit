// Package output writes reports as JSON files or plain text.
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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

// SaveJSON writes the report to a new file readable only by its owner, because
// it lists accounts, keys and weaknesses.
//
// The tool often runs as root on behalf of someone with limited sudo rights, so
// the path is treated as untrusted. Refusing to overwrite means it cannot destroy
// /etc/shadow, or follow a planted symlink or block on a FIFO, since O_EXCL fails
// on anything already there. Under sudo the file goes back to the invoking user,
// so the parent directory must be one that user could write to anyway; otherwise
// -o /etc/cron.d/x would hand them a root owned location they then control.
func SaveJSON(path string, r *model.Report) error {
	uid, gid, viaSudo := invokingUser()
	if viaSudo {
		if err := checkParent(path, uid, gid); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists, and reports never overwrite a file", path)
		}
		return err
	}
	defer f.Close()
	if viaSudo {
		// On the descriptor, so a path swapped after the open changes nothing.
		if err := f.Chown(uid, gid); err != nil {
			return err
		}
	}
	if err := JSON(f, r); err != nil {
		return err
	}
	return f.Close()
}

func invokingUser() (uid, gid int, ok bool) {
	if os.Geteuid() != 0 {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid <= 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

func checkParent(path string, uid, gid int) error {
	dir := filepath.Dir(path)
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !parentAllows(st.Mode().Perm(), int(sys.Uid), int(sys.Gid), uid, gid) {
		return fmt.Errorf("%s is not writable by the user who ran sudo, so choose a directory they can write to", dir)
	}
	return nil
}

// parentAllows checks only the primary group. Refusing a directory that a
// supplementary group could write to is the safe way to be wrong.
func parentAllows(mode fs.FileMode, ownerUID, ownerGID, uid, gid int) bool {
	switch {
	case ownerUID == uid:
		return mode&0o200 != 0
	case ownerGID == gid:
		return mode&0o020 != 0
	}
	return mode&0o002 != 0
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
	fmt.Fprintf(w, "Host %s  %s %s  kernel %s  %s\n", h.Hostname, h.OSName, h.OSVersion, h.Kernel, h.Arch)
	if !h.IsRoot {
		fmt.Fprintln(w, "Warning: not running as root, so some items were not checked.")
	}
	fmt.Fprintln(w, Summary(r))
	if r.Incomplete {
		fmt.Fprintln(w, "Incomplete: some items could not be checked, so do not treat this as a clean result.")
	}
	fmt.Fprintln(w)
	for _, f := range r.Findings {
		// Unfinished checks are always listed: hiding them would make a partial
		// scan look complete.
		if f.Severity > minSeverity && f.Severity != model.Skipped {
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
			fmt.Fprintf(w, "    Remediation: %s\n", f.Remediation)
		}
		for _, ref := range f.Refs {
			fmt.Fprintf(w, "    Reference: %s\n", ref)
		}
		fmt.Fprintln(w)
	}
}

// Summary returns a one line count of findings.
func Summary(r *model.Report) string {
	s := r.Summary
	return fmt.Sprintf("Critical %d  High %d  Medium %d  Info %d  Passed %d  Not checked %d  (%.1fs)",
		s.Critical, s.High, s.Medium, s.Info, s.OK, s.Skipped, float64(r.DurationMS)/1000)
}
