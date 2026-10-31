package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"ubuntu-sys-audit/internal/dpkg"
	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
)

func checkPreload(c *Context) []model.Finding {
	const cat = model.CatIntegrity
	b, err := fsx.Read("/etc/ld.so.preload", 1<<16)
	if err != nil {
		if os.IsNotExist(err) {
			return []model.Finding{finding("integrity.preload", cat, model.OK, "/etc/ld.so.preload does not exist")}
		}
		return []model.Finding{skipped("integrity.preload", cat, "ld.so.preload", err.Error())}
	}
	var entries []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			entries = append(entries, line)
		}
	}
	if len(entries) == 0 {
		return []model.Finding{finding("integrity.preload", cat, model.OK, "/etc/ld.so.preload is empty")}
	}
	f := finding("integrity.preload", cat, model.Critical, "/etc/ld.so.preload has entries")
	f.Detail = "The listed libraries are injected into every process. Userland rootkits such as Jynx and Azazel use this to make ps, ls and ss lie. Some EDR products use it too, so check whether it is your own agent. This tool reads /proc directly and is not affected by the injection."
	f.Evidence = entries
	f.Remediation = "Find out where the library came from. If unexpected, treat the host as compromised."
	return []model.Finding{f}
}

// parseModuleFlags returns the taint flags printed for a /proc/modules row, for
// example "(OE)".
func parseModuleFlags(line string) (name, flags string) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return "", ""
	}
	name = f[0]
	if last := f[len(f)-1]; strings.HasPrefix(last, "(") && strings.HasSuffix(last, ")") {
		flags = strings.Trim(last, "()")
	}
	return name, flags
}

var knownThirdPartyModules = regexp.MustCompile(`^(nvidia|zfs|spl|vbox|vmw|vmmon|vmnet|wireguard|falcon|sentinel|ena|xt_|nv_|openvswitch|drbd|lkrg|cbsensor)`)

func checkModules(c *Context) []model.Finding {
	const cat = model.CatIntegrity
	b, err := fsx.ReadProc("/proc/modules")
	if err != nil {
		return []model.Finding{skipped("integrity.modules", cat, "Kernel modules", err.Error())}
	}
	listed := map[string]bool{}
	var thirdParty, unknownThird []string
	for _, line := range strings.Split(string(b), "\n") {
		name, flags := parseModuleFlags(line)
		if name == "" {
			continue
		}
		listed[name] = true
		if flags != "" && strings.ContainsAny(flags, "OEPF") {
			entry := name + "  (" + flags + ")"
			if knownThirdPartyModules.MatchString(name) {
				thirdParty = append(thirdParty, entry)
			} else {
				unknownThird = append(unknownThird, entry)
			}
		}
	}
	var out []model.Finding
	// Rootkits such as Diamorphine unlink themselves from the list behind
	// /proc/modules, but the sysfs entry usually survives. Built-in modules
	// also live in /sys/module; they have no initstate file.
	var hidden []string
	if dirs, err := os.ReadDir("/sys/module"); err == nil {
		for _, d := range dirs {
			if _, err := os.Stat(filepath.Join("/sys/module", d.Name(), "initstate")); err != nil {
				continue
			}
			if !listed[d.Name()] {
				hidden = append(hidden, d.Name())
			}
		}
	}
	if len(hidden) > 0 {
		f := finding("integrity.hidden_module", cat, model.Critical, "Kernel modules hidden from /proc/modules")
		f.Detail = "These modules appear in /sys/module but not in /proc/modules, typical behaviour of a kernel rootkit."
		f.Evidence = hidden
		f.Remediation = "Isolate the host, boot from clean media and perform offline forensics. Output from this host can no longer be trusted."
		out = append(out, f)
	} else if c.Host.IsRoot {
		out = append(out, finding("integrity.hidden_module", cat, model.OK, "/proc/modules matches /sys/module"))
	}
	if len(unknownThird) > 0 {
		f := finding("integrity.tainted_module", cat, model.Medium, "Unsigned or out-of-tree kernel modules are loaded")
		f.Detail = "O means out-of-tree, E means unsigned and P means proprietary. Confirm they are drivers you installed."
		f.Evidence = unknownThird
		out = append(out, f)
	}
	if len(thirdParty) > 0 {
		f := finding("integrity.known_modules", cat, model.Info, "Common third-party kernel modules are loaded")
		f.Evidence = thirdParty
		out = append(out, f)
	}
	return out
}

func checkPAM(c *Context) []model.Finding {
	const cat = model.CatIntegrity
	var out []model.Finding
	var mods []string
	for _, pat := range []string{"/lib/security/*.so", "/lib/*-linux-gnu*/security/*.so", "/usr/lib/security/*.so", "/usr/lib/*-linux-gnu*/security/*.so"} {
		m, _ := filepath.Glob(pat)
		mods = append(mods, m...)
	}
	if _, err := c.Owners(); err != nil {
		return []model.Finding{skipped("integrity.pam", cat, "PAM modules", "Cannot read the dpkg database: "+err.Error())}
	}
	seen := map[string]bool{}
	var rogue []string
	for _, m := range mods {
		real, err := filepath.EvalSymlinks(m)
		if err != nil {
			real = m
		}
		if seen[real] {
			continue
		}
		seen[real] = true
		if !c.Owned(real) {
			rogue = append(rogue, real)
		}
	}
	if len(rogue) > 0 {
		f := finding("integrity.pam_rogue", cat, model.Critical, "PAM modules that belong to no package")
		f.Detail = "A malicious PAM module can record every password or accept a master password."
		f.Evidence = rogue
		f.Remediation = "Check whether /etc/pam.d references it. If unexpected, treat the host as compromised."
		out = append(out, f)
	} else {
		out = append(out, finding("integrity.pam_modules", cat, model.OK, fmt.Sprintf("All %d PAM modules come from packages", len(seen))))
	}

	configs, _ := filepath.Glob("/etc/pam.d/*")
	var execLines []string
	for _, p := range configs {
		b, err := fsx.Read(p, 1<<18)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if strings.Contains(t, "pam_exec") || strings.Contains(t, "pam_permit.so") && strings.HasPrefix(t, "auth") && strings.Contains(t, "sufficient") {
				execLines = append(execLines, base(p)+": "+t)
			}
		}
	}
	if len(execLines) > 0 {
		f := finding("integrity.pam_config", cat, model.High, "PAM configuration has pam_exec or an allow-all rule")
		f.Detail = "pam_exec runs an external program during authentication, and auth sufficient pam_permit.so accepts any password."
		f.Evidence = execLines
		out = append(out, f)
	}
	return out
}

var keyBinary = regexp.MustCompile(`/(ssh|sshd|sshd-session|sshd-auth|scp|sftp|sudo|sudo\.ws|sudo-rs|su|login|passwd|ps|ss|netstat|lsof|ls|top|find|who|w|last|lastlog|id|dpkg|apt|apt-get|bash|dash|sh|systemctl|crontab|ip|ifconfig|iptables|md5sum|sha256sum|kill|pgrep|pkill|mount|cron|rsyslogd|pam_unix\.so|libpam\.so[.0-9]*|libkeyutils\.so[.0-9]*|liblzma\.so[.0-9]*|libaudit\.so[.0-9]*|libc\.so[.0-9]*|libcrypto\.so[.0-9]*)$`)

var verifiedLib = regexp.MustCompile(`/(security/[^/]+\.so|libpam[^/]*\.so[.0-9]*|libkeyutils\.so[.0-9]*|liblzma\.so[.0-9]*|libaudit\.so[.0-9]*|libc\.so[.0-9]*|libcrypto\.so[.0-9]*|libssl\.so[.0-9]*|ld-linux[^/]*\.so[.0-9]*)$`)

// verifiedDirs holds real executables. /usr/lib/cargo/bin matters from 26.04 on:
// ls, who and the rest of coreutils are symlinks into it, so checking /usr/bin
// alone would miss a trojaned ls there.
var verifiedDirs = []string{"/usr/bin/", "/usr/sbin/", "/usr/lib/openssh/", "/usr/libexec/", "/usr/lib/cargo/bin/"}

func wantVerify(path string) bool {
	for _, dir := range verifiedDirs {
		if strings.HasPrefix(path, dir) {
			return true
		}
	}
	return strings.HasPrefix(path, "/usr/lib/") && verifiedLib.MatchString(path)
}

func checkBinaries(c *Context) []model.Finding {
	const cat = model.CatIntegrity
	owners, err := c.Owners()
	if err != nil {
		return []model.Finding{skipped("integrity.binaries", cat, "System binary hashes", "Cannot read the dpkg database: "+err.Error())}
	}
	ctx, cancel := context.WithCancel(c.Ctx)
	defer cancel()
	res, err := dpkg.Verify(ctx, owners, wantVerify)
	if err != nil {
		return []model.Finding{skipped("integrity.binaries", cat, "System binary hashes", err.Error())}
	}
	var out []model.Finding
	var key, other []string
	for _, m := range res.Mismatches {
		line := m.Path + "  (package " + m.Package + ")"
		if keyBinary.MatchString(m.Path) {
			key = append(key, line)
		} else {
			other = append(other, line)
		}
	}
	sort.Strings(key)
	sort.Strings(other)
	hint := "Restore with apt install --reinstall <package>. Copy the suspect file somewhere safe first."
	if len(key) > 0 {
		f := finding("integrity.binaries_key", cat, model.Critical, fmt.Sprintf("Key system files do not match package hashes (%d)", len(key)))
		f.Detail = "Replacing files like ssh, sudo and ps is a typical sign of a trojan or rootkit."
		f.Evidence = key
		f.Remediation = hint
		f.Focus = true
		out = append(out, f)
	}
	if len(other) > 0 {
		f := finding("integrity.binaries_other", cat, model.High, fmt.Sprintf("System files do not match package hashes (%d)", len(other)))
		f.Detail = "This may be a manual edit or local patch, or the file may have been tampered with."
		f.Evidence = other
		f.Remediation = hint
		out = append(out, f)
	}
	if len(key)+len(other) == 0 {
		f := finding("integrity.binaries", cat, model.OK, "Verified "+strconv.Itoa(res.Checked)+" system files against package hashes, all match")
		f.Detail = "The baseline is the local dpkg database. An attacker who also changes the database will not be caught by this check."
		out = append(out, f)
	}
	if res.Incomplete {
		out = append(out, skipped("integrity.binaries_partial", cat, "System binary hash check did not finish", "Ran out of time after verifying "+strconv.Itoa(res.Checked)+" files."))
	}
	return out
}
