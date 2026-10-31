package checks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"ubuntu-sys-audit/internal/fsx"
	"ubuntu-sys-audit/internal/model"
)

// Filesystems a local audit must not walk: virtual ones, network ones whose
// content and latency belong to another host, and read only images.
var skipFSTypes = map[string]bool{
	"proc": true, "sysfs": true, "devpts": true, "cgroup": true, "cgroup2": true, "securityfs": true,
	"debugfs": true, "tracefs": true, "configfs": true, "pstore": true, "bpf": true, "mqueue": true,
	"hugetlbfs": true, "binfmt_misc": true, "autofs": true, "fusectl": true, "efivarfs": true,
	"rpc_pipefs": true, "nfsd": true, "nsfs": true, "nfs": true, "nfs4": true, "cifs": true, "smb3": true,
	"smbfs": true, "ceph": true, "glusterfs": true, "lustre": true, "9p": true, "virtiofs": true,
	"vboxsf": true, "davfs": true, "afs": true, "squashfs": true, "iso9660": true,
}

var skipWalkDirs = map[string]bool{
	"/proc": true, "/sys": true, "/snap": true, "/var/lib/docker": true, "/var/lib/containerd": true,
	"/var/lib/kubelet": true, "/var/lib/lxd": true, "/var/lib/snapd": true, "/var/snap": true,
	"/var/lib/containers": true, "/var/lib/libvirt/images": true, "/lost+found": true, "/mnt/mac": true,
	"/opt/orbstack-guest": true,
}

// parseMountSkips returns mount points to avoid given /proc/self/mountinfo.
func parseMountSkips(mountinfo string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(mountinfo, "\n") {
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		lf, rf := strings.Fields(left), strings.Fields(right)
		if len(lf) < 5 || len(rf) < 1 {
			continue
		}
		mp, typ := unescapeMount(lf[4]), rf[0]
		if mp == "/" {
			continue
		}
		if skipFSTypes[typ] || strings.HasPrefix(typ, "fuse") || typ == "overlay" {
			out[mp] = true
		}
	}
	return out
}

func unescapeMount(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

var dangerousSUID = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true, "python": true, "python2": true,
	"python3": true, "perl": true, "ruby": true, "lua": true, "php": true, "node": true, "find": true,
	"vim": true, "vi": true, "nano": true, "less": true, "more": true, "awk": true, "gawk": true,
	"mawk": true, "sed": true, "tar": true, "cp": true, "mv": true, "nmap": true, "env": true,
	"tee": true, "dd": true, "gdb": true, "strace": true, "nc": true, "ncat": true, "socat": true,
	"wget": true, "curl": true, "git": true, "docker": true, "chmod": true, "chown": true,
}

const (
	capDacOverride   = 1
	capDacReadSearch = 2
	capFowner        = 3
	capSetgid        = 6
	capSetuid        = 7
	capSysModule     = 16
	capSysRawio      = 17
	capSysPtrace     = 19
	capSysAdmin      = 21
)

var dangerousCaps = map[uint]string{
	capDacOverride: "cap_dac_override", capDacReadSearch: "cap_dac_read_search", capFowner: "cap_fowner",
	capSetgid: "cap_setgid", capSetuid: "cap_setuid", capSysModule: "cap_sys_module",
	capSysRawio: "cap_sys_rawio", capSysPtrace: "cap_sys_ptrace", capSysAdmin: "cap_sys_admin",
}

// parseFileCaps decodes a security.capability xattr and returns the names of
// any dangerous permitted capabilities plus whether any capability is set.
func parseFileCaps(b []byte) (dangerous []string, any bool) {
	if len(b) < 12 {
		return nil, false
	}
	lo := binary.LittleEndian.Uint32(b[4:])
	var mask uint64 = uint64(lo)
	if len(b) >= 20 {
		mask |= uint64(binary.LittleEndian.Uint32(b[12:])) << 32
	}
	if mask == 0 {
		return nil, false
	}
	for bit, name := range dangerousCaps {
		if mask&(1<<bit) != 0 {
			dangerous = append(dangerous, name)
		}
	}
	sort.Strings(dangerous)
	return dangerous, true
}

var tmpHiddenAllow = regexp.MustCompile(`^\.(X\d*-lock|X11-unix|ICE-unix|XIM-unix|font-unix|Test-unix|XPRA.*|mount_.*|s\.PGSQL\..*|snap.*|com\.google.*|org\.chromium.*|java_pid\d+|dotnet.*)$`)

type walkResult struct {
	files, suidOwned, capOwned                                      int
	suidCritical, suidHigh, capDanger, capInfo, tempELF, tempScript []string
	tempHidden, worldWritable, unmanagedBin, regularInDev           []string
	incomplete                                                      bool
}

func checkFilesystem(c *Context) []model.Finding {
	const cat = model.CatFilesystem
	if c.Opts.SkipFS {
		return []model.Finding{skipped("filesystem.walk", cat, "檔案系統掃描", "已用 --skip-fs 略過。")}
	}
	if !c.Host.IsRoot {
		return []model.Finding{needRoot("filesystem.walk", cat, "檔案系統掃描")}
	}
	if _, err := c.Owners(); err != nil {
		return []model.Finding{skipped("filesystem.walk", cat, "檔案系統掃描", "無法讀取 dpkg 資料庫，不能判斷檔案來源："+err.Error())}
	}
	budget := c.Opts.FSTimeout
	if budget <= 0 {
		budget = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(c.Ctx, budget)
	defer cancel()

	mi, _ := fsx.ReadProc("/proc/self/mountinfo")
	skips := parseMountSkips(string(mi))
	var r walkResult
	_ = filepath.WalkDir("/", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			r.incomplete = true
			return filepath.SkipAll
		}
		if d.IsDir() {
			if path != "/" && (skipWalkDirs[path] || skips[path]) {
				return filepath.SkipDir
			}
			if inTemp(path) && strings.HasPrefix(d.Name(), ".") && !tmpHiddenAllow.MatchString(d.Name()) {
				r.tempHidden = append(r.tempHidden, path)
			}
			if inDirs(path, "/etc", "/usr", "/opt") || path == "/etc" || path == "/usr" {
				if info, err := d.Info(); err == nil && info.Mode().Perm()&0o002 != 0 && info.Mode()&os.ModeSticky == 0 {
					r.worldWritable = append(r.worldWritable, path+"/")
				}
			}
			return nil
		}
		t := d.Type()
		if t&fs.ModeSymlink != 0 || !t.IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		r.files++
		inspectFile(c, path, info, &r)
		return nil
	})
	return filesystemFindings(&r)
}

func inspectFile(c *Context, path string, info os.FileInfo, r *walkResult) {
	mode := info.Mode()
	name := filepath.Base(path)
	if mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
		line := fmt.Sprintf("%s  %s", mode.String(), path)
		owned := c.Owned(path)
		switch {
		case dangerousSUID[strings.TrimRight(name, "0123456789.")]:
			r.suidCritical = append(r.suidCritical, line+"（這支程式不該有 SUID，可直接提權）")
		case !owned && (inTemp(path) || inDirs(path, "/home", "/root", "/var", "/dev")):
			r.suidCritical = append(r.suidCritical, line+"（位於使用者可寫的位置）")
		case !owned:
			r.suidHigh = append(r.suidHigh, line)
		default:
			r.suidOwned++
		}
	}
	if mode.Perm()&0o111 != 0 {
		buf := make([]byte, 64)
		if n, err := syscall.Getxattr(path, "security.capability", buf); err == nil && n > 0 {
			danger, any := parseFileCaps(buf[:n])
			owned := c.Owned(path)
			switch {
			case len(danger) > 0:
				r.capDanger = append(r.capDanger, path+"  "+strings.Join(danger, ","))
			case any && !owned:
				r.capInfo = append(r.capInfo, path)
			case any:
				r.capOwned++
			}
		}
	}
	if inTemp(path) {
		switch {
		case isELF(path):
			r.tempELF = append(r.tempELF, fmt.Sprintf("%s  %d bytes  %s", path, info.Size(), info.ModTime().Format("2006-01-02 15:04")))
		case mode.Perm()&0o111 != 0:
			r.tempScript = append(r.tempScript, path)
		}
	}
	if inDirs(path, "/dev") && !inDirs(path, "/dev/shm", "/dev/mqueue", "/dev/hugepages") {
		r.regularInDev = append(r.regularInDev, path)
	}
	if mode.Perm()&0o002 != 0 && (inDirs(path, "/etc", "/usr", "/opt") || inDirs(path, "/bin", "/sbin", "/lib")) {
		r.worldWritable = append(r.worldWritable, path)
	}
	if mode.Perm()&0o111 != 0 && (filepath.Dir(path) == "/usr/bin" || filepath.Dir(path) == "/usr/sbin" ||
		filepath.Dir(path) == "/bin" || filepath.Dir(path) == "/sbin") && !c.Owned(path) {
		r.unmanagedBin = append(r.unmanagedBin, fmt.Sprintf("%s  %s", path, info.ModTime().Format("2006-01-02")))
	}
}

func isELF(path string) bool {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)
	var b [4]byte
	n, err := syscall.Read(fd, b[:])
	return err == nil && n == 4 && string(b[:]) == "\x7fELF"
}

func filesystemFindings(r *walkResult) []model.Finding {
	const cat = model.CatFilesystem
	var out []model.Finding
	add := func(id string, sev model.Severity, title, detail, fix string, ev []string) {
		if len(ev) == 0 {
			return
		}
		sort.Strings(ev)
		f := finding("filesystem."+id, cat, sev, fmt.Sprintf(title, len(ev)))
		f.Detail, f.Remediation, f.Evidence = detail, fix, ev
		out = append(out, f)
	}
	add("suid_critical", model.Critical, "%d 個危險的 SUID／SGID 檔案", "這些檔案能讓任何本機使用者直接變成 root，是常見的提權後門。", "先記錄檔案資訊與修改時間，再 chmod u-s,g-s 移除。", r.suidCritical)
	add("suid_unowned", model.High, "%d 個 SUID／SGID 檔案不屬於任何套件", "自行安裝的軟體偶爾會這樣，但應逐一確認。", "不需要就 chmod u-s,g-s 移除。", r.suidHigh)
	add("cap_danger", model.High, "%d 個檔案帶有危險的 Capabilities", "cap_setuid 這類權限和 SUID 一樣能提權，而且一般的 SUID 掃描看不到。", "確認用途，不需要就 setcap -r 移除。", r.capDanger)
	add("cap_unowned", model.Medium, "%d 個非套件檔案帶有 Capabilities", "", "", r.capInfo)
	add("temp_elf", model.High, "暫存目錄內有 %d 個 ELF 執行檔", "編譯或安裝過程可能留下這類檔案，它也是攻擊工具最常見的落腳處。", "確認來源後移除。先保留樣本再刪除。", r.tempELF)
	add("temp_script", model.Medium, "暫存目錄內有 %d 個可執行腳本", "", "確認來源。", r.tempScript)
	add("temp_hidden", model.Medium, "暫存目錄內有 %d 個隱藏目錄", "攻擊者常用 .x 或 ... 這類名稱藏工具。", "檢查內容。", r.tempHidden)
	add("dev_regular", model.High, "/dev 內有 %d 個一般檔案", "/dev 應該只有裝置檔。把檔案藏在這裡是老牌 rootkit 的手法。", "檢查內容。", r.regularInDev)
	add("world_writable", model.High, "系統目錄內有 %d 個任何人都可寫入的項目", "任何本機使用者都能修改它們，可用來提權。", "chmod o-w。", r.worldWritable)
	add("unmanaged_bin", model.Medium, "系統 bin 目錄有 %d 個非套件管理的執行檔", "手動安裝的工具會列在這裡，攻擊者投放的也會。這些檔案不會收到 apt 更新。", "確認來源。", r.unmanagedBin)
	if len(r.suidCritical)+len(r.suidHigh) == 0 {
		out = append(out, finding("filesystem.suid_ok", cat, model.OK, fmt.Sprintf("%d 個 SUID／SGID 檔案都來自套件", r.suidOwned)))
	}
	if r.incomplete {
		out = append(out, skipped("filesystem.partial", cat, "檔案系統掃描未完成", fmt.Sprintf("達到時間上限，只掃描了 %d 個檔案，以上結果不完整。可用 --fs-timeout 調整。", r.files)))
	} else {
		out = append(out, finding("filesystem.stats", cat, model.Info, fmt.Sprintf("已掃描 %d 個檔案", r.files)))
	}
	return out
}
