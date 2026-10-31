// Package procinfo reads processes and sockets straight from procfs. No host
// binary such as ps or ss is executed: running them as root would trust the
// PATH, and a trojaned copy could lie about the very thing being checked.
package procinfo

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ubuntu-sys-audit/internal/fsx"
)

// Process is a snapshot of one process.
type Process struct {
	PID         int
	PPID        int
	UID         int
	Comm        string
	Cmdline     []string
	Exe         string // resolved path, without the " (deleted)" suffix
	ExeDeleted  bool
	KernelTh    bool
	InContainer bool // runs in a different PID namespace from this tool
	NetNS       string
	Sockets     []uint64
	StdioSocket map[int]uint64 // fd 0, 1, 2 -> socket inode, when they are sockets
}

// CmdlineString returns the command line joined by spaces.
func (p *Process) CmdlineString() string { return strings.Join(p.Cmdline, " ") }

// Label is a short description for evidence lines.
func (p *Process) Label() string {
	s := "pid=" + strconv.Itoa(p.PID) + " uid=" + strconv.Itoa(p.UID) + " " + p.Comm
	if p.Exe != "" {
		s += " exe=" + p.Exe
		if p.ExeDeleted {
			s += " (deleted)"
		}
	}
	if p.InContainer {
		s += " [container]"
	}
	return s
}

const pfKthread = 0x00200000

// Snapshot reads every visible process.
func Snapshot(ctx context.Context) ([]*Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	selfPidNS, _ := os.Readlink("/proc/self/ns/pid")
	var out []*Process
	for _, e := range entries {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if p := readProcess(pid, selfPidNS); p != nil {
			out = append(out, p)
		}
	}
	return out, nil
}

func readProcess(pid int, selfPidNS string) *Process {
	dir := "/proc/" + strconv.Itoa(pid)
	statB, err := fsx.ReadProc(dir + "/stat")
	if err != nil {
		return nil
	}
	p := &Process{PID: pid}
	var flags uint64
	p.Comm, p.PPID, flags = ParseStat(string(statB))
	p.KernelTh = flags&pfKthread != 0

	if st, err := fsx.ReadProc(dir + "/status"); err == nil {
		for _, line := range strings.Split(string(st), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				if f := strings.Fields(line); len(f) >= 2 {
					p.UID, _ = strconv.Atoi(f[1])
				}
				break
			}
		}
	}
	if p.KernelTh {
		return p
	}
	if b, err := fsx.ReadProc(dir + "/cmdline"); err == nil && len(b) > 0 {
		for _, a := range strings.Split(strings.TrimRight(string(b), "\x00"), "\x00") {
			p.Cmdline = append(p.Cmdline, a)
		}
	}
	if exe, err := os.Readlink(dir + "/exe"); err == nil {
		p.Exe, p.ExeDeleted = strings.CutSuffix(exe, " (deleted)")
	}
	if ns, err := os.Readlink(dir + "/ns/pid"); err == nil && selfPidNS != "" {
		p.InContainer = ns != selfPidNS
	}
	p.NetNS, _ = os.Readlink(dir + "/ns/net")
	readSockets(p, dir)
	return p
}

// ParseStat extracts comm, ppid and flags from /proc/pid/stat. comm is wrapped
// in parentheses and may itself contain spaces or parentheses, so fields are
// counted from the last closing parenthesis.
func ParseStat(s string) (comm string, ppid int, flags uint64) {
	open := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if open < 0 || end < open {
		return "", 0, 0
	}
	comm = s[open+1 : end]
	f := strings.Fields(s[end+1:])
	if len(f) > 1 {
		ppid, _ = strconv.Atoi(f[1])
	}
	if len(f) > 6 {
		flags, _ = strconv.ParseUint(f[6], 10, 64)
	}
	return comm, ppid, flags
}

func readSockets(p *Process, dir string) {
	fds, err := os.ReadDir(dir + "/fd")
	if err != nil {
		return
	}
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
		if err != nil {
			continue
		}
		p.Sockets = append(p.Sockets, ino)
		if n, err := strconv.Atoi(fd.Name()); err == nil && n <= 2 {
			if p.StdioSocket == nil {
				p.StdioSocket = map[int]uint64{}
			}
			p.StdioSocket[n] = ino
		}
	}
}

// Environ returns the value of one environment variable of a process. Only the
// requested key is extracted so unrelated secrets never enter a report.
func Environ(pid int, key string) (string, bool) {
	b, err := fsx.ReadProc("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		return "", false
	}
	prefix := key + "="
	for _, kv := range strings.Split(string(b), "\x00") {
		if v, ok := strings.CutPrefix(kv, prefix); ok {
			return v, true
		}
	}
	return "", false
}
