package procinfo

import (
	"fmt"
	"strings"
	"testing"
)

// FuzzParseStat builds a /proc/pid/stat line around an arbitrary process
// name, which any user can set with prctl, and checks that comm, ppid and
// flags come back unchanged even when the name holds spaces or parentheses.
func FuzzParseStat(f *testing.F) {
	f.Add("bash", 1, uint64(4194560))
	f.Add("a) S 1 (b", 42, uint64(0))
	f.Add(") 9 9 9 9 9 9", 7, uint64(1))
	f.Add("", 0, uint64(1)<<63)
	f.Fuzz(func(t *testing.T, comm string, ppid int, flags uint64) {
		// The kernel keeps at most 15 bytes of a name, and never a NUL.
		if len(comm) > 15 || strings.IndexByte(comm, 0) >= 0 || ppid < 0 {
			return
		}
		line := fmt.Sprintf("4321 (%s) S %d 4321 4321 0 -1 %d 120 0 0 0 3 1 0 0 20 0 1 0 2650 1000 200\n", comm, ppid, flags)
		gotComm, gotPPID, gotFlags := ParseStat(line)
		if gotComm != comm || gotPPID != ppid || gotFlags != flags {
			t.Fatalf("ParseStat(%q) = %q, %d, %d; want %q, %d, %d", line, gotComm, gotPPID, gotFlags, comm, ppid, flags)
		}
	})
}
