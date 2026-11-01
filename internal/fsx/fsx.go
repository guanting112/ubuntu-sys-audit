// Package fsx holds file helpers that are safe to use as root against paths
// other users control.
package fsx

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// ErrNotRegular is returned when a path is a FIFO, device, socket or directory.
var ErrNotRegular = errors.New("not a regular file")

// DefaultLimit bounds how much of a config file is read.
const DefaultLimit = 4 << 20

// oPath is O_PATH, missing from the frozen syscall package. It has this value on
// amd64 and arm64, the only architectures the tool is built for.
const oPath = 0x200000

// reopenRegular turns an O_PATH descriptor into a readable file if, and only if,
// it refers to a regular file, and closes it either way.
//
// The type is checked before anything is really opened. Opening has side effects
// on special files: a FIFO blocks, and opening /dev/watchdog arms the watchdog.
// Reopening through /proc/self/fd reads the inode already checked, so swapping
// the path in between changes nothing.
func reopenRegular(pathFD int, path string) (*os.File, error) {
	defer syscall.Close(pathFD)
	var st syscall.Stat_t
	if err := syscall.Fstat(pathFD, &st); err != nil {
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, &os.PathError{Op: "read", Path: path, Err: ErrNotRegular}
	}
	fd, err := syscall.Open("/proc/self/fd/"+strconv.Itoa(pathFD), syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openRegular(path string, flags int) (*os.File, error) {
	pathFD, err := syscall.Open(path, oPath|syscall.O_CLOEXEC|flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return reopenRegular(pathFD, path)
}

// OpenRegular opens a file for reading, following symlinks, and refuses anything
// but a regular file without touching it.
func OpenRegular(path string) (*os.File, error) {
	return openRegular(path, 0)
}

func read(path string, limit int64, flags int) ([]byte, error) {
	f, err := openRegular(path, flags)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// ReadUnder reads rel below base and refuses a symlink in any component of rel.
// O_NOFOLLOW alone covers only the last one, so ~/.ssh -> /root/.ssh would get
// past it. Use this for anything inside a home directory. base itself is trusted
// and may be a symlink, as a home directory set in /etc/passwd can be.
func ReadUnder(base, rel string, limit int64) ([]byte, error) {
	dir, err := syscall.Open(base, oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: base, Err: err}
	}
	parts := strings.Split(rel, "/")
	for _, part := range parts[:len(parts)-1] {
		next, err := syscall.Openat(dir, part, oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(dir)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: base + "/" + rel, Err: err}
		}
		dir = next
	}
	last, err := syscall.Openat(dir, parts[len(parts)-1], oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	syscall.Close(dir)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: base + "/" + rel, Err: err}
	}
	f, err := reopenRegular(last, base+"/"+rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// ReadNoFollow reads a regular file and refuses symlinks. Use it for anything
// under a user's control, such as files in a home directory, so that a link
// to /etc/shadow cannot make a root scan quote secrets.
func ReadNoFollow(path string, limit int64) ([]byte, error) {
	return read(path, limit, syscall.O_NOFOLLOW)
}

// Read reads a regular file and follows symlinks. Use it for root owned
// configuration, where links such as sites-enabled are normal.
func Read(path string, limit int64) ([]byte, error) {
	return read(path, limit, 0)
}

// ReadProc reads a procfs or sysfs file, whose reported size is meaningless.
func ReadProc(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 64<<20))
}

// ProcString reads a procfs file and trims surrounding whitespace.
func ProcString(path string) string {
	b, err := ReadProc(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Tail returns up to limit bytes from the end of a regular file, starting at a
// line boundary when the file was truncated.
func Tail(path string, limit int64) ([]byte, error) {
	f, err := openRegular(path, syscall.O_NOFOLLOW)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	offset := st.Size() - limit
	truncated := offset > 0
	if !truncated {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, err
	}
	if truncated {
		for i, c := range b {
			if c == '\n' {
				return b[i+1:], nil
			}
		}
	}
	return b, nil
}
