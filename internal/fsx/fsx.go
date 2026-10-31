// Package fsx holds file helpers that are safe to use as root against paths
// other users control.
package fsx

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

// ErrNotRegular is returned when a path is a FIFO, device, socket or directory.
var ErrNotRegular = errors.New("not a regular file")

// DefaultLimit bounds how much of a config file is read.
const DefaultLimit = 4 << 20

func read(path string, limit int64, flags int) ([]byte, error) {
	// O_NONBLOCK keeps a FIFO planted by a local user from hanging a root
	// scan at open(); the file type is then checked on the opened descriptor,
	// so there is no gap between check and read.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, &os.PathError{Op: "read", Path: path, Err: ErrNotRegular}
	}
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
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, &os.PathError{Op: "read", Path: path, Err: ErrNotRegular}
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
