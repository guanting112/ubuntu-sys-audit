package fsx

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func noHang[T any](t *testing.T, name string, fn func() (T, error)) (T, error) {
	t.Helper()
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := fn()
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s blocked", name)
	}
	panic("unreachable")
}

func TestSpecialFilesAreRefusedWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, "/dev/null"} {
		if _, err := noHang(t, "Read", func() ([]byte, error) { return Read(path, 16) }); !errors.Is(err, ErrNotRegular) {
			t.Errorf("Read(%s): %v", path, err)
		}
		if _, err := noHang(t, "ReadNoFollow", func() ([]byte, error) { return ReadNoFollow(path, 16) }); !errors.Is(err, ErrNotRegular) {
			t.Errorf("ReadNoFollow(%s): %v", path, err)
		}
		if _, err := noHang(t, "OpenRegular", func() (*os.File, error) { return OpenRegular(path) }); !errors.Is(err, ErrNotRegular) {
			t.Errorf("OpenRegular(%s): %v", path, err)
		}
		if _, err := noHang(t, "Tail", func() ([]byte, error) { return Tail(path, 16) }); !errors.Is(err, ErrNotRegular) {
			t.Errorf("Tail(%s): %v", path, err)
		}
	}
}

func TestSymlinkHandling(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if b, err := Read(link, 16); err != nil || string(b) != "secret" {
		t.Errorf("Read should follow a link: %q %v", b, err)
	}
	if _, err := ReadNoFollow(link, 16); err == nil {
		t.Error("ReadNoFollow must refuse a symlink")
	}
	if b, err := ReadNoFollow(real, 3); err != nil || string(b) != "sec" {
		t.Errorf("limit not honoured: %q %v", b, err)
	}
}

func TestReadUnderRefusesASymlinkInAnyComponent(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "authorized_keys"), []byte("root key"), 0o600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadUnder(home, ".ssh/authorized_keys", 64); err == nil {
		t.Errorf("a symlinked parent directory was followed: %q", b)
	}

	if err := os.Mkdir(filepath.Join(home, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".config", "x"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadUnder(home, ".config/x", 64); err != nil || string(b) != "mine" {
		t.Errorf("a normal nested file must read: %q %v", b, err)
	}
	if err := os.Symlink(filepath.Join(home, ".config", "x"), filepath.Join(home, "lastlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadUnder(home, "lastlink", 64); err == nil {
		t.Error("a symlink as the last component must be refused")
	}
	baseLink := filepath.Join(t.TempDir(), "homelink")
	if err := os.Symlink(home, baseLink); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadUnder(baseLink, ".config/x", 64); err != nil || string(b) != "mine" {
		t.Errorf("base may be a symlink: %q %v", b, err)
	}
}
