package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"ubuntu-sys-audit/internal/model"
)

func report() *model.Report {
	r := &model.Report{Findings: []model.Finding{
		{ID: "a", Severity: model.Critical, Title: "bad thing"},
		{ID: "b", Severity: model.Skipped, Title: "could not check"},
		{ID: "c", Severity: model.Info, Title: "just info"},
	}}
	r.Finalize()
	return r
}

func TestSaveJSONCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	if err := SaveJSON(path, report()); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %o, want 600", st.Mode().Perm())
	}
}

func TestSaveJSONNeverTouchesWhatIsAlreadyThere(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "shadow")
	if err := os.WriteFile(existing, []byte("keep me"), 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(existing, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "created-through-link"), dangling); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{existing, link, dangling, fifo} {
		done := make(chan error, 1)
		go func() { done <- SaveJSON(path, report()) }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: expected a refusal", path)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: SaveJSON blocked", path)
		}
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep me" {
		t.Errorf("existing file changed: %q", b)
	}
	if _, err := os.Lstat(filepath.Join(dir, "created-through-link")); err == nil {
		t.Error("a dangling symlink was followed")
	}
}

func TestParentAllows(t *testing.T) {
	const me, myGroup, other, otherGroup = 1000, 1000, 2000, 2000
	cases := []struct {
		name               string
		mode               os.FileMode
		ownerUID, ownerGID int
		want               bool
	}{
		{"own directory", 0o755, me, myGroup, true},
		{"root owned /etc", 0o755, 0, 0, false},
		{"group writable, my group", 0o775, 0, myGroup, true},
		{"group writable, other group", 0o775, other, otherGroup, false},
		{"sticky /tmp", 0o777, 0, 0, true},
		{"own but read only", 0o555, me, myGroup, false},
	}
	for _, c := range cases {
		if got := parentAllows(c.mode, c.ownerUID, c.ownerGID, me, myGroup); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestTextAlwaysListsUncheckedItems(t *testing.T) {
	var out bytes.Buffer
	Text(&out, report(), model.Critical)
	text := out.String()
	for _, want := range []string{"bad thing", "could not check", "Incomplete:"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "just info") {
		t.Errorf("info should be filtered at critical:\n%s", text)
	}
}
