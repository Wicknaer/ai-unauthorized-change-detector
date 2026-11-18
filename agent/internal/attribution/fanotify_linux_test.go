//go:build linux

package attribution

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func openOrSkip(t *testing.T, root string) Source {
	t.Helper()
	src, err := Open([]string{root})
	if err != nil {
		t.Skipf("fanotify unavailable (run as root with CAP_SYS_ADMIN): %v", err)
	}
	t.Cleanup(func() { src.Close() })
	return src
}

func waitWrite(src Source, path string, d time.Duration) (Write, bool) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if w, ok := src.LastWrite(path); ok {
			return w, true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return Write{}, false
}

func TestFanotifyAttributesWriterProcess(t *testing.T) {
	root := t.TempDir()
	src := openOrSkip(t, root)
	if m, ok := src.(ModeReporter); ok {
		t.Logf("mark mode: %s", m.Mode())
	}
	path := filepath.Join(root, "model.safetensors")
	os.WriteFile(path, []byte("weights"), 0o644) // written by the test process itself

	// A separate, long enough lived writer so /proc is still readable.
	cmd := exec.Command("sh", "-c", `printf X >> "$0"; sleep 0.3`, path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cmd.Wait()

	w, ok := waitWrite(src, path, 2*time.Second)
	if !ok {
		t.Fatal("no write recorded")
	}
	if w.Proc.PID != pid || w.Proc.Comm != "sh" || w.Proc.Exe == "" || w.Proc.User == "" {
		t.Errorf("got %+v, want pid %d comm sh", w.Proc, pid)
	}
	fi, _ := os.Stat(path)
	if !w.Explains(fi.ModTime()) {
		t.Error("write should explain the current mtime")
	}
}

func TestFanotifyIgnoresOwnWrites(t *testing.T) {
	root := t.TempDir()
	src := openOrSkip(t, root)
	path := filepath.Join(root, "baseline.json")
	os.WriteFile(path, []byte("{}"), 0o644)
	if _, ok := waitWrite(src, path, 300*time.Millisecond); ok {
		t.Error("the agent's own writes must not be recorded")
	}
}

func TestReadProcSelf(t *testing.T) {
	p := ReadProc(os.Getpid())
	if p.Comm == "" || p.Exe == "" || p.User == "" {
		t.Errorf("got %+v", p)
	}
}
