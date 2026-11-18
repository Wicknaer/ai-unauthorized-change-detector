//go:build linux

package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/attribution"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/logger"
)

// writerNamed returns a copy of /bin/sh called name, so the kernel reports that command name.
func writerNamed(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh")
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRealFanotifyT03T04 runs the agent with real fanotify attribution: a process named
// "chroma" (the whitelisted server) and one named "sqlite3" write the vector database.
func TestRealFanotifyT03T04(t *testing.T) {
	l := newLab(t, chromaWhitelist)
	src, err := attribution.Open(l.cfg.Roots())
	if err != nil {
		t.Skipf("fanotify unavailable: %v", err)
	}
	defer src.Close()
	a := l.agent()
	a.SetAttribution(src)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); a.Run(ctx) }()
	defer func() { cancel(); wg.Wait() }()
	for i := 0; i < 200 && len(l.records(logger.TypeSummary)) < 2; i++ {
		time.Sleep(10 * time.Millisecond)
	}

	db := l.path("chroma/chroma.sqlite3")
	write := func(bin, data string) logger.Record {
		before := len(l.records(logger.TypeDetection))
		cmd := exec.Command(writerNamed(t, bin), "-c", `printf "$1" >> "$0"; sleep 0.2`, db, data)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", bin, err, out)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if recs := l.records(logger.TypeDetection); len(recs) > before {
				return recs[len(recs)-1]
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("no detection after %s write", bin)
		return logger.Record{}
	}

	legit := write("chroma", "api-row") // T-04
	if legit.Severity != decision.Info || legit.Process == nil || legit.Process.Comm != "chroma" || !*legit.Authorized {
		t.Fatalf("T-04: %+v proc=%+v", legit, legit.Process)
	}
	attack := write("sqlite3", "injected-row") // T-03
	if attack.Severity != decision.High || attack.Process == nil || attack.Process.Comm != "sqlite3" || *attack.Authorized {
		t.Fatalf("T-03: %+v proc=%+v", attack, attack.Process)
	}
	t.Logf("T-04: %s by %s (pid %d); T-03: %s by %s (pid %d)", legit.Severity, legit.Process.Comm, legit.Process.PID,
		attack.Severity, attack.Process.Comm, attack.Process.PID)
}
