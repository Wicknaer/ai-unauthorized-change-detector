package logger

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
)

func writeN(t *testing.T, n int) (string, *bytes.Buffer) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log", "alerts.jsonl")
	var console bytes.Buffer
	l, err := New(path, &console)
	if err != nil {
		t.Fatal(err)
	}
	sev := []decision.Severity{decision.Info, decision.Critical, decision.Medium}
	for i := 0; i < n; i++ {
		if err := l.Write(Record{Type: TypeDetection, Severity: sev[i%3], Path: "/data/f", Message: strings.Repeat("x", i)}); err != nil {
			t.Fatal(err)
		}
	}
	return path, &console
}

func TestChainVerifies(t *testing.T) {
	path, console := writeN(t, 6)
	n, err := Verify(path)
	if err != nil || n != 6 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
	// Only CRITICAL/HIGH reach the console (FR-15).
	if got := strings.Count(console.String(), "\n"); got != 2 {
		t.Errorf("console lines = %d, want 2:\n%s", got, console)
	}
}

func TestChainDetectsTampering(t *testing.T) {
	cases := map[string]func([]string) []string{
		"line deleted": func(l []string) []string { return append(l[:2:2], l[3:]...) },
		"line modified": func(l []string) []string {
			l[1] = strings.Replace(l[1], `"severity":"CRITICAL"`, `"severity":"INFO"`, 1)
			return l
		},
		"lines swapped":  func(l []string) []string { l[1], l[2] = l[2], l[1]; return l },
		"head truncated": func(l []string) []string { return l[1:] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			path, _ := writeN(t, 5)
			data, _ := os.ReadFile(path)
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			os.WriteFile(path, []byte(strings.Join(mutate(lines), "\n")+"\n"), 0o640)
			var ce *ChainError
			if _, err := Verify(path); !errors.As(err, &ce) {
				t.Fatalf("tampering not detected: %v", err)
			}
		})
	}
}

func TestAppendAfterReopenKeepsChain(t *testing.T) {
	path, _ := writeN(t, 3)
	l, _ := New(path, nil)
	l.Write(Record{Type: TypeHeartbeat})
	if n, err := Verify(path); err != nil || n != 4 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
}

func TestLastHashLongLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l, _ := New(path, nil)
	for i := 0; i < 3; i++ {
		l.Write(Record{Type: TypeAgent, Message: strings.Repeat("y", 10000)}) // longer than the first read window
	}
	if n, err := Verify(path); err != nil || n != 3 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
}
