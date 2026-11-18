package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/baseline"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/config"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/hasher"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/logger"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/state"
)

// lab is a miniature copy of the Docker test environment: model weights, a dataset,
// a vector DB directory and the agent's private state directory.
type lab struct {
	t    *testing.T
	dir  string
	cfg  *config.Config
	log  *logger.Logger
	key  []byte
	data string
}

func newLab(t *testing.T, extra string) *lab {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "ai-data")
	files := map[string]string{
		"models/gpt2.safetensors":      strings.Repeat("W", 4096),
		"models/tinyllama.gguf":        strings.Repeat("G", 2048),
		"datasets/train.jsonl":         `{"text":"great movie","label":1}` + "\n",
		"chroma/chroma.sqlite3":        "SQLite format 3",
		"chroma/index/data_level0.bin": "hnsw",
	}
	for rel, body := range files {
		p := filepath.Join(data, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	yaml := `agent:
  state_dir: state
  scan_interval: 1h
  debounce: 50ms
  heartbeat_interval: 1h
watch:
  - {name: models, path: ai-data/models, asset: model, patterns: ["*.safetensors", "*.gguf", "*.bin", "*.pt"]}
  - {name: datasets, path: ai-data/datasets, asset: dataset}
  - {name: chroma, path: ai-data/chroma, asset: vectordb}
exclude: ["*-journal", "*-wal", "*-shm"]
` + extra
	cfgPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfgPath, []byte(yaml), 0o644)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	log, err := logger.New(cfg.Agent.LogFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := state.Dir(cfg.Agent.StateDir).Key(true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := baseline.Build(cfg, hasher.New(cfg.ChunkSize()), "test", "initial")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Save(state.Dir(cfg.Agent.StateDir).BaselinePath(), key); err != nil {
		t.Fatal(err)
	}
	return &lab{t: t, dir: dir, cfg: cfg, log: log, key: key, data: data}
}

func (l *lab) path(rel string) string { return filepath.Join(l.data, filepath.FromSlash(rel)) }

func (l *lab) agent() *Agent {
	a, err := New(l.cfg, l.log)
	if err != nil {
		l.t.Fatal(err)
	}
	return a
}

func (l *lab) records(typ string) []logger.Record {
	var out []logger.Record
	logger.ReadAll(l.cfg.Agent.LogFile, func(r logger.Record) error {
		if typ == "" || r.Type == typ {
			out = append(out, r)
		}
		return nil
	})
	return out
}

func (l *lab) detection(path string) (logger.Record, bool) {
	recs := l.records(logger.TypeDetection)
	for i := len(recs) - 1; i >= 0; i-- {
		if recs[i].Path == path {
			return recs[i], true
		}
	}
	return logger.Record{}, false
}

// flipByte overwrites one byte in place, like "dd conv=notrunc" (T-01).
func flipByte(t *testing.T, path string, off int64) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteAt([]byte{'X'}, off)
	f.Close()
}

func TestAttackScenariosDetectedByFullScan(t *testing.T) {
	l := newLab(t, "")
	a := l.agent()

	model := l.path("models/gpt2.safetensors")
	fi, _ := os.Stat(model)
	flipByte(t, model, 100)                       // T-01
	os.Chtimes(model, fi.ModTime(), fi.ModTime()) // T-08: restore mtime like "touch -r"

	dataset := l.path("datasets/train.jsonl")
	f, _ := os.OpenFile(dataset, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"text":"terrible movie","label":1}` + "\n") // T-02: poisoned, flipped label
	f.Close()

	gguf := l.path("models/tinyllama.gguf")
	poisoned := gguf + ".tmp"
	os.WriteFile(poisoned, []byte("backdoored"), 0o644)
	if err := os.Rename(poisoned, gguf); err != nil { // T-05: atomic replace with mv
		t.Fatal(err)
	}

	os.Remove(l.path("chroma/index/data_level0.bin"))                 // T-06
	os.WriteFile(l.path("chroma/chroma.sqlite3-journal"), nil, 0o644) // excluded temp file: no alert
	os.WriteFile(l.path("datasets/extra.csv"), []byte("a,b"), 0o644)  // new file

	st, err := a.ScanOnce("test")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		event string
		sev   decision.Severity
	}{
		model:                                  {"modified", decision.Critical},
		dataset:                                {"modified", decision.High},
		gguf:                                   {"modified", decision.Critical},
		l.path("chroma/index/data_level0.bin"): {"deleted", decision.High},
		l.path("datasets/extra.csv"):           {"created", decision.Medium},
	}
	if st.Changes != len(want) {
		t.Errorf("changes = %d, want %d", st.Changes, len(want))
	}
	for p, w := range want {
		r, ok := l.detection(p)
		if !ok {
			t.Errorf("%s: no detection", p)
			continue
		}
		if r.Event != w.event || r.Severity != w.sev || r.Authorized == nil || *r.Authorized {
			t.Errorf("%s: got %s/%s, want %s/%s", p, r.Event, r.Severity, w.event, w.sev)
		}
		if w.event == "modified" && (r.OldSHA256 == "" || r.NewSHA256 == "" || r.OldSHA256 == r.NewSHA256) {
			t.Errorf("%s: old/new hash missing (FR-13)", p)
		}
	}
	if _, ok := l.detection(l.path("chroma/chroma.sqlite3-journal")); ok {
		t.Error("excluded SQLite journal raised a detection")
	}

	// A second scan must not repeat the same alerts.
	before := len(l.records(logger.TypeDetection))
	a.ScanOnce("again")
	if after := len(l.records(logger.TypeDetection)); after != before {
		t.Errorf("repeated scan added %d detections", after-before)
	}
	if n, err := logger.Verify(l.cfg.Agent.LogFile); err != nil {
		t.Errorf("log chain broken after %d lines: %v", n, err)
	}
}

func TestPermissionChange(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	l := newLab(t, "")
	a := l.agent()
	model := l.path("models/gpt2.safetensors")
	os.Chmod(model, 0o777) // T-07
	a.ScanOnce("test")
	r, ok := l.detection(model)
	if !ok || r.Event != "meta" || r.Severity != decision.Medium || r.NewMode != "0777" {
		t.Errorf("got %+v", r)
	}
}

func TestTamperedBaselineIsRejected(t *testing.T) {
	l := newLab(t, "")
	bp := state.Dir(l.cfg.Agent.StateDir).BaselinePath()
	data, _ := os.ReadFile(bp)
	os.WriteFile(bp, []byte(strings.Replace(string(data), `"size": 4096`, `"size": 4097`, 1)), 0o600) // T-11

	_, err := New(l.cfg, l.log)
	if !errors.Is(err, baseline.ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
	recs := l.records(logger.TypeIntegrity)
	if len(recs) != 1 || recs[0].Severity != decision.Critical {
		t.Fatalf("integrity records: %+v", recs)
	}
}

func TestTamperWhileRunningIsReported(t *testing.T) {
	l := newLab(t, "")
	a := l.agent()
	bp := state.Dir(l.cfg.Agent.StateDir).BaselinePath()
	data, _ := os.ReadFile(bp)
	time.Sleep(20 * time.Millisecond) // make sure the mtime moves
	os.WriteFile(bp, []byte(strings.Replace(string(data), `"created_by": "test"`, `"created_by": "evil"`, 1)), 0o600)
	a.checkState()
	a.checkState() // reported once, not on every poll
	recs := l.records(logger.TypeIntegrity)
	if len(recs) != 1 || recs[0].Event != "baseline_tampered" || recs[0].Severity != decision.Critical {
		t.Fatalf("got %+v", recs)
	}
}

func TestMaintenanceModeSuppressesAlerts(t *testing.T) {
	l := newLab(t, "")
	a := l.agent()
	st := state.Dir(l.cfg.Agent.StateDir)
	st.SetMaintenance(state.Maintenance{Enabled: true, By: "ml-engineer", Since: time.Now()})
	a.checkState()

	model := l.path("models/gpt2.safetensors")
	os.WriteFile(model, []byte("new authorized weights"), 0o644) // T-12
	a.ScanOnce("test")
	r, _ := l.detection(model)
	if r.Severity != decision.Info || r.Authorized == nil || !*r.Authorized {
		t.Fatalf("during maintenance: %+v", r)
	}
	if a.Alerts() != 0 {
		t.Errorf("alerts = %d during maintenance", a.Alerts())
	}

	// Closing maintenance renews the baseline (what 'fimagent maintenance off' does).
	time.Sleep(20 * time.Millisecond)
	b, _ := baseline.Build(l.cfg, hasher.New(0), "ml-engineer", "maintenance window closed")
	b.Save(st.BaselinePath(), l.key)
	st.SetMaintenance(state.Maintenance{})
	a.checkState()
	if len(l.records(logger.TypeBaseline)) != 1 {
		t.Error("baseline reload was not logged")
	}
	stats, _ := a.ScanOnce("after")
	if stats.Changes != 0 || a.Alerts() != 0 {
		t.Errorf("after renewal: %d changes, %d alerts", stats.Changes, a.Alerts())
	}
}

func TestRealtimeDetection(t *testing.T) {
	l := newLab(t, "")
	a := l.agent()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); a.Run(ctx) }()
	defer func() { cancel(); wg.Wait() }()

	waitFor := func(path string, d time.Duration) (logger.Record, bool) {
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			if r, ok := l.detection(path); ok {
				return r, true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return logger.Record{}, false
	}
	// Wait until the startup scan has finished so the watcher is live.
	for i := 0; i < 200 && len(l.records(logger.TypeSummary)) < 2; i++ {
		time.Sleep(10 * time.Millisecond)
	}

	model := l.path("models/gpt2.safetensors")
	start := time.Now()
	flipByte(t, model, 7)
	r, ok := waitFor(model, 3*time.Second)
	if !ok {
		t.Fatal("no real-time detection within 3s")
	}
	elapsed := time.Since(start)
	if r.Source != "realtime" || r.Severity != decision.Critical || r.LatencyMS == nil {
		t.Errorf("got %+v", r)
	}
	t.Logf("write-to-log latency %s (debounce %s, logged latency %.1f ms)", elapsed.Round(time.Millisecond), l.cfg.Agent.Debounce, *r.LatencyMS)
	if elapsed > time.Second {
		t.Errorf("detection took %s, target is <= 1s (NFR-02)", elapsed)
	}

	// FR-06: a file written into a brand-new subdirectory.
	sub := l.path("datasets/new-split")
	os.Mkdir(sub, 0o755)
	os.WriteFile(filepath.Join(sub, "poison.jsonl"), []byte("{}"), 0o644)
	if _, ok := waitFor(filepath.Join(sub, "poison.jsonl"), 3*time.Second); !ok {
		t.Error("file in new subdirectory not detected")
	}

	// Restoring the original content clears the deviation.
	os.WriteFile(model, []byte(strings.Repeat("W", 4096)), 0o644)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r, _ := l.detection(model); r.Event == "restored" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("restore was not logged")
}

func TestConfigFileChangeIsCritical(t *testing.T) {
	l := newLab(t, "")
	a := l.agent()
	a.checkConfigFile() // starting signature
	f, _ := os.OpenFile(l.cfg.Path(), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("# attacker narrows the monitored set\n") // SR-07
	f.Close()
	a.checkConfigFile()
	r, ok := l.detection(l.cfg.Path())
	if !ok || r.Severity != decision.Critical || r.Asset != "config" {
		t.Fatalf("got %+v", r)
	}
}

func TestMonitoringGap(t *testing.T) {
	l := newLab(t, "")
	st := state.Dir(l.cfg.Agent.StateDir)
	st.SetHeartbeat(time.Now().Add(-3 * time.Hour)) // UC-05: agent was stopped
	a := l.agent()
	a.checkGap(time.Now())
	recs := l.records(logger.TypeIntegrity)
	if len(recs) != 1 || recs[0].Event != "monitoring_gap" {
		t.Fatalf("got %+v", recs)
	}
}

// rebaseline does what 'fimagent rebaseline' does: a new signed baseline, accepted changes dropped.
func (l *lab) rebaseline(t *testing.T) {
	t.Helper()
	st := state.Dir(l.cfg.Agent.StateDir)
	b, err := baseline.Build(l.cfg, hasher.New(0), "admin", "test renewal")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Save(st.BaselinePath(), l.key); err != nil {
		t.Fatal(err)
	}
	os.Remove(st.AcceptedPath())
}
