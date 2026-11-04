package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"data/models", "data/datasets", "data/chroma"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, p
}

const validYAML = `
agent:
  state_dir: state
  scan_interval: 2m
watch:
  - name: models
    path: data/models
    asset: model
    patterns: ["*.safetensors", "*.gguf"]
  - name: chroma
    path: data/chroma
    asset: vectordb
exclude: ["*-journal", "*-wal", "*-shm"]
whitelist:
  - name: chroma
    comm: chroma
    paths: [data/chroma]
`

func TestLoadDefaultsAndRelativePaths(t *testing.T) {
	dir, p := writeConfig(t, validYAML)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := c.Agent.StateDir, filepath.Join(dir, "state"); got != want {
		t.Errorf("state_dir = %q, want %q", got, want)
	}
	if got, want := c.Agent.LogFile, filepath.Join(dir, "state", "alerts.jsonl"); got != want {
		t.Errorf("log_file = %q, want %q", got, want)
	}
	if c.Agent.ScanInterval.Duration != 2*time.Minute {
		t.Errorf("scan_interval = %v", c.Agent.ScanInterval)
	}
	if c.Agent.Debounce.Duration != DefaultDebounce || c.ChunkSize() != 4<<20 {
		t.Errorf("defaults not applied: debounce=%v chunk=%d", c.Agent.Debounce, c.ChunkSize())
	}
	if c.Whitelist[0].Paths[0] != filepath.Join(dir, "data", "chroma") {
		t.Errorf("whitelist path not resolved: %q", c.Whitelist[0].Paths[0])
	}
}

func TestClassify(t *testing.T) {
	dir, p := writeConfig(t, validYAML)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path  string
		asset Asset
		ok    bool
	}{
		{"data/models/gpt2.safetensors", AssetModel, true},
		{"data/models/sub/tiny.gguf", AssetModel, true},
		{"data/models/readme.txt", "", false},               // pattern mismatch
		{"data/chroma/chroma.sqlite3", AssetVectorDB, true}, // no patterns: everything
		{"data/chroma/chroma.sqlite3-journal", "", false},   // excluded SQLite temp file
		{"data/chroma/chroma.sqlite3-wal", "", false},
		{"data/datasets/train.jsonl", "", false}, // directory not configured
		{"config.yaml", AssetConfig, true},       // SR-07: the config itself
		{"../outside.bin", "", false},
	}
	for _, tc := range cases {
		asset, ok := c.Classify(filepath.Join(dir, tc.path))
		if asset != tc.asset || ok != tc.ok {
			t.Errorf("Classify(%s) = %q,%v want %q,%v", tc.path, asset, ok, tc.asset, tc.ok)
		}
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"unknown key": {`
watch:
  - {name: m, path: data/models, asset: model, patern: ["*"]}`, "patern"},
		"no watch":       {`agent: {scan_interval: 1m}`, "at least one watch entry"},
		"bad asset":      {"watch:\n  - {name: m, path: data/models, asset: weights}", "invalid asset"},
		"missing dir":    {"watch:\n  - {name: m, path: data/nope, asset: model}", "cannot access"},
		"bad pattern":    {"watch:\n  - {name: m, path: data/models, asset: model, patterns: ['[']}", "invalid pattern"},
		"bad duration":   {"agent: {scan_interval: soon}\nwatch:\n  - {name: m, path: data/models, asset: model}", "invalid duration"},
		"debounce>=scan": {"agent: {scan_interval: 2s, debounce: 3s}\nwatch:\n  - {name: m, path: data/models, asset: model}", "debounce"},
		"nested roots": {`
watch:
  - {name: all, path: data, asset: dataset}
  - {name: m, path: data/models, asset: model}`, "nested"},
		"state in watch":  {"agent: {state_dir: data/models/state}\nwatch:\n  - {name: m, path: data/models, asset: model}", "state_dir"},
		"empty whitelist": {"watch:\n  - {name: m, path: data/models, asset: model}\nwhitelist:\n  - {name: x}", "exe or comm"},
		"duplicate name": {`
watch:
  - {name: m, path: data/models, asset: model}
  - {name: m, path: data/chroma, asset: vectordb}`, "duplicate"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, p := writeConfig(t, tc.yaml)
			_, err := Load(p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestExampleConfigsAreValidYAML(t *testing.T) {
	// The shipped example configs must at least decode with KnownFields; paths are not checked here.
	for _, p := range []string{"../../../config/agent.docker.yaml", "../../../examples/demo/config.yaml"} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if _, err := Parse(data, filepath.Join(t.TempDir(), "c.yaml")); err != nil && strings.Contains(err.Error(), "cannot parse") {
			t.Errorf("%s: %v", p, err)
		}
	}
}
