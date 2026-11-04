package baseline

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/config"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/hasher"
)

func setup(t *testing.T) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "models", "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "models", "a.safetensors"), []byte("weights-a"), 0o644)
	os.WriteFile(filepath.Join(dir, "models", "sub", "b.gguf"), []byte("weights-b"), 0o644)
	os.WriteFile(filepath.Join(dir, "models", "notes.txt"), []byte("ignored"), 0o644)
	yaml := "agent: {state_dir: state}\nwatch:\n  - {name: m, path: models, asset: model, patterns: ['*.safetensors', '*.gguf']}\n"
	p := filepath.Join(dir, "config.yaml")
	os.WriteFile(p, []byte(yaml), 0o644)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, dir
}

var key = []byte("0123456789abcdef0123456789abcdef")

func TestBuildIncludesMatchingFilesAndConfig(t *testing.T) {
	cfg, dir := setup(t)
	b, err := Build(cfg, hasher.New(0), "tester", "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Entries) != 3 {
		t.Fatalf("entries = %d, want 3 (2 models + config): %v", len(b.Entries), b.Entries)
	}
	e, ok := b.Entries[filepath.Join(dir, "models", "a.safetensors")]
	if !ok || e.Asset != config.AssetModel || e.Size != 9 || len(e.SHA256) != 64 || e.Mode == "" {
		t.Errorf("bad entry: %+v", e)
	}
	if b.Entries[cfg.Path()].Asset != config.AssetConfig {
		t.Error("config file is not in the baseline as a config asset")
	}
}

func TestSaveLoadAndTamperDetection(t *testing.T) {
	cfg, dir := setup(t)
	b, _ := Build(cfg, hasher.New(0), "tester", "test")
	path := filepath.Join(dir, "state", "baseline.json")
	if err := b.Save(path, key); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, key); err != nil {
		t.Fatalf("load of a fresh baseline failed: %v", err)
	}
	if _, err := Load(path, []byte("another-key-another-key-another!")); !errors.Is(err, ErrSignature) {
		t.Errorf("wrong key: err = %v, want ErrSignature", err)
	}

	// T-11: an attacker replaces a hash so a poisoned model would look approved.
	data, _ := os.ReadFile(path)
	target := b.Entries[filepath.Join(dir, "models", "a.safetensors")].SHA256
	forged := strings.Replace(string(data), target, strings.Repeat("0", 64), 1)
	os.WriteFile(path, []byte(forged), 0o600)
	if _, err := Load(path, key); !errors.Is(err, ErrSignature) {
		t.Errorf("forged baseline: err = %v, want ErrSignature", err)
	}

	os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := Load(path, key); !errors.Is(err, ErrSignature) {
		t.Errorf("garbage baseline: err = %v, want ErrSignature", err)
	}
}

func TestObserveMissingAndDirectory(t *testing.T) {
	_, dir := setup(t)
	h := hasher.New(0)
	if e, err := Observe(filepath.Join(dir, "missing"), config.AssetModel, h); e != nil || err != nil {
		t.Errorf("missing file: %v %v", e, err)
	}
	if e, err := Observe(filepath.Join(dir, "models"), config.AssetModel, h); e != nil || err != nil {
		t.Errorf("directory: %v %v", e, err)
	}
}
