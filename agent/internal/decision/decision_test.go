package decision

import (
	"path/filepath"
	"testing"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/config"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/scanner"
)

func engine() *Engine {
	return &Engine{whitelist: []config.WhitelistEntry{
		{Name: "chroma", Comm: "chroma", Paths: []string{filepath.FromSlash("/data/chroma")}},
		{Name: "trainer", Exe: "/usr/bin/python3", User: "ml"},
	}}
}

func TestSeverityByAssetAndKind(t *testing.T) {
	e := engine()
	cases := []struct {
		kind  scanner.Kind
		asset config.Asset
		want  Severity
	}{
		{scanner.Modified, config.AssetModel, Critical},  // T-01
		{scanner.Modified, config.AssetConfig, Critical}, // SR-07
		{scanner.Modified, config.AssetDataset, High},    // T-02
		{scanner.Modified, config.AssetVectorDB, High},   // T-03
		{scanner.Deleted, config.AssetModel, Critical},   // T-06
		{scanner.Meta, config.AssetModel, Medium},        // T-07
		{scanner.Created, config.AssetDataset, Medium},   // new file
	}
	for _, tc := range cases {
		v := e.Decide(scanner.Change{Path: "/data/x", Kind: tc.kind, Asset: tc.asset}, nil, false)
		if v.Severity != tc.want || v.Authorized {
			t.Errorf("%s/%s: got %s authorized=%v, want %s", tc.kind, tc.asset, v.Severity, v.Authorized, tc.want)
		}
	}
}

func TestMaintenanceSuppressesAlerts(t *testing.T) {
	v := engine().Decide(scanner.Change{Path: "/data/m", Kind: scanner.Modified, Asset: config.AssetModel}, nil, true)
	if v.Severity != Info || !v.Authorized {
		t.Errorf("got %+v", v)
	}
}

func TestWhitelist(t *testing.T) {
	e := engine()
	ch := scanner.Change{Path: filepath.FromSlash("/data/chroma/chroma.sqlite3"), Kind: scanner.Modified, Asset: config.AssetVectorDB}

	// T-04: the ChromaDB server writing its own database.
	if v := e.Decide(ch, &Process{PID: 10, Comm: "chroma"}, false); v.Severity != Info || !v.Authorized {
		t.Errorf("chroma: %+v", v)
	}
	// T-03: sqlite3 writing the same file directly is not whitelisted.
	if v := e.Decide(ch, &Process{PID: 11, Comm: "sqlite3"}, false); v.Severity != High || v.Authorized {
		t.Errorf("sqlite3: %+v", v)
	}
	// A whitelisted process outside its allowed paths is still an alert.
	model := scanner.Change{Path: filepath.FromSlash("/data/models/m.gguf"), Kind: scanner.Modified, Asset: config.AssetModel}
	if v := e.Decide(model, &Process{PID: 10, Comm: "chroma"}, false); v.Severity != Critical {
		t.Errorf("chroma on model: %+v", v)
	}
	// User must match when set.
	if v := e.Decide(model, &Process{Exe: "/usr/bin/python3", User: "root"}, false); v.Authorized {
		t.Errorf("wrong user accepted: %+v", v)
	}
	if v := e.Decide(model, &Process{Exe: "/usr/bin/python3", User: "ml"}, false); !v.Authorized {
		t.Errorf("trainer rejected: %+v", v)
	}
}

func TestParseSeverity(t *testing.T) {
	if s, ok := ParseSeverity(" high "); !ok || s != High {
		t.Errorf("got %q %v", s, ok)
	}
	if _, ok := ParseSeverity("urgent"); ok {
		t.Error("unknown severity accepted")
	}
	if !Medium.IsAlert() || Info.IsAlert() {
		t.Error("IsAlert")
	}
}
