package agent

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/attribution"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/logger"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/state"
)

const chromaWhitelist = `whitelist:
  - {name: chromadb-server, comm: chroma, paths: [ai-data/chroma]}
`

func writeBy(t *testing.T, src *attribution.Static, path, content string, p decision.Process) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	src.Set(path, attribution.Write{Proc: p, At: time.Now()})
}

var (
	chromaProc = decision.Process{PID: 100, Comm: "chroma", Exe: "/usr/local/bin/python3.11", User: "chroma"}
	sqliteProc = decision.Process{PID: 200, Comm: "sqlite3", Exe: "/usr/bin/sqlite3", User: "root"}
)

func TestWhitelistedWriterIsInfoAndAccepted(t *testing.T) {
	l := newLab(t, chromaWhitelist)
	a := l.agent()
	src := attribution.NewStatic()
	a.SetAttribution(src)
	db := l.path("chroma/chroma.sqlite3")

	writeBy(t, src, db, "SQLite format 3 + new collection rows", chromaProc) // T-04
	a.checkPath(db, time.Now())
	r, _ := l.detection(db)
	if r.Severity != decision.Info || r.Authorized == nil || !*r.Authorized || r.Process == nil || r.Process.Comm != "chroma" {
		t.Fatalf("legitimate ChromaDB write: %+v", r)
	}
	if a.Accepted() != 1 {
		t.Fatalf("accepted = %d", a.Accepted())
	}

	// The periodic scan must not turn the accepted change into an alert (NFR-07).
	a.ScanOnce("periodic")
	if a.Alerts() != 0 {
		t.Fatalf("scan raised %d alert(s) for an accepted change", a.Alerts())
	}

	// T-03: sqlite3 writes the same file directly, bypassing the API.
	writeBy(t, src, db, "SQLite format 3 + injected row", sqliteProc)
	a.checkPath(db, time.Now())
	r, _ = l.detection(db)
	if r.Severity != decision.High || *r.Authorized || r.Process.Comm != "sqlite3" {
		t.Fatalf("direct sqlite3 write: %+v", r)
	}
	if r.OldSHA256 == r.NewSHA256 {
		t.Error("old hash should be the accepted state, new hash the injected one")
	}
}

func TestWhitelistIsScopedToPaths(t *testing.T) {
	l := newLab(t, chromaWhitelist)
	a := l.agent()
	src := attribution.NewStatic()
	a.SetAttribution(src)
	model := l.path("models/gpt2.safetensors")
	writeBy(t, src, model, "chroma should never write here", chromaProc)
	a.checkPath(model, time.Now())
	if r, _ := l.detection(model); r.Severity != decision.Critical {
		t.Fatalf("whitelisted process outside its paths: %+v", r)
	}
}

func TestLaterUnattributedWriteIsNotCredited(t *testing.T) {
	l := newLab(t, chromaWhitelist)
	a := l.agent()
	src := attribution.NewStatic()
	a.SetAttribution(src)
	db := l.path("chroma/chroma.sqlite3")

	// ChromaDB wrote a minute ago; then the content changed without a write event, as an
	// mmap write does (T-09). The stale record must not make the change look authorized.
	os.WriteFile(db, []byte("modified through mmap"), 0o644)
	src.Set(db, attribution.Write{Proc: chromaProc, At: time.Now().Add(-time.Minute)})
	a.ScanOnce("periodic")
	r, _ := l.detection(db)
	if r.Severity != decision.High || r.Process != nil {
		t.Fatalf("got %+v", r)
	}
}

func TestAcceptedSurvivesRestartAndTamperIsCaught(t *testing.T) {
	l := newLab(t, chromaWhitelist)
	a := l.agent()
	src := attribution.NewStatic()
	a.SetAttribution(src)
	db := l.path("chroma/chroma.sqlite3")
	writeBy(t, src, db, "rows added through the API", chromaProc)
	a.checkPath(db, time.Now())

	// Restart: the startup scan compares against baseline + accepted changes.
	b := l.agent()
	if b.Accepted() != 1 {
		t.Fatalf("accepted after restart = %d", b.Accepted())
	}
	if st, _ := b.ScanOnce("startup"); st.Changes != 0 {
		t.Fatalf("startup scan found %d change(s)", st.Changes)
	}

	// An attacker edits accepted.json to whitelist a poisoned model.
	p := state.Dir(l.cfg.Agent.StateDir).AcceptedPath()
	data, _ := os.ReadFile(p)
	time.Sleep(20 * time.Millisecond)
	os.WriteFile(p, []byte(strings.Replace(string(data), `"asset": "vectordb"`, `"asset": "model"`, 1)), 0o600)
	b.checkState()
	recs := l.records(logger.TypeIntegrity)
	if len(recs) != 1 || recs[0].Event != "accepted_tampered" || recs[0].Severity != decision.Critical {
		t.Fatalf("tamper: %+v", recs)
	}
	if _, err := New(l.cfg, l.log); err == nil {
		t.Error("agent must refuse to start with a forged accepted-changes file")
	}
}

func TestBaselineRenewalClearsAccepted(t *testing.T) {
	l := newLab(t, chromaWhitelist)
	a := l.agent()
	src := attribution.NewStatic()
	a.SetAttribution(src)
	db := l.path("chroma/chroma.sqlite3")
	writeBy(t, src, db, "rows", chromaProc)
	a.checkPath(db, time.Now())

	time.Sleep(20 * time.Millisecond)
	l.rebaseline(t)
	a.checkState()
	if a.Accepted() != 0 {
		t.Errorf("accepted = %d after renewal", a.Accepted())
	}
	if _, err := os.Stat(state.Dir(l.cfg.Agent.StateDir).AcceptedPath()); !os.IsNotExist(err) {
		t.Error("accepted.json should be removed after renewal")
	}
}
