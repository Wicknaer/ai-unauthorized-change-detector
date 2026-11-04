package report

import (
	"bytes"
	"encoding/csv"
	"path/filepath"
	"testing"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/logger"
)

func TestFilterAndCSV(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	l, _ := logger.New(path, nil)
	now := time.Now().UTC()
	yes := true
	l.Write(logger.Record{Time: now.Add(-48 * time.Hour), Type: logger.TypeDetection, Severity: decision.Critical, Path: "/old"})
	l.Write(logger.Record{Time: now.Add(-time.Hour), Type: logger.TypeDetection, Severity: decision.Critical, Path: "/m", Event: "modified"})
	l.Write(logger.Record{Time: now.Add(-time.Hour), Type: logger.TypeDetection, Severity: decision.Info, Path: "/c", Authorized: &yes})
	l.Write(logger.Record{Time: now.Add(-time.Minute), Type: logger.TypeHeartbeat, Severity: decision.Info})
	l.Write(logger.Record{Time: now, Type: logger.TypeDetection, Severity: decision.Medium, Path: "/perm"})

	recs, err := Read(path, Filter{Since: now.Add(-24 * time.Hour), MinSeverity: decision.Medium})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Path != "/m" || recs[1].Path != "/perm" {
		t.Fatalf("got %+v", recs)
	}
	recs, _ = Read(path, Filter{Types: map[string]bool{logger.TypeHeartbeat: true}})
	if len(recs) != 1 {
		t.Fatalf("type filter: %d", len(recs))
	}

	all, _ := Read(path, Filter{})
	var buf bytes.Buffer
	if err := WriteCSV(&buf, all); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(rows) != 6 || rows[0][0] != "ts" || rows[3][6] != "true" {
		t.Fatalf("csv rows: %v %v", rows, err)
	}
	if c := Counts(all); c[decision.Critical] != 2 || c[decision.Info] != 2 {
		t.Errorf("counts: %v", c)
	}
}
