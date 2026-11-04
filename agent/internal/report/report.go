// Package report lists records from the alert log for a time range and exports them
// as a table, CSV or JSON (FR-18, UC-06).
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/logger"
)

type Filter struct {
	Since, Until time.Time
	MinSeverity  decision.Severity
	Types        map[string]bool // empty means every type
}

func (f Filter) match(r logger.Record) bool {
	if !f.Since.IsZero() && r.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && r.Time.After(f.Until) {
		return false
	}
	if f.MinSeverity != "" && r.Severity.Rank() < f.MinSeverity.Rank() {
		return false
	}
	if len(f.Types) > 0 && !f.Types[r.Type] {
		return false
	}
	return true
}

// Read returns the matching records in log order.
func Read(path string, f Filter) ([]logger.Record, error) {
	var out []logger.Record
	err := logger.ReadAll(path, func(r logger.Record) error {
		if f.match(r) {
			out = append(out, r)
		}
		return nil
	})
	return out, err
}

// Counts returns the number of records per severity.
func Counts(recs []logger.Record) map[decision.Severity]int {
	c := map[decision.Severity]int{}
	for _, r := range recs {
		c[r.Severity]++
	}
	return c
}

var csvHeader = []string{"ts", "severity", "type", "event", "path", "asset", "authorized", "source", "latency_ms", "old_sha256", "new_sha256", "process", "message"}

func WriteCSV(w io.Writer, recs []logger.Record) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, r := range recs {
		auth := ""
		if r.Authorized != nil {
			auth = strconv.FormatBool(*r.Authorized)
		}
		lat := ""
		if r.LatencyMS != nil {
			lat = strconv.FormatFloat(*r.LatencyMS, 'f', 3, 64)
		}
		proc := ""
		if r.Process != nil {
			proc = fmt.Sprintf("%d %s", r.Process.PID, r.Process.Exe)
		}
		row := []string{r.Time.Format(time.RFC3339Nano), string(r.Severity), r.Type, r.Event, r.Path, r.Asset, auth, r.Source, lat, r.OldSHA256, r.NewSHA256, proc, r.Message}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func WriteJSON(w io.Writer, recs []logger.Record) error {
	if recs == nil {
		recs = []logger.Record{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(recs)
}

func WriteTable(w io.Writer, recs []logger.Record) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tSEVERITY\tTYPE\tEVENT\tPATH\tMESSAGE")
	for _, r := range recs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Time.Local().Format("2006-01-02 15:04:05"), r.Severity, r.Type, r.Event, r.Path, r.Message)
	}
	return tw.Flush()
}
