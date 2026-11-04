// Command fimagent is the unauthorized change detection agent for AI file systems.
//
//	fimagent init         create the HMAC key and the first signed baseline (UC-01)
//	fimagent watch        run the agent: real-time events + periodic full scan (UC-02)
//	fimagent scan         one-shot full scan against the baseline
//	fimagent maintenance  turn maintenance mode on/off; "off" renews the baseline (UC-03)
//	fimagent rebaseline   renew the baseline outside maintenance mode (FR-03)
//	fimagent report       list/export alerts for a time range (UC-06)
//	fimagent verify-log   check the hash chain of the alert log (SR-06)
//	fimagent status       show baseline, maintenance and heartbeat information
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/agent"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/baseline"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/config"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/hasher"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/logger"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/report"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/state"
)

var version = "0.1.0"

const usage = `fimagent - unauthorized change detection for AI file systems

Usage:
  fimagent <command> [flags]

Commands:
  init          create the HMAC key and the first signed baseline
  watch         run the agent (real-time events + periodic full scan)
  scan          one-shot full scan against the baseline (exit code 1 if alerts)
  maintenance   on|off - suppress alerts during authorized updates; "off" renews the baseline
  rebaseline    renew the signed baseline
  report        list or export records (-since, -min, -format table|csv|json)
  verify-log    verify the hash chain of the alert log
  status        show baseline, maintenance and heartbeat state
  version       print the version

Every command accepts -config (default $FIM_CONFIG or ./config.yaml).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	code := 0
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "watch":
		err = cmdWatch(args)
	case "scan":
		code, err = cmdScan(args)
	case "maintenance":
		err = cmdMaintenance(args)
	case "rebaseline":
		err = cmdRebaseline(args)
	case "report":
		err = cmdReport(args)
	case "verify-log":
		code, err = cmdVerifyLog(args)
	case "status":
		err = cmdStatus(args)
	case "version", "-v", "--version":
		fmt.Println("fimagent", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fimagent:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// common holds what most commands need: the parsed config, the state dir and the logger.
type common struct {
	cfg *config.Config
	st  state.Dir
	log *logger.Logger
}

func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	def := os.Getenv("FIM_CONFIG")
	if def == "" {
		def = "config.yaml"
	}
	return fs, fs.String("config", def, "path to the YAML configuration file")
}

func load(cfgPath string, console io.Writer) (*common, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	log, err := logger.New(cfg.Agent.LogFile, console)
	if err != nil {
		return nil, err
	}
	return &common{cfg: cfg, st: state.Dir(cfg.Agent.StateDir), log: log}, nil
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "unknown"
}

// renew builds, signs and saves a new baseline and logs who did it and why (FR-03).
func (c *common) renew(key []byte, by, reason, event string) (*baseline.Baseline, error) {
	b, err := baseline.Build(c.cfg, hasher.New(c.cfg.ChunkSize()), by, reason)
	if err != nil {
		return nil, err
	}
	if err := b.Save(c.st.BaselinePath(), key); err != nil {
		return nil, err
	}
	err = c.log.Write(logger.Record{Type: logger.TypeBaseline, Event: event, Path: c.st.BaselinePath(), Actor: by, Message: reason,
		Fields: map[string]any{"files": len(b.Entries), "bytes": b.TotalSize()}})
	return b, err
}

func cmdInit(args []string) error {
	fs, cfgPath := newFlags("init")
	by := fs.String("by", currentUser(), "operator name recorded in the baseline")
	force := fs.Bool("force", false, "overwrite an existing baseline")
	fs.Parse(args)

	c, err := load(*cfgPath, os.Stdout)
	if err != nil {
		return err
	}
	if _, err := os.Stat(c.st.BaselinePath()); err == nil && !*force {
		return fmt.Errorf("baseline already exists at %s (use 'rebaseline' or -force)", c.st.BaselinePath())
	}
	key, err := c.st.Key(true)
	if err != nil {
		return err
	}
	start := time.Now()
	b, err := c.renew(key, *by, "initial baseline", "baseline_created")
	if err != nil {
		return err
	}
	fmt.Printf("baseline created: %d files, %s, %s\n  %s\n", len(b.Entries), humanBytes(b.TotalSize()),
		time.Since(start).Round(time.Millisecond), c.st.BaselinePath())
	return nil
}

func cmdRebaseline(args []string) error {
	fs, cfgPath := newFlags("rebaseline")
	by := fs.String("by", currentUser(), "operator name recorded in the baseline")
	reason := fs.String("reason", "", "why the baseline is renewed (required)")
	fs.Parse(args)
	if strings.TrimSpace(*reason) == "" {
		return errors.New("-reason is required so every renewal is accountable")
	}
	c, err := load(*cfgPath, os.Stdout)
	if err != nil {
		return err
	}
	key, err := c.st.Key(false)
	if err != nil {
		return err
	}
	// Refuse to paper over a tampered baseline silently.
	if _, err := baseline.Load(c.st.BaselinePath(), key); errors.Is(err, baseline.ErrSignature) {
		return fmt.Errorf("current baseline failed verification; investigate before renewing (%w)", err)
	}
	b, err := c.renew(key, *by, *reason, "baseline_renewed")
	if err != nil {
		return err
	}
	fmt.Printf("baseline renewed by %s: %d files\n", *by, len(b.Entries))
	return nil
}

func cmdMaintenance(args []string) error {
	fs, cfgPath := newFlags("maintenance")
	by := fs.String("by", currentUser(), "operator name")
	reason := fs.String("reason", "", "reason for the maintenance window")
	if len(args) == 0 || (args[0] != "on" && args[0] != "off" && args[0] != "status") {
		return errors.New("usage: fimagent maintenance on|off|status [-by NAME] [-reason TEXT]")
	}
	mode := args[0]
	fs.Parse(args[1:])

	c, err := load(*cfgPath, os.Stdout)
	if err != nil {
		return err
	}
	cur, err := c.st.Maintenance()
	if err != nil {
		return err
	}
	switch mode {
	case "status":
		if cur.Enabled {
			fmt.Printf("maintenance: ON since %s by %s (%s)\n", cur.Since.Local().Format(time.RFC3339), cur.By, cur.Reason)
		} else {
			fmt.Println("maintenance: off")
		}
		return nil
	case "on":
		if cur.Enabled {
			return fmt.Errorf("maintenance is already on (since %s, by %s)", cur.Since.Local().Format(time.RFC3339), cur.By)
		}
		m := state.Maintenance{Enabled: true, By: *by, Since: time.Now().UTC(), Reason: *reason}
		if err := c.st.SetMaintenance(m); err != nil {
			return err
		}
		fmt.Println("maintenance mode ON: alerts are suppressed until 'fimagent maintenance off'")
		return c.log.Write(logger.Record{Type: logger.TypeMaintenance, Severity: decision.Medium, Event: "maintenance_on", Actor: *by, Message: *reason})
	default: // off
		if !cur.Enabled {
			return errors.New("maintenance is not on")
		}
		key, err := c.st.Key(false)
		if err != nil {
			return err
		}
		// Renew the baseline before clearing the flag so the agent never compares against the old one.
		why := "maintenance window closed"
		if cur.Reason != "" {
			why += ": " + cur.Reason
		}
		b, err := c.renew(key, *by, why, "baseline_renewed")
		if err != nil {
			return err
		}
		if err := c.st.SetMaintenance(state.Maintenance{}); err != nil {
			return err
		}
		fmt.Printf("maintenance mode OFF: baseline renewed (%d files)\n", len(b.Entries))
		return c.log.Write(logger.Record{Type: logger.TypeMaintenance, Event: "maintenance_off", Actor: *by,
			Fields: map[string]any{"duration_s": int(time.Since(cur.Since).Seconds())}})
	}
}

func cmdScan(args []string) (int, error) {
	fs, cfgPath := newFlags("scan")
	fs.Parse(args)
	c, err := load(*cfgPath, os.Stdout)
	if err != nil {
		return 0, err
	}
	a, err := agent.New(c.cfg, c.log)
	if err != nil {
		return 0, err
	}
	st, err := a.ScanOnce("manual")
	if err != nil {
		return 0, err
	}
	fmt.Printf("scan complete: %d files, %s, %d change(s), %d alert(s), %s\n",
		st.Files, humanBytes(st.Bytes), st.Changes, a.Alerts(), st.Duration.Round(time.Millisecond))
	if a.Alerts() > 0 {
		return 1, nil
	}
	return 0, nil
}

func cmdWatch(args []string) error {
	fs, cfgPath := newFlags("watch")
	fs.Parse(args)
	c, err := load(*cfgPath, os.Stdout)
	if err != nil {
		return err
	}
	a, err := agent.New(c.cfg, c.log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("fimagent %s watching %s (log: %s)\n", version, strings.Join(c.cfg.Roots(), ", "), c.cfg.Agent.LogFile)
	return a.Run(ctx)
}

func cmdReport(args []string) error {
	fs, cfgPath := newFlags("report")
	since := fs.String("since", "24h", "time range: a duration (24h, 30m) or an RFC3339 timestamp")
	until := fs.String("until", "", "end of the range as an RFC3339 timestamp (default: now)")
	minSev := fs.String("min", "MEDIUM", "minimum severity: INFO, MEDIUM, HIGH, CRITICAL")
	types := fs.String("type", "", "comma-separated record types (default: all)")
	format := fs.String("format", "table", "table, csv or json")
	out := fs.String("out", "", "write to a file instead of stdout")
	fs.Parse(args)

	c, err := load(*cfgPath, nil)
	if err != nil {
		return err
	}
	f := report.Filter{Types: map[string]bool{}}
	if f.Since, err = parseTime(*since); err != nil {
		return err
	}
	if *until != "" {
		if f.Until, err = time.Parse(time.RFC3339, *until); err != nil {
			return fmt.Errorf("invalid -until: %w", err)
		}
	}
	sev, ok := decision.ParseSeverity(*minSev)
	if !ok {
		return fmt.Errorf("invalid -min %q", *minSev)
	}
	f.MinSeverity = sev
	for _, t := range strings.Split(*types, ",") {
		if t = strings.TrimSpace(t); t != "" {
			f.Types[t] = true
		}
	}
	recs, err := report.Read(c.cfg.Agent.LogFile, f)
	if err != nil {
		return err
	}
	var w io.Writer = os.Stdout
	if *out != "" {
		file, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer file.Close()
		w = file
	}
	switch *format {
	case "csv":
		err = report.WriteCSV(w, recs)
	case "json":
		err = report.WriteJSON(w, recs)
	case "table":
		err = report.WriteTable(w, recs)
	default:
		return fmt.Errorf("invalid -format %q", *format)
	}
	if err != nil {
		return err
	}
	if *format == "table" || *out != "" {
		counts := report.Counts(recs)
		var parts []string
		for _, s := range []decision.Severity{decision.Critical, decision.High, decision.Medium, decision.Info} {
			if counts[s] > 0 {
				parts = append(parts, fmt.Sprintf("%s=%d", s, counts[s]))
			}
		}
		fmt.Fprintf(os.Stderr, "%d record(s) %s\n", len(recs), strings.Join(parts, " "))
	}
	return nil
}

func cmdVerifyLog(args []string) (int, error) {
	fs, cfgPath := newFlags("verify-log")
	fs.Parse(args)
	c, err := load(*cfgPath, nil)
	if err != nil {
		return 0, err
	}
	n, err := logger.Verify(c.cfg.Agent.LogFile)
	var ce *logger.ChainError
	if errors.As(err, &ce) {
		fmt.Printf("log chain BROKEN after %d valid line(s): %v\n", n, ce)
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	fmt.Printf("log chain OK: %d line(s) verified\n", n)
	return 0, nil
}

func cmdStatus(args []string) error {
	fs, cfgPath := newFlags("status")
	fs.Parse(args)
	c, err := load(*cfgPath, nil)
	if err != nil {
		return err
	}
	fmt.Println("config:     ", c.cfg.Path())
	fmt.Println("state dir:  ", c.cfg.Agent.StateDir)
	fmt.Println("log file:   ", c.cfg.Agent.LogFile)
	for _, w := range c.cfg.Watch {
		pat := "*"
		if len(w.Patterns) > 0 {
			pat = strings.Join(w.Patterns, " ")
		}
		fmt.Printf("watch:       %-10s %-9s %s [%s]\n", w.Name, w.Asset, w.Path, pat)
	}
	key, err := c.st.Key(false)
	if err != nil {
		fmt.Println("baseline:    no key -", err)
	} else if b, err := baseline.Load(c.st.BaselinePath(), key); err != nil {
		fmt.Println("baseline:    INVALID -", err)
	} else {
		perAsset := map[string]int{}
		for _, e := range b.Entries {
			perAsset[string(e.Asset)]++
		}
		keys := make([]string, 0, len(perAsset))
		for k := range perAsset {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, perAsset[k]))
		}
		fmt.Printf("baseline:    signature OK, %d files (%s), %s, created %s by %s\n", len(b.Entries), strings.Join(parts, " "),
			humanBytes(b.TotalSize()), b.CreatedAt.Local().Format(time.RFC3339), b.CreatedBy)
	}
	if m, err := c.st.Maintenance(); err == nil && m.Enabled {
		fmt.Printf("maintenance: ON since %s by %s\n", m.Since.Local().Format(time.RFC3339), m.By)
	} else {
		fmt.Println("maintenance: off")
	}
	if hb, err := c.st.LastHeartbeat(); err == nil && !hb.Time.IsZero() {
		fmt.Printf("heartbeat:   %s ago (pid %d)\n", time.Since(hb.Time).Round(time.Second), hb.PID)
	} else {
		fmt.Println("heartbeat:   never")
	}
	return nil
}

func parseTime(s string) (time.Time, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time %q: use a duration like 24h or an RFC3339 timestamp", s)
	}
	return t, nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
