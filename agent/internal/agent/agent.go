// Package agent wires the components together: real-time events and the periodic full scan
// both go through the same decision step (Section 3.3 of the requirements), and every result
// is written to the hash-chained log.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/attribution"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/baseline"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/config"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/hasher"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/logger"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/scanner"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/state"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/watcher"
)

// stateCheckInterval is how often the agent polls the state directory for maintenance mode
// changes and baseline file tampering.
const stateCheckInterval = 2 * time.Second

type Agent struct {
	cfg *config.Config
	st  state.Dir
	key []byte
	sc  *scanner.Scanner
	eng *decision.Engine
	log *logger.Logger

	base        *baseline.Baseline
	baseModTime time.Time
	baseBroken  bool               // on-disk baseline failed verification; reported once
	acc         *accepted          // changes accepted from whitelisted processes (FR-11)
	accModTime  time.Time          // mtime of accepted.json after our last write
	accBroken   bool               // accepted.json failed verification; reported once
	view        *baseline.Baseline // base + acc: what files are compared to
	src         attribution.Source // writer of each file (FR-10); nil if unavailable
	maint       state.Maintenance  // last known maintenance state
	reported    map[string]string  // path -> fingerprint of the last reported deviation
	configSig   string             // size|mtime of the config file at the last poll
	alerts      int
}

// New loads the key and the signed baseline. A bad signature is logged as CRITICAL (SR-01).
func New(cfg *config.Config, log *logger.Logger) (*Agent, error) {
	st := state.Dir(cfg.Agent.StateDir)
	key, err := st.Key(false)
	if err != nil {
		return nil, err
	}
	a := &Agent{
		cfg:      cfg,
		st:       st,
		key:      key,
		sc:       scanner.New(cfg, hasher.New(cfg.ChunkSize())),
		eng:      decision.NewEngine(cfg),
		log:      log,
		reported: map[string]string{},
	}
	if err := a.loadBaseline(); err != nil {
		if errors.Is(err, baseline.ErrSignature) {
			a.write(logger.Record{
				Type: logger.TypeIntegrity, Severity: decision.Critical, Event: "baseline_signature_invalid",
				Path: st.BaselinePath(), Message: "baseline signature verification failed; refusing to start",
			})
		}
		return nil, err
	}
	if err := a.loadAccepted(); err != nil {
		a.write(logger.Record{
			Type: logger.TypeIntegrity, Severity: decision.Critical, Event: "accepted_signature_invalid",
			Path: st.AcceptedPath(), Message: "accepted-changes file failed verification; refusing to start",
		})
		return nil, err
	}
	if a.maint, err = st.Maintenance(); err != nil {
		return nil, err
	}
	return a, nil
}

// SetAttribution sets the source used to find the writer of a file. Run opens fanotify
// itself when none was set.
func (a *Agent) SetAttribution(src attribution.Source) { a.src = src }

func (a *Agent) loadAccepted() error {
	x, stale, err := loadAccepted(a.st.AcceptedPath(), a.key, a.base)
	if err != nil {
		return err
	}
	if stale {
		os.Remove(a.st.AcceptedPath())
	}
	a.acc, a.accBroken = x, false
	a.accModTime = modTime(a.st.AcceptedPath())
	a.view = view(a.base, a.acc)
	return nil
}

func modTime(p string) time.Time {
	if fi, err := os.Stat(p); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

// accept records a change made by a whitelisted process so later scans compare against it.
func (a *Agent) accept(ch scanner.Change) {
	a.acc.Entries[ch.Path] = ch.New
	if err := a.acc.save(a.st.AcceptedPath(), a.key); err != nil {
		a.write(logger.Record{Type: logger.TypeAgent, Severity: decision.Medium, Path: a.st.AcceptedPath(),
			Message: "cannot save accepted changes: " + err.Error()})
	}
	a.accModTime = modTime(a.st.AcceptedPath())
	a.view = view(a.base, a.acc)
	delete(a.reported, ch.Path) // the file now matches the view
}

// attribute returns the process that last wrote the file, if that write explains its
// current content (see attribution.Write.Explains).
func (a *Agent) attribute(ch scanner.Change) *decision.Process {
	if a.src == nil || ch.New == nil {
		return nil
	}
	w, ok := a.src.LastWrite(ch.Path)
	if !ok || !w.Explains(ch.New.MTime) {
		return nil
	}
	p := w.Proc
	return &p
}

func (a *Agent) loadBaseline() error {
	p := a.st.BaselinePath()
	b, err := baseline.Load(p, a.key)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("no baseline at %s; run 'fimagent init' first", p)
		}
		return err
	}
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	a.base, a.baseModTime, a.baseBroken = b, fi.ModTime(), false
	a.view = view(a.base, a.acc)
	a.reported = map[string]string{}
	return nil
}

func (a *Agent) Baseline() *baseline.Baseline { return a.base }

// Accepted is the number of changes currently accepted from whitelisted processes.
func (a *Agent) Accepted() int { return len(a.acc.Entries) }

// Alerts is the number of alerts (MEDIUM or above) written since the agent was created.
func (a *Agent) Alerts() int { return a.alerts }

func (a *Agent) write(r logger.Record) {
	if r.Severity.IsAlert() {
		a.alerts++
	}
	if err := a.log.Write(r); err != nil {
		fmt.Fprintln(os.Stderr, "fimagent: cannot write log:", err)
	}
}

// handle runs the decision step for one change and logs the result once per distinct deviation.
func (a *Agent) handle(ch scanner.Change, first time.Time) {
	fp := ch.Fingerprint()
	if a.reported[ch.Path] == fp {
		return
	}
	a.reported[ch.Path] = fp
	proc := a.attribute(ch)
	v := a.eng.Decide(ch, proc, a.maint.Enabled)
	rec := logger.Record{
		Type:       logger.TypeDetection,
		Severity:   v.Severity,
		Event:      string(ch.Kind),
		Path:       ch.Path,
		Asset:      string(ch.Asset),
		Process:    proc,
		Authorized: &v.Authorized,
		Source:     ch.Source,
		Message:    v.Reason,
	}
	if ch.Old != nil {
		rec.OldSHA256, rec.OldMode, rec.OldOwner = ch.Old.SHA256, ch.Old.Mode, ch.Old.Owner
	}
	if ch.New != nil {
		rec.NewSHA256, rec.NewMode, rec.NewOwner = ch.New.SHA256, ch.New.Mode, ch.New.Owner
	}
	if !first.IsZero() {
		ms := float64(time.Since(first).Microseconds()) / 1000
		rec.LatencyMS = &ms
	}
	a.write(rec)
	if v.Authorized && !a.maint.Enabled {
		a.accept(ch) // maintenance changes are folded into the renewed baseline instead
	}
}

// checkPath compares one path with the baseline after a real-time event.
func (a *Agent) checkPath(path string, first time.Time) {
	ch, err := a.sc.Path(a.view, path)
	if err != nil {
		a.write(logger.Record{Type: logger.TypeAgent, Severity: decision.Medium, Path: path, Message: "cannot check file: " + err.Error()})
		return
	}
	if ch == nil {
		// The file matches the baseline again (for example it was restored); clear the old deviation.
		if _, ok := a.reported[path]; ok {
			delete(a.reported, path)
			a.write(logger.Record{Type: logger.TypeDetection, Event: "restored", Path: path, Source: scanner.SourceRealtime,
				Message: "file matches the baseline again"})
		}
		return
	}
	ch.Source = scanner.SourceRealtime
	a.handle(*ch, first)
}

func (a *Agent) onEvent(ev watcher.Event) {
	if ev.Overflow {
		a.write(logger.Record{Type: logger.TypeAgent, Severity: decision.Medium, Event: "queue_overflow",
			Message: "kernel event queue overflowed; running a full scan"})
		a.ScanOnce("overflow")
		return
	}
	paths := []string{ev.Path}
	if ev.NewDir {
		_ = filepath.WalkDir(ev.Path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				paths = append(paths, p)
			}
			return nil
		})
	}
	// A removed or renamed directory may not produce events for the files inside it.
	paths = append(paths, scanner.Under(a.view, ev.Path)...)
	for _, p := range paths {
		a.checkPath(p, ev.First)
	}
}

// ScanOnce rehashes everything, logs each deviation and writes a summary record (FR-08, FR-17).
func (a *Agent) ScanOnce(reason string) (scanner.Stats, error) {
	a.verifyBaselineOnDisk()
	changes, st, err := a.sc.Full(a.view)
	if err != nil {
		a.write(logger.Record{Type: logger.TypeAgent, Severity: decision.High, Message: "full scan failed: " + err.Error()})
		return st, err
	}
	current := map[string]bool{}
	for _, ch := range changes {
		current[ch.Path] = true
		a.handle(ch, time.Time{})
	}
	for p := range a.reported {
		if !current[p] {
			delete(a.reported, p) // the deviation is gone (restored or re-baselined)
		}
	}
	a.write(logger.Record{Type: logger.TypeSummary, Event: "scan_complete", Message: reason, Fields: map[string]any{
		"files": st.Files, "bytes": st.Bytes, "changes": st.Changes, "errors": st.Errors,
		"duration_ms": st.Duration.Milliseconds(),
	}})
	return st, nil
}

// verifyBaselineOnDisk detects tampering with the baseline file (T-11) and reloads it after
// an authorized renewal (maintenance off or 'fimagent rebaseline').
func (a *Agent) verifyBaselineOnDisk() {
	p := a.st.BaselinePath()
	fi, err := os.Stat(p)
	if err == nil && fi.ModTime().Equal(a.baseModTime) && !a.baseBroken {
		return
	}
	b, lerr := baseline.Load(p, a.key)
	if err != nil || lerr != nil {
		if !a.baseBroken {
			a.baseBroken = true
			msg := "baseline file changed and its signature is invalid; keeping the last trusted baseline in memory"
			if err != nil {
				msg = "baseline file is missing; keeping the last trusted baseline in memory"
			}
			a.write(logger.Record{Type: logger.TypeIntegrity, Severity: decision.Critical, Event: "baseline_tampered", Path: p, Message: msg})
		}
		return
	}
	renewed := b.Signature != a.base.Signature
	a.base, a.baseModTime, a.baseBroken = b, fi.ModTime(), false
	if renewed {
		a.acc = newAccepted(b) // accepted changes are part of the renewed baseline
		os.Remove(a.st.AcceptedPath())
		a.accModTime = time.Time{}
		a.view = view(a.base, a.acc)
		a.reported = map[string]string{}
		a.write(logger.Record{Type: logger.TypeBaseline, Event: "baseline_reloaded", Path: p, Actor: b.CreatedBy,
			Message: "signed baseline renewed: " + b.Reason, Fields: map[string]any{"files": len(b.Entries)}})
	}
}

func (a *Agent) checkState() {
	m, err := a.st.Maintenance()
	if err == nil && m.Enabled != a.maint.Enabled {
		a.maint = m
	}
	a.verifyBaselineOnDisk()
	a.verifyAcceptedOnDisk()
	a.checkConfigFile()
}

// verifyAcceptedOnDisk detects tampering with accepted.json: only the agent writes it.
func (a *Agent) verifyAcceptedOnDisk() {
	p := a.st.AcceptedPath()
	if mt := modTime(p); mt.Equal(a.accModTime) && !a.accBroken {
		return
	}
	x, _, err := loadAccepted(p, a.key, a.base)
	if err != nil {
		if !a.accBroken {
			a.accBroken = true
			a.write(logger.Record{Type: logger.TypeIntegrity, Severity: decision.Critical, Event: "accepted_tampered", Path: p,
				Message: "accepted-changes file was modified outside the agent; keeping the trusted copy in memory"})
		}
		return
	}
	if len(x.Entries) < len(a.acc.Entries) {
		a.write(logger.Record{Type: logger.TypeIntegrity, Severity: decision.Medium, Event: "accepted_reset", Path: p,
			Message: "accepted-changes file was removed or reset; earlier authorized changes will be reported again"})
	}
	a.acc, a.accModTime, a.accBroken = x, modTime(p), false
	a.view = view(a.base, a.acc)
}

// checkConfigFile polls the agent's own configuration file (SR-07); the full check only runs
// when its size or mtime moved, and the decision itself still relies on the hash.
func (a *Agent) checkConfigFile() {
	p := a.cfg.Path()
	sig := "missing"
	if fi, err := os.Stat(p); err == nil {
		sig = fmt.Sprintf("%d|%d", fi.Size(), fi.ModTime().UnixNano())
	}
	if sig == a.configSig {
		return
	}
	first := a.configSig == ""
	a.configSig = sig
	if !first {
		a.checkPath(p, time.Now())
	}
}

// checkGap reports a monitoring gap when the previous run stopped sending heartbeats (UC-05, SR-05).
func (a *Agent) checkGap(now time.Time) {
	hb, err := a.st.LastHeartbeat()
	if err != nil || hb.Time.IsZero() {
		return
	}
	gap := now.Sub(hb.Time)
	if gap > 2*a.cfg.Agent.HeartbeatInterval.Duration {
		a.write(logger.Record{Type: logger.TypeIntegrity, Severity: decision.High, Event: "monitoring_gap",
			Message: fmt.Sprintf("agent was not running for %s; changes made in this window are detected by the startup scan", gap.Round(time.Second)),
			Fields:  map[string]any{"last_heartbeat": hb.Time, "gap_seconds": int(gap.Seconds())}})
	}
}

func (a *Agent) heartbeat(now time.Time) {
	_ = a.st.SetHeartbeat(now)
	a.write(logger.Record{Type: logger.TypeHeartbeat, Fields: map[string]any{"pid": os.Getpid(), "alerts": a.alerts}})
}

// Run starts real-time monitoring and blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	start := time.Now()
	a.checkGap(start)

	a.checkConfigFile() // record the starting signature
	attrMode := "unavailable"
	if a.src == nil {
		src, err := attribution.Open(a.cfg.Roots())
		if err != nil {
			a.write(logger.Record{Type: logger.TypeAgent, Event: "attribution_unavailable",
				Message: "process attribution disabled: " + err.Error()})
		} else {
			a.src = src
			defer src.Close()
		}
	}
	if a.src != nil {
		attrMode = "enabled"
		if m, ok := a.src.(attribution.ModeReporter); ok {
			attrMode = "fanotify/" + m.Mode()
		}
	}
	w, err := watcher.New(a.cfg.Roots(), a.cfg.Agent.Debounce.Duration)
	if err != nil {
		return fmt.Errorf("cannot start watcher: %w", err)
	}
	defer w.Close()
	go w.Run(ctx)

	a.write(logger.Record{Type: logger.TypeSummary, Event: "agent_start", Message: "monitoring started", Fields: map[string]any{
		"pid": os.Getpid(), "roots": a.cfg.Roots(), "baseline_files": len(a.base.Entries), "baseline_by": a.base.CreatedBy,
		"maintenance": a.maint.Enabled, "accepted_changes": len(a.acc.Entries), "attribution": attrMode,
	}})
	a.heartbeat(start)
	a.ScanOnce("startup") // catches changes made while the agent was stopped (NFR-10)

	scanT := time.NewTicker(a.cfg.Agent.ScanInterval.Duration)
	hbT := time.NewTicker(a.cfg.Agent.HeartbeatInterval.Duration)
	stT := time.NewTicker(stateCheckInterval)
	defer scanT.Stop()
	defer hbT.Stop()
	defer stT.Stop()

	for {
		select {
		case <-ctx.Done():
			a.write(logger.Record{Type: logger.TypeSummary, Event: "agent_stop", Message: "monitoring stopped",
				Fields: map[string]any{"uptime_s": int(time.Since(start).Seconds()), "alerts": a.alerts}})
			return nil
		case ev := <-w.Events():
			a.checkState()
			a.onEvent(ev)
		case <-scanT.C:
			a.ScanOnce("periodic")
		case t := <-hbT.C:
			a.heartbeat(t)
		case <-stT.C:
			a.checkState()
		}
	}
}
