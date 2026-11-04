// Package decision turns a detected change into a severity: authorized writes become INFO
// records, everything else becomes an alert whose level depends on the asset type (FR-11, FR-12, FR-14).
package decision

import (
	"path/filepath"
	"strings"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/config"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/scanner"
)

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Info     Severity = "INFO"
)

var rank = map[Severity]int{Info: 0, Medium: 1, High: 2, Critical: 3}

// Rank orders severities; unknown values rank below INFO.
func (s Severity) Rank() int {
	if r, ok := rank[s]; ok {
		return r
	}
	return -1
}

// IsAlert reports whether the severity is an alert rather than an informational record.
func (s Severity) IsAlert() bool { return s.Rank() >= Medium.Rank() }

// ParseSeverity accepts a severity name in any letter case.
func ParseSeverity(s string) (Severity, bool) {
	v := Severity(strings.ToUpper(strings.TrimSpace(s)))
	_, ok := rank[v]
	return v, ok
}

// AssetSeverity is the alert level for content changes and deletions (Section 3.1 of the requirements).
func AssetSeverity(a config.Asset) Severity {
	switch a {
	case config.AssetModel, config.AssetConfig:
		return Critical
	default:
		return High
	}
}

// Process is the process that made the change (FR-10). It is nil when the event source cannot tell.
type Process struct {
	PID  int    `json:"pid"`
	User string `json:"user,omitempty"`
	Exe  string `json:"exe,omitempty"`
	Comm string `json:"comm,omitempty"`
}

type Verdict struct {
	Severity   Severity
	Authorized bool
	Reason     string
}

type Engine struct {
	whitelist []config.WhitelistEntry
}

func NewEngine(cfg *config.Config) *Engine { return &Engine{whitelist: cfg.Whitelist} }

// Decide classifies a change. Maintenance mode suppresses alerts (FR-12).
func (e *Engine) Decide(ch scanner.Change, proc *Process, maintenance bool) Verdict {
	if maintenance {
		return Verdict{Info, true, "maintenance mode is on"}
	}
	if name, ok := e.whitelisted(ch.Path, proc); ok {
		return Verdict{Info, true, "whitelisted process: " + name}
	}
	switch ch.Kind {
	case scanner.Meta:
		return Verdict{Medium, false, "permission or ownership changed"}
	case scanner.Created:
		return Verdict{Medium, false, "new file in monitored directory"}
	case scanner.Deleted:
		return Verdict{AssetSeverity(ch.Asset), false, "monitored file deleted"}
	default:
		return Verdict{AssetSeverity(ch.Asset), false, "content differs from baseline"}
	}
}

func (e *Engine) whitelisted(path string, proc *Process) (string, bool) {
	if proc == nil {
		return "", false
	}
	for _, w := range e.whitelist {
		if w.Exe != "" && w.Exe != proc.Exe {
			continue
		}
		if w.Comm != "" && w.Comm != proc.Comm {
			continue
		}
		if w.User != "" && w.User != proc.User {
			continue
		}
		if len(w.Paths) > 0 && !underAny(path, w.Paths) {
			continue
		}
		name := w.Name
		if name == "" {
			name = filepath.Base(proc.Exe + proc.Comm)
		}
		return name, true
	}
	return "", false
}

func underAny(path string, dirs []string) bool {
	for _, d := range dirs {
		if config.Within(path, d) {
			return true
		}
	}
	return false
}
