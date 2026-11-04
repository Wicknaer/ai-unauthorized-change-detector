// Package scanner compares the current state of files with the baseline.
// It is used both for a single file after a real-time event (FR-07) and for the periodic full scan (FR-08).
package scanner

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/baseline"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/config"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/hasher"
)

type Kind string

const (
	Created  Kind = "created"  // new file that is not in the baseline
	Modified Kind = "modified" // content (hash) changed
	Deleted  Kind = "deleted"  // baseline file no longer exists
	Meta     Kind = "meta"     // only mode or owner changed
)

// Source is how a change was noticed.
const (
	SourceRealtime = "realtime"
	SourceScan     = "scan"
)

type Change struct {
	Path   string
	Kind   Kind
	Asset  config.Asset
	Old    *baseline.Entry
	New    *baseline.Entry
	Source string
}

// Fingerprint is a short digest used so the same deviation does not raise repeated alerts.
func (c Change) Fingerprint() string {
	if c.New == nil {
		return string(c.Kind)
	}
	return string(c.Kind) + "|" + c.New.SHA256 + "|" + c.New.Mode + "|" + c.New.Owner
}

// Compare compares a baseline entry (old) with the observed state (cur). It returns nil if they match.
// mtime is ignored on purpose: a timestamp restored with "touch -r" must not hide a change (T-08).
func Compare(path string, asset config.Asset, old, cur *baseline.Entry) *Change {
	ch := &Change{Path: path, Asset: asset, Old: old, New: cur}
	switch {
	case old == nil && cur == nil:
		return nil
	case old == nil:
		ch.Kind = Created
	case cur == nil:
		ch.Kind = Deleted
		ch.Asset = old.Asset
	case !old.SameContent(*cur):
		ch.Kind = Modified
	case !old.SameMeta(*cur):
		ch.Kind = Meta
	default:
		return nil
	}
	return ch
}

// Stats summarizes a full scan (FR-17).
type Stats struct {
	Files    int           `json:"files"`
	Bytes    int64         `json:"bytes"`
	Changes  int           `json:"changes"`
	Errors   int           `json:"errors"`
	Duration time.Duration `json:"-"`
}

type Scanner struct {
	cfg *config.Config
	h   *hasher.Hasher
}

func New(cfg *config.Config, h *hasher.Hasher) *Scanner { return &Scanner{cfg: cfg, h: h} }

// Path compares a single path with the baseline.
func (s *Scanner) Path(base *baseline.Baseline, path string) (*Change, error) {
	path = filepath.Clean(path)
	old, inBase := base.Entries[path]
	asset, tracked := s.cfg.Classify(path)
	if !tracked && !inBase {
		return nil, nil
	}
	if !tracked {
		asset = old.Asset
	}
	cur, err := baseline.Observe(path, asset, s.h)
	if err != nil {
		return nil, err
	}
	if !tracked && cur != nil {
		cur = nil // the file left the monitored set; treat it like a deletion
	}
	var oldp *baseline.Entry
	if inBase {
		oldp = &old
	}
	return Compare(path, asset, oldp, cur), nil
}

// Under returns the baseline paths below dir. When a directory is deleted or moved,
// some platforms send no event for the files inside it.
func Under(base *baseline.Baseline, dir string) []string {
	prefix := filepath.Clean(dir) + string(filepath.Separator)
	var out []string
	for p := range base.Entries {
		if strings.HasPrefix(p, prefix) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// Full rehashes every monitored file and compares it with the baseline.
func (s *Scanner) Full(base *baseline.Baseline) ([]Change, Stats, error) {
	start := time.Now()
	var (
		changes []Change
		st      Stats
		seen    = make(map[string]bool, len(base.Entries))
	)
	err := baseline.Walk(s.cfg, func(p string, asset config.Asset) error {
		seen[p] = true
		cur, err := baseline.Observe(p, asset, s.h)
		if err != nil {
			st.Errors++
			return nil
		}
		if cur == nil {
			return nil
		}
		st.Files++
		st.Bytes += cur.Size
		var oldp *baseline.Entry
		if old, ok := base.Entries[p]; ok {
			oldp = &old
		}
		if ch := Compare(p, asset, oldp, cur); ch != nil {
			ch.Source = SourceScan
			changes = append(changes, *ch)
		}
		return nil
	})
	if err != nil {
		return nil, st, err
	}
	// Baseline entries the walk did not visit were deleted or no longer match the configured patterns.
	for p, old := range base.Entries {
		if seen[p] {
			continue
		}
		old := old
		ch := Compare(p, old.Asset, &old, nil)
		ch.Source = SourceScan
		changes = append(changes, *ch)
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	st.Changes = len(changes)
	st.Duration = time.Since(start)
	return changes, st, nil
}
