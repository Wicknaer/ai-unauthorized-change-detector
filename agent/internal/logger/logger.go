// Package logger writes every record as a single JSON line (FR-13, NFR-14).
// Each line carries the hash of the previous line, so deleting or editing a line
// breaks the chain and is detectable (SR-06). Records never contain file content (SR-09).
package logger

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
)

// Record types.
const (
	TypeDetection   = "detection"   // a change compared against the baseline
	TypeIntegrity   = "integrity"   // baseline signature or log chain problem
	TypeHeartbeat   = "heartbeat"   // agent liveness (SR-05)
	TypeSummary     = "summary"     // start, stop and periodic scan summaries (FR-17)
	TypeBaseline    = "baseline"    // baseline created or renewed (FR-03)
	TypeMaintenance = "maintenance" // maintenance mode on/off (FR-12)
	TypeAgent       = "agent"       // other operational messages
)

// GenesisHash is the prev_hash of the first line in a log.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

type Record struct {
	Time       time.Time         `json:"ts"`
	Type       string            `json:"type"`
	Severity   decision.Severity `json:"severity"`
	Event      string            `json:"event,omitempty"`
	Path       string            `json:"path,omitempty"`
	Asset      string            `json:"asset,omitempty"`
	OldSHA256  string            `json:"old_sha256,omitempty"`
	NewSHA256  string            `json:"new_sha256,omitempty"`
	OldMode    string            `json:"old_mode,omitempty"`
	NewMode    string            `json:"new_mode,omitempty"`
	OldOwner   string            `json:"old_owner,omitempty"`
	NewOwner   string            `json:"new_owner,omitempty"`
	Process    *decision.Process `json:"process,omitempty"`
	Authorized *bool             `json:"authorized,omitempty"`
	Source     string            `json:"source,omitempty"`
	LatencyMS  *float64          `json:"latency_ms,omitempty"`
	Message    string            `json:"msg,omitempty"`
	Actor      string            `json:"actor,omitempty"`
	Fields     map[string]any    `json:"fields,omitempty"`
	PrevHash   string            `json:"prev_hash"`
	Hash       string            `json:"hash"`
}

// computeHash hashes the record with its own hash field empty; prev_hash is included,
// which is what links the lines into a chain.
func computeHash(r Record) (string, error) {
	r.Hash = ""
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

type Logger struct {
	path    string
	console io.Writer
	mu      sync.Mutex
}

// New opens (or creates) the log file. CRITICAL and HIGH records are also printed to console (FR-15).
func New(path string, console io.Writer) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	f.Close()
	return &Logger{path: path, console: console}, nil
}

func (l *Logger) Path() string { return l.path }

// Write appends a record. The previous hash is read from the end of the file on every write,
// so the CLI and a running agent can share one log without breaking the chain.
func (l *Logger) Write(r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	if r.Severity == "" {
		r.Severity = decision.Info
	}
	prev, err := lastHash(l.path)
	if err != nil {
		return err
	}
	r.PrevHash = prev
	if r.Hash, err = computeHash(r); err != nil {
		return err
	}
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(line, '\n'))
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	if l.console != nil && r.Severity.Rank() >= decision.High.Rank() {
		fmt.Fprintln(l.console, Human(r))
	}
	return nil
}

// Human formats a record as a short single line for the console.
func Human(r Record) string {
	s := fmt.Sprintf("%s [%s] %s", r.Time.Local().Format("2006-01-02 15:04:05.000"), r.Severity, r.Type)
	if r.Event != "" {
		s += " " + r.Event
	}
	if r.Path != "" {
		s += " " + r.Path
	}
	if r.Message != "" {
		s += " - " + r.Message
	}
	return s
}

// lastHash returns the hash of the last line in the file, or GenesisHash for an empty file.
func lastHash(path string) (string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return GenesisHash, nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	size := fi.Size()
	if size == 0 {
		return GenesisHash, nil
	}
	// Read backwards in growing windows until a complete last line is found.
	for window := int64(4096); ; window *= 2 {
		if window > size {
			window = size
		}
		buf := make([]byte, window)
		if _, err := f.ReadAt(buf, size-window); err != nil && err != io.EOF {
			return "", err
		}
		buf = bytes.TrimRight(buf, "\r\n")
		if i := bytes.LastIndexByte(buf, '\n'); i >= 0 || window == size {
			line := buf[i+1:]
			var r struct {
				Hash string `json:"hash"`
			}
			if err := json.Unmarshal(line, &r); err != nil || r.Hash == "" {
				return "", fmt.Errorf("log %s: last line is not a valid record", path)
			}
			return r.Hash, nil
		}
	}
}

// ChainError reports where the hash chain is broken.
type ChainError struct {
	Line   int
	Reason string
}

func (e *ChainError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Reason) }

// Verify walks the whole log and checks every line's hash and link. It returns the number of valid lines.
func Verify(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	prev, n := GenesisHash, 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return n, &ChainError{n + 1, "not valid JSON"}
		}
		if r.PrevHash != prev {
			return n, &ChainError{n + 1, "prev_hash does not match the previous line (line deleted or reordered)"}
		}
		want, err := computeHash(r)
		if err != nil {
			return n, err
		}
		if r.Hash != want {
			return n, &ChainError{n + 1, "hash does not match the content (line modified)"}
		}
		prev = r.Hash
		n++
	}
	return n, sc.Err()
}

// ReadAll decodes every record in the log, calling fn for each one.
func ReadAll(path string, fn func(Record) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for line := 1; sc.Scan(); line++ {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(b, &r); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return sc.Err()
}
