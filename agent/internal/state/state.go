// Package state manages the files in the agent's private state directory: the HMAC key,
// the baseline, the maintenance flag and the last heartbeat. In Docker this directory is the
// agent-state volume, which the monitored application cannot reach (SR-02).
package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	keyFile         = "hmac.key"
	baselineFile    = "baseline.json"
	maintenanceFile = "maintenance.json"
	heartbeatFile   = "heartbeat.json"

	// EnvKey and EnvKeyFile let the key come from a Docker secret or environment variable (SR-08).
	EnvKey     = "FIM_HMAC_KEY"
	EnvKeyFile = "FIM_HMAC_KEY_FILE"
)

var ErrNoKey = errors.New("HMAC key not found; run 'fimagent init' first or set " + EnvKey)

type Dir string

func (d Dir) BaselinePath() string { return filepath.Join(string(d), baselineFile) }

func (d Dir) ensure() error { return os.MkdirAll(string(d), 0o700) }

// Key returns the HMAC key. Priority: FIM_HMAC_KEY, FIM_HMAC_KEY_FILE, then hmac.key in the
// state directory. With create set, a random 32-byte key is generated when none exists.
func (d Dir) Key(create bool) ([]byte, error) {
	if v := os.Getenv(EnvKey); v != "" {
		return decodeKey(v)
	}
	path := filepath.Join(string(d), keyFile)
	if v := os.Getenv(EnvKeyFile); v != "" {
		path = v
	}
	data, err := os.ReadFile(path)
	if err == nil {
		return decodeKey(string(data))
	}
	if !errors.Is(err, os.ErrNotExist) || !create || os.Getenv(EnvKeyFile) != "" {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoKey
		}
		return nil, err
	}
	if err := d.ensure(); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil && len(b) >= 16 {
		return b, nil
	}
	if len(s) < 16 {
		return nil, fmt.Errorf("HMAC key is too short (minimum 16 bytes)")
	}
	return []byte(s), nil
}

// Maintenance is the maintenance mode flag (FR-12).
type Maintenance struct {
	Enabled bool      `json:"enabled"`
	By      string    `json:"by,omitempty"`
	Since   time.Time `json:"since,omitempty"`
	Reason  string    `json:"reason,omitempty"`
}

func (d Dir) Maintenance() (Maintenance, error) {
	var m Maintenance
	err := d.readJSON(maintenanceFile, &m)
	if errors.Is(err, os.ErrNotExist) {
		return Maintenance{}, nil
	}
	return m, err
}

func (d Dir) SetMaintenance(m Maintenance) error { return d.writeJSON(maintenanceFile, m) }

type Heartbeat struct {
	Time time.Time `json:"ts"`
	PID  int       `json:"pid"`
}

// LastHeartbeat returns the zero time if the agent has never run.
func (d Dir) LastHeartbeat() (Heartbeat, error) {
	var h Heartbeat
	err := d.readJSON(heartbeatFile, &h)
	if errors.Is(err, os.ErrNotExist) {
		return Heartbeat{}, nil
	}
	return h, err
}

func (d Dir) SetHeartbeat(t time.Time) error {
	return d.writeJSON(heartbeatFile, Heartbeat{Time: t.UTC(), PID: os.Getpid()})
}

func (d Dir) readJSON(name string, v any) error {
	data, err := os.ReadFile(filepath.Join(string(d), name))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (d Dir) writeJSON(name string, v any) error {
	if err := d.ensure(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(string(d), name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
