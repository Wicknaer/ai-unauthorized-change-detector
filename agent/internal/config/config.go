// Package config reads and validates the agent's YAML configuration file (FR-01).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Asset is the kind of monitored file; the alert severity is derived from it.
type Asset string

const (
	AssetModel    Asset = "model"    // model weights
	AssetConfig   Asset = "config"   // agent configuration and baseline
	AssetVectorDB Asset = "vectordb" // ChromaDB
	AssetDataset  Asset = "dataset"  // training / fine-tuning datasets
)

func (a Asset) valid() bool {
	switch a {
	case AssetModel, AssetConfig, AssetVectorDB, AssetDataset:
		return true
	}
	return false
}

// Defaults come from the targets in the requirements analysis.
const (
	DefaultScanInterval      = 5 * time.Minute        // FR-08
	DefaultDebounce          = 500 * time.Millisecond // FR-09
	DefaultHeartbeatInterval = 60 * time.Second       // SR-05
	DefaultChunkMB           = 4                      // FR-04
	DefaultLogMaxMB          = 100                    // NFR-11: 5 x 100 MB
	DefaultLogKeep           = 5
)

// Duration is a time.Duration written in YAML as "5m", "500ms", etc.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q", n.Line, s)
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

type AgentConfig struct {
	StateDir          string   `yaml:"state_dir"`
	LogFile           string   `yaml:"log_file"`
	ScanInterval      Duration `yaml:"scan_interval"`
	Debounce          Duration `yaml:"debounce"`
	HeartbeatInterval Duration `yaml:"heartbeat_interval"`
	HashChunkMB       int      `yaml:"hash_chunk_mb"`
	LogMaxMB          int      `yaml:"log_max_mb"` // rotate the alert log at this size (NFR-11)
	LogKeep           int      `yaml:"log_keep"`   // files kept, including the active one
}

// WatchEntry describes a monitored directory. An empty Patterns list matches every file.
type WatchEntry struct {
	Name     string   `yaml:"name"`
	Path     string   `yaml:"path"`
	Asset    Asset    `yaml:"asset"`
	Patterns []string `yaml:"patterns"`
}

// WhitelistEntry is a process that is allowed to modify monitored files (FR-11).
// At least one of Exe or Comm must be set; an empty Paths list applies to every monitored directory.
type WhitelistEntry struct {
	Name  string   `yaml:"name"`
	Exe   string   `yaml:"exe"`
	Comm  string   `yaml:"comm"`
	User  string   `yaml:"user"`
	Paths []string `yaml:"paths"`
}

type Config struct {
	Agent     AgentConfig      `yaml:"agent"`
	Watch     []WatchEntry     `yaml:"watch"`
	Exclude   []string         `yaml:"exclude"`
	Whitelist []WhitelistEntry `yaml:"whitelist"`

	path string // absolute path of the config file (monitored itself, SR-07)
}

// Load reads the file, applies defaults and validates the result.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("cannot read config: %w", err)
	}
	return Parse(data, abs)
}

// Parse decodes YAML content. Relative paths are resolved against the config file's directory.
func Parse(data []byte, path string) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // misspelled keys must not be silently ignored
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("cannot parse config: %w", err)
	}
	c.path = filepath.Clean(path)
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	base := filepath.Dir(c.path)
	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return filepath.Clean(p)
		}
		return filepath.Join(base, p)
	}
	if c.Agent.StateDir == "" {
		c.Agent.StateDir = "state"
	}
	if c.Agent.LogFile == "" {
		c.Agent.LogFile = filepath.Join(c.Agent.StateDir, "alerts.jsonl")
	}
	c.Agent.StateDir = resolve(c.Agent.StateDir)
	c.Agent.LogFile = resolve(c.Agent.LogFile)
	if c.Agent.ScanInterval.Duration == 0 {
		c.Agent.ScanInterval.Duration = DefaultScanInterval
	}
	if c.Agent.Debounce.Duration == 0 {
		c.Agent.Debounce.Duration = DefaultDebounce
	}
	if c.Agent.HeartbeatInterval.Duration == 0 {
		c.Agent.HeartbeatInterval.Duration = DefaultHeartbeatInterval
	}
	if c.Agent.HashChunkMB == 0 {
		c.Agent.HashChunkMB = DefaultChunkMB
	}
	if c.Agent.LogMaxMB == 0 {
		c.Agent.LogMaxMB = DefaultLogMaxMB
	}
	if c.Agent.LogKeep == 0 {
		c.Agent.LogKeep = DefaultLogKeep
	}
	for i := range c.Watch {
		c.Watch[i].Path = resolve(c.Watch[i].Path)
	}
	for i := range c.Whitelist {
		for j, p := range c.Whitelist[i].Paths {
			c.Whitelist[i].Paths[j] = resolve(p)
		}
	}
}

func (c *Config) validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if len(c.Watch) == 0 {
		add("at least one watch entry is required")
	}
	names := map[string]bool{}
	for i, w := range c.Watch {
		label := w.Name
		if label == "" {
			add("watch[%d]: name must not be empty", i)
			label = fmt.Sprintf("watch[%d]", i)
		} else if names[w.Name] {
			add("%s: duplicate watch name", label)
		}
		names[w.Name] = true
		if !w.Asset.valid() {
			add("%s: invalid asset %q (model, config, vectordb, dataset)", label, w.Asset)
		}
		if w.Path == "" || w.Path == "." {
			add("%s: path must not be empty", label)
		} else if fi, err := os.Stat(w.Path); err != nil {
			add("%s: cannot access monitored directory: %v", label, err)
		} else if !fi.IsDir() {
			add("%s: %s is not a directory", label, w.Path)
		}
		for _, p := range w.Patterns {
			if _, err := filepath.Match(p, ""); err != nil {
				add("%s: invalid pattern %q", label, p)
			}
		}
	}
	// Nested roots would put the same file under two asset types.
	for i := range c.Watch {
		for j := range c.Watch {
			if i != j && c.Watch[i].Path != "" && within(c.Watch[j].Path, c.Watch[i].Path) {
				add("%s and %s: monitored directories must not be nested", c.Watch[i].Name, c.Watch[j].Name)
			}
		}
	}
	for _, p := range c.Exclude {
		if _, err := filepath.Match(p, ""); err != nil {
			add("exclude: invalid pattern %q", p)
		}
	}
	for i, w := range c.Whitelist {
		if w.Exe == "" && w.Comm == "" {
			add("whitelist[%d]: one of exe or comm must be set", i)
		}
	}
	a := c.Agent
	if a.ScanInterval.Duration < time.Second {
		add("agent.scan_interval must be at least 1s")
	}
	if a.Debounce.Duration < 0 || a.Debounce.Duration >= a.ScanInterval.Duration {
		add("agent.debounce must be between 0 and scan_interval")
	}
	if a.HeartbeatInterval.Duration < time.Second {
		add("agent.heartbeat_interval must be at least 1s")
	}
	if a.HashChunkMB < 1 || a.HashChunkMB > 256 {
		add("agent.hash_chunk_mb must be between 1 and 256")
	}
	if a.LogMaxMB < 1 {
		add("agent.log_max_mb must be at least 1")
	}
	if a.LogKeep < 2 || a.LogKeep > 100 {
		add("agent.log_keep must be between 2 and 100")
	}
	// A state dir inside a monitored directory would turn every heartbeat into a change.
	for _, w := range c.Watch {
		if w.Path != "" && within(a.StateDir, w.Path) {
			add("agent.state_dir must not be inside monitored directory %s", w.Name)
		}
	}
	return errors.Join(errs...)
}

// Path is the absolute path of the config file.
func (c *Config) Path() string { return c.path }

// ChunkSize is the hash read chunk size in bytes.
func (c *Config) ChunkSize() int { return c.Agent.HashChunkMB << 20 }

// Classify reports whether a path is monitored and which asset type it belongs to.
// The file does not need to exist, so deleted files are classified the same way.
func (c *Config) Classify(path string) (Asset, bool) {
	path = filepath.Clean(path)
	if samePath(path, c.path) {
		return AssetConfig, true // SR-07: the agent's own configuration
	}
	for _, w := range c.Watch {
		if !within(path, w.Path) || samePath(path, w.Path) {
			continue
		}
		name := filepath.Base(path)
		rel, _ := filepath.Rel(w.Path, path)
		if c.Excluded(rel, name) {
			return "", false
		}
		if len(w.Patterns) == 0 {
			return w.Asset, true
		}
		for _, p := range w.Patterns {
			if ok, _ := filepath.Match(p, name); ok {
				return w.Asset, true
			}
		}
		return "", false
	}
	return "", false
}

// Excluded reports whether the file name, or its path relative to the watch root, matches an exclude pattern.
func (c *Config) Excluded(rel, name string) bool {
	rel = filepath.ToSlash(rel)
	for _, p := range c.Exclude {
		if ok, _ := filepath.Match(p, name); ok {
			return true
		}
		if ok, _ := filepath.Match(p, rel); ok {
			return true
		}
	}
	return false
}

// Roots returns the monitored root directories.
func (c *Config) Roots() []string {
	roots := make([]string, 0, len(c.Watch))
	for _, w := range c.Watch {
		roots = append(roots, w.Path)
	}
	return roots
}

// Within reports whether path is dir itself or below it.
func Within(path, dir string) bool { return within(filepath.Clean(path), filepath.Clean(dir)) }

func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func samePath(a, b string) bool {
	if filepath.Separator == '\\' {
		return strings.EqualFold(a, b)
	}
	return a == b
}
