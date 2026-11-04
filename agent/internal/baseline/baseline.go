// Package baseline holds the approved state of every monitored file (SHA-256, size, mode,
// owner, mtime) and signs it with HMAC-SHA256 (FR-02, FR-03, SR-01).
package baseline

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/config"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/hasher"
)

const FormatVersion = 1

// ErrSignature means the baseline signature could not be verified (T-11).
var ErrSignature = errors.New("invalid baseline signature")

// Entry is the approved state of a single file.
type Entry struct {
	SHA256 string       `json:"sha256"`
	Size   int64        `json:"size"`
	Mode   string       `json:"mode"`  // permission bits in octal, e.g. "0644"
	Owner  string       `json:"owner"` // "uid:gid"; empty on Windows
	MTime  time.Time    `json:"mtime"` // informational only, decisions rely on the hash
	Asset  config.Asset `json:"asset"`
}

// SameContent reports whether two entries have the same content.
func (e Entry) SameContent(o Entry) bool { return e.SHA256 == o.SHA256 && e.Size == o.Size }

// SameMeta reports whether two entries have the same mode and owner.
func (e Entry) SameMeta(o Entry) bool { return e.Mode == o.Mode && e.Owner == o.Owner }

type Baseline struct {
	Version   int              `json:"version"`
	CreatedAt time.Time        `json:"created_at"`
	CreatedBy string           `json:"created_by"`
	Reason    string           `json:"reason"`
	Algorithm string           `json:"algorithm"`
	Entries   map[string]Entry `json:"entries"`
	Signature string           `json:"signature"`
}

// Stat builds an entry from file metadata, without the content digest.
func Stat(fi fs.FileInfo, asset config.Asset) Entry {
	return Entry{
		Size:  fi.Size(),
		Mode:  fmt.Sprintf("%04o", fi.Mode().Perm()),
		Owner: owner(fi),
		MTime: fi.ModTime().UTC().Truncate(time.Millisecond),
		Asset: asset,
	}
}

// Observe reads the current state of a file. It returns (nil, nil) if the file does not exist.
func Observe(path string, asset config.Asset, h *hasher.Hasher) (*Entry, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil
	}
	e := Stat(fi, asset)
	sum, n, err := h.File(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // deleted between stat and open
	}
	if err != nil {
		return nil, err
	}
	e.SHA256, e.Size = sum, n
	return &e, nil
}

// Walk visits every monitored file in the configuration and calls fn for each one.
// The configuration file itself is included (SR-07).
func Walk(cfg *config.Config, fn func(path string, asset config.Asset) error) error {
	if asset, ok := cfg.Classify(cfg.Path()); ok {
		if _, err := os.Stat(cfg.Path()); err == nil {
			if err := fn(cfg.Path(), asset); err != nil {
				return err
			}
		}
	}
	for _, root := range cfg.Roots() {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p == root {
					return err
				}
				return nil // an unreadable subdirectory must not stop the scan
			}
			if !d.Type().IsRegular() {
				return nil
			}
			asset, ok := cfg.Classify(p)
			if !ok {
				return nil
			}
			return fn(p, asset)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// Build hashes every monitored file and returns a new, unsigned baseline.
func Build(cfg *config.Config, h *hasher.Hasher, by, reason string) (*Baseline, error) {
	b := &Baseline{
		Version:   FormatVersion,
		CreatedAt: time.Now().UTC(),
		CreatedBy: by,
		Reason:    reason,
		Algorithm: "HMAC-SHA256",
		Entries:   map[string]Entry{},
	}
	err := Walk(cfg, func(p string, asset config.Asset) error {
		e, err := Observe(p, asset, h)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if e != nil {
			b.Entries[p] = *e
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return b, nil
}

// payload is the canonical signed content: the JSON encoding with an empty signature.
// encoding/json sorts map keys, so the output is deterministic.
func (b *Baseline) payload() ([]byte, error) {
	c := *b
	c.Signature = ""
	return json.Marshal(&c)
}

func (b *Baseline) mac(key []byte) ([]byte, error) {
	p, err := b.payload()
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key)
	m.Write(p)
	return m.Sum(nil), nil
}

func (b *Baseline) Sign(key []byte) error {
	sum, err := b.mac(key)
	if err != nil {
		return err
	}
	b.Signature = hex.EncodeToString(sum)
	return nil
}

func (b *Baseline) Verify(key []byte) error {
	want, err := b.mac(key)
	if err != nil {
		return err
	}
	got, err := hex.DecodeString(b.Signature)
	if err != nil || !hmac.Equal(got, want) {
		return ErrSignature
	}
	return nil
}

// Save signs the baseline and writes it atomically (temp file + rename).
func (b *Baseline) Save(path string, key []byte) error {
	if err := b.Sign(key); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".baseline-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Load reads a baseline and verifies its signature. A bad signature returns ErrSignature.
func Load(path string, key []byte) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%w: cannot parse: %v", ErrSignature, err)
	}
	if b.Version != FormatVersion {
		return nil, fmt.Errorf("unsupported baseline version %d", b.Version)
	}
	if err := b.Verify(key); err != nil {
		return nil, err
	}
	if b.Entries == nil {
		b.Entries = map[string]Entry{}
	}
	return &b, nil
}

// TotalSize is the combined size of every file in the baseline.
func (b *Baseline) TotalSize() int64 {
	var n int64
	for _, e := range b.Entries {
		n += e.Size
	}
	return n
}
