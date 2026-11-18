package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/baseline"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/state"
)

// accepted is the set of changes made by whitelisted processes since the baseline was taken
// (FR-11). The baseline itself is only ever renewed from the CLI (FR-03); this overlay lets
// the periodic scan compare a vector database that ChromaDB legitimately keeps writing against
// its last authorized state instead of raising the same false alarm every five minutes.
//
// It is signed with the same HMAC key as the baseline and bound to one baseline signature, so
// it cannot be forged and is discarded automatically when the baseline is renewed.
type accepted struct {
	Version           int                        `json:"version"`
	BaselineSignature string                     `json:"baseline_signature"`
	UpdatedAt         time.Time                  `json:"updated_at"`
	Entries           map[string]*baseline.Entry `json:"entries"` // nil value: deleted by an authorized process
	Signature         string                     `json:"signature"`
}

func newAccepted(base *baseline.Baseline) *accepted {
	return &accepted{Version: 1, BaselineSignature: base.Signature, Entries: map[string]*baseline.Entry{}}
}

func (x *accepted) mac(key []byte) ([]byte, error) {
	c := *x
	c.Signature = ""
	p, err := json.Marshal(&c)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key)
	m.Write(p)
	return m.Sum(nil), nil
}

func (x *accepted) save(path string, key []byte) error {
	x.UpdatedAt = time.Now().UTC()
	sum, err := x.mac(key)
	if err != nil {
		return err
	}
	x.Signature = hex.EncodeToString(sum)
	data, err := json.MarshalIndent(x, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".accepted-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// loadAccepted returns the overlay for the given baseline. A missing file, or one written for
// an older baseline, yields an empty overlay; a bad signature returns baseline.ErrSignature.
func loadAccepted(path string, key []byte, base *baseline.Baseline) (*accepted, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return newAccepted(base), false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var x accepted
	if err := json.Unmarshal(data, &x); err != nil {
		return nil, false, baseline.ErrSignature
	}
	want, err := x.mac(key)
	if err != nil {
		return nil, false, err
	}
	got, err := hex.DecodeString(x.Signature)
	if err != nil || !hmac.Equal(got, want) {
		return nil, false, baseline.ErrSignature
	}
	if x.BaselineSignature != base.Signature {
		return newAccepted(base), true, nil // stale: belongs to a previous baseline
	}
	if x.Entries == nil {
		x.Entries = map[string]*baseline.Entry{}
	}
	return &x, false, nil
}

// view is the baseline with the accepted changes applied; this is what files are compared to.
func view(base *baseline.Baseline, x *accepted) *baseline.Baseline {
	if x == nil || len(x.Entries) == 0 {
		return base
	}
	v := *base
	v.Entries = make(map[string]baseline.Entry, len(base.Entries)+len(x.Entries))
	for p, e := range base.Entries {
		v.Entries[p] = e
	}
	for p, e := range x.Entries {
		if e == nil {
			delete(v.Entries, p)
		} else {
			v.Entries[p] = *e
		}
	}
	return &v
}

// AcceptedCount verifies the accepted-changes file of a state directory and returns its size.
func AcceptedCount(st state.Dir, key []byte, base *baseline.Baseline) (int, error) {
	x, _, err := loadAccepted(st.AcceptedPath(), key, base)
	if err != nil {
		return 0, err
	}
	return len(x.Entries), nil
}
