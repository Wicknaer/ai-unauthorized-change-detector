package scanner

import (
	"testing"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/baseline"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/config"
)

func entry(sha, mode string, mtime time.Time) *baseline.Entry {
	return &baseline.Entry{SHA256: sha, Size: 10, Mode: mode, Owner: "0:0", MTime: mtime, Asset: config.AssetModel}
}

func TestCompare(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	t1 := t0.Add(time.Hour)
	cases := []struct {
		name     string
		old, cur *baseline.Entry
		want     Kind
	}{
		{"unchanged", entry("a", "0644", t0), entry("a", "0644", t0), ""},
		{"only mtime changed is not a change", entry("a", "0644", t0), entry("a", "0644", t1), ""},
		{"content changed, mtime restored (T-08)", entry("a", "0644", t0), entry("b", "0644", t0), Modified},
		{"chmod (T-07)", entry("a", "0644", t0), entry("a", "0777", t0), Meta},
		{"content wins over meta", entry("a", "0644", t0), entry("b", "0777", t0), Modified},
		{"deleted (T-06)", entry("a", "0644", t0), nil, Deleted},
		{"created", nil, entry("a", "0644", t0), Created},
	}
	for _, tc := range cases {
		ch := Compare("/p", config.AssetModel, tc.old, tc.cur)
		got := Kind("")
		if ch != nil {
			got = ch.Kind
		}
		if got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestFingerprintDistinguishesStates(t *testing.T) {
	a := Change{Kind: Modified, New: entry("a", "0644", time.Time{})}
	b := Change{Kind: Modified, New: entry("b", "0644", time.Time{})}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("different contents must have different fingerprints")
	}
	if (Change{Kind: Deleted}).Fingerprint() != "deleted" {
		t.Error("deleted fingerprint")
	}
}
