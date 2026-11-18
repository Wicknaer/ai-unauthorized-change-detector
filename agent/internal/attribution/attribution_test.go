package attribution

import (
	"testing"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
)

func TestCacheEvictsOldest(t *testing.T) {
	c := NewCache(2)
	t0 := time.Now()
	c.Put(Key{1, 1}, Write{Proc: decision.Process{PID: 1}, At: t0})
	c.Put(Key{1, 2}, Write{Proc: decision.Process{PID: 2}, At: t0.Add(time.Second)})
	c.Put(Key{1, 1}, Write{Proc: decision.Process{PID: 3}, At: t0.Add(2 * time.Second)}) // update, no eviction
	c.Put(Key{1, 3}, Write{Proc: decision.Process{PID: 4}, At: t0.Add(3 * time.Second)}) // evicts {1,2}
	if c.Len() != 2 {
		t.Fatalf("len = %d", c.Len())
	}
	if _, ok := c.Get(Key{1, 2}); ok {
		t.Error("oldest entry not evicted")
	}
	if w, _ := c.Get(Key{1, 1}); w.Proc.PID != 3 {
		t.Errorf("update lost: %+v", w)
	}
}

func TestExplains(t *testing.T) {
	at := time.Now()
	w := Write{At: at}
	if !w.Explains(at.Add(-time.Minute)) || !w.Explains(at.Add(time.Second)) {
		t.Error("mtime at or before the write must be explained")
	}
	// An mmap write later moves the mtime without a fanotify event (T-09).
	if w.Explains(at.Add(10 * time.Second)) {
		t.Error("a later modification must not be credited to this write")
	}
}
