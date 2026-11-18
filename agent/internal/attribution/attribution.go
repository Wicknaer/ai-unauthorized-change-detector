// Package attribution tells which process last wrote to a file (FR-10).
//
// inotify/fsnotify events do not carry the writer's PID, so a second event source listens
// for write events with fanotify (Linux only) and remembers, per file (device + inode),
// which process wrote it and when. The agent asks this cache when it decides on a change;
// keying on the inode instead of the path makes it independent of where each container
// mounts the shared volume.
package attribution

import (
	"errors"
	"os"
	"sync"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
)

// ErrUnsupported is returned by Open on platforms without fanotify.
var ErrUnsupported = errors.New("process attribution needs fanotify (Linux)")

// Key identifies a file independently of its path.
type Key struct{ Dev, Ino uint64 }

// Write is the last write seen for a file.
type Write struct {
	Proc decision.Process
	At   time.Time
}

// Source answers "who last wrote this file". Implementations must be safe for concurrent use.
type Source interface {
	// LastWrite returns the last write recorded for the file currently at path.
	LastWrite(path string) (Write, bool)
	Close() error
}

// Cache is a bounded map of the most recent write per file. When full, the oldest
// entry is evicted.
type Cache struct {
	mu  sync.Mutex
	max int
	m   map[Key]Write
}

func NewCache(max int) *Cache {
	if max <= 0 {
		max = 65536
	}
	return &Cache{max: max, m: make(map[Key]Write)}
}

func (c *Cache) Put(k Key, w Write) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[k]; !ok && len(c.m) >= c.max {
		var oldest Key
		var t time.Time
		first := true
		for key, v := range c.m {
			if first || v.At.Before(t) {
				oldest, t, first = key, v.At, false
			}
		}
		delete(c.m, oldest)
	}
	c.m[k] = w
}

func (c *Cache) Get(k Key) (Write, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w, ok := c.m[k]
	return w, ok
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// lookup resolves a path to its key and returns the cached write.
func (c *Cache) lookup(path string) (Write, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return Write{}, false
	}
	k, ok := FileKey(fi)
	if !ok {
		return Write{}, false
	}
	return c.Get(k)
}

// Explains reports whether the recorded write can explain the file's current state: the
// file must not have been modified after that write. A write made through mmap produces no
// fanotify event but still moves the mtime, so it is not wrongly credited to an earlier
// whitelisted writer (T-09).
func (w Write) Explains(mtime time.Time) bool {
	const slack = 2 * time.Second // mtime granularity and event delivery delay
	return !mtime.After(w.At.Add(slack))
}

// Static is a fixed Source, used by tests and on platforms without fanotify.
type Static struct {
	mu sync.Mutex
	m  map[string]Write
}

func NewStatic() *Static { return &Static{m: map[string]Write{}} }

func (s *Static) Set(path string, w Write) {
	s.mu.Lock()
	s.m[path] = w
	s.mu.Unlock()
}

func (s *Static) LastWrite(path string) (Write, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.m[path]
	return w, ok
}

func (s *Static) Close() error { return nil }

// ModeReporter is implemented by sources that can say how they are attached
// ("filesystem" or "mount" mark for fanotify).
type ModeReporter interface{ Mode() string }
