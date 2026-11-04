// Package watcher listens for kernel file events (inotify on Linux via fsnotify) on every
// monitored directory (FR-05), adds new subdirectories automatically (FR-06) and coalesces
// bursts of events on the same path into one (FR-09).
//
// fsnotify does not report which process made a change; process attribution with fanotify
// (FR-10) is a separate, Linux-only event source planned for the next iteration.
package watcher

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Event is a debounced change notification for a single path.
type Event struct {
	Path     string
	Op       string    // last raw operation seen, e.g. "WRITE", "REMOVE"
	First    time.Time // time of the first raw event in the burst; used for latency (NFR-01)
	Overflow bool      // the kernel queue overflowed; the caller should run a full scan
	NewDir   bool      // a directory appeared; the caller should check everything under it
}

type Watcher struct {
	fs       *fsnotify.Watcher
	debounce time.Duration
	out      chan Event

	mu      sync.Mutex
	pending map[string]*pending
}

type pending struct {
	timer *time.Timer
	first time.Time
	op    string
}

// New starts watching every root recursively.
// Only directory trees are watched; single files outside them (such as the agent's own config)
// are polled by the agent, because watching an ancestor of a root breaks delivery on Windows.
func New(roots []string, debounce time.Duration) (*Watcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	w := &Watcher{fs: fw, debounce: debounce, out: make(chan Event, 1024), pending: map[string]*pending{}}
	for _, r := range roots {
		if err := w.addTree(r); err != nil {
			fw.Close()
			return nil, err
		}
	}
	return w, nil
}

func (w *Watcher) Events() <-chan Event { return w.out }

func (w *Watcher) Close() error { return w.fs.Close() }

func (w *Watcher) addTree(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil
		}
		if d.IsDir() {
			return w.fs.Add(p)
		}
		return nil
	})
}

// Run forwards events until ctx is cancelled. The Events channel is never closed because
// debounce timers may still fire; consumers should stop on ctx instead.
func (w *Watcher) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			w.stopTimers()
			return nil
		case ev, ok := <-w.fs.Events:
			if !ok {
				return nil
			}
			w.handle(ctx, ev)
		case err, ok := <-w.fs.Errors:
			if !ok {
				return nil
			}
			if errors.Is(err, fsnotify.ErrEventOverflow) {
				w.send(ctx, Event{Overflow: true, First: time.Now()})
			}
		}
	}
}

func (w *Watcher) handle(ctx context.Context, ev fsnotify.Event) {
	path := filepath.Clean(ev.Name)
	if ev.Has(fsnotify.Create) {
		if fi, err := os.Lstat(path); err == nil && fi.IsDir() {
			// FR-06: watch the new directory, then report it so files written before the
			// watch was added are not missed. fsnotify's Add must not run on the goroutine
			// that drains its event channel: on Windows that deadlocks when events are queued.
			first := time.Now()
			go func() {
				_ = w.addTree(path)
				w.send(ctx, Event{Path: path, Op: "CREATE", First: first, NewDir: true})
			}()
			return
		}
	}
	w.schedule(ctx, path, opName(ev.Op))
}

// schedule resets the per-path debounce timer; the event is emitted once the path is quiet.
func (w *Watcher) schedule(ctx context.Context, path, op string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if p, ok := w.pending[path]; ok {
		p.op = op
		p.timer.Reset(w.debounce)
		return
	}
	p := &pending{first: time.Now(), op: op}
	p.timer = time.AfterFunc(w.debounce, func() {
		w.mu.Lock()
		delete(w.pending, path)
		ev := Event{Path: path, Op: p.op, First: p.first}
		w.mu.Unlock()
		w.send(ctx, ev)
	})
	w.pending[path] = p
}

func (w *Watcher) send(ctx context.Context, ev Event) {
	select {
	case w.out <- ev:
	case <-ctx.Done():
	}
}

func (w *Watcher) stopTimers() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, p := range w.pending {
		p.timer.Stop()
		delete(w.pending, k)
	}
}

func opName(op fsnotify.Op) string {
	switch {
	case op.Has(fsnotify.Remove):
		return "REMOVE"
	case op.Has(fsnotify.Rename):
		return "RENAME"
	case op.Has(fsnotify.Create):
		return "CREATE"
	case op.Has(fsnotify.Write):
		return "WRITE"
	case op.Has(fsnotify.Chmod):
		return "CHMOD"
	}
	return op.String()
}
