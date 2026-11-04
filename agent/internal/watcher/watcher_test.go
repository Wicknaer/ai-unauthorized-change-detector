package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func collect(t *testing.T, w *Watcher, want func(Event) bool, d time.Duration) (Event, bool) {
	t.Helper()
	timeout := time.After(d)
	for {
		select {
		case ev := <-w.Events():
			t.Logf("event %+v", ev)
			if want(ev) {
				return ev, true
			}
		case <-timeout:
			return Event{}, false
		}
	}
}

func TestDebounceNewDirAndRepeatedWrites(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "model.bin")
	os.WriteFile(file, []byte("a"), 0o644)

	w, err := New([]string{root}, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	// A burst of writes on one file becomes a single event (FR-09).
	for i := 0; i < 20; i++ {
		os.WriteFile(file, []byte{byte(i)}, 0o644)
	}
	if _, ok := collect(t, w, func(e Event) bool { return e.Path == file }, 2*time.Second); !ok {
		t.Fatal("no event for first burst")
	}
	select {
	case ev := <-w.Events():
		if ev.Path == file {
			t.Errorf("burst produced more than one event: %+v", ev)
		}
	case <-time.After(200 * time.Millisecond):
	}

	// A later write on the same file must produce a new event.
	os.WriteFile(file, []byte("again"), 0o644)
	if _, ok := collect(t, w, func(e Event) bool { return e.Path == file }, 2*time.Second); !ok {
		t.Fatal("no event for second write")
	}

	// FR-06: files inside a new subdirectory are reported.
	sub := filepath.Join(root, "new")
	os.Mkdir(sub, 0o755)
	if _, ok := collect(t, w, func(e Event) bool { return e.Path == sub && e.NewDir }, 2*time.Second); !ok {
		t.Fatal("no event for new directory")
	}
	inner := filepath.Join(sub, "poison.jsonl")
	os.WriteFile(inner, []byte("{}"), 0o644)
	if _, ok := collect(t, w, func(e Event) bool { return e.Path == inner }, 2*time.Second); !ok {
		t.Fatal("no event for file in new directory")
	}
}
