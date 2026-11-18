package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/logger"
)

func TestWebhookSendsOnlySevereRecords(t *testing.T) {
	var mu sync.Mutex
	var got []payload
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // first attempt fails, retry succeeds
			return
		}
		var p payload
		json.NewDecoder(r.Body).Decode(&p)
		got = append(got, p)
	}))
	defer srv.Close()

	w := NewWebhook(srv.URL, decision.Critical)
	w.Notify(logger.Record{Severity: decision.Info, Type: logger.TypeHeartbeat})
	w.Notify(logger.Record{Severity: decision.High, Type: logger.TypeDetection, Path: "/data/datasets/train.jsonl"})
	w.Notify(logger.Record{Time: time.Now(), Severity: decision.Critical, Type: logger.TypeDetection, Event: "modified", Path: "/data/models/gpt2.safetensors"})
	w.Close(5 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Record.Path != "/data/models/gpt2.safetensors" || got[0].Content == "" || got[0].Text != got[0].Content {
		t.Fatalf("got %+v", got)
	}
	if sent, failed, dropped := w.Stats(); sent != 1 || failed != 0 || dropped != 0 {
		t.Errorf("stats sent=%d failed=%d dropped=%d", sent, failed, dropped)
	}
}

func TestWebhookClientErrorIsNotRetried(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	w := NewWebhook(srv.URL, "")
	w.Notify(logger.Record{Severity: decision.Critical})
	w.Close(5 * time.Second)
	if _, failed, _ := w.Stats(); failed != 1 || calls != 1 {
		t.Errorf("failed=%d calls=%d", failed, calls)
	}
}
