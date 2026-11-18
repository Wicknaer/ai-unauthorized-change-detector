// Package notify forwards alerts to a chat webhook (FR-16). The URL is a secret and comes
// from the environment, never from the config file (SR-08).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/logger"
)

const (
	EnvURL = "FIM_WEBHOOK_URL"
	EnvMin = "FIM_WEBHOOK_MIN" // minimum severity to send, default CRITICAL
)

// Webhook posts records in the background so a slow or unreachable endpoint never delays
// detection. When the queue is full, records are dropped and counted.
type Webhook struct {
	url     string
	min     decision.Severity
	client  *http.Client
	q       chan logger.Record
	wg      sync.WaitGroup
	sent    atomic.Int64
	failed  atomic.Int64
	dropped atomic.Int64
}

func NewWebhook(url string, min decision.Severity) *Webhook {
	if min == "" {
		min = decision.Critical
	}
	w := &Webhook{url: url, min: min, client: &http.Client{Timeout: 5 * time.Second}, q: make(chan logger.Record, 256)}
	w.wg.Add(1)
	go w.loop()
	return w
}

// Notify queues a record if it is severe enough. It never blocks.
func (w *Webhook) Notify(r logger.Record) {
	if r.Severity.Rank() < w.min.Rank() {
		return
	}
	select {
	case w.q <- r:
	default:
		w.dropped.Add(1)
	}
}

// Close sends what is queued (up to the timeout) and stops.
func (w *Webhook) Close(timeout time.Duration) {
	close(w.q)
	done := make(chan struct{})
	go func() { w.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// Stats returns sent, failed and dropped counts.
func (w *Webhook) Stats() (sent, failed, dropped int64) {
	return w.sent.Load(), w.failed.Load(), w.dropped.Load()
}

func (w *Webhook) loop() {
	defer w.wg.Done()
	for r := range w.q {
		if err := w.post(r); err != nil {
			w.failed.Add(1)
		} else {
			w.sent.Add(1)
		}
	}
}

// payload is accepted by Slack ("text") and Discord ("content") incoming webhooks; the full
// record is attached for generic receivers.
type payload struct {
	Text     string        `json:"text"`
	Content  string        `json:"content"`
	Username string        `json:"username"`
	Record   logger.Record `json:"record"`
}

func (w *Webhook) post(r logger.Record) error {
	msg := "fimagent: " + logger.Human(r)
	if len(msg) > 1900 { // Discord limit is 2000 characters
		msg = msg[:1900]
	}
	body, err := json.Marshal(payload{Text: msg, Content: msg, Username: "fimagent", Record: r})
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := w.client.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("webhook returned %s", resp.Status)
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			break // a client error will not fix itself
		}
	}
	return lastErr
}
