package hasher

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestFileMatchesSHA256AcrossChunkBoundaries(t *testing.T) {
	const chunk = 1024
	h := New(chunk)
	dir := t.TempDir()
	for _, size := range []int{0, 1, chunk - 1, chunk, chunk + 1, 5*chunk + 17} {
		data := make([]byte, size)
		rand.Read(data)
		p := filepath.Join(dir, "f.bin")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		got, n, err := h.File(p)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if want := hex.EncodeToString(sum[:]); got != want || n != int64(size) {
			t.Errorf("size %d: got %s (%d bytes), want %s", size, got, n, want)
		}
	}
}

// countingReader records the largest single read so we can check that the chunk size is respected.
type countingReader struct {
	r   *bytes.Reader
	max int
}

func (c *countingReader) Read(p []byte) (int, error) {
	if len(p) > c.max {
		c.max = len(p)
	}
	return c.r.Read(p)
}

func TestReaderUsesChunkSizedBuffer(t *testing.T) {
	h := New(4096)
	cr := &countingReader{r: bytes.NewReader(make([]byte, 1<<20))}
	if _, _, err := h.Reader(cr); err != nil {
		t.Fatal(err)
	}
	if cr.max != 4096 {
		t.Errorf("largest read = %d, want 4096", cr.max)
	}
}

func TestMissingFile(t *testing.T) {
	if _, _, err := New(0).File(filepath.Join(t.TempDir(), "nope")); !os.IsNotExist(err) {
		t.Errorf("err = %v, want not-exist", err)
	}
}

func BenchmarkHash64MB(b *testing.B) {
	data := make([]byte, 64<<20)
	h := New(DefaultChunkSize)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		h.Reader(bytes.NewReader(data))
	}
}
