// Package hasher computes SHA-256 digests by reading files in fixed-size chunks (FR-04).
// Memory use does not depend on file size: each call uses a single chunk-sized buffer.
package hasher

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

const DefaultChunkSize = 4 << 20

type Hasher struct {
	chunk int
	pool  sync.Pool
}

func New(chunkSize int) *Hasher {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	h := &Hasher{chunk: chunkSize}
	h.pool.New = func() any {
		b := make([]byte, chunkSize)
		return &b
	}
	return h
}

func (h *Hasher) ChunkSize() int { return h.chunk }

// File returns the hex SHA-256 digest of the file and the number of bytes read.
func (h *Hasher) File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	return h.Reader(f)
}

// Reader returns the SHA-256 digest of everything read from r.
func (h *Hasher) Reader(r io.Reader) (string, int64, error) {
	bp := h.pool.Get().(*[]byte)
	defer h.pool.Put(bp)

	sum := sha256.New()
	// io.CopyBuffer skips the buffer when the reader implements WriterTo, which *os.File does.
	// Wrapping the reader forces our chunk-sized buffer to be used.
	n, err := io.CopyBuffer(sum, struct{ io.Reader }{r}, *bp)
	if err != nil {
		return "", n, err
	}
	return hex.EncodeToString(sum.Sum(nil)), n, nil
}
