//go:build !linux

package attribution

// Open is only implemented on Linux.
func Open(roots []string) (Source, error) { return nil, ErrUnsupported }
