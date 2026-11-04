//go:build !unix

package baseline

import "io/fs"

// Ownership is only recorded on Linux/Unix; the agent runs on Linux in production.
func owner(fs.FileInfo) string { return "" }
