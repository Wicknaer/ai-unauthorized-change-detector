//go:build unix

package attribution

import (
	"os"
	"syscall"
)

// FileKey returns the device and inode number of a file.
func FileKey(fi os.FileInfo) (Key, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Key{}, false
	}
	return Key{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, true
}
