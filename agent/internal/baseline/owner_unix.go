//go:build unix

package baseline

import (
	"fmt"
	"io/fs"
	"syscall"
)

func owner(fi fs.FileInfo) string {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", st.Uid, st.Gid)
	}
	return ""
}
