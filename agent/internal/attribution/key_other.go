//go:build !unix

package attribution

import "os"

func FileKey(os.FileInfo) (Key, bool) { return Key{}, false }
