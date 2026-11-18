package logger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Segments returns the log files oldest first: alerts.jsonl.N ... alerts.jsonl.1, alerts.jsonl.
// The active file is included even if it does not exist yet, so callers can open it.
func Segments(path string) ([]string, error) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var nums []int
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Name(), base+".")
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(rest); err == nil && n > 0 {
			nums = append(nums, n)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(nums)))
	out := make([]string, 0, len(nums)+1)
	for _, n := range nums {
		out = append(out, fmt.Sprintf("%s.%d", path, n))
	}
	if _, err := os.Stat(path); err == nil || len(out) == 0 {
		out = append(out, path)
	}
	return out, nil
}

// rotate shifts alerts.jsonl.i to .i+1, drops files beyond keep, and moves the active file to .1.
func rotate(path string, keep int) error {
	if keep < 2 {
		keep = 2
	}
	os.Remove(fmt.Sprintf("%s.%d", path, keep-1))
	for i := keep - 2; i >= 1; i-- {
		err := os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Rename(path, path+".1")
}

// chainHead is the hash the next record must link to: the last line of the active file, or
// of the most recent rotated file right after a rotation.
func chainHead(path string) (string, error) {
	h, err := lastHash(path)
	if err != nil || h != GenesisHash {
		return h, err
	}
	if _, err := os.Stat(path + ".1"); err == nil {
		return lastHash(path + ".1")
	}
	return GenesisHash, nil
}
