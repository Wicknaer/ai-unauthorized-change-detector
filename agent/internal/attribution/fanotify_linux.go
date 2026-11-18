//go:build linux

package attribution

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/Wicknaer/ai-unauthorized-change-detector/agent/internal/decision"
)

// fanotifySource listens for FAN_MODIFY / FAN_CLOSE_WRITE events and records the writer.
// It needs CAP_SYS_ADMIN; to see processes in other containers the agent also needs the
// host PID namespace (pid: host in docker-compose).
type fanotifySource struct {
	f     *os.File
	cache *Cache
	self  int

	procMu sync.Mutex
	procs  map[int]procEntry // short-lived cache: one process usually writes many times

	mode string
	done chan struct{}
}

type procEntry struct {
	p  decision.Process
	at time.Time
}

// Open starts listening on the file systems that contain the given roots. It prefers a
// file-system-wide mark (FAN_MARK_FILESYSTEM): a mount mark only sees writes made through
// the same mount, and the attacker writes to the shared volume through its own mount.
func Open(roots []string) (Source, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w (CAP_SYS_ADMIN required)", err)
	}
	s := &fanotifySource{cache: NewCache(0), self: os.Getpid(), procs: map[int]procEntry{}, done: make(chan struct{})}
	mode := "filesystem"
	for _, r := range roots {
		mask := uint64(unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE)
		err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM, mask, unix.AT_FDCWD, r)
		if err != nil {
			// Some file systems (e.g. overlayfs on older kernels) refuse filesystem marks.
			if err2 := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, mask, unix.AT_FDCWD, r); err2 != nil {
				unix.Close(fd)
				return nil, fmt.Errorf("fanotify_mark %s: %v / %v", r, err, err2)
			}
			mode = "mount"
		}
	}
	s.f = os.NewFile(uintptr(fd), "fanotify")
	s.mode = mode
	go s.loop()
	return s, nil
}

func (s *fanotifySource) Mode() string { return s.mode }

func (s *fanotifySource) Close() error {
	err := s.f.Close()
	<-s.done
	return err
}

func (s *fanotifySource) LastWrite(path string) (Write, bool) { return s.cache.lookup(path) }

func (s *fanotifySource) loop() {
	defer close(s.done)
	buf := make([]byte, 64<<10)
	const metaLen = int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for {
		n, err := s.f.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			return
		}
		for off := 0; off+metaLen <= n; {
			m := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[off]))
			if m.Event_len < uint32(metaLen) || off+int(m.Event_len) > n {
				break
			}
			if m.Vers == unix.FANOTIFY_METADATA_VERSION {
				s.handle(m)
			}
			if m.Fd >= 0 {
				unix.Close(int(m.Fd))
			}
			off += int(m.Event_len)
		}
	}
}

func (s *fanotifySource) handle(m *unix.FanotifyEventMetadata) {
	if m.Fd < 0 || int(m.Pid) == s.self || m.Mask&unix.FAN_Q_OVERFLOW != 0 {
		return
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(m.Fd), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return
	}
	now := time.Now()
	s.cache.Put(Key{Dev: uint64(st.Dev), Ino: st.Ino}, Write{Proc: s.process(int(m.Pid), now), At: now})
}

// process reads the writer's details from /proc. Short-lived writers (dd, sqlite3) may exit
// before this runs; then only the PID is known.
func (s *fanotifySource) process(pid int, now time.Time) decision.Process {
	s.procMu.Lock()
	if e, ok := s.procs[pid]; ok && now.Sub(e.at) < 2*time.Second {
		s.procMu.Unlock()
		return e.p
	}
	s.procMu.Unlock()

	p := ReadProc(pid)

	s.procMu.Lock()
	if len(s.procs) > 4096 {
		s.procs = map[int]procEntry{}
	}
	s.procs[pid] = procEntry{p, now}
	s.procMu.Unlock()
	return p
}

// ReadProc collects PID, command name, executable and user of a process from /proc.
func ReadProc(pid int) decision.Process {
	p := decision.Process{PID: pid}
	dir := "/proc/" + strconv.Itoa(pid)
	if b, err := os.ReadFile(dir + "/comm"); err == nil {
		p.Comm = string(bytes.TrimSpace(b))
	}
	if exe, err := os.Readlink(dir + "/exe"); err == nil {
		p.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	if b, err := os.ReadFile(dir + "/status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				if f := strings.Fields(line); len(f) > 1 {
					p.User = f[1] // real UID
					if u, err := user.LookupId(f[1]); err == nil {
						p.User = u.Username
					}
				}
				break
			}
		}
	}
	return p
}
