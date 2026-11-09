package honeypot

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

const (
	tailBuf  = 64 << 10
	headSize = 1024
	// maxBehind is how much unread log core accepts: more than this behind (core was down while the container wrote a
	// flood) and the reader jumps to the end and counts the bytes it skipped.
	maxBehind = 64 << 20
)

// errNotRegular says the log name is not a regular file (a FIFO, a socket, a device, a directory). It is skipped, never
// opened for reading, so a hostile container cannot block the run loop with it.
var errNotRegular = errors.New("honeypot: the log is not a regular file")

// tailPos is where the reader stands; the service keeps it in hp_config so a restart neither replays nor skips lines.
// Head is the hash of the first HeadLen bytes of the file the offset belongs to: a different head means the file was
// replaced (rotation), a size below the offset means it was truncated; both start over at 0.
type tailPos struct {
	Offset  int64  `json:"offset"`
	HeadLen int    `json:"head_len"`
	Head    string `json:"head"`
}

// tailer reads the JSON-lines file of OpenCanary from tailPos on, one poll at a time (D-89). It follows the name, not
// the open file, so a rotated file is noticed. A line longer than max is dropped and counted; only whole lines are
// handed out, a half-written last line waits for its newline. The folder belongs to the container, so the file is opened
// through os.Root (nothing can lead out of the folder) without following a symlink and without blocking (a FIFO is
// refused after fstat, not waited for).
type tailer struct {
	dir, name    string
	max          int
	pos          tailPos
	discarding   bool  // inside a line that was too long: its rest is skipped up to the newline
	dropped      int   // lines dropped for length since the start
	rotations    int   // files replaced since the start
	notRegular   int   // polls that found something else than a regular file at the log name
	skippedBytes int64 // bytes of log jumped over because the reader was more than maxBehind behind
}

// headLen is the length of the first line of the file (at most headSize bytes, at most offset): lines carry a time to the
// microsecond and the ports of a connection, so two files never share one.
func headLen(f *os.File, offset int64) int {
	buf := make([]byte, min(int64(headSize), offset))
	n, _ := f.ReadAt(buf, 0)
	if i := bytes.IndexByte(buf[:n], '\n'); i >= 0 {
		return i + 1
	}
	return n
}

func hashHead(f *os.File, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, 0); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:8]), nil
}

// openLog opens the log read-only through os.Root, refusing a symlink as the last component and never blocking. It
// returns fs.ErrNotExist when the folder or the file is missing and errNotRegular for anything but a regular file.
func (t *tailer) openLog() (*os.File, os.FileInfo, error) {
	root, err := os.OpenRoot(t.dir)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.OpenFile(t.name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, errNotRegular
	}
	return f, st, nil
}

// poll hands the lines that appeared since the last call to fn (which must copy what it keeps) with the offset just
// after each line, at most maxBytes of file per call. changed reports that the position moved and should be saved.
func (t *tailer) poll(maxBytes int64, fn func(line []byte, end int64)) (changed bool, err error) {
	f, st, err := t.openLog()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if t.pos != (tailPos{}) {
			t.pos, t.discarding, changed = tailPos{}, false, true
		}
		return changed, nil
	case errors.Is(err, errNotRegular):
		t.notRegular++
		return false, err
	case err != nil:
		return false, fmt.Errorf("honeypot: open log: %w", err)
	}
	defer func() { _ = f.Close() }()
	if t.pos.Offset > 0 {
		replaced := st.Size() < t.pos.Offset
		if !replaced && t.pos.HeadLen > 0 {
			h, err := hashHead(f, t.pos.HeadLen)
			replaced = err != nil || h != t.pos.Head
		}
		if replaced {
			t.pos, t.discarding, changed = tailPos{}, false, true
			t.rotations++
		}
	}
	if behind := st.Size() - t.pos.Offset; behind > maxBehind {
		// Jump to the end. The byte before the end tells whether a line is half written there: its rest is skipped too.
		t.skippedBytes += behind
		t.pos.Offset = st.Size()
		var last [1]byte
		_, rerr := f.ReadAt(last[:], st.Size()-1)
		t.discarding = rerr == nil && last[0] != '\n'
		changed = true
		if hl := headLen(f, t.pos.Offset); hl > 0 {
			if h, err := hashHead(f, hl); err == nil {
				t.pos.HeadLen, t.pos.Head = hl, h
			}
		}
		return changed, nil
	}
	if _, err := f.Seek(t.pos.Offset, io.SeekStart); err != nil {
		return changed, fmt.Errorf("honeypot: seek log: %w", err)
	}
	r := bufio.NewReaderSize(f, tailBuf)
	var read int64
	for read < maxBytes {
		chunk, rerr := r.ReadSlice('\n')
		n := int64(len(chunk))
		switch {
		case errors.Is(rerr, bufio.ErrBufferFull): // longer than the buffer: too long for sure
			if !t.discarding {
				t.discarding = true
				t.dropped++
			}
			t.pos.Offset += n
			read += n
			changed = true
			continue
		case rerr == nil:
			t.pos.Offset += n
			read += n
			changed = true
			if t.discarding {
				t.discarding = false
				continue
			}
			line := chunk[:len(chunk)-1]
			if k := len(line); k > 0 && line[k-1] == '\r' {
				line = line[:k-1]
			}
			switch {
			case len(line) == 0:
			case len(line) > t.max:
				t.dropped++
			default:
				fn(line, t.pos.Offset)
			}
			continue
		case errors.Is(rerr, io.EOF):
			switch {
			case t.discarding: // the rest of a too-long line: skip it, the newline has not come yet
				t.pos.Offset += n
				changed = changed || n > 0
			case len(chunk) > t.max: // a half-written line that is already too long
				t.discarding = true
				t.dropped++
				t.pos.Offset += n
				changed = true
			}
		default:
			return changed, fmt.Errorf("honeypot: read log: %w", rerr)
		}
		break
	}
	if t.pos.Offset > 0 && changed {
		if hl := headLen(f, t.pos.Offset); hl > 0 {
			if h, err := hashHead(f, hl); err == nil {
				t.pos.HeadLen, t.pos.Head = hl, h
			}
		}
	}
	return changed, nil
}
