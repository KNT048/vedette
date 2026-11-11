package listen

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// Errors of the TCP framer. Both end the connection: after them the stream cannot be resynchronised.
var (
	// ErrFrameTooLarge is a frame (an octet count, or a line without a newline) of more than the frame limit.
	ErrFrameTooLarge = errors.New("listen: frame larger than the limit")
	// ErrShortFrame is a connection that ended inside an octet-counted frame.
	ErrShortFrame = errors.New("listen: connection ended inside a frame")
)

// maxPrefixDigits is the longest octet count read (999,999: above any frame limit this package allows).
const maxPrefixDigits = 6

// ReadFrame reads the next message of a TCP syslog stream. Two framings share a connection (RFC 6587): octet counting
// ("123 <34>..."), recognised only when the digits and the space are followed by the "<" of a priority, and a line ended by a
// newline (a carriage return before it is dropped). The frame it returns has at most maxLine bytes: a longer message is cut and
// truncated is true. A frame of more than maxFrame bytes, an octet count above it, or a line of more than maxFrame bytes
// without a newline is an error (ErrFrameTooLarge). Empty lines are skipped. It reads at most maxFrame bytes past what it keeps
// and never allocates more than maxLine for one frame. io.EOF comes only between frames; a last line without a newline is
// returned first.
func ReadFrame(r *bufio.Reader, maxLine, maxFrame int) (frame []byte, truncated bool, err error) {
	for {
		n, counted, err := octetPrefix(r, maxFrame)
		if err != nil {
			return nil, false, err
		}
		if counted {
			return readCounted(r, n, maxLine)
		}
		frame, truncated, err = readLine(r, maxLine, maxFrame)
		if err != nil {
			return nil, false, err
		}
		if len(frame) == 0 && !truncated {
			continue
		}
		return frame, truncated, nil
	}
}

// octetPrefix looks at the start of the next frame without consuming it, unless it is an octet count; then it consumes the count
// and the space. It decides byte by byte, so it never waits for more than the next byte of what could still be a count.
func octetPrefix(r *bufio.Reader, maxFrame int) (n int, counted bool, err error) {
	b, err := r.Peek(1)
	if err != nil {
		return 0, false, err
	}
	if b[0] < '1' || b[0] > '9' {
		return 0, false, nil
	}
	for i := 0; i <= maxPrefixDigits; i++ {
		b, err = r.Peek(i + 1)
		if err != nil {
			return 0, false, soften(err)
		}
		c := b[i]
		switch {
		case c >= '0' && c <= '9':
			if i == maxPrefixDigits {
				return 0, false, nil // seven digits: not a count
			}
			n = n*10 + int(c-'0')
		case c == ' ':
			b, err = r.Peek(i + 2)
			if err != nil {
				return 0, false, soften(err)
			}
			if b[i+1] != '<' {
				return 0, false, nil
			}
			if n > maxFrame {
				return 0, false, ErrFrameTooLarge
			}
			_, _ = r.Discard(i + 1)
			return n, true, nil
		default:
			return 0, false, nil
		}
	}
	return 0, false, nil
}

// soften turns the end of the stream in the middle of a possible count into "not a count": the bytes are a short line.
func soften(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func readCounted(r *bufio.Reader, n, maxLine int) ([]byte, bool, error) {
	keep := min(n, maxLine)
	buf := make([]byte, keep)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, false, ErrShortFrame
		}
		return nil, false, err
	}
	if n > keep {
		if _, err := r.Discard(n - keep); err != nil {
			if errors.Is(err, io.EOF) {
				return nil, false, ErrShortFrame
			}
			return nil, false, err
		}
	}
	return buf, n > keep, nil
}

// readLine reads up to a newline. It works on what is buffered, so a line that is longer than the frame limit is refused as soon
// as that many bytes are in, not when a newline finally comes (or the frame timeout ends).
func readLine(r *bufio.Reader, maxLine, maxFrame int) ([]byte, bool, error) {
	var out []byte
	total := 0
	truncated := false
	for {
		if _, err := r.Peek(1); err != nil {
			if errors.Is(err, io.EOF) && total > 0 {
				return out, truncated, nil // a last line without a newline
			}
			return nil, false, err
		}
		buf, _ := r.Peek(r.Buffered())
		n, done := len(buf), false
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			n, done = i+1, true
		}
		total += n
		if total > maxFrame+1 { // +1: the newline
			return nil, false, ErrFrameTooLarge
		}
		data := buf[:n]
		if done {
			data = data[:n-1]
		}
		if room := maxLine - len(out); len(data) > room {
			data, truncated = data[:max(room, 0)], true
		}
		out = append(out, data...)
		_, _ = r.Discard(n)
		if done {
			if len(out) > 0 && out[len(out)-1] == '\r' {
				out = out[:len(out)-1]
			}
			return out, truncated, nil
		}
	}
}
