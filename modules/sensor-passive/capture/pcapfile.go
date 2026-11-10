package capture

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// FileSource replays a pcap or pcapng recording (pure Go, no libpcap). It is what development on macOS and
// every test use: fixtures replace the real network (agent-safety). It is read-only by construction: it
// holds an io.Reader.
type FileSource struct {
	r      *bufio.Reader
	closer io.Closer

	ng     bool
	order  binary.ByteOrder
	nano   bool          // classic pcap: timestamps in nanoseconds
	ifaces []ngInterface // pcapng: interfaces of the current section
}

type ngInterface struct {
	ethernet bool
	unit     time.Duration // one timestamp tick
}

const (
	maxRecord   = 1 << 18 // a record longer than this is refused (a corrupt length must not allocate gigabytes)
	pcapMagicLE = 0xa1b2c3d4
	pcapMagicNS = 0xa1b23c4d
	ngSHB       = 0x0a0d0d0a
	ngIDB       = 1
	ngSPB       = 3
	ngEPB       = 6
	ngByteOrder = 0x1a2b3c4d
)

// OpenFile opens a recording for replay.
func OpenFile(path string) (*FileSource, error) {
	f, err := os.Open(path) //nolint:gosec // dev replay: the caller names the recording
	if err != nil {
		return nil, fmt.Errorf("capture: open recording: %w", err)
	}
	s, err := NewFileSource(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	s.closer = f
	return s, nil
}

// NewFileSource reads the header of a recording from r.
func NewFileSource(r io.Reader) (*FileSource, error) {
	s := &FileSource{r: bufio.NewReaderSize(r, 64<<10)}
	head, err := s.r.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("capture: recording header: %w", err)
	}
	switch magic := binary.LittleEndian.Uint32(head); magic {
	case ngSHB:
		s.ng = true
	case pcapMagicLE, pcapMagicNS:
		s.order, s.nano = binary.LittleEndian, magic == pcapMagicNS
	case swap32(pcapMagicLE), swap32(pcapMagicNS):
		s.order, s.nano = binary.BigEndian, magic == swap32(pcapMagicNS)
	default:
		return nil, errors.New("capture: not a pcap or pcapng file")
	}
	if !s.ng {
		var h [24]byte
		if _, err := io.ReadFull(s.r, h[:]); err != nil {
			return nil, fmt.Errorf("capture: pcap header: %w", err)
		}
		if lt := s.order.Uint32(h[20:24]); lt != 1 {
			return nil, fmt.Errorf("capture: link type %d is not Ethernet", lt)
		}
	}
	return s, nil
}

func swap32(v uint32) uint32 {
	return v>>24 | v>>8&0xff00 | v<<8&0xff0000 | v<<24
}

// Close implements Source.
func (s *FileSource) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}

// Next implements Source. It returns io.EOF at the end of the recording and ErrDropped for a record that is
// too long or belongs to a non-Ethernet interface; a recording cut in the middle of a record is an error.
func (s *FileSource) Next(ctx context.Context) (Packet, error) {
	if err := ctx.Err(); err != nil {
		return Packet{}, err
	}
	if s.ng {
		return s.nextNG()
	}
	var h [16]byte
	if _, err := io.ReadFull(s.r, h[:]); err != nil {
		return Packet{}, eofOr(err, "pcap record header")
	}
	sec, frac, capLen := s.order.Uint32(h[0:4]), s.order.Uint32(h[4:8]), s.order.Uint32(h[8:12])
	unit := time.Microsecond
	if s.nano {
		unit = time.Nanosecond
	}
	data, err := s.take(capLen)
	if err != nil {
		return Packet{}, err
	}
	if data == nil {
		return Packet{}, ErrDropped
	}
	return Packet{At: time.Unix(int64(sec), int64(frac)*int64(unit)).UTC(), Data: data}, nil
}

// take reads n bytes; a length over maxRecord is skipped (nil, nil). n stays unsigned until it is checked, so a
// hostile 32-bit length cannot wrap on a 32-bit system.
func (s *FileSource) take(n uint32) ([]byte, error) {
	if n > maxRecord {
		if _, err := io.CopyN(io.Discard, s.r, int64(n)); err != nil {
			return nil, eofOr(err, "pcap record body")
		}
		return nil, nil
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(s.r, b); err != nil {
		return nil, fmt.Errorf("capture: recording is cut short: %w", err)
	}
	return b, nil
}

func eofOr(err error, what string) error {
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	return fmt.Errorf("capture: %s: %w", what, err)
}

func (s *FileSource) nextNG() (Packet, error) {
	for {
		var h [8]byte
		if _, err := io.ReadFull(s.r, h[:]); err != nil {
			return Packet{}, eofOr(err, "pcapng block header")
		}
		order := s.order
		if order == nil { // first block must be a section header; its byte order is inside
			order = binary.LittleEndian
		}
		typ := order.Uint32(h[0:4])
		if typ == ngSHB { // a new section: read its byte order from the body
			bo, err := s.r.Peek(4)
			if err != nil {
				return Packet{}, fmt.Errorf("capture: pcapng section header: %w", err)
			}
			switch binary.LittleEndian.Uint32(bo) {
			case ngByteOrder:
				s.order = binary.LittleEndian
			case swap32(ngByteOrder):
				s.order = binary.BigEndian
			default:
				return Packet{}, errors.New("capture: pcapng byte-order magic")
			}
			order = s.order
			s.ifaces = s.ifaces[:0]
		} else if s.order == nil {
			return Packet{}, errors.New("capture: pcapng must start with a section header")
		}
		total := order.Uint32(h[4:8])
		if total < 12 || total%4 != 0 || total > maxRecord+64 {
			return Packet{}, errors.New("capture: pcapng block length")
		}
		body, err := s.take(total - 8)
		if err != nil {
			return Packet{}, err
		}
		if body == nil {
			return Packet{}, ErrDropped
		}
		body = body[:len(body)-4] // trailing block length
		switch typ {
		case ngIDB:
			if len(body) < 8 {
				return Packet{}, errors.New("capture: pcapng interface block")
			}
			ifc := ngInterface{ethernet: order.Uint16(body[0:2]) == 1, unit: time.Microsecond}
			for opts := body[8:]; len(opts) >= 4; {
				code, l := order.Uint16(opts[0:2]), int(order.Uint16(opts[2:4]))
				if code == 0 || 4+l > len(opts) {
					break
				}
				if code == 9 && l == 1 { // if_tsresol
					ifc.unit = tsUnit(opts[4])
				}
				opts = opts[4+(l+3)/4*4:]
			}
			s.ifaces = append(s.ifaces, ifc)
		case ngEPB:
			if len(body) < 20 {
				return Packet{}, errors.New("capture: pcapng packet block")
			}
			id, capLen := order.Uint32(body[0:4]), order.Uint32(body[12:16])
			if int64(id) >= int64(len(s.ifaces)) || int64(20)+int64(capLen) > int64(len(body)) {
				return Packet{}, errors.New("capture: pcapng packet block length")
			}
			if !s.ifaces[id].ethernet {
				return Packet{}, ErrDropped
			}
			ticks := uint64(order.Uint32(body[4:8]))<<32 | uint64(order.Uint32(body[8:12]))
			at := time.Unix(0, 0).UTC().Add(time.Duration(ticks) * s.ifaces[id].unit) //nolint:gosec // a hostile 64-bit tick count wraps to an odd timestamp, nothing more
			return Packet{At: at, Data: append([]byte(nil), body[20:20+int(capLen)]...)}, nil
		case ngSPB:
			if len(s.ifaces) == 0 || len(body) < 4 {
				return Packet{}, errors.New("capture: pcapng simple packet block")
			}
			n := int(min(int64(order.Uint32(body[0:4])), int64(len(body)-4)))
			if !s.ifaces[0].ethernet {
				return Packet{}, ErrDropped
			}
			return Packet{Data: append([]byte(nil), body[4:4+n]...)}, nil
		}
	}
}

// tsUnit converts an if_tsresol byte into the length of one tick.
func tsUnit(v byte) time.Duration {
	if v&0x80 != 0 { // powers of two: not used by common writers; read as microseconds
		return time.Microsecond
	}
	d := time.Second
	for range min(int(v), 9) {
		d /= 10
	}
	if d < time.Nanosecond {
		d = time.Nanosecond
	}
	return d
}
