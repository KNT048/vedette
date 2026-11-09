package sensorpassive

import (
	"encoding/binary"
	"strings"
)

// parseClientHelloSNI returns the server name of a TLS ClientHello that starts at b[0] (the first bytes of a
// TCP segment). It reads the record, handshake and extension headers and nothing else: no random, no cipher
// list, no session. errIgnore: not a ClientHello (data records, a segment that continues one) or no SNI.
func parseClientHelloSNI(b []byte) (string, error) {
	if len(b) < 6 || b[0] != 0x16 || b[1] != 3 || b[2] > 4 {
		return "", errIgnore
	}
	if b[5] != 1 { // handshake type: ClientHello
		return "", errIgnore
	}
	rec := int(binary.BigEndian.Uint16(b[3:5]))
	if rec < 4 || rec > 1<<14 {
		return "", malformed("tls: record length")
	}
	body := b[5:]
	if len(body) > rec { // never read past the record
		body = body[:rec]
	}
	if len(body) < 4 {
		return "", errIgnore // the handshake header itself is split over segments
	}
	hl := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if hl+4 > rec {
		return "", malformed("tls: handshake longer than its record")
	}
	if len(body) >= hl+4 { // shorter: the hello is split over segments and the SNI may be out of reach
		body = body[:hl+4]
	}
	r := reader{b: body[4:]}
	r.skip(2 + 32) // version, random
	r.skip(int(r.u8()))
	r.skip(int(r.u16()))
	r.skip(int(r.u8()))
	if r.err {
		return "", errIgnore // truncated before the extensions: nothing to read
	}
	extLen := int(r.u16())
	if r.err {
		return "", errIgnore
	}
	if extLen > len(r.b)-r.i {
		extLen = len(r.b) - r.i
	}
	ext := reader{b: r.b[r.i : r.i+extLen]}
	for ext.i+4 <= len(ext.b) {
		typ, l := ext.u16(), int(ext.u16())
		if ext.i+l > len(ext.b) {
			return "", errIgnore
		}
		if typ != 0 { // server_name
			ext.skip(l)
			continue
		}
		v := reader{b: ext.b[ext.i : ext.i+l]}
		listLen := int(v.u16())
		if v.err || listLen > l-2 {
			return "", malformed("tls: server_name list")
		}
		for v.i+3 <= len(v.b) {
			nt, nl := v.u8(), int(v.u16())
			if v.i+nl > len(v.b) {
				return "", malformed("tls: server name overruns")
			}
			if nt == 0 {
				name := strings.ToLower(string(v.b[v.i : v.i+nl]))
				if !hostnameOK(name) {
					return "", malformed("tls: server name is not a host name")
				}
				return name, nil
			}
			v.skip(nl)
		}
		return "", errIgnore
	}
	return "", errIgnore
}

// reader is a bounds-checked cursor: reading past the end sets err and returns zeros.
type reader struct {
	b   []byte
	i   int
	err bool
}

func (r *reader) skip(n int) {
	if n < 0 || r.i+n > len(r.b) {
		r.err, r.i = true, len(r.b)
		return
	}
	r.i += n
}

func (r *reader) u8() uint8 {
	if r.i+1 > len(r.b) {
		r.err = true
		return 0
	}
	v := r.b[r.i]
	r.i++
	return v
}

func (r *reader) u16() uint16 {
	if r.i+2 > len(r.b) {
		r.err = true
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.i:])
	r.i += 2
	return v
}
