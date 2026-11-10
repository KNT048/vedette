package ops

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// The MAC of a decoy (D-102 (7)): derived from the IP and a 32-byte key private to this
// installation (hp/mac.key), so the same IP always gets the same MAC, across restarts, yet two boxes
// give the same IP different MACs. Without an OUI the MAC is the first six bytes of
// HMAC-SHA256(key, the four bytes of the IPv4 address) with the locally administered bit set and the
// multicast bit cleared; with an OUI it is the OUI and the next three bytes of the HMAC.

const macKeyLen = 32

var ouiRE = regexp.MustCompile(`^[0-9a-fA-F]{6}$`)

// parseOUI checks an OUI: exactly six hex digits, unicast and globally administered (the two low
// bits of the first byte are 0). "" means none.
func parseOUI(s string) (oui [3]byte, ok bool, err error) {
	if s == "" {
		return oui, false, nil
	}
	if !ouiRE.MatchString(s) {
		return oui, false, errors.New("must be exactly six hex digits")
	}
	var v [3]byte
	_, err = fmt.Sscanf(strings.ToLower(s), "%02x%02x%02x", &v[0], &v[1], &v[2])
	if err != nil {
		return oui, false, errors.New("must be exactly six hex digits")
	}
	if v[0]&0x01 != 0 {
		return oui, false, errors.New("is a multicast prefix")
	}
	if v[0]&0x02 != 0 {
		return oui, false, errors.New("is locally administered; an OUI is globally administered")
	}
	return v, true, nil
}

// deriveMAC computes the MAC of ip (an IPv4 address) under key.
func deriveMAC(key []byte, ip netip.Addr, oui *[3]byte) net.HardwareAddr {
	b := ip.As4()
	h := hmac.New(sha256.New, key)
	h.Write(b[:])
	sum := h.Sum(nil)
	mac := make(net.HardwareAddr, 6)
	if oui != nil {
		copy(mac, oui[:])
		copy(mac[3:], sum[:3])
		return mac
	}
	copy(mac, sum[:6])
	mac[0] = (mac[0] | 0x02) &^ 0x01
	return mac
}

// loadMACKey reads hp/mac.key, creating it (32 random bytes, 0600, atomically) when it is absent.
// It refuses a symlink, anything but a regular file, another owner, any group or other access and
// any length but 32: a key that is silently replaced would change every MAC.
func (o *Ops) loadMACKey() ([]byte, error) {
	dir := o.stateFile("hp")
	if err := privDir(dir, o.cfg.OwnerUID); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "mac.key")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		key := make([]byte, macKeyLen)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("ops: random key: %w", err)
		}
		if err := writeFileAtomic(path, key, 0o600); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // a fixed name in the host's own state directory
	if err != nil {
		return nil, fmt.Errorf("ops: open mac.key: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("ops: stat mac.key: %w", err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.Mode().IsRegular():
		return nil, errors.New("ops: mac.key is not a regular file")
	case !ok || int(sys.Uid) != o.cfg.OwnerUID:
		return nil, errors.New("ops: mac.key has the wrong owner")
	case st.Mode().Perm() != 0o600:
		return nil, fmt.Errorf("ops: mac.key has mode %o, want 600", st.Mode().Perm())
	case st.Size() != macKeyLen:
		return nil, errors.New("ops: mac.key is not 32 bytes")
	}
	key := make([]byte, macKeyLen)
	if _, err := io.ReadFull(f, key); err != nil {
		return nil, errors.New("ops: mac.key could not be read")
	}
	return key, nil
}
