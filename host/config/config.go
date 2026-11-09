// Package config parses /etc/vedette/host.conf, the small file the installer writes for
// vedette-host (docs/specs/host-api.md section 3 and 13). Strict on purpose: an unknown key,
// a duplicate, a bad value or a file others can write is an error, never a default.
//
// Format: one "key = value" per line; blank lines and lines starting with # are ignored.
//
//	core_uid  = 10001                        # uid that runs core (never 0)
//	core_unit = vedette-core.service         # systemd unit whose cgroup core's processes are in
//	socket    = /run/vedette/host.sock       # absolute path, at most 100 bytes
//	socket_gid = 990                         # gid of the group "vedette" (owns the socket, mode 0660)
//	core_cgroup = /user.slice/user-990.slice/user@990.service/app.slice/vedette-core.service   # optional
package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/knt048/vedette/host/peer"
)

// MaxSize is the largest accepted file.
const MaxSize = 4 << 10

// maxSocketPath keeps the path below the 108-byte sun_path limit with room to spare.
const maxSocketPath = 100

// ErrInvalid is wrapped by every parse failure.
var ErrInvalid = errors.New("host config: invalid")

// Config is the parsed file.
type Config struct {
	CoreUID   int
	CoreUnit  string
	Socket    string
	SocketGID int
	// CoreCgroup is the unified-hierarchy path core's processes must be at or below. Optional;
	// empty means /system.slice/<core_unit>. A rootless Quadlet core lives under its user manager,
	// so the installer writes the real path (WP-08).
	CoreCgroup string
}

var (
	unitRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9:_.@-]{0,100}\.service$`)
	keyRE  = regexp.MustCompile(`^[a-z_]+$`)
)

// Parse reads and validates the config text.
func Parse(r io.Reader) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return Config{}, fmt.Errorf("host config: read: %w", err)
	}
	if len(data) > MaxSize {
		return Config{}, fmt.Errorf("%w: file is larger than %d bytes", ErrInvalid, MaxSize)
	}
	var (
		c    Config
		seen = map[string]bool{}
		sc   = bufio.NewScanner(bytes.NewReader(data))
		line int
	)
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		k, v, ok := strings.Cut(text, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || !keyRE.MatchString(k) {
			return Config{}, fmt.Errorf("%w: line %d is not key = value", ErrInvalid, line)
		}
		if seen[k] {
			return Config{}, fmt.Errorf("%w: line %d repeats %s", ErrInvalid, line, k)
		}
		seen[k] = true
		if err := c.set(k, v); err != nil {
			return Config{}, fmt.Errorf("%w: line %d: %w", ErrInvalid, line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return Config{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	for _, k := range []string{"core_uid", "core_unit", "socket", "socket_gid"} {
		if !seen[k] {
			return Config{}, fmt.Errorf("%w: %s is required", ErrInvalid, k)
		}
	}
	return c, nil
}

func (c *Config) set(k, v string) error {
	switch k {
	case "core_uid":
		n, err := id(v)
		if err != nil {
			return fmt.Errorf("core_uid: %w", err)
		}
		if n == 0 {
			return errors.New("core_uid must not be 0: core never runs as root")
		}
		c.CoreUID = n
	case "socket_gid":
		n, err := id(v)
		if err != nil {
			return fmt.Errorf("socket_gid: %w", err)
		}
		c.SocketGID = n
	case "core_unit":
		if !unitRE.MatchString(v) {
			return errors.New("core_unit must be a systemd service unit name")
		}
		c.CoreUnit = v
	case "core_cgroup":
		if err := peer.ValidAnchor(v); err != nil {
			return fmt.Errorf("core_cgroup: %w", err)
		}
		c.CoreCgroup = v
	case "socket":
		if err := ValidSocketPath(v); err != nil {
			return err
		}
		c.Socket = v
	default:
		return fmt.Errorf("unknown key %q", k)
	}
	return nil
}

func id(v string) (int, error) {
	n, err := strconv.ParseUint(v, 10, 31)
	if err != nil {
		return 0, errors.New("must be a decimal number")
	}
	return int(n), nil
}

// ValidSocketPath accepts a clean absolute path short enough for a unix socket.
func ValidSocketPath(p string) error {
	switch {
	case p == "" || p[0] != '/':
		return errors.New("socket path must be absolute")
	case len(p) > maxSocketPath:
		return fmt.Errorf("socket path is longer than %d bytes", maxSocketPath)
	case strings.ContainsAny(p, "\x00\n\r") || p != cleanPath(p):
		return errors.New("socket path must be clean (no .., //, trailing /)")
	case p == "/":
		return errors.New("socket path must name a file")
	}
	return nil
}

func cleanPath(p string) string {
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		switch s {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, s)
		}
	}
	return "/" + strings.Join(out, "/")
}

// Load reads the file at path. The file must be a regular file owned by owner (0 in production)
// that neither group nor others can write, otherwise anyone who can edit it could choose
// which uid is allowed to command root.
func Load(path string, owner int) (Config, error) {
	f, err := os.Open(path) //nolint:gosec // path is the -config flag chosen by the operator
	if err != nil {
		return Config{}, fmt.Errorf("host config: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("host config: %w", err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.Mode().IsRegular():
		return Config{}, fmt.Errorf("%w: %s is not a regular file", ErrInvalid, path)
	case st.Mode().Perm()&0o022 != 0:
		return Config{}, fmt.Errorf("%w: %s must not be writable by group or others", ErrInvalid, path)
	case !ok || int(sys.Uid) != owner:
		return Config{}, fmt.Errorf("%w: %s must be owned by uid %d", ErrInvalid, path, owner)
	}
	return Parse(f)
}
