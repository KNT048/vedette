package transport

import (
	"bufio"
	"io"
	"strings"
)

// Event is one server-sent event (the text/event-stream format of the WHATWG HTML standard, as far as MCP's streamable HTTP uses it).
type Event struct {
	Type string // "message" when the stream names none
	ID   string
	Data string // the data lines joined with a line feed
}

// ReadEvents reads r and calls fn for each complete event until fn returns true, the stream ends, or r fails. A line longer
// than MaxResponse is an error. An event that is cut off by the end of the stream is not delivered. Comments (lines that begin
// with a colon) and unknown fields are skipped.
func ReadEvents(r io.Reader, fn func(Event) (stop bool)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxResponse+1)
	var typ, id string
	var data []string
	have := false
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if line == "" {
			if have {
				t := typ
				if t == "" {
					t = "message"
				}
				ev := Event{Type: t, ID: id, Data: strings.Join(data, "\n")}
				typ, id, data, have = "", "", nil, false
				if fn(ev) {
					return nil
				}
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			typ, have = value, true
		case "data":
			data, have = append(data, value), true
		case "id":
			id, have = value, true
		}
	}
	return sc.Err()
}
