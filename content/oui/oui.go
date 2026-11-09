// Package oui maps the first bits of a MAC address to the company the IEEE registered them to (D-83).
// The table is built by `make oui` from runZero's mac-tracker (MIT; the data comes from the IEEE Registration
// Authority registries), committed as oui.tsv.gz and embedded: the product never downloads it.
package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed" // oui.tsv.gz
	"strconv"
	"strings"
	"sync"
)

//go:embed oui.tsv.gz
var data []byte

var (
	once  sync.Once
	table map[string]string // hex prefix of 6, 7 or 9 digits (24, 28, 36 bits) → vendor
)

// load parses the embedded table once. The file is ours and checked by a test; a line that does not parse
// is skipped rather than trusted.
func load() {
	table = make(map[string]string, 60000)
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		prefix, rest, ok := strings.Cut(sc.Text(), "\t")
		bits, vendor, ok2 := strings.Cut(rest, "\t")
		n, err := strconv.Atoi(bits)
		if !ok || !ok2 || err != nil || len(prefix) != n/4 || vendor == "" {
			continue
		}
		table[prefix] = vendor
	}
}

// Len is the number of prefixes in the table.
func Len() int {
	once.Do(load)
	return len(table)
}

// Lookup returns the vendor of a MAC address by the longest registered prefix (/36, then /28, then /24).
// Group (multicast) addresses and locally administered addresses (bit 1 of the first octet: randomised phone
// addresses, virtual machines) were not issued by the IEEE and have no vendor.
func Lookup(mac [6]byte) (vendor string, ok bool) {
	if mac[0]&0x03 != 0 {
		return "", false
	}
	once.Do(load)
	const hexd = "0123456789abcdef"
	var h [9]byte
	for i := range 9 {
		b := mac[i/2]
		if i%2 == 0 {
			h[i] = hexd[b>>4]
		} else {
			h[i] = hexd[b&15]
		}
	}
	for _, n := range [...]int{9, 7, 6} {
		if v, found := table[string(h[:n])]; found {
			return v, true
		}
	}
	return "", false
}
