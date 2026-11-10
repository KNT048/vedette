package sensorpassive

import (
	"container/list"
	"hash/maphash"
	"time"

	"github.com/knt048/vedette/core/observe"
)

// repeatTTL and maxRepeats bound core's repeat filter: the same (MAC, IP, field, value) is written at most once in a quarter of an
// hour (the capture's own filter says the same, D-80). The filter is what stops a sensor from turning one observation into a
// write for each time it sends it.
const (
	repeatTTL  = 15 * time.Minute
	maxRepeats = 100_000
)

// repeatFilter remembers observations by a keyed hash (8 bytes, seed chosen at start-up), bounded as an LRU. Not safe for
// concurrent use: the caller holds Service.submitMu.
type repeatFilter struct {
	seed  maphash.Seed
	index map[uint64]*list.Element
	order *list.List // of *repeatEntry, most recent first
}

type repeatEntry struct {
	key uint64
	at  time.Time
}

func newRepeatFilter() *repeatFilter {
	return &repeatFilter{seed: maphash.MakeSeed(), index: map[uint64]*list.Element{}, order: list.New()}
}

func (f *repeatFilter) key(o observe.Observation) uint64 {
	var h maphash.Hash
	h.SetSeed(f.seed)
	for _, part := range []string{o.AssetHint.MAC, o.AssetHint.IP.String(), string(o.Field), o.Value} {
		_, _ = h.WriteString(part)
		_ = h.WriteByte(0)
	}
	return h.Sum64()
}

// seen reports whether o was recorded within the TTL before now.
func (f *repeatFilter) seen(o observe.Observation, now time.Time) bool {
	el, ok := f.index[f.key(o)]
	return ok && now.Sub(el.Value.(*repeatEntry).at) < repeatTTL
}

// add records o as written at now; the least recently written is forgotten when the filter is full.
func (f *repeatFilter) add(o observe.Observation, now time.Time) {
	k := f.key(o)
	if el, ok := f.index[k]; ok {
		el.Value.(*repeatEntry).at = now
		f.order.MoveToFront(el)
		return
	}
	if f.order.Len() >= maxRepeats {
		last := f.order.Back()
		delete(f.index, last.Value.(*repeatEntry).key)
		f.order.Remove(last)
	}
	f.index[k] = f.order.PushFront(&repeatEntry{key: k, at: now})
}
