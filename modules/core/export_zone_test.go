package core

// DefaultTimezone lets the external tests compare the organization's default zone with the one core/schedule reads.
const DefaultTimezone = defaultTimezone

// ZoneAlignedForTest reports whether the operating system side of the box's zone has been aligned at least once by this process.
func (h *OSHandlers) ZoneAlignedForTest() bool {
	h.tz.lastMu.Lock()
	defer h.tz.lastMu.Unlock()
	return h.tz.last != nil
}
