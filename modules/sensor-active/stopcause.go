package sensoractive

import (
	"errors"
	"strings"
)

// stopCause is why a run in progress was stopped while it ran (it is ErrStopped): words is what its run page and its probe row say,
// and again says a person's check may go on after it (the device moved, the settings changed but still allow it).
type stopCause struct {
	words string
	again bool
}

func (e *stopCause) Error() string        { return "sensoractive: stopped: " + e.words }
func (e *stopCause) Is(target error) bool { return target == ErrStopped }

// The reasons a run in progress is stopped for, one per path that stops it (SettingsChanged, AssetChanged, Stop, the weekly scan's
// give way, probe's own checks right before nmap).
var (
	// errLeftAddress: the device is no longer at the address the run probes (it moved, or another device took the address: #874, #882).
	// What an earlier scan of the run found at that address is dropped too, since it is recorded by address.
	errLeftAddress    = &stopCause{words: "the device was no longer at the address being checked (it moved, or another device took the address)", again: true}
	errSettingsMoved  = &stopCause{words: "the scan settings changed just before nmap started", again: true}
	errDeviceGone     = &stopCause{words: "the device was removed from the inventory"}
	errDeviceUnread   = &stopCause{words: "the device could not be read from the inventory"}
	errSettingsUnread = &stopCause{words: "the scan settings could not be read"}
	errScanOff        = &stopCause{words: "active scanning was turned off"}
	errScopeOff       = &stopCause{words: "the scan scope is no longer confirmed"}
	errWindowClosed   = &stopCause{words: "the scan window closed or was shortened"}
	errRateLowered    = &stopCause{words: "the scan rate was lowered below the rate it ran at"}
	errLeftScope      = &stopCause{words: "its address is no longer inside the scan scope"}
	errBatchProtected = &stopCause{words: "a device in the batch may no longer be scanned"}
	errModuleOff      = &stopCause{words: "the module was turned off"}
	errGaveWay        = &stopCause{words: "it gave way to other work queued behind it"}
)

// settingsStop is the reason of a run stopped because the settings no longer allow scanning (Settings.allowed's error).
func settingsStop(err error) *stopCause {
	if errors.Is(err, ErrScanningOff) {
		return errScanOff
	}
	return errScopeOff
}

// policyStop is the reason of a device run stopped because the device's own safety rules changed under it: why is the inventory's
// reason ("" when the decision still allows it, but more gently or more slowly than it runs).
func policyStop(dec Decision, why string) *stopCause {
	switch {
	case dec.Never || why == reasonNever:
		return &stopCause{words: "the device was set to never be scanned"}
	case why == reasonScanningOff:
		return errScanOff
	case why == reasonScopeNotConfirmed:
		return errScopeOff
	case why == "out_of_scope":
		return errLeftScope
	case dec.Fragile || why == reasonFragilePassive:
		return &stopCause{words: "the device was marked fragile, so it may only have its gentle scan"}
	case dec.Unclassified || why == reasonUnclassifiedPassive:
		return &stopCause{words: "the device's type became unknown, so it may only be scanned gently"}
	case why != "" && why != "ok":
		return &stopCause{words: "the device's scan settings no longer allow it (" + why + ")"}
	}
	return &stopCause{words: "the device's scan settings now allow only a gentler or slower scan"}
}

// stopCur stops the run in progress for why: the first reason stays, so the run says the one that stopped it.
func (s *Service) stopCur(cur *running, why *stopCause) {
	s.mu.Lock()
	if cur.why == nil {
		cur.why = why
	}
	s.mu.Unlock()
	cur.cancel()
}

// whyStopped is the reason run cur was stopped for (stopCur), nil when none was given.
func (s *Service) whyStopped(cur *running) error {
	if cur == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cur.why
}

// curWhy is whyStopped of the run in progress.
func (s *Service) curWhy() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil
	}
	return s.cur.why
}

// cmpErr is why when there is one, else err.
func cmpErr(why, err error) error {
	if why != nil {
		return why
	}
	return err
}

// stopWords is what a stop says in words: the reason when one is known; a run cut by its own deadline or by a stop asked from outside
// (a person's Stop, Vedette stopping) says so.
func stopWords(err error) string {
	var c *stopCause
	switch {
	case errors.As(err, &c):
		return c.words
	case errors.Is(err, errDeadline):
		return "its time ran out (the end of the scan window, or the longest a run may take)"
	}
	return "the run was stopped"
}

// stoppedLine is the line of a probe row or a run log for a stop: "stopped: " and its words.
func stoppedLine(err error) string {
	return "stopped: " + strings.TrimPrefix(stopWords(err), "stopped: ")
}

// canGoOn says a person's check stopped by err may run again at once: the device moved, or the settings changed but may still allow it.
func canGoOn(err error) bool {
	var c *stopCause
	return errors.As(err, &c) && c.again
}
