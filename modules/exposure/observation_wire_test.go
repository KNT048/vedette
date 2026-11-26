package exposure

import (
	"context"
	"errors"
	"net/netip"
	"slices"
)

// The matrix's network answers the calibration of the vantage (PathChecker) too: what a never-routed address gets on each port, a
// reset included, and whether the target's own answer on a port differs from it (omWire.distinct).

func (w *omWire) PathAnswers(_ context.Context, ports []int) (map[int]string, error) {
	if w.pathErr {
		return nil, errors.New("the check could not run")
	}
	out := map[int]string{}
	for _, p := range ports {
		out[p] = map[omAnswer]string{omSynAck: PortOpen, omReset: PortClosed, omSilence: PortSilent}[w.answer(omRunner, omTestNet, p)]
	}
	return out, nil
}

func (w *omWire) SameAsPath(_ context.Context, _ netip.Addr, port int) (bool, error) {
	if w.pathErr || w.sameErr {
		return false, errors.New("the check could not run")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return !slices.Contains(w.distinct, port), nil
}
