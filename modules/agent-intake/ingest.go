package agentintake

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
)

// Log takes the results of one log request from an enrolled node (INV-7, INV-12). errNodeInvalid for a key that is not a node's;
// a 429 apierr over the node's rate; nil otherwise, even when nothing was written (an unmatched node, an empty list): the answer to
// osquery is the same, what it did not write is in the server log.
func (s *Service) Log(ctx context.Context, src netip.Addr, in logIn) error {
	n, err := s.authNode(ctx, "log", src, in.nodeKey, "log", logPerMin)
	if err != nil {
		return err
	}
	if !in.result {
		return s.touch(ctx, n)
	}
	ip, mac, update := binding(n, src, in)
	if err := s.markResult(ctx, n, ip, mac, update); err != nil {
		return err
	}
	if !ip.IsValid() {
		s.warnUnmatched(ctx, n.id,
			"node", n.id, "src", src.String(), "declared_interfaces", len(in.snaps["interfaces"]))
		return nil
	}
	return s.deliver(ctx, observe.AssetHint{IP: ip, MAC: mac}, mac, n.id, in)
}

// binding is the anti-spoofing rule of D-169 (5): the inventory is written only for the device whose address is the one this connection
// came from, and the MAC is the one of that very card. The address is the TCP peer, which the client cannot forge and no proxy hides;
// it must be among the IPv4 the node declared in its interfaces result of this request, or in the last one that matched. No match,
// an IPv6 or a NAT'd peer: nothing is written (fail closed). update says the request carried an interfaces result, so the stored
// binding is replaced by the answer (also by "none").
func binding(n nodeRow, src netip.Addr, in logIn) (ip netip.Addr, mac string, update bool) {
	src = src.Unmap().WithZone("")
	rows, declared := in.snaps["interfaces"]
	if declared {
		if src.Is4() {
			for _, i := range parseInterfaces(rows) {
				if i.ip == src {
					return src, i.mac, true
				}
			}
		}
		return netip.Addr{}, "", true
	}
	if src.Is4() && n.boundIP == src && n.boundMAC != "" {
		return src, n.boundMAC, false
	}
	return netip.Addr{}, "", false
}

// markResult stores that the node delivered a result log, and its new binding when the request had an interfaces result.
func (s *Service) markResult(ctx context.Context, n nodeRow, ip netip.Addr, mac string, update bool) error {
	ts := store.FormatTS(s.now())
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET last_seen = ?, last_result_at = ? WHERE id = ?`, ts, ts, n.id); err != nil {
			return fmt.Errorf("agentintake: mark node: %w", err)
		}
		if update {
			var bip, bmac any
			if ip.IsValid() {
				bip, bmac = ip.String(), mac
			}
			if _, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET bound_ip = ?, bound_mac = ? WHERE id = ?`, bip, bmac, n.id); err != nil {
				return fmt.Errorf("agentintake: bind node: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE intake_agent_tokens SET last_received = ? WHERE id = ?`, ts, n.tokenID); err != nil {
			return fmt.Errorf("agentintake: mark token: %w", err)
		}
		return nil
	})
}

// deliver hands the device facts and the package list to the inventory. An empty package list never replaces the stored one
// (POST-2 of the plan): a node whose package table failed or is empty must not wipe what was known.
func (s *Service) deliver(ctx context.Context, hint observe.AssetHint, mac, node string, in logIn) error {
	if obs := observations(hint, in.snaps, mac); len(obs) > 0 {
		if err := s.record(ctx, obs); err != nil {
			return err
		}
	}
	items, dropped := mapPackages(in.snaps)
	if dropped > 0 || len(in.truncated) > 0 || in.dropped > 0 {
		s.cfg.Log.InfoContext(ctx, "agent-intake: rows dropped", "node", node, "rows_not_fitting", dropped, "events_or_rows_refused", in.dropped, "truncated", len(in.truncated))
	}
	if len(items) == 0 {
		if hasPackageQuery(in) {
			s.cfg.Log.InfoContext(ctx, "agent-intake: an empty package list kept the stored one", "node", node)
		}
		return nil
	}
	if err := s.cfg.Software.ReplaceSoftware(ctx, hint, observe.Agent, items); err != nil {
		if transient(err) {
			return fmt.Errorf("agentintake: software: %w", err)
		}
		// The inventory refused this list. osquery would resend it for ever; the next snapshot is a whole new list, so drop it here.
		s.cfg.Log.ErrorContext(ctx, "agent-intake: the inventory refused a software list", "node", node, "error", err.Error())
	}
	return nil
}

func hasPackageQuery(in logIn) bool {
	for _, q := range []string{"deb_packages", "rpm_packages", "programs"} {
		if _, ok := in.snaps[q]; ok {
			return true
		}
	}
	return false
}

// transient says the error is the store being busy or the request going away: the caller retries, osquery resends the log.
func transient(err error) bool {
	return errors.Is(err, store.ErrBusy) || errors.Is(err, store.ErrFrozen) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// record sends observations, dropping the one the inventory rejects at its boundary and sending the rest (observe.ErrRejected).
func (s *Service) record(ctx context.Context, obs []observe.Observation) error {
	for range len(obs) + 1 {
		err := s.cfg.Sink.Record(ctx, obs)
		if err == nil {
			return nil
		}
		var rej *observe.ErrRejected
		if !errors.As(err, &rej) || rej.Index < 0 || rej.Index >= len(obs) {
			if transient(err) {
				return fmt.Errorf("agentintake: observations: %w", err)
			}
			s.cfg.Log.ErrorContext(ctx, "agent-intake: the inventory refused observations", "error", err.Error())
			return nil
		}
		obs = slices.Delete(obs, rej.Index, rej.Index+1)
		if len(obs) == 0 {
			return nil
		}
	}
	return nil
}
