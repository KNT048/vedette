package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// A phone or laptop that uses a private (randomised) Wi-Fi address shows up under a new MAC and a new lease again and again. Sameness
// by host name (sameMachine) folds what it can; the rest would each raise a To review item and a new-device notice for a device that
// shows nothing wrong. A **quiet** device is one of those: it stays in the inventory, searchable, in To review's collapsed Seen briefly
// group (state seen), and counts toward To review and the new-device notice only when it earns a look (INV-49).

// stablePrefixes are locally administered MAC prefixes that are set by hand or by a hypervisor and never rotate: QEMU/KVM and libvirt
// guests (52:54:00), Docker's default bridge (02:42), VirtualBox host-only adapters (0a:00:27), Kubernetes CNI pod and bridge interfaces (0a:58, the CNI bridge plugin's derived MACs). A device with one is not a phone's
// random address: it is reviewed as any other.
var stablePrefixes = []string{"52:54:00", "02:42", "0a:00:27", "0a:58"}

// PrivateMAC reports a locally administered MAC that a device picks for itself and changes (a private Wi-Fi address): the
// locally administered bit is set and the prefix is not one of stablePrefixes. mac is normalised (lower case, colons).
func PrivateMAC(mac string) bool {
	if len(mac) != 17 || !localMAC(mac) {
		return false
	}
	for _, p := range stablePrefixes {
		if strings.HasPrefix(mac, p) {
			return false
		}
	}
	return true
}

// stablePrefixSQL is the SQL test that the MAC expression x starts with one of stablePrefixes.
func stablePrefixSQL(x string) string {
	parts := make([]string, len(stablePrefixes))
	for i, p := range stablePrefixes {
		parts[i] = fmt.Sprintf("substr(%s, 1, %d) = '%s'", x, len(p), p)
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// privateSQL is the SQL test of a private MAC (PrivateMAC): not burned in and not a stable prefix.
func privateSQL(x string) string {
	return "(" + x + " IS NOT NULL AND NOT " + fmt.Sprintf(universalMAC, x) + " AND NOT " + stablePrefixSQL(x) + ")"
}

// quietClassSQL is the SQL test, on inv_asset aliased a, of a device that is quiet unless it earned review: found (not declared), not
// approved, not suspicious, not the box, no enrolled agent, not ignored, and its MAC and every other MAC a sensor saw on it private (a
// burned-in or stable one means it is a real machine).
const quietClassSQL = `(a.approved = 0 AND a.origin = 'discovered' AND a.suspicious = 0 AND a.is_box = 0 AND a.agent_key IS NULL AND a.ignored_at IS NULL
	AND PRIV_A_MAC
	AND NOT EXISTS (SELECT 1 FROM inv_observation q WHERE q.asset_id = a.id AND q.field = 'mac' AND q.evidence IS NOT 'chassis' AND NOT PRIV_Q_VALUE))`

// quietSQL is a quiet device: of that class, with no open service on record, seen over no more than a day (first to last sighting),
// and no review earned yet (review_earned_at, sticky: INV-49).
const quietSQL = `(CLASS AND a.review_earned_at IS NULL
	AND NOT EXISTS (SELECT 1 FROM inv_service s WHERE s.asset_id = a.id)
	AND julianday(a.last_seen) - julianday(a.first_seen) <= 1.0)`

var quietClass = strings.NewReplacer("PRIV_A_MAC", privateSQL("a.mac"), "PRIV_Q_VALUE", privateSQL("q.value")).Replace(quietClassSQL)
var quietExpr = strings.Replace(quietSQL, "CLASS", quietClass, 1)

// DeviceState is where a device stands (INV-9): the one rule the Devices list, To review and its Seen briefly group, the row text, the
// counts and the new-device notice read. A device a sensor found is never shown as added until a person adds it or its agent's first
// report does (INV-25), as endpoint tools keep discovered devices apart from onboarded ones.
type DeviceState string

// The states, in the order stateSQL decides them.
const (
	DeviceIgnored DeviceState = "ignored" // a person ignored it (INV-38)
	DeviceAdded   DeviceState = "added"   // approved: added by a person, approved by one, its agent's first report, or the box
	DeviceSeen    DeviceState = "seen"    // not added and quiet (quietSQL, INV-49): To review's collapsed Seen briefly group
	DeviceReview  DeviceState = "review"  // not added: To review
)

// stateSQL is DeviceState on inv_asset aliased a.
var stateSQL = "(CASE WHEN a.ignored_at IS NOT NULL THEN 'ignored' WHEN a.approved = 1 THEN 'added' WHEN " + quietExpr + " THEN 'seen' ELSE 'review' END)"

// toReviewSQL is the SQL test of a device in To review's count and notice: state review.
var toReviewSQL = "(" + stateSQL + " = 'review')"

// isQuiet reports whether device id is quiet now (quietSQL), inside tx.
func isQuiet(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	var q bool
	err := tx.QueryRowContext(ctx, `SELECT `+quietExpr+` FROM inv_asset a WHERE a.id = ?`, id).Scan(&q)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("inventory: read the review state: %w", err)
	}
	return q, nil
}

// earnReview makes the review of a device sticky once it has a reason: a quiet-class device (quietClassSQL) that has an open service,
// has stayed past a day, or (reason) a finding or a honeypot hit, gets review_earned_at set and, when the new-device alert is on,
// one new-device notice, both in this write. It stays in To review until a person approves or ignores it; a later write finds the mark
// set and announces nothing. Every write that can add a service, move last_seen, fold or merge a device calls it (INV-49).
func (s *Service) earnReview(ctx context.Context, tx *sql.Tx, o *outbox, id string, reason bool) error {
	var class, quiet bool
	err := tx.QueryRowContext(ctx, `SELECT `+quietClass+` AND a.review_earned_at IS NULL, `+quietExpr+` FROM inv_asset a WHERE a.id = ?`, id).Scan(&class, &quiet)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inventory: read the review state: %w", err)
	}
	if !class || (quiet && !reason) {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET review_earned_at = ? WHERE id = ? AND review_earned_at IS NULL`, s.now(), id); err != nil {
		return fmt.Errorf("inventory: mark the device for review: %w", err)
	}
	notify, err := notifyNew(ctx, tx)
	if err != nil || !notify {
		return err
	}
	o.add(EventAssetUpdated, AssetEvent{AssetID: id, Notify: true})
	return nil
}

// EarnReview is earnReview for a reason outside inventory: a finding raised on the device or a honeypot hit from it. A device that is
// not quiet, or unknown, is left alone.
func (s *Service) EarnReview(ctx context.Context, id string) error {
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error { return s.earnReview(ctx, tx, o, id, true) })
}
