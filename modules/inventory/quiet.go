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
// shows nothing wrong. A **quiet** device is one of those: it stays in the inventory, searchable and listed with the approved
// devices, and counts toward To review and the new-device notice only when it earns a look (INV-49).

// stablePrefixes are locally administered MAC prefixes that are set by hand or by a hypervisor and never rotate: QEMU/KVM and libvirt
// guests (52:54:00), Docker's default bridge (02:42), VirtualBox host-only adapters (0a:00:27). A device with one is not a phone's
// random address: it is reviewed as any other.
var stablePrefixes = []string{"52:54:00", "02:42", "0a:00:27"}

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

// quietSQL is the SQL test, on inv_asset aliased a, of a quiet device: found (not declared), not approved, not suspicious, not the
// box and no enrolled agent; its MAC is private, and so is every other MAC a sensor saw on it (a burned-in or stable one means it is
// a real machine); it has no open service on record; and it has been seen over no more than a day (first to last sighting): one that keeps coming back longer is a regular and is reviewed.
const quietSQL = `(a.approved = 0 AND a.origin = 'discovered' AND a.suspicious = 0 AND a.is_box = 0 AND a.agent_key IS NULL AND a.ignored_at IS NULL
	AND PRIV_A_MAC
	AND NOT EXISTS (SELECT 1 FROM inv_observation q WHERE q.asset_id = a.id AND q.field = 'mac' AND q.evidence IS NOT 'chassis' AND NOT PRIV_Q_VALUE)
	AND NOT EXISTS (SELECT 1 FROM inv_service s WHERE s.asset_id = a.id)
	AND julianday(a.last_seen) - julianday(a.first_seen) <= 1.0)`

var quietExpr = strings.NewReplacer("PRIV_A_MAC", privateSQL("a.mac"), "PRIV_Q_VALUE", privateSQL("q.value")).Replace(quietSQL)

// toReviewSQL is the SQL test of a device in To review: not approved, and not quiet. Ignored devices are in no list or count of
// theirs (the callers add that condition).
var toReviewSQL = "(a.approved = 0 AND NOT " + quietExpr + ")"

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

// announceIfEarned publishes the new-device notice of a device that was quiet before a write (wasQuiet) and no longer is: it got an
// open service, or it stayed past a day. The notice is the one a device found with a burned-in MAC gets at once, so nothing is lost
// by waiting, only the noise of a rotating address. A device that stays quiet, or that was never quiet, announces nothing here.
func announceIfEarned(ctx context.Context, tx *sql.Tx, o *outbox, id string, wasQuiet bool) error {
	if !wasQuiet {
		return nil
	}
	quiet, err := isQuiet(ctx, tx, id)
	if err != nil || quiet {
		return err
	}
	var approved, ignored bool
	if err := tx.QueryRowContext(ctx, `SELECT approved, ignored_at IS NOT NULL FROM inv_asset WHERE id = ?`, id).Scan(&approved, &ignored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("inventory: read the review state: %w", err)
	}
	if approved || ignored { // a person already dealt with it
		return nil
	}
	notify, err := notifyNew(ctx, tx)
	if err != nil || !notify {
		return err
	}
	o.add(EventAssetUpdated, AssetEvent{AssetID: id, Notify: true})
	return nil
}
