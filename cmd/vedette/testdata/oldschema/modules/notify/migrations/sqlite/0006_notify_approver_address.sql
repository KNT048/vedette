-- +goose Up
-- D-242: one approver address on a channel belongs to one person. A reply or a button press names its sender by address, and an
-- address listed for two people stands for nobody (response refuses it, D-135), so the list never holds one twice. Rows saved before
-- this rule that share an address on one channel could never approve anything: they are removed so the index can be made; the
-- channel's other approvers stay.
DELETE FROM notify_approver WHERE (channel_type, address) IN (
    SELECT channel_type, address FROM notify_approver GROUP BY channel_type, address HAVING COUNT(*) > 1
);
CREATE UNIQUE INDEX notify_approver_address_ux ON notify_approver (channel_type, address);
