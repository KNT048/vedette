-- +goose Up
-- The history row a message sent again (Send again): the History marks it "Sent again", so a resend with the same words reads as
-- the copy of an earlier message, not as a second alert. NULL for a message sent the first time. The id is written by Resend only, from
-- a row it just read. Forward-only: there is no Down section.
ALTER TABLE notify_send ADD COLUMN resend_of TEXT;
