-- +goose Up
-- An other address of a device that its main network card (inv_asset.mac) answers on too: a router or server with two addresses on one
-- card, or a router answering ARP for a second address. 1 marks such a row (an IPv4 address, no MAC of its own). Its address was
-- proven to be the card's own (the card answered there and at the main address within minutes), so a sighting at either address keeps
-- the main address where it is, and another MAC seen at that address is another machine, never this one. Validated in Go (0 or 1).
-- Forward-only: there is no Down section.
ALTER TABLE inv_asset_address ADD COLUMN main_card INTEGER NOT NULL DEFAULT 0;
