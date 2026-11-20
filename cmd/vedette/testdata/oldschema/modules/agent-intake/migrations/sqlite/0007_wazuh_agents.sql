-- +goose Up
-- #849: the address and card of every Wazuh agent the pull delivered to the inventory, so the Devices list can tell a device Wazuh
-- reports from one osquery reports (both write source agent; osquery binds its node key, Wazuh cannot: its agent ids are per
-- manager). A row belongs to the connection generation that wrote it; readers take the saved connection's generation only, so a
-- deleted or replaced connection names no device. A completed pass deletes the agents it no longer read. Forward-only (DATA_MODEL 6).
CREATE TABLE intake_wazuh_agent (
    agent_id   TEXT    NOT NULL PRIMARY KEY CHECK (length(agent_id) BETWEEN 3 AND 10 AND agent_id NOT GLOB '*[^0-9]*'),
    generation INTEGER NOT NULL,
    ip         TEXT    NOT NULL CHECK (length(ip) BETWEEN 7 AND 15),
    mac        TEXT    NOT NULL DEFAULT '' CHECK (mac = '' OR length(mac) = 17),
    seen_at    TEXT    NOT NULL
);
