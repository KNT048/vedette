-- name: InsertSensorCert :exec
INSERT INTO core_sensor_cert (serial, role, not_after) VALUES (?, ?, ?);

-- name: ListLiveSensorCerts :many
SELECT serial, role, not_after, retired_at FROM core_sensor_cert
WHERE role = ? AND retired_at IS NULL
ORDER BY rowid DESC;

-- name: RetireSensorCert :exec
UPDATE core_sensor_cert SET retired_at = ? WHERE serial = ? AND retired_at IS NULL;
