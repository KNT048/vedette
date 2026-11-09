// Package sensorlink is the wire between core and the sensor containers (D-109 to D-112, docs/specs/sensor-protocol.md): an
// HTTPS and JSON server for core's second listener (:8444) and the client vedette-sensor uses. Mutual TLS 1.3 against a CA
// that only signs sensor identities (core/pki) says which role a caller has; the role decides which routes it may call, and
// everything a sensor sends is untrusted data: capped, strictly decoded, validated at the edge.
//
// The package is standard library plus internal/jsonstrict, so the sensor binary can link it without core's database,
// secrets or SQLite. It never imports core/pki: the server takes an Identity, which pki.Authority implements.
package sensorlink
