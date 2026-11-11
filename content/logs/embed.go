// Package logsdata embeds the data of the logs module that the web interface reads too: the 48 log source kinds (D-30),
// the protocols each can send with (first is the default) and whether Vedette reads it ("parsed") or only stores and
// searches it ("stored"). ONE data source for both sides: web/src/features/logs/catalog.ts must agree with this file
// (kinds.parity.test.ts), so a kind cannot be added to one side only.
package logsdata

import _ "embed"

// Kinds is kinds.json: [{"id", "protos", "reads"}].
//
//go:embed kinds.json
var Kinds []byte
