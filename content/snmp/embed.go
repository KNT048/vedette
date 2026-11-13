// Package snmpdata embeds what an SNMP agent's sysObjectID says about the device (D-512): the vendor of an IANA Private Enterprise
// Number, the product family of a documented sub-tree, and the device kind where that is clear. sensor-active reads it once at start
// (modules/sensor-active/snmpmap.go) and its tests check every row.
package snmpdata

import _ "embed"

// Enterprises is enterprises.json: {"enterprises": [{"number", "vendor", "kind"?, "families"?: [{"prefix", "product", "kind"?}]}],
// "descr": [{"phrase", "kind"}]}.
//
//go:embed enterprises.json
var Enterprises []byte
