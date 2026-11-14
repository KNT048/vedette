// Package catalogdata embeds the data files of the product catalog, which the web interface imports too:
// ONE data source for both sides (INV-12, D-30, D-58: knowledge about products is data, not code).
//
//   - curated.json: products small businesses use, by commercial name, in popularity order.
//   - kev-products.json: every vendor/product pair ever in CISA KEV (CC0), made by `pnpm fixtures`. It is a
//     stand-in until feeds (WP-20) supplies the live list through inventory.KEV.
package catalogdata

import _ "embed"

// Curated is curated.json.
//
//go:embed curated.json
var Curated []byte

// KEVProducts is kev-products.json.
//
//go:embed kev-products.json
var KEVProducts []byte

// NVDCPE is nvd-cpe.json: the NVD CPE products of an inventory vendor|product (D-500), read by findings.
//
//go:embed nvd-cpe.json
var NVDCPE []byte

// NmapCPE maps a CPE nmap -sV prints to the NVD CPE products of the same software (W11-2; cmd/vedette exposurematch.go).
//
//go:embed nmap-cpe.json
var NmapCPE []byte
