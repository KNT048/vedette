// Package modules embeds every module's MANIFEST.yaml so the binary can load them with
// core/modreg without reading the source tree at run time. cmd/vedette passes Manifests to the
// registry; core never imports this package (FORBID-2).
package modules

import "embed"

// Manifests holds <module>/MANIFEST.yaml for every folder of modules/, including the _template
// (the registry skips folders that start with an underscore).
//
//go:embed */MANIFEST.yaml
var Manifests embed.FS
