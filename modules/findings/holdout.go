//go:build holdout

package findings

// The hold-out build (go test -tags holdout, never a release build): the matcher without the product catalogue's CPE aliases, so a
// match pass shows what the box decides from standard data alone and the coverage gap names what still rests on catalogue rows.
func init() { cpeAliases = map[identity][]identity{} }
