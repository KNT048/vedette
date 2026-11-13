// Package devicetypes is the one list of device types (D-511): 14 categories for people and the types under them, each acting as
// one of the 13 kinds Vedette had before (the kinds behaviour is keyed on: fragile defaults, never-touch gateways, honeypot, SSH
// candidates, PDPL, response rules). types.json is the source: Go embeds it, the web imports it, and the zod contracts, the OpenAPI
// file and ogen are generated from it. rules.json holds the identification rules (Identify). Standard library only: every module may
// import it.
package devicetypes

import (
	_ "embed" // types.json, rules.json
	"encoding/json"
	"slices"
	"strings"
	"unicode"
)

//go:embed types.json
var typesJSON []byte

// Type is one device type.
type Type struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Category string   `json:"category"`
	ActsAs   string   `json:"acts_as"` // one of Kinds: what behaviour treats the type as
	Aliases  []string `json:"aliases"`
}

// Category is one group of types.
type Category struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Kinds are the 13 kinds behaviour is keyed on (the device types before D-511), in the order the settings list them. Every type acts
// as one of them; each of them is a type of its own.
var Kinds = []string{"firewall", "router", "switch", "ap", "nas", "server", "pc", "printer", "camera", "nvr", "iot", "web", "unknown"}

// Unknown is the type of a device nobody has classified.
const Unknown = "unknown"

var (
	types      []Type
	categories []Category
	byID       = map[string]*Type{}
	byName     = map[string]string{} // folded id, label or alias → id
	ids        []string
)

func init() {
	var doc struct {
		Categories []Category `json:"categories"`
		Types      []Type     `json:"types"`
	}
	if err := json.Unmarshal(typesJSON, &doc); err != nil {
		panic("devicetypes: types.json: " + err.Error()) // our own file, checked by a test
	}
	types, categories = doc.Types, doc.Categories
	for i := range types {
		t := &types[i]
		byID[t.ID] = t
		ids = append(ids, t.ID)
	}
	// ids first, then labels, then aliases: an alias never takes a name an id or a label already has.
	for _, t := range types {
		byName[Fold(t.ID)] = t.ID
	}
	for _, t := range types {
		if _, ok := byName[Fold(t.Label)]; !ok {
			byName[Fold(t.Label)] = t.ID
		}
	}
	for _, t := range types {
		for _, a := range t.Aliases {
			if _, ok := byName[Fold(a)]; !ok {
				byName[Fold(a)] = t.ID
			}
		}
	}
}

// Valid reports whether id is a type.
func Valid(id string) bool { _, ok := byID[id]; return ok }

// IDs returns every type id, in the file's order (grouped by category). The caller may not change it.
func IDs() []string { return ids }

// Types returns every type. The caller may not change it.
func Types() []Type { return types }

// Categories returns the categories in display order. The caller may not change it.
func Categories() []Category { return categories }

// ActsAs is the kind behaviour treats the type as; Unknown for an id that is not a type.
func ActsAs(id string) string {
	if t, ok := byID[id]; ok {
		return t.ActsAs
	}
	return Unknown
}

// CategoryOf is the category of the type; "unknown" for an id that is not a type.
func CategoryOf(id string) string {
	if t, ok := byID[id]; ok {
		return t.Category
	}
	return Unknown
}

// Label is what a person reads for the type; the id itself when it is not a type.
func Label(id string) string {
	if t, ok := byID[id]; ok {
		return t.Label
	}
	return id
}

// ActingAs returns every type that acts as one of kinds, and every type listed in kinds itself, in the file's order: what a read keyed
// on kinds (never-touch gateways, the devices logs names) must ask the database for.
func ActingAs(kinds []string) []string {
	var out []string
	for _, t := range types {
		if slices.Contains(kinds, t.ActsAs) || slices.Contains(kinds, t.ID) {
			out = append(out, t.ID)
		}
	}
	return out
}

// Lookup finds the type a person wrote: its id, label or one of its aliases, without case, accents or punctuation ("Wi-Fi (AP)",
// "camera_recorder", "IP phone").
func Lookup(name string) (string, bool) {
	id, ok := byName[Fold(name)]
	return id, ok
}

// Fold lower-cases, strips accents and turns every run of other characters into one space: "Wi-Fi (AP)" -> "wi fi ap".
func Fold(s string) string {
	var b strings.Builder
	space := true
	for _, r := range strings.ToLower(s) {
		if r > unicode.MaxASCII {
			r = baseLetter(r)
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			space = false
		} else if !space {
			b.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSuffix(b.String(), " ")
}

// baseLetter maps a Latin letter with a diacritic (Vietnamese included) to its base letter; anything else to a space.
func baseLetter(r rune) rune {
	for base, group := range accents {
		if strings.ContainsRune(group, r) {
			return base
		}
	}
	return ' '
}

var accents = map[rune]string{
	'a': "àáạảãâầấậẩẫăằắặẳẵäåāą", 'e': "èéẹẻẽêềếệểễëēę", 'i': "ìíịỉĩïī", 'o': "òóọỏõôồốộổỗơờớợởỡöō",
	'u': "ùúụủũưừứựửữüū", 'y': "ỳýỵỷỹÿ", 'c': "çćč", 'n': "ñń", 's': "śš", 'z': "źżž", 'd': "đ",
}
