// Command apigen prepares api/openapi.json for ogen and writes the role table.
//
//	go run ./core/api/apigen -in api/openapi.json -spec $TMP/openapi.json -routes core/api/routes/routes_gen.go
//
// It fails (and writes nothing) when any operation lacks a valid x-min-role (INV-5).
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	in := flag.String("in", "api/openapi.json", "contract to read")
	spec := flag.String("spec", "", "where to write the normalised spec for ogen (a temp path; never committed)")
	routes := flag.String("routes", "", "where to write the Go role table")
	flag.Parse()
	if *spec == "" || *routes == "" {
		return fmt.Errorf("apigen: -spec and -routes are required")
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return fmt.Errorf("apigen: %w", err)
	}
	doc, err := Parse(raw)
	if err != nil {
		return err
	}
	ops, err := Operations(doc)
	if err != nil {
		return err
	}
	src, err := RoutesSource(ops)
	if err != nil {
		return err
	}
	st := Normalise(doc)
	out, err := Marshal(doc)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*spec, out, 0o600); err != nil {
		return fmt.Errorf("apigen: %w", err)
	}
	if err := os.WriteFile(*routes, src, 0o644); err != nil { //nolint:gosec // generated source file, not a secret
		return fmt.Errorf("apigen: %w", err)
	}
	fmt.Printf("apigen: %d operations; normalised %+v\n", len(ops), st)
	return nil
}
