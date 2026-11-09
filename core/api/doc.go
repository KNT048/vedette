// Package api holds the server side generated from api/openapi.json (D-18, D-60).
//
//   - apigen: generation-time tool that normalises the contract for ogen and writes the role table.
//   - oas: ogen server code (types, strict handler interface, router, request validation).
//   - routes: operationId -> method, path, minimum role, module tag (from x-min-role).
//
// Regenerate with `make generate-api`; never edit the generated files.
package api
