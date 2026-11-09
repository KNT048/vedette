package feeds

// BodyLimits is the per-operation request cap this module needs above the server default (operationId → bytes).
// cmd/vedette hands it to server.Config through moduleWiring.BodyLimits.
//
// parse-test takes a sample of up to 5 000 000 characters (contract.ts, INV-2) inside a JSON body: newlines and quotes
// grow by one byte each when escaped, so 8 MiB holds any real sample. A bigger body is refused before it is read.
var BodyLimits = map[string]int64{"feeds_post_feeds_parse_test": 8 << 20}
