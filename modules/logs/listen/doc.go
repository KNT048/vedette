// Package listen receives syslog from the customer's devices over UDP and TCP and hands it to a Sink in batches (WP-24 L2,
// S-LOG-1). It imports neither database/sql nor core/store, on purpose: like modules/sensor-passive/capture it runs inside
// core now and moves to vedette-sensor unchanged (L6); the module (modules/logs) owns storage and gives it a Sink.
//
// Everything that arrives is untrusted (SYS-6, INV-1): framing and parsing fail closed and are bounded in size and time, a
// sender that is not a declared source is dropped and counted, and a source that floods is rate limited. Nothing in a line is
// ever interpreted; the text is passed on as received and the module's Ingest cleans it.
package listen
