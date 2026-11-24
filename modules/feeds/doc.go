// Package feeds is the pure library behind the feeds module: parsing of
// untrusted feed data, boundary validation, the HTTP fetcher, scheduling rules and
// the IOC verdict. It has no database, no events and no job registration; the
// module wiring calls into it.
//
// Everything that reads feed data is fail-closed (SYS-6): size and row limits,
// bad rows are rejected and counted, never half-accepted.
package feeds
