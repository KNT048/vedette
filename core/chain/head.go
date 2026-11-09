package chain

// Head is the newest row of a chain as recorded in core_chain_head (issue #17): its hash and the number of
// rows the chain holds now. Every append moves it in the same transaction (chainhead.Advance); a retention
// prune must lower Count in its own transaction. Like the chain itself it is tamper-evident, not
// tamper-proof: someone who can rewrite the database file can rewrite the head too (DATA_MODEL 5.3).
// Reading and writing it lives in package chainhead, so this package stays free of any database code
// (vedette-host, the root process, links chain for its audit hash and must not link SQLite: D-87).
type Head struct {
	Hash  string
	Count int64
}
