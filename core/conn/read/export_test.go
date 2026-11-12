package read

import (
	"context"
	"time"
)

// CloseTimeForTest is how long the close of a session under ctx may take.
func CloseTimeForTest(ctx context.Context) time.Duration { return closeTime(ctx) }

// SetBudgetForTest shortens the time of a call.
func (r *Reader) SetBudgetForTest(d time.Duration) { r.budget = d }

// SetAfterCredentialForTest runs f between opening the credential and dialling.
func (r *Reader) SetAfterCredentialForTest(f func()) { r.afterCredential = f }

// SetListBudgetForTest shortens the time of a listing.
func (r *Reader) SetListBudgetForTest(d time.Duration) { r.listBudget = d }

// FlushCacheForTest forgets the tools the MCP servers listed.
func (r *Reader) FlushCacheForTest() {
	r.mu.Lock()
	r.cache = map[string]cacheEntry{}
	r.mu.Unlock()
}
