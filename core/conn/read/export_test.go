package read

import (
	"context"
	"time"
)

// CloseDeadlineForTest is when the close of a session under ctx must end.
func CloseDeadlineForTest(ctx context.Context) time.Time { return closeDeadline(ctx) }

// SetOnCloseForTest runs f with the context of the call and the one its session's close runs under, just before the close.
func (r *Reader) SetOnCloseForTest(f func(call, closing context.Context)) { r.onClose = f }

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
