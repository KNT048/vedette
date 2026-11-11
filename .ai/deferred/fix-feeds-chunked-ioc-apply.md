applyVulns for a custom vulnerability list (≤ 50k rows) holds the writer ~3 s in one tx; chunking needs care with `replace` and `markAnnounced`
