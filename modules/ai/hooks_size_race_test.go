//go:build race

package ai

// hostileSize is small under the race detector, which makes every byte about ten times dearer.
const hostileSize = 1 << 16
