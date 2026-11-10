//go:build !webui

package webui

import "io/fs"

// FS is nil in a build without the `webui` tag: Handler then answers with the stub page.
func FS() fs.FS { return nil }
