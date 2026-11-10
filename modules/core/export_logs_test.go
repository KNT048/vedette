package core

import "github.com/knt048/vedette/core/logexport"

// LogSourcesForTest is the registry behind GET /core/logs/export: external tests register fake sources on it.
func (h *APIHandlers) LogSourcesForTest() *logexport.Registry { return h.logs }

// SetLogsCapForTest lowers the size cap of the export.
func (h *APIHandlers) SetLogsCapForTest(n int64) { h.logsCap = n }
