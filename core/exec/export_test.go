package exec

// SetPTMX points the Runner at another master device, so a test sees what happens when no terminal can be opened.
func SetPTMX(r *Runner, path string) { r.ptmx = path }
