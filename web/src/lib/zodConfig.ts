import { z } from 'zod'

// Zod 4 probes once whether `new Function` works (to compile fast parsers). The shipped CSP has no 'unsafe-eval' (D-149), so the
// probe fails quietly but the browser still reports a CSP violation in the console (issue #201). jitless skips the probe and the
// compiled path; parsing stays correct, only slightly slower, which these small API bodies do not notice.
z.config({ jitless: true })
