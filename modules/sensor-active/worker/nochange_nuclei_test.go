package worker_test

import "testing"

// D-528: in every job, a LAN one too, a template file that writes, uploads or goes to another host is invalid_job, even when the
// image's index lists it with its hash; nuclei never starts.
func TestNucleiRefusesATemplateThatChangesTheTarget(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"a PUT":    "id: CVE-2024-2\nhttp:\n  - raw:\n      - |\n        PUT /api/changePw HTTP/1.1\n        Host: {{Hostname}}\n",
		"an @Host": "id: CVE-2024-2\nhttp:\n  - raw:\n      - |\n        @Host: https://login.microsoftonline.com:443\n        GET /x HTTP/1.1\n        Host: {{Hostname}}\n",
		"a shell":  "id: CVE-2024-2\nhttp:\n  - raw:\n      - |\n        POST /q HTTP/1.1\n        Host: {{Hostname}}\n\n        q=1;exec xp_cmdshell 'whoami'\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := startNuclei(t, printJSONL)
			rewrite(t, r.pack.Index, r.pack.File("CVE-2024-2"), body)
			r.core.push(r.job(id1))
			if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "invalid_job" || r.nu.Argv() != "" {
				t.Fatalf("result = %+v, argv %q", got.res, r.nu.Argv())
			}
		})
	}
}
