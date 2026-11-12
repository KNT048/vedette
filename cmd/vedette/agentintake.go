package main

import (
	"path/filepath"

	"github.com/knt048/vedette/core/jobs"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
)

// agentIntakeJobs is the node-prune job of agent-intake: a normal job (not Housekeeping), so it never runs while the module is off (D-265 (8)).
func agentIntakeJobs(d deps) []jobs.Job {
	if d.AgentIntake == nil {
		return nil
	}
	return d.AgentIntake.Jobs()
}

// defaultOsqueryDir is where the core image keeps the pinned osquery packages (deploy/containers/core/Containerfile).
const defaultOsqueryDir = "/usr/share/vedette/osquery"

// trustAnchor is agentintake.Config.TrustAnchor: the certificates osquery pins to trust this box (INV-11), read once at start from the
// certificate the listener serves, so ca.pem and the scripts always match what is served. Plain HTTP on loopback has no certificate
// (agentintake.ErrNoTrustAnchor); an owner's certificate (-tls-cert) gives the chain they supplied.
func trustAnchor(o options) func() ([]byte, error) {
	certPath, owner := o.tlsCert, o.tlsCert != ""
	if loop, err := isLoopback(o.listen); !owner && (err != nil || loop) {
		return func() ([]byte, error) { return nil, agentintake.ErrNoTrustAnchor }
	}
	if !owner {
		certPath = filepath.Join(filepath.Dir(o.db), "vedette-selfsigned.crt")
	}
	pem, err := trustAnchorPEM(certPath, owner)
	return func() ([]byte, error) { return pem, err }
}
