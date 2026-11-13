package main

import (
	"context"
	"fmt"
	"os"

	"github.com/knt048/vedette/core/jobs"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
)

// agentIntakeJobs is the jobs of agent-intake (node-prune, wazuh-pull, approve-enrolled): normal jobs (not Housekeeping), so none runs
// while the module is off (D-265 (8)).
func agentIntakeJobs(d deps) []jobs.Job {
	if d.AgentIntake == nil {
		return nil
	}
	return d.AgentIntake.Jobs()
}

// defaultOsqueryDir is where the core image keeps the pinned osquery packages (deploy/containers/core/Containerfile).
const defaultOsqueryDir = "/usr/share/vedette/osquery"

// trustAnchor is agentintake.Config.TrustAnchor: the certificates osquery pins to trust this box (INV-11). Plain HTTP on loopback has no
// certificate (agentintake.ErrNoTrustAnchor). An owner's certificate (-tls-cert) gives the chain they supplied, read once at start. Otherwise
// it is the box CA sealed in core_secret (D-351, core INV-33), asked each time through sealed (intakeTrustAnchor), which answers 503
// server_busy while the 8443 leaf is being re-issued under a new CA. The bytes go over as read: agent-intake keeps only their CERTIFICATE
// blocks (its INV-11), so the key of an owner's combined file never leaves.
func trustAnchor(o options, sealed func(context.Context) ([]byte, error)) func() ([]byte, error) {
	if o.tlsCert != "" {
		raw, err := os.ReadFile(o.tlsCert)
		if err != nil {
			err = fmt.Errorf("tls: trust anchor: %w", err)
		}
		return func() ([]byte, error) { return raw, err }
	}
	if loop, err := isLoopback(o.listen); sealed == nil || err != nil || loop {
		return func() ([]byte, error) { return nil, agentintake.ErrNoTrustAnchor }
	}
	return func() ([]byte, error) { return sealed(context.Background()) }
}
