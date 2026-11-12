package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

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

// trustAnchor is agentintake.Config.TrustAnchor: the certificates osquery pins to trust this box (INV-11). Plain HTTP on loopback has no
// certificate (agentintake.ErrNoTrustAnchor). An owner's certificate (-tls-cert) gives the chain they supplied, read once at start. Otherwise
// it is the box CA sealed in core_secret (D-351, core INV-33), asked each time through sealed (intakeTrustAnchor), which answers 503
// server_busy while the 8443 leaf is being re-issued under a new CA. Only CERTIFICATE blocks are ever handed out (no key next to an
// owner's certificate, no PEM headers).
func trustAnchor(o options, sealed func(context.Context) ([]byte, error)) func() ([]byte, error) {
	owner := o.tlsCert != ""
	if loop, err := isLoopback(o.listen); sealed == nil || (!owner && (err != nil || loop)) {
		return func() ([]byte, error) { return nil, agentintake.ErrNoTrustAnchor }
	}
	if owner {
		raw, err := os.ReadFile(o.tlsCert)
		if err != nil {
			err = fmt.Errorf("tls: trust anchor: %w", err)
		}
		certs, cerr := certBlocks(raw)
		if err == nil {
			err = cerr
		}
		return func() ([]byte, error) { return certs, err }
	}
	return func() ([]byte, error) {
		raw, err := sealed(context.Background())
		if err != nil {
			return nil, err
		}
		return certBlocks(raw)
	}
}

// certBlocks copies only the CERTIFICATE blocks of a PEM text, without headers.
func certBlocks(raw []byte) ([]byte, error) {
	var out []byte
	for {
		var blk *pem.Block
		if blk, raw = pem.Decode(raw); blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: blk.Type, Bytes: blk.Bytes})...)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("tls: the trust anchor holds no certificate")
	}
	return out, nil
}
