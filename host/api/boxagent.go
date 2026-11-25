package api

import (
	"crypto/x509"
	"encoding/pem"
)

// The osquery agent on the box itself (spec 6.19). The Linux install command of the Agents page can be run on the box like on any
// server; it writes the box CA of that moment to /etc/osquery/vedette-ca.pem. A reinstall or a data purge gives the box a new CA, and
// /etc/osquery is not Vedette's package, so it survives both: the agent would then fail every few seconds against a box that no longer
// trusts it. core asks the host, at its start, to compare that file with the CA agents pin now.

// CmdBoxAgentCheck is box_agent.check.
const CmdBoxAgentCheck = "box_agent.check"

// MaxBoxAgentCA is the largest trust anchor core passes (a box CA is under 1 KiB; an owner's chain a few).
const MaxBoxAgentCA = 16 << 10

// States of box_agent.check.
const (
	BoxAgentNone      = "none"      // no Vedette agent configuration on the box
	BoxAgentCurrent   = "current"   // it pins a certificate of the anchor core gave: left as it is
	BoxAgentElsewhere = "elsewhere" // it reports to another address than the box's own (another Vedette box): left as it is
	// BoxAgentNotVedettes: the osquery here is not set up the way Vedette's install command sets it up (its flags or its unit could
	// point it at another server): a doubt, so it is left as it is.
	BoxAgentNotVedettes = "not_vedette"
	BoxAgentRemoved     = "removed" // it pinned another CA and pointed at the box: stopped, disabled and its Vedette settings removed
)

// BoxAgentCheckArgs are the args of box_agent.check: the certificates (PEM) agents pin to trust the box now (GET /intake/ca.pem).
type BoxAgentCheckArgs struct {
	CA string `json:"ca"`
}

// BoxAgentCheckResult is the result of box_agent.check.
type BoxAgentCheckResult struct {
	State string `json:"state"`
}

// ParseAnchor returns the certificates of a PEM trust anchor; nil when it holds none, holds anything else, or is too large.
func ParseAnchor(pemText []byte) []*x509.Certificate {
	if len(pemText) == 0 || len(pemText) > MaxBoxAgentCA {
		return nil
	}
	var out []*x509.Certificate
	for rest := pemText; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil
		}
		out = append(out, c)
	}
	return out
}
