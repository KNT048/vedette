package domainfence

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/knt048/vedette/core/domainfence/proofat"
	"github.com/knt048/vedette/core/localnet"
)

// The zone's own name servers, asked directly, the way ACME clients (lego's propagation check) confirm a DNS-01 record: a recursive
// resolver keeps an answer for as long as its TTL (often an hour), so a record a person has just put in place, or changed, may not
// be seen through it yet. When the resolver's answer proves nothing, Owned asks the zone's authoritative servers for the same names,
// with the same rules:
//
//   - the servers are the NS records of the registered domain of the name asked (proofat.Registered), looked up through the box's
//     resolver (none when that name is a CNAME: the NS records would be its target's), at most maxNameServers of them, each at
//     its first public IPv4 address (never a private, loopback or local one);
//   - each query asks for no recursion; an answer counts only from a server that answers with authority (the AA flag), for the
//     question asked, with the message id sent: a referral (a server answering for a parent zone only), a lame server, a recursive
//     resolver listed as a name server, or an answer to another question counts for nothing;
//   - only records whose owner is the name asked count; a CNAME there means the name is not proved (its target's records are not its own);
//   - every server that answers with authority must carry the record (lego's rule): one server of a lame or hijacked delegation
//     cannot prove a name the others deny. A server that does not answer, or refuses, is left out, as a resolver would leave it out.
//
// Whoever answers for the zone at its delegated servers is whoever a recursive resolver would end up asking: this trusts no one new,
// it only skips the resolver's cache.

// maxNameServers bounds the servers asked for one name.
const maxNameServers = 4

// authQueryTimeout bounds each query to one server (a server that does not answer is left out).
const authQueryTimeout = 2 * time.Second

// ednsSize is the UDP payload size the query offers (the DNS Flag Day 2020 value); a truncated answer is asked again over TCP.
const ednsSize = 1232

// AuthAnswer is what the zone's own name servers answer for the TXT records of one name.
type AuthAnswer struct {
	Servers []string // the servers that answered with authority, sorted
	TXT     []string // the TXT values every one of them answers for the name
	Some    []string // the TXT values at least one of them answers
	CNAME   bool     // one of them answers that the name is a CNAME
}

// Authority asks a zone's own name servers for the TXT records of a name. A resolver that implements it lets Owned look past a
// stale cached answer; one that does not keeps to the recursive answer.
type Authority interface {
	AuthTXT(ctx context.Context, name string) (AuthAnswer, error)
}

// NSResolver is what Authoritative asks the box's resolver: the zone's NS records and their addresses, and whether the zone's name is
// a CNAME; *net.Resolver satisfies it.
type NSResolver interface {
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Authoritative is the Authority that finds a zone's servers through R and asks them over the network (UDP, then TCP when the
// answer is truncated). Exchange replaces the network in tests: it sends the query to the server and returns its answer.
type Authoritative struct {
	R        NSResolver
	Exchange func(ctx context.Context, server netip.Addr, query []byte) ([]byte, error)
}

// SystemResolver is the system resolver with the zone's own name servers behind it: what production passes to New, Owned and
// exposure.
type SystemResolver struct {
	*net.Resolver
	auth *Authoritative
}

// NewSystemResolver is net.DefaultResolver with its Authority.
func NewSystemResolver() SystemResolver {
	return SystemResolver{Resolver: net.DefaultResolver, auth: &Authoritative{R: net.DefaultResolver}}
}

// AuthTXT asks the zone's own name servers (Authoritative.AuthTXT).
func (s SystemResolver) AuthTXT(ctx context.Context, name string) (AuthAnswer, error) {
	return s.auth.AuthTXT(ctx, name)
}

// errNoAuthority is the answer when no server of the zone answered with authority: nothing is known from them.
var errNoAuthority = errors.New("no name server of the zone answered with authority")

// hostName says whether name is a DNS name the check may ask: labels of letters, digits, hyphens and underscores (the
// _vedette-verify label), 1 to 63 bytes each, at most 253 in all.
func hostName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for l := range strings.SplitSeq(name, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
		for _, c := range []byte(l) {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}

// AuthTXT asks the name servers of name's registered domain for its TXT records, each without recursion, side by side.
func (a *Authoritative) AuthTXT(ctx context.Context, name string) (AuthAnswer, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	zone, ok := proofat.Registered(name)
	if !hostName(name) || !ok || !ValidDomain(zone) || (name != zone && !strings.HasSuffix(name, "."+zone)) {
		return AuthAnswer{}, errors.New("not a name under a registered domain")
	}
	servers, err := a.servers(ctx, zone)
	if err != nil {
		return AuthAnswer{}, err
	}
	type result struct {
		host string
		ans  answer
		ok   bool
	}
	res := make([]result, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Go(func() {
			qctx, cancel := context.WithTimeout(ctx, authQueryTimeout)
			defer cancel()
			ans, ok := a.ask(qctx, s.addr, name)
			res[i] = result{host: s.host, ans: ans, ok: ok}
		})
	}
	wg.Wait()
	var out AuthAnswer
	first := true
	for _, r := range res {
		if !r.ok {
			continue
		}
		out.Servers = append(out.Servers, r.host)
		out.CNAME = out.CNAME || r.ans.cname
		for _, v := range r.ans.txt {
			if !slices.Contains(out.Some, v) {
				out.Some = append(out.Some, v)
			}
		}
		if first {
			out.TXT, first = slices.Clone(r.ans.txt), false
			continue
		}
		out.TXT = slices.DeleteFunc(out.TXT, func(v string) bool { return !slices.Contains(r.ans.txt, v) })
	}
	if len(out.Servers) == 0 {
		return AuthAnswer{}, errNoAuthority
	}
	return out, nil
}

type nameServer struct {
	host string
	addr netip.Addr
}

// servers is the zone's name servers, each with its first public IPv4 address, sorted by name, at most maxNameServers.
func (a *Authoritative) servers(ctx context.Context, zone string) ([]nameServer, error) {
	// A resolver follows a CNAME, and LookupNS keeps every NS record of the answer: for a registered domain that is a CNAME (a name
	// under a private public suffix such as a platform's host name) those would be the NS records of the CNAME's target, whose
	// servers may claim the zone's names. Such a zone has no servers of its own to ask.
	cn, err := a.R.LookupCNAME(ctx, zone+".")
	switch {
	case err != nil && !notFound(err):
		return nil, err
	case err == nil && strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cn), ".")) != zone:
		return nil, errors.New(zone + " is a CNAME to another name: it has no name servers of its own")
	}
	nss, err := a.R.LookupNS(ctx, zone+".")
	if err != nil {
		return nil, err
	}
	var hosts []string
	for _, ns := range nss {
		h := strings.ToLower(strings.TrimSuffix(ns.Host, "."))
		if ValidDomain(h) && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	slices.Sort(hosts)
	if len(hosts) > maxNameServers {
		hosts = hosts[:maxNameServers]
	}
	out := make([]nameServer, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Go(func() {
			addrs, err := a.R.LookupNetIP(ctx, "ip4", h+".")
			if err != nil {
				return
			}
			for _, ad := range addrs {
				if ad = ad.Unmap(); ad.Is4() && localnet.Public(ad) {
					out[i] = nameServer{host: h, addr: ad}
					return
				}
			}
		})
	}
	wg.Wait()
	out = slices.DeleteFunc(out, func(s nameServer) bool { return !s.addr.IsValid() })
	if len(out) == 0 {
		return nil, errors.New("no public address for a name server of " + zone)
	}
	return out, nil
}

// answer is one server's authoritative answer for a name: its TXT values and whether the name is a CNAME there.
type answer struct {
	txt   []string
	cname bool
}

// ask sends one query to server and reads its answer; ok is false when it does not count (no answer, not authoritative, not
// for this question).
func (a *Authoritative) ask(ctx context.Context, server netip.Addr, name string) (answer, bool) {
	q, id, err := query(name)
	if err != nil {
		return answer{}, false
	}
	var resp []byte
	if a.Exchange != nil {
		resp, err = a.Exchange(ctx, server, q)
	} else {
		resp, err = exchange(ctx, server, q, id)
	}
	if err != nil {
		return answer{}, false
	}
	return parseAnswer(resp, id, name)
}

// query is the TXT question for name without recursion, with a random id and an EDNS0 payload size.
func query(name string) ([]byte, uint16, error) {
	var idb [2]byte
	_, _ = rand.Read(idb[:]) // crypto/rand.Read never fails (Go 1.24+)
	id := binary.BigEndian.Uint16(idb[:])
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, 0, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id})
	if err := b.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, 0, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(ednsSize, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, 0, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, 0, err
	}
	msg, err := b.Finish()
	return msg, id, err
}

// parseAnswer reads a server's answer to the TXT question for name sent with id. It counts only when it is a response with that id,
// to that one question, authoritative, NOERROR or NXDOMAIN, not truncated. Of its answer records only those owned by name count:
// TXT values (the strings of one record joined, as net.LookupTXT does) and a CNAME.
func parseAnswer(resp []byte, id uint16, name string) (answer, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil || h.ID != id || !h.Response || h.OpCode != 0 || !h.Authoritative || h.Truncated ||
		(h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError) {
		return answer{}, false
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 || qs[0].Type != dnsmessage.TypeTXT || qs[0].Class != dnsmessage.ClassINET || !sameName(qs[0].Name, name) {
		return answer{}, false
	}
	var out answer
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return answer{}, false
		}
		if !sameName(rh.Name, name) || rh.Class != dnsmessage.ClassINET {
			if err := p.SkipAnswer(); err != nil {
				return answer{}, false
			}
			continue
		}
		switch rh.Type {
		case dnsmessage.TypeTXT:
			r, err := p.TXTResource()
			if err != nil {
				return answer{}, false
			}
			out.txt = append(out.txt, strings.Join(r.TXT, ""))
		case dnsmessage.TypeCNAME:
			out.cname = true
			if err := p.SkipAnswer(); err != nil {
				return answer{}, false
			}
		default:
			if err := p.SkipAnswer(); err != nil {
				return answer{}, false
			}
		}
	}
	return out, true
}

func sameName(n dnsmessage.Name, name string) bool {
	return strings.EqualFold(strings.TrimSuffix(n.String(), "."), name)
}

// exchange sends q to server's port 53 over UDP and, when the answer is truncated, again over TCP.
func exchange(ctx context.Context, server netip.Addr, q []byte, id uint16) ([]byte, error) {
	addr := netip.AddrPortFrom(server, 53).String()
	resp, err := roundTrip(ctx, "udp", addr, q, id)
	if err == nil && len(resp) > 2 && resp[2]&0x02 != 0 { // TC: the answer did not fit
		return roundTrip(ctx, "tcp", addr, q, id)
	}
	return resp, err
}

// roundTrip sends q and reads the answer with id; over UDP a datagram with another id (stray or spoofed) is skipped, and the
// connected socket takes datagrams from the server's address only.
func roundTrip(ctx context.Context, network, addr string, q []byte, id uint16) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if network == "tcp" {
		if len(q) > 0xffff {
			return nil, errors.New("the query is too long")
		}
		msg := binary.BigEndian.AppendUint16(nil, uint16(len(q))) //nolint:gosec // bounded to 0xffff just above
		if _, err := c.Write(append(msg, q...)); err != nil {
			return nil, err
		}
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, resp); err != nil {
			return nil, err
		}
		return resp, nil
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 12 && binary.BigEndian.Uint16(buf[:2]) == id && buf[2]&0x80 != 0 {
			return slices.Clone(buf[:n]), nil
		}
	}
}
