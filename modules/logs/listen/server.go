package listen

import (
	"bufio"
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Limits are the bounds of the listener (S-LOG-1, SYS-6; starting points to measure, ponytail). A zero field takes its default.
type Limits struct {
	MaxLine       int           // bytes of one message kept (8 KiB, the rsyslog default); a longer one is cut and counted
	MaxFrame      int           // largest datagram, octet count or newline-less line read (64 KiB)
	MaxConns      int           // TCP connections at once, all sources (1,000)
	MaxConnsIP    int           // TCP connections at once from one source (256)
	Idle          time.Duration // a connection that sends nothing for this long is closed (5 min)
	FrameTimeout  time.Duration // once a frame has started, the rest must arrive within this (30 s): slow-loris
	Rate          float64       // lines a second one source may send (2,000)
	Burst         int           // and the burst it may send at once (10,000); above Queue on purpose: the queue is the buffer behind the bucket, a UDP burst over it is dropped and counted, and TCP waits
	BatchLines    int           // lines in a batch (500)
	BatchBytes    int           // bytes of text in a batch (1 MiB)
	BatchWait     time.Duration // the longest a line waits for its batch (2 s)
	Queue         int           // lines waiting for a batch (4,096); a datagram is dropped and counted when it is full
	UnknownKept   int           // senders remembered while counting the unknown ones (256, least recently seen out)
	FlushOnClose  time.Duration // the longest a Sink call may take once the server is stopping (5 s)
	ErrorLogEvery time.Duration // the least time between two log lines about a failing Sink (10 s)
}

func (l Limits) withDefaults() Limits {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	defD := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&l.MaxLine, 8<<10)
	def(&l.MaxFrame, 64<<10)
	def(&l.MaxConns, 1000)
	def(&l.MaxConnsIP, 256)
	defD(&l.Idle, 5*time.Minute)
	defD(&l.FrameTimeout, 30*time.Second)
	if l.Rate <= 0 {
		l.Rate = 2000
	}
	def(&l.Burst, 10000)
	def(&l.BatchLines, 500)
	def(&l.BatchBytes, 1<<20)
	defD(&l.BatchWait, 2*time.Second)
	def(&l.Queue, 4096)
	def(&l.UnknownKept, 256)
	defD(&l.FlushOnClose, 5*time.Second)
	defD(&l.ErrorLogEvery, 10*time.Second)
	return l
}

// Source is a declared sender: the line's source id and the protocol it was declared with ("udp" or "tcp"; "tls" is not served
// here). The sender is identified by its IP address only.
type Source struct {
	ID    string
	Proto string
}

// Line is one received message, handed to the Sink.
type Line struct {
	SourceID string
	At       time.Time // receive time
	Text     string    // the message as received (framing removed, cut at Limits.MaxLine): untrusted
	Env      Envelope
}

// Config is what New needs.
type Config struct {
	// Host is the address to bind ("" = every IPv4 address). Ports are tried in order for the first listener that opens, and the
	// one that works is kept: a port is skipped only when binding it is not permitted (514 for a process without the right).
	// The list must not be empty; port 0 picks a free port (tests).
	Host  string
	Ports []int
	// Sink takes a batch of at most Limits.BatchLines lines. A batch it refuses is dropped and counted (the module's Ingest has
	// its own idempotence and bounds); it runs in one goroutine, one batch at a time.
	Sink   func(ctx context.Context, lines []Line) error
	Log    *slog.Logger
	Now    func() time.Time // nil: time.Now
	Limits Limits
}

// Server owns the sockets. It opens a UDP socket only while a UDP source is declared and a TCP one only while a TCP source is
// (nothing listens on a box with no sources), and closes them when the last such source goes (SetSources).
type Server struct {
	cfg Config
	lim Limits
	now func() time.Time

	mu       sync.Mutex
	running  bool
	ctx      context.Context
	sources  map[netip.Addr]Source
	srcView  atomic.Pointer[map[netip.Addr]Source]
	udp      *net.UDPConn
	tcp      net.Listener
	bindErr  [2]string // why udp and tcp are wanted but not open
	port     int       // the port chosen by the first listener that opened, 0 until then
	fellBack bool
	conns    map[net.Conn]netip.Addr
	perIP    map[netip.Addr]int
	wg       sync.WaitGroup

	queue chan Line

	rateMu  sync.Mutex
	buckets map[string]*bucket

	unkMu   sync.Mutex
	unknown *lru

	logMu   sync.Mutex
	lastLog time.Time

	st counters
}

type counters struct {
	received, unknown, rateDropped, queueDropped, truncated atomic.Int64
	connRejected, badFrames, sinkLost                       atomic.Int64
	rfc5424, rfc3164, cef, leef, raw                        atomic.Int64
}

// New returns a Server that is not listening yet.
func New(cfg Config) (*Server, error) {
	if cfg.Sink == nil || cfg.Log == nil || len(cfg.Ports) == 0 {
		return nil, errors.New("listen: creating server: Sink, Log and Ports are required")
	}
	s := &Server{cfg: cfg, lim: cfg.Limits.withDefaults(), now: cfg.Now, sources: map[netip.Addr]Source{}, conns: map[net.Conn]netip.Addr{}, perIP: map[netip.Addr]int{}, buckets: map[string]*bucket{}}
	if s.now == nil {
		s.now = time.Now
	}
	s.queue = make(chan Line, s.lim.Queue)
	s.unknown = newLRU(s.lim.UnknownKept)
	empty := map[netip.Addr]Source{}
	s.srcView.Store(&empty) // a map of its own: SetSources replaces the view, and nothing but the view is read without the lock
	return s, nil
}

// SetSources replaces the declared senders. While the server runs it opens or closes the sockets to match, and closes the
// connections of a sender that is gone or declared with another protocol. It returns the error of a socket that could not be
// opened (the joined errors of both protocols; the one that opened stays up, and Status says which one is down and why). The
// sources are kept, and calling it again retries the bind of the socket that is missing.
func (s *Server) SetSources(m map[netip.Addr]Source) error {
	cp := make(map[netip.Addr]Source, len(m))
	for ip, src := range m {
		cp[ip.Unmap()] = src
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = cp
	s.srcView.Store(&cp)
	s.rateMu.Lock()
	live := map[string]bool{}
	for _, src := range cp {
		live[src.ID] = true
	}
	for id := range s.buckets {
		if !live[id] {
			delete(s.buckets, id)
		}
	}
	s.rateMu.Unlock()
	if !s.running {
		return nil
	}
	return s.applyLocked()
}

func (s *Server) lookup(ip netip.Addr, proto string) (Source, bool) {
	src, ok := (*s.srcView.Load())[ip]
	return src, ok && src.Proto == proto
}

// Run serves until ctx ends: it opens the sockets the sources need, then closes everything and flushes the last batch. A socket
// that cannot be opened does not end it: Status says why, and the caller retries with SetSources. It returns ctx.Err().
func (s *Server) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("listen: already running")
	}
	s.running, s.ctx = true, ctx
	_ = s.applyLocked() // a failure is recorded in the status and logged; it is retried by SetSources
	s.mu.Unlock()
	// The batcher outlives ctx: only quit, after every producer is gone, ends it, so that what was accepted is stored. The Sink
	// is never given a context that quit cancels (a batch being stored is finished, not cut): see batcher.
	quit := make(chan struct{})
	batchDone := make(chan struct{})
	go func() { defer close(batchDone); s.batcher(context.WithoutCancel(ctx), quit) }()
	<-ctx.Done()
	s.mu.Lock()
	s.running = false
	s.closeLocked(true, true)
	s.mu.Unlock()
	s.wg.Wait() // no producer is left: the batcher flushes what is queued and ends
	close(quit)
	<-batchDone
	return ctx.Err()
}

// applyLocked opens and closes sockets to match the sources.
func (s *Server) applyLocked() error {
	var needUDP, needTCP bool
	for _, src := range s.sources {
		needUDP = needUDP || src.Proto == "udp"
		needTCP = needTCP || src.Proto == "tcp"
	}
	s.closeLocked(!needUDP, !needTCP)
	for conn, ip := range s.conns { // a sender that is gone or changed protocol
		if src, ok := s.sources[ip]; !ok || src.Proto != "tcp" {
			_ = conn.Close()
		}
	}
	var errs []error
	if needUDP && s.udp == nil {
		if sock, err := s.bind("udp"); err != nil {
			errs = append(errs, fmt.Errorf("udp: %w", err))
			s.noteBind(0, err)
		} else {
			s.udp = sock.(*net.UDPConn)
			s.wg.Add(1)
			go s.udpLoop(s.udp)
		}
	}
	if needTCP && s.tcp == nil {
		if sock, err := s.bind("tcp"); err != nil {
			errs = append(errs, fmt.Errorf("tcp: %w", err))
			s.noteBind(1, err)
		} else {
			s.tcp = sock.(net.Listener)
			s.wg.Add(1)
			go s.acceptLoop(s.tcp)
		}
	}
	if s.udp != nil || !needUDP {
		s.noteBind(0, nil)
	}
	if s.tcp != nil || !needTCP {
		s.noteBind(1, nil)
	}
	return errors.Join(errs...)
}

// noteBind records why socket i (0 udp, 1 tcp) is not open, or clears it, and logs a failure when the reason is new (a retry
// every half minute must not fill the log).
func (s *Server) noteBind(i int, err error) {
	text := ""
	if err != nil {
		text = err.Error()
	}
	if s.bindErr[i] == text {
		return
	}
	s.bindErr[i] = text
	if err != nil {
		s.cfg.Log.WarnContext(s.ctx, "logs: could not open a syslog socket; the other protocol is not affected and this one is retried", "proto", [2]string{"udp", "tcp"}[i], "err", err)
	}
}

func (s *Server) closeLocked(udp, tcp bool) {
	if udp && s.udp != nil {
		_ = s.udp.Close()
		s.udp = nil
	}
	if tcp && s.tcp != nil {
		_ = s.tcp.Close()
		s.tcp = nil
		if !s.running {
			for conn := range s.conns {
				_ = conn.Close()
			}
		}
	}
}

// bind opens one socket on the port in use, or tries the configured ports in order until one is permitted.
func (s *Server) bind(proto string) (sock io.Closer, err error) {
	ports := s.cfg.Ports
	if s.port != 0 {
		ports = []int{s.port}
	}
	var lc net.ListenConfig
	for i, p := range ports {
		addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(p))
		if proto == "udp" {
			sock, err = lc.ListenPacket(s.ctx, "udp4", addr)
		} else {
			sock, err = lc.Listen(s.ctx, "tcp4", addr)
		}
		if err == nil {
			if p != 0 {
				s.port = p
			}
			if i > 0 && !s.fellBack {
				s.fellBack = true
				s.cfg.Log.WarnContext(s.ctx, "logs: listening for syslog on a fallback port because the preferred one is not allowed", "port", p, "preferred", s.cfg.Ports[0])
			}
			return sock, nil
		}
		if !errors.Is(err, fs.ErrPermission) || i == len(ports)-1 {
			break
		}
	}
	return nil, err
}

// Addrs are the addresses the sockets are bound to; nil for a socket that is not open.
func (s *Server) Addrs() (udp, tcp net.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udp != nil {
		udp = s.udp.LocalAddr()
	}
	if s.tcp != nil {
		tcp = s.tcp.Addr()
	}
	return udp, tcp
}

// Status says which port is in use and whether it is not the preferred one.
type Status struct {
	Port      int  // 0 until a socket has opened
	Preferred int  // the first configured port
	FellBack  bool // Port is not Preferred, because Preferred was not permitted
	UDP, TCP  bool // sockets open
	// UDPErr and TCPErr are why a socket that is wanted (a source of that protocol exists) is not open; empty otherwise.
	UDPErr, TCPErr string
	Conns          int // TCP connections open now
}

// Status reports where the server listens.
func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{Port: s.port, Preferred: s.cfg.Ports[0], FellBack: s.fellBack, UDP: s.udp != nil, TCP: s.tcp != nil, UDPErr: s.bindErr[0], TCPErr: s.bindErr[1], Conns: len(s.conns)}
}

// UnknownSender is a sender that is not a declared source, with the lines it sent since the server started.
type UnknownSender struct {
	IP    netip.Addr
	Count int64
	Last  time.Time
}

// Stats are the counters since the server started.
type Stats struct {
	Received     int64 // lines accepted into the queue
	Unknown      int64 // datagrams and connections from senders that are not declared (or declared with another protocol)
	RateDropped  int64 // lines over the per-source rate
	QueueDropped int64 // datagrams dropped because the queue was full
	Truncated    int64 // messages cut at MaxLine
	ConnRejected int64 // connections over the total or per-sender limit
	BadFrames    int64 // connections closed for a bad octet count, an oversized frame or a stream that ended inside one
	SinkLost     int64 // lines in batches the Sink refused
	// Formats counts accepted lines by what their header was: rfc5424, rfc3164, cef, leef, raw.
	Formats       map[string]int64
	UnknownSender []UnknownSender // most recent first, at most Limits.UnknownKept
}

// Stats returns a snapshot.
func (s *Server) Stats() Stats {
	return Stats{
		Received: s.st.received.Load(), Unknown: s.st.unknown.Load(), RateDropped: s.st.rateDropped.Load(), QueueDropped: s.st.queueDropped.Load(),
		Truncated: s.st.truncated.Load(), ConnRejected: s.st.connRejected.Load(), BadFrames: s.st.badFrames.Load(), SinkLost: s.st.sinkLost.Load(),
		Formats:       map[string]int64{FormatRFC5424: s.st.rfc5424.Load(), FormatRFC3164: s.st.rfc3164.Load(), "cef": s.st.cef.Load(), "leef": s.st.leef.Load(), FormatRaw: s.st.raw.Load()},
		UnknownSender: s.unknownList(),
	}
}

// accept makes a Line from a message, counts it and queues it; block says whether a full queue holds the caller (TCP, which then
// stops reading and lets the sender's window close) or drops the line (UDP, which has no way to say "wait").
func (s *Server) accept(ctx context.Context, src Source, text []byte, truncated, block bool) bool {
	if !s.allow(src.ID) {
		s.st.rateDropped.Add(1)
		return true
	}
	if truncated {
		s.st.truncated.Add(1)
	}
	l := Line{SourceID: src.ID, At: s.now(), Text: string(text)}
	l.Env = Parse(l.Text)
	if block {
		select {
		case s.queue <- l:
		case <-ctx.Done():
			return false
		}
	} else {
		select {
		case s.queue <- l:
		default:
			s.st.queueDropped.Add(1)
			return true
		}
	}
	s.st.received.Add(1)
	switch l.Env.Counted() {
	case FormatRFC5424:
		s.st.rfc5424.Add(1)
	case FormatRFC3164:
		s.st.rfc3164.Add(1)
	case "cef":
		s.st.cef.Add(1)
	case "leef":
		s.st.leef.Add(1)
	default:
		s.st.raw.Add(1)
	}
	return true
}

// udpLoop reads datagrams; one datagram is one message (RFC 5426).
func (s *Server) udpLoop(c *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, s.lim.MaxFrame+1)
	for {
		n, ap, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select { // a transient error (an ICMP refusal): go on, but not in a hot loop
			case <-time.After(10 * time.Millisecond):
				continue
			case <-s.ctx.Done():
				return
			}
		}
		ip := ap.Addr().Unmap()
		src, ok := s.lookup(ip, "udp")
		if !ok {
			s.noteUnknown(ip)
			continue
		}
		msg := buf[:n]
		for len(msg) > 0 && (msg[len(msg)-1] == '\n' || msg[len(msg)-1] == '\r') {
			msg = msg[:len(msg)-1]
		}
		if len(msg) == 0 {
			continue
		}
		trunc := false
		if len(msg) > s.lim.MaxLine {
			msg, trunc = msg[:s.lim.MaxLine], true
		}
		s.accept(s.ctx, src, msg, trunc, false)
	}
}

func (s *Server) acceptLoop(l net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-time.After(10 * time.Millisecond):
				continue
			case <-s.ctx.Done():
				return
			}
		}
		ap, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = conn.Close()
			continue
		}
		ip := ap.AddrPort().Addr().Unmap()
		if _, ok := s.lookup(ip, "tcp"); !ok {
			s.noteUnknown(ip)
			_ = conn.Close()
			continue
		}
		switch s.register(l, conn, ip) {
		case regOverLimit:
			s.st.connRejected.Add(1)
			_ = conn.Close()
			continue
		case regStale: // the sources changed while it was being accepted: not over a limit
			s.noteUnknown(ip)
			_ = conn.Close()
			continue
		case regGone:
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go s.serveConn(conn, ip)
	}
}

// The answers of register.
const (
	regOK        = iota
	regOverLimit // the total or the per-sender limit is reached
	regStale     // the sender is no longer a TCP source
	regGone      // the listener is no longer the one in use
)

// register counts a connection against the limits, and refuses it (regOK is the only success) when the sources changed while it
// was being accepted: the sender must still be a TCP source and l still the listener in use, else the connection would outlive both.
func (s *Server) register(l net.Listener, conn net.Conn, ip netip.Addr) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l == nil || s.tcp != l {
		return regGone
	}
	if src, ok := s.sources[ip]; !ok || src.Proto != "tcp" {
		return regStale
	}
	if len(s.conns) >= s.lim.MaxConns || s.perIP[ip] >= s.lim.MaxConnsIP {
		return regOverLimit
	}
	s.conns[conn] = ip
	s.perIP[ip]++
	return regOK
}

func (s *Server) unregister(conn net.Conn, ip netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
	if s.perIP[ip]--; s.perIP[ip] <= 0 {
		delete(s.perIP, ip)
	}
}

func (s *Server) serveConn(conn net.Conn, ip netip.Addr) {
	defer s.wg.Done()
	defer s.unregister(conn, ip)
	defer func() { _ = conn.Close() }()
	done := make(chan struct{})
	defer close(done)
	go func() { // a shutdown must not wait for a silent sender's deadline
		select {
		case <-s.ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	br := bufio.NewReaderSize(conn, 4096)
	for {
		// Wait for the first byte of a frame under the idle deadline, past the line ends that a sender puts between frames (the
		// LF after an octet-counted frame, a blank line): they are not the start of a frame, so they must not arm the short one.
		_ = conn.SetReadDeadline(time.Now().Add(s.lim.Idle)) // once per gap: line ends alone do not renew it
		for {
			b, err := br.Peek(1)
			if err != nil {
				return
			}
			if b[0] != '\n' && b[0] != '\r' {
				break
			}
			_, _ = br.Discard(1)
		}
		_ = conn.SetReadDeadline(time.Now().Add(s.lim.FrameTimeout)) // absolute: a trickle of single bytes does not extend it
		frame, trunc, err := ReadFrame(br, s.lim.MaxLine, s.lim.MaxFrame)
		if err != nil {
			if errors.Is(err, ErrFrameTooLarge) || errors.Is(err, ErrShortFrame) {
				s.st.badFrames.Add(1)
			}
			return
		}
		src, ok := s.lookup(ip, "tcp") // still declared, and under the same id
		if !ok {
			return
		}
		if !s.accept(s.ctx, src, frame, trunc, true) {
			return
		}
	}
}

// bucket is a token bucket for one source.
type bucket struct {
	tokens float64
	last   time.Time
}

// allow spends one token of the source's bucket: Rate a second, Burst at most.
func (s *Server) allow(id string) bool {
	now := s.now()
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	b := s.buckets[id]
	if b == nil {
		b = &bucket{tokens: float64(s.lim.Burst), last: now}
		s.buckets[id] = b
	}
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(float64(s.lim.Burst), b.tokens+d.Seconds()*s.lim.Rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (s *Server) noteUnknown(ip netip.Addr) {
	s.st.unknown.Add(1)
	s.unkMu.Lock()
	s.unknown.touch(ip, s.now())
	s.unkMu.Unlock()
}

func (s *Server) unknownList() []UnknownSender {
	s.unkMu.Lock()
	defer s.unkMu.Unlock()
	return s.unknown.list()
}

// batcher groups the queued lines and hands them to the Sink: at most BatchLines lines or BatchBytes of text, or when the oldest
// has waited BatchWait. ctx is never cancelled; quit says that no producer is left, and then what is queued is flushed once more.
// A Sink call is not cut when quit fires: it gets the same context, but once quit has fired no call may take longer than
// FlushOnClose (a Sink that hangs must not hold the shutdown).
func (s *Server) batcher(ctx context.Context, quit <-chan struct{}) {
	var batch []Line
	size := 0
	var timer *time.Timer
	var tick <-chan time.Time
	store := func(lines []Line) {
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		over := make(chan struct{})
		defer close(over)
		go func() {
			select {
			case <-quit:
				t := time.NewTimer(s.lim.FlushOnClose)
				defer t.Stop()
				select {
				case <-t.C:
					cancel()
				case <-over:
				}
			case <-over:
			}
		}()
		if err := s.cfg.Sink(cctx, lines); err != nil {
			s.st.sinkLost.Add(int64(len(lines)))
			s.sinkFailed(ctx, err, len(lines))
		}
	}
	flush := func() {
		if timer != nil {
			timer.Stop()
			timer, tick = nil, nil
		}
		if len(batch) == 0 {
			return
		}
		store(batch)
		batch, size = nil, 0
	}
	add := func(l Line) {
		if len(batch) > 0 && size+len(l.Text) > s.lim.BatchBytes {
			flush()
		}
		if len(batch) == 0 {
			timer = time.NewTimer(s.lim.BatchWait)
			tick = timer.C
		}
		batch = append(batch, l)
		size += len(l.Text)
		if len(batch) >= s.lim.BatchLines || size >= s.lim.BatchBytes {
			flush()
		}
	}
	for {
		select {
		case l := <-s.queue:
			add(l)
		case <-tick:
			timer, tick = nil, nil
			flush()
		case <-quit:
			for {
				select {
				case l := <-s.queue:
					add(l)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *Server) sinkFailed(ctx context.Context, err error, n int) {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	if now := s.now(); now.Sub(s.lastLog) >= s.lim.ErrorLogEvery {
		s.lastLog = now
		s.cfg.Log.WarnContext(ctx, "logs: a batch of syslog lines was refused and dropped", "lines", n, "err", err)
	}
}

// lru counts the senders that are not declared, bounded: the least recently seen is forgotten first.
type lru struct {
	max int
	ll  *list.List
	idx map[netip.Addr]*list.Element
}

type lruEntry struct {
	ip    netip.Addr
	count int64
	last  time.Time
}

func newLRU(limit int) *lru {
	return &lru{max: limit, ll: list.New(), idx: map[netip.Addr]*list.Element{}}
}

func (l *lru) touch(ip netip.Addr, at time.Time) {
	if e, ok := l.idx[ip]; ok {
		en := e.Value.(*lruEntry)
		en.count++
		en.last = at
		l.ll.MoveToFront(e)
		return
	}
	l.idx[ip] = l.ll.PushFront(&lruEntry{ip: ip, count: 1, last: at})
	if l.ll.Len() > l.max {
		old := l.ll.Back()
		delete(l.idx, old.Value.(*lruEntry).ip)
		l.ll.Remove(old)
	}
}

func (l *lru) list() []UnknownSender {
	out := make([]UnknownSender, 0, l.ll.Len())
	for e := l.ll.Front(); e != nil; e = e.Next() {
		en := e.Value.(*lruEntry)
		out = append(out, UnknownSender{IP: en.ip, Count: en.count, Last: en.last})
	}
	return out
}
