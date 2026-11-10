package sensorpassive_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
	sp "github.com/knt048/vedette/modules/sensor-passive"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

func frames() map[string][]pktgen.Frame {
	return map[string][]pktgen.Frame{"eth0": pktgen.LANDiscovery(), "eth1": pktgen.SpanMetadata()}
}

// sources parses every non-test Go file of the package and of its capture subpackage (all build tags: the Linux file is read too).
func sources(t *testing.T) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	more, err := filepath.Glob("capture/*.go") // the capture half lives in a package of its own
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, more...)
	out := map[string]*ast.File{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		out[f] = af
	}
	if len(out) < 10 {
		t.Fatalf("found only %d source files", len(out))
	}
	return out
}

// selectors lists the X.Sel pairs used with a package identifier, per file.
func selectors(af *ast.File, pkg string) []string {
	var out []string
	ast.Inspect(af, func(n ast.Node) bool {
		if se, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := se.X.(*ast.Ident); ok && id.Name == pkg {
				out = append(out, se.Sel.Name)
			}
		}
		return true
	})
	return out
}

// INV-1: nothing in the module can put a frame on a network. Checked three ways: the capture types have no
// method but Next and Close; the code uses only receive calls of syscall and net.InterfaceByName; and no
// package that could send or listen is imported.
func TestContract_INV1_NeverTransmits(t *testing.T) {
	t.Parallel()
	checkNeverTransmits(t)
}

func checkNeverTransmits(t *testing.T) {
	t.Helper()
	var _ capture.Source = (*capture.FileSource)(nil) // compile time: FileSource is a Source, and Source is only Next+Close
	want := []string{"Close", "Next"}
	for name, typ := range map[string]reflect.Type{"FileSource": reflect.TypeOf(&capture.FileSource{}), "Source": reflect.TypeFor[capture.Source]()} {
		var got []string
		for i := range typ.NumMethod() {
			got = append(got, typ.Method(i).Name)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s has methods %v, want exactly %v: no capture type may have a write or send method", name, got, want)
		}
	}
	allowedSyscall := []string{"AF_PACKET", "SOCK_RAW", "SOCK_CLOEXEC", "ETH_P_ALL", "Socket", "Bind", "SockaddrLinklayer",
		"SOL_SOCKET", "SO_RCVTIMEO", "NsecToTimeval", "SetsockoptTimeval", "Recvfrom", "EAGAIN", "EINTR", "Close"}
	// x/sys/unix only for the promiscuous membership (a receive-side socket option), so no unsafe pointer is needed
	allowedUnix := []string{"PacketMreq", "PACKET_MR_PROMISC", "SetsockoptPacketMreq", "SOL_PACKET", "PACKET_ADD_MEMBERSHIP"}
	for name, af := range sources(t) {
		for _, imp := range af.Imports {
			switch path := strings.Trim(imp.Path.Value, `"`); path {
			case "net/http", "net/rpc", "net/smtp", "net/textproto", "crypto/tls", "os/exec", "golang.org/x/net/ipv4", "golang.org/x/net/ipv6":
				t.Errorf("%s imports %s: the module must not be able to talk to a network", name, path)
			}
		}
		for _, s := range selectors(af, "syscall") {
			if !slices.Contains(allowedSyscall, s) {
				t.Errorf("%s uses syscall.%s: only the receive-side calls are allowed", name, s)
			}
		}
		for _, s := range selectors(af, "unix") {
			if !slices.Contains(allowedUnix, s) {
				t.Errorf("%s uses unix.%s: only the audited receive-side calls are allowed", name, s)
			}
		}
		for _, s := range selectors(af, "net") {
			if s != "InterfaceByName" {
				t.Errorf("%s uses net.%s: only net.InterfaceByName (a lookup) is allowed", name, s)
			}
		}
		ast.Inspect(af, func(n ast.Node) bool {
			if se, ok := n.(*ast.SelectorExpr); ok && slices.Contains([]string{"Sendto", "Sendmsg", "SendmsgN", "Sendfile", "WriteTo", "WriteMsgUDP", "WriteToUDP"}, se.Sel.Name) {
				t.Errorf("%s calls %s", name, se.Sel.Name)
			}
			return true
		})
	}
}

// INV-2: only CAP_NET_RAW, no listening port.
func TestContract_INV2_OnlyNetRawNoListener(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("MANIFEST.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Permissions []string `yaml:"permissions"`
		Ports       []any    `yaml:"ports"`
	}
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	slices.Sort(m.Permissions)
	if !slices.Equal(m.Permissions, []string{"net_raw", "pcap"}) || len(m.Ports) != 0 {
		t.Errorf("manifest permissions %v ports %v: want [net_raw pcap] and none", m.Permissions, m.Ports)
	}
}

// INV-3: the only fields that leave a packet are the allowed ones, and the secrets of the HTTP fixture
// do not survive into the metadata, the observations, the database or the audit log.
func TestContract_INV3_NoPayloadStored(t *testing.T) {
	t.Parallel()
	var fields []string
	for f := range reflect.TypeFor[capture.MetaItem]().Fields() {
		fields = append(fields, f.Name)
	}
	allowed := []string{"Kind", "At", "SrcMAC", "SrcIP", "DstIP", "Name", "QType", "Proto", "SrcPort", "DstPort", "Packets", "Bytes", "First"}
	if !slices.Equal(fields, allowed) {
		t.Fatalf("MetaItem fields %v, want %v: a new field is a new thing stored about traffic; change CONTRACT INV-3 first (D-43)", fields, allowed)
	}
	for f := range reflect.TypeFor[capture.MetaItem]().Fields() {
		if k := f.Type.Kind(); k == reflect.Slice || k == reflect.Map || k == reflect.Interface || k == reflect.Pointer {
			t.Errorf("MetaItem.%s is a %s: it could carry bytes of a packet", f.Name, k)
		}
	}
	e := newEnv(t, map[string][]pktgen.Frame{"eth1": pktgen.SpanMetadata()}, false)
	e.host.setFilters()
	e.setInterface("eth1", true)
	stop := e.run()
	want := []capture.MetaKind{capture.MetaDNS, capture.MetaSNI, capture.MetaHTTP, capture.MetaFlow}
	kindsOf := func(items []capture.MetaItem) map[capture.MetaKind]bool {
		k := map[capture.MetaKind]bool{}
		for _, it := range items {
			k[it.Kind] = true
		}
		return k
	}
	// Wait for every kind, not for the first item: a slow machine delivers the recording in several flushes.
	waitFor(t, "metadata of every kind", func() bool {
		k := kindsOf(e.meta.all())
		return e.sink.count() > 0 && k[capture.MetaDNS] && k[capture.MetaSNI] && k[capture.MetaHTTP] && k[capture.MetaFlow]
	})
	stop()
	items := e.meta.all()
	kinds := kindsOf(items)
	for _, k := range want {
		if !kinds[k] {
			t.Errorf("no %s item in %d items", k, len(items))
		}
	}
	dump := fmt.Sprintf("%+v %+v", items, e.sink.got)
	dump += fmt.Sprintf("%+v %+v", e.devices(), e.observations())
	for _, tbl := range []string{"core_audit", "sp_sensor", "sp_span_stat", "sp_seq"} {
		rows, err := e.db.Reader().QueryContext(t.Context(), "SELECT * FROM "+tbl)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		for rows.Next() {
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			dump += fmt.Sprint(vals...)
		}
		_ = rows.Close()
	}
	for _, secret := range []string{"SECRET", "hunter2", "Bearer", "Cookie", "/login"} {
		if strings.Contains(dump, secret) {
			t.Errorf("%q reached storage or a sink", secret)
		}
	}
	// the tables of the module hold no column that could carry content
	for _, c := range columns(t, e, "sp_sensor", "sp_span_stat", "sp_seq") {
		if !slices.Contains([]string{"id", "name", "interface", "span", "version", "last_seen", "devices_seen", "sensor_id", "packets_per_s", "other_macs", "last_packet_at", "measured_at", "epoch", "last_seq"}, c) {
			t.Errorf("unexpected column %s", c)
		}
	}
}

func columns(t *testing.T, e *env, tables ...string) []string {
	t.Helper()
	var out []string
	for _, tbl := range tables {
		rows, err := e.db.Reader().QueryContext(t.Context(), "SELECT name FROM pragma_table_info('"+tbl+"')")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			out = append(out, n)
		}
		_ = rows.Close()
	}
	return out
}

// INV-4: there is a fuzz target for every parser, malformed input is counted and the loop carries on.
func TestContract_INV4_ParsersAreFuzzedAndFailClosed(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("capture/fuzz_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"FuzzParseARP", "FuzzParseDHCP", "FuzzParseDNS", "FuzzParseSSDP", "FuzzParseLLDP", "FuzzParseClientHelloSNI", "FuzzParseHTTPHost", "FuzzFileSource", "FuzzEngineHandle"} {
		if !strings.Contains(string(src), "func "+name+"(") {
			t.Errorf("no fuzz target %s", name)
		}
	}
	e := newEnv(t, map[string][]pktgen.Frame{"eth1": pktgen.Malformed()}, false)
	e.setInterface("eth1", true)
	stop := e.run()
	waitFor(t, "the good packet after the bad ones", func() bool { return e.sink.count() == 1 })
	stop()
}

// INV-5: every observation is source passive with a confidence in [0,1], goes through observe.Sink, and the
// module never touches inv_* itself.
func TestContract_INV5_ObservationsArePassiveThroughTheSink(t *testing.T) {
	t.Parallel()
	e := newEnv(t, frames(), false)
	e.setInterface("eth0", false)
	stop := e.run()
	waitFor(t, "observations", func() bool {
		return e.obsCount(func(o inventory.ObservationRow) bool { return o.Source == "passive" }) >= 10
	})
	stop()
	for _, o := range e.sink.got {
		if o.Source != observe.Passive || o.Confidence <= 0 || o.Confidence > 1 || !observe.ValidField(o.Field) {
			t.Errorf("bad observation %+v", o)
		}
	}
	if n := e.obsCount(func(o inventory.ObservationRow) bool { return o.Source != "passive" }); n != 0 {
		t.Errorf("%d observations with another source", n)
	}
	if e.obsCount(func(o inventory.ObservationRow) bool { return o.Source == "passive" }) == 0 {
		t.Error("the inventory recorded nothing")
	}
	for name, af := range sources(t) {
		ast.Inspect(af, func(n ast.Node) bool {
			if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING && strings.Contains(bl.Value, "inv_") {
				t.Errorf("%s mentions %s: the module must not touch inv_* (FORBID-3)", name, bl.Value)
			}
			return true
		})
	}
}

// INV-6: a new MAC becomes an unapproved device; the box itself never becomes a device.
func TestContract_INV6_NewMACUnapprovedBoxIsNotADevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t, frames(), false)
	e.setInterface("eth0", false)
	stop := e.run()
	want := []pktgen.MAC{pktgen.PC, pktgen.Printer, pktgen.Router, pktgen.Switch}
	// Wait for every device, not the first one: a slow machine delivers the recording in several flushes.
	waitFor(t, "every device", func() bool {
		for _, m := range want {
			if e.device(m.String()) == nil {
				return false
			}
		}
		return true
	})
	stop()
	for _, m := range want {
		if d := e.device(m.String()); d == nil || d.Approved || d.Origin != "discovered" {
			t.Errorf("device %s: %+v, want one unapproved discovered device", m, d)
		}
	}
	for _, d := range e.devices() {
		if (d.MAC != nil && *d.MAC == pktgen.Box.String()) || d.IP == pktgen.BoxIP.String() {
			t.Errorf("the box became a device: %+v", d)
		}
	}
	// a name pointed at a device that is not the sender is not stored for it
	if n := e.obsCount(func(o inventory.ObservationRow) bool { return strings.Contains(o.Value, "liar") }); n != 0 {
		t.Errorf("%d observations from a spoofed mDNS name", n)
	}
}

// INV-7: excluded traffic leaves no row at all, not even a device or a stat of its own.
func TestContract_INV7_ExclusionBeforeExtraction(t *testing.T) {
	t.Parallel()
	e := newEnv(t, map[string][]pktgen.Frame{"eth1": pktgen.SpanMetadata()}, false)
	e.host.setFilters(sensorlink.Filter{Type: "cidr", Value: pktgen.PhoneIP.String() + "/32"}, sensorlink.Filter{Type: "host", Value: pktgen.PCIP.String()})
	e.setInterface("eth1", true)
	stop := e.run()
	waitFor(t, "the printer's ARP", func() bool { return e.sink.count() > 0 })
	stop()
	for _, it := range e.meta.all() {
		if it.SrcIP == pktgen.PhoneIP || it.SrcIP == pktgen.PCIP || it.DstIP == pktgen.PCIP || it.DstIP == pktgen.PhoneIP {
			t.Errorf("excluded traffic left an item: %+v", it)
		}
	}
	for _, o := range e.sink.got {
		if o.AssetHint.MAC == pktgen.Phone.String() || o.AssetHint.MAC == pktgen.PC.String() {
			t.Errorf("excluded device observed: %+v", o)
		}
	}
	for _, d := range e.devices() {
		if (d.MAC != nil && (*d.MAC == pktgen.Phone.String() || *d.MAC == pktgen.PC.String())) || d.IP == pktgen.PhoneIP.String() || d.IP == pktgen.PCIP.String() {
			t.Errorf("an excluded device is in the inventory: %+v", d)
		}
	}
	// an unreadable filter stops the capture instead of being ignored
	bad := newEnv(t, map[string][]pktgen.Frame{"eth1": pktgen.SpanMetadata()}, false)
	bad.host.setFilters(sensorlink.Filter{Type: "port", Value: "nope"})
	bad.setInterface("eth1", true)
	stopBad := bad.run()
	pause(t, 100*time.Millisecond)
	stopBad()
	if bad.sink.count() != 0 || len(bad.meta.all()) != 0 {
		t.Error("capture ran with a filter that could not be read")
	}
}

// INV-8: the sensor only calls out, and a batch is applied once per (epoch, seq).
func TestContract_INV8_OutboundOnlyIdempotentBySeq(t *testing.T) {
	t.Parallel()
	checkNeverTransmits(t) // no listener and no sender: the package cannot be called into
	e := newEnv(t, nil, false)
	ctx := t.Context()
	batch := func(seq int64, value string) *sensorlink.ObservationsRequest {
		return &sensorlink.ObservationsRequest{Epoch: strings.Repeat("a", 32), Seq: seq, Items: []sensorlink.ObservationItem{
			{MAC: "aa:bb:cc:00:00:99", Field: "hostname", Value: value, Confidence: 0.6, SeenAt: pktgen.T0}}}
	}
	rep, err := e.svc.Observations(ctx, batch(1, "x"))
	if err != nil || rep.AckSeq != 1 || len(rep.Rejected) != 0 {
		t.Fatalf("first submit: %+v %v", rep, err)
	}
	if rep, err := e.svc.Observations(ctx, batch(1, "x")); err != nil || rep.AckSeq != 1 || len(rep.Rejected) != 0 {
		t.Fatalf("replayed seq: %+v %v", rep, err)
	}
	if n := e.obsCount(func(o inventory.ObservationRow) bool { return o.Value == "x" && o.Source == "passive" }); n != 1 {
		t.Fatalf("%d observations after a replay, want 1", n)
	}
}

// INV-9: interface must be one of the box's, a SPAN card has no IP, the change is audited with the update;
// a SPAN port that only carries the box's own frames is reported as own_only.
func TestContract_INV9_InterfaceRulesAndOwnOnlyWarning(t *testing.T) {
	t.Parallel()
	e := newEnv(t, map[string][]pktgen.Frame{"eth1": pktgen.SpanOwnOnly()}, true, withClock(pktgen.T0.Add(5*time.Second)))
	ctx := t.Context()
	for name, c := range map[string]struct {
		iface string
		span  bool
	}{"unknown card": {"eth9", false}, "SPAN on a card with an IP": {"eth0", true}, "SPAN without a card": {"", true}} {
		err := e.svc.SetInterface(ctx, "admin@example.org", sp.SensorID, c.iface, c.span)
		if !errors.Is(err, sp.ErrBadInterface) {
			t.Errorf("%s: got %v, want ErrBadInterface", name, err)
		}
	}
	if err := e.svc.SetInterface(ctx, "admin@example.org", "sn-other", "eth1", true); !errors.Is(err, sp.ErrNotFound) {
		t.Errorf("unknown sensor: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'sensor.interface_set'`); n != 0 {
		t.Errorf("%d audit rows for refused changes", n)
	}
	e.setInterface("eth1", true)
	var user, detail string
	if err := e.db.Reader().QueryRowContext(ctx, `SELECT user, detail FROM core_audit WHERE action = 'sensor.interface_set'`).Scan(&user, &detail); err != nil || user != "admin@example.org" || !strings.Contains(detail, "eth1") {
		t.Fatalf("audit row: %q %q %v", user, detail, err)
	}
	list, err := e.svc.Status(ctx)
	if err != nil || len(list) != 1 || list[0].Interface == nil || *list[0].Interface != "eth1" || !list[0].Span || !slices.Equal(list[0].Interfaces, []string{"eth0", "eth1"}) {
		t.Fatalf("status %+v %v", list, err)
	}
	e.run()
	waitFor(t, "own_only", func() bool {
		st, err := e.svc.SpanStats(ctx)
		return err == nil && st.Verdict == sp.VerdictOwnOnly
	})
	e.host.setLink("eth1", false) // the sensor says so in its next heartbeat
	waitFor(t, "no_link", func() bool {
		st, _ := e.svc.SpanStats(ctx)
		return st.Verdict == sp.VerdictNoLink
	})
}

// INV-10: Fingerbank is not part of this module yet; nothing in it can reach out.
func TestContract_INV10_FingerbankAbsent(t *testing.T) {
	t.Parallel()
	for name, af := range sources(t) {
		ast.Inspect(af, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && strings.Contains(strings.ToLower(id.Name), "fingerbank") {
				t.Errorf("%s has %s: Fingerbank needs its own work package, a BYOK key and a PRIVACY.md row first", name, id.Name)
			}
			return true
		})
	}
}

// POST-1: while capturing, the sensor is online and last_seen moves.
func TestContract_POST1_OnlineWhileCapturing(t *testing.T) {
	t.Parallel()
	e := newEnv(t, frames(), true)
	if list, _ := e.svc.Status(t.Context()); list[0].Status != "offline" || list[0].LastSeen != nil || len(list[0].Interfaces) != 0 {
		t.Fatalf("before the sensor said anything: %+v", list[0])
	}
	e.setInterface("eth0", false)
	e.run()
	waitFor(t, "online", func() bool {
		list, err := e.svc.Status(t.Context())
		return err == nil && list[0].Status == "online" && list[0].LastSeen != nil && list[0].DevicesSeen > 0
	})
	if got := e.src.opens(); !slices.Equal(got, []string{"eth0"}) {
		t.Errorf("opened %v", got)
	}
}

// POST-2: SetInterface moves the capture to the new card in the same request, and audits it.
func TestContract_POST2_CaptureMovesToTheNewCard(t *testing.T) {
	t.Parallel()
	e := newEnv(t, frames(), true)
	e.setInterface("eth0", false)
	e.run()
	waitFor(t, "first card", func() bool { return len(e.src.opens()) == 1 })
	e.setInterface("eth1", true)
	waitFor(t, "second card", func() bool { return slices.Equal(e.src.opens(), []string{"eth0", "eth1"}) })
	waitFor(t, "the first source closed", func() bool { return e.src.closes() >= 1 })
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'sensor.interface_set'`); n != 2 {
		t.Errorf("%d audit rows, want 2", n)
	}
	waitFor(t, "SPAN metadata after the move", func() bool { return len(e.meta.all()) > 0 })
}

// POST-3: the same seq twice creates no second observation; a lower one neither; a new epoch starts over.
func TestContract_POST3_SameSeqNoSecondObservation(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil, false)
	epoch := strings.Repeat("b", 32)
	req := func(epoch string, seq int64, v string) *sensorlink.ObservationsRequest {
		return &sensorlink.ObservationsRequest{Epoch: epoch, Seq: seq, Items: []sensorlink.ObservationItem{
			{MAC: "aa:bb:cc:00:00:98", Field: "hostname", Value: v, Confidence: 0.6, SeenAt: pktgen.T0}}}
	}
	ctx := t.Context()
	for _, c := range []struct {
		seq int64
		val string
	}{{5, "one"}, {5, "two"}, {4, "three"}, {6, "four"}} {
		rep, err := e.svc.Observations(ctx, req(epoch, c.seq, c.val))
		if err != nil || rep.AckSeq != c.seq {
			t.Errorf("seq %d: %+v %v", c.seq, rep, err)
		}
	}
	hostnames := func() int {
		return e.obsCount(func(o inventory.ObservationRow) bool { return o.Source == "passive" && o.Field == "hostname" })
	}
	if n := hostnames(); n != 2 {
		t.Errorf("%d hostname observations, want 2 (one, four)", n)
	}
	if e.count(`SELECT last_seq FROM sp_seq WHERE epoch = '`+epoch+`'`) != 6 {
		t.Error("last_seq of the epoch is not 6")
	}
	if _, err := e.svc.Observations(ctx, req(epoch, 1, "after a restart")); err != nil { // an old seq of a known epoch
		t.Fatal(err)
	}
	if _, err := e.svc.Observations(ctx, req(strings.Repeat("c", 32), 1, "new epoch")); err != nil { // the sensor restarted: seq 1 of a new epoch counts
		t.Fatal(err)
	}
	if n := hostnames(); n != 3 {
		t.Errorf("%d hostname observations after a new epoch, want 3", n)
	}
	var e1 *sensorlink.Error
	if _, err := e.svc.Observations(ctx, req(epoch, 0, "x")); !errors.As(err, &e1) || e1.Code != sensorlink.CodeInvalidRequest {
		t.Errorf("seq 0: %v", err)
	}
	rep, err := e.svc.Observations(ctx, &sensorlink.ObservationsRequest{Epoch: strings.Repeat("d", 32), Seq: 1, Items: []sensorlink.ObservationItem{
		{MAC: "aa:bb:cc:00:00:97", Field: "ip", Value: "x", Confidence: 0.5, SeenAt: pktgen.T0}}})
	if err != nil || len(rep.Rejected) != 1 || rep.Rejected[0].Code != "invalid_item" {
		t.Errorf("an unknown field: %+v %v", rep, err)
	}
}

// POST-4: the SPAN stats are measured from the frames heard: a mirror with other devices is ok, with the
// box only it is own_only, a quiet one has no traffic, a stopped capture too.
func TestContract_POST4_SpanStatsAreMeasured(t *testing.T) {
	t.Parallel()
	e := newEnv(t, map[string][]pktgen.Frame{"eth1": pktgen.SpanMetadata()}, true, withClock(pktgen.T0.Add(13*time.Second)), withSinglePass())
	ctx := t.Context()
	if st, _ := e.svc.SpanStats(ctx); st.Verdict != sp.VerdictOff {
		t.Fatalf("no SPAN configured: %+v", st)
	}
	e.setInterface("eth1", true)
	if st, _ := e.svc.SpanStats(ctx); st.Verdict != sp.VerdictNoTraffic || st.PPS != 0 {
		t.Fatalf("configured but not listening: %+v", st)
	}
	e.run()
	var st sp.SpanStats
	waitFor(t, "measurement", func() bool {
		st, _ = e.svc.SpanStats(ctx)
		return st.Verdict == sp.VerdictOK && st.OtherMACs == 3 && st.LastPacket.Equal(pktgen.T0.Add(10*time.Second))
	})
	// the fixture has 13 frames in 10 s of the 13 s window, from PC, Router, Phone, Printer and the box; the printer's ARP is a broadcast, so others = PC, Router, Phone = 3
	if st.OtherMACs != 3 || st.PPS < 1 || !st.LastPacket.Equal(pktgen.T0.Add(10*time.Second)) {
		t.Errorf("stats %+v", st)
	}
	waitFor(t, "stats saved", func() bool {
		return e.count(`SELECT count(*) FROM sp_span_stat WHERE other_macs = 3 AND last_packet_at IS NOT NULL`) == 1
	})
	list, _ := e.svc.Status(ctx)
	if list[0].SpanStatus.Verdict != "ok" || list[0].SpanStatus.OtherMACs != 3 {
		t.Errorf("sensor card: %+v", list[0].SpanStatus)
	}
	e.setClock(func() time.Time { return pktgen.T0.Add(5 * time.Minute) }) // five quiet minutes later
	if st, _ := e.svc.SpanStats(ctx); st.Verdict != sp.VerdictNoTraffic || st.PPS != 0 {
		t.Errorf("silent mirror: %+v", st)
	}
}

// SYS-5: the capture runs only while the module is on and leaves no goroutine behind; nothing is written
// after it was turned off.
func TestContract_CaptureFollowsTheModuleSwitch(t *testing.T) {
	t.Parallel()
	e := newEnv(t, frames(), true)
	e.setInterface("eth0", false)
	gate := &switchGate{on: map[string]bool{}}
	sched := jobs.New(nopLog(), gate, nil)
	if err := sched.Add(jobs.Job{Module: "sensor-passive", Name: "capture", Every: 20 * time.Millisecond, Run: e.job()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); sched.Run(ctx) }()
	pause(t, 60*time.Millisecond)
	if len(e.src.opens()) != 0 {
		t.Fatal("capture started while the module was off")
	}
	gate.set(true)
	sched.ModuleChanged("sensor-passive", true)
	waitFor(t, fmt.Sprintf("capture to start (opens %v sink %d)", e.src.opens(), e.sink.count()), func() bool { return len(e.src.opens()) == 1 && e.sink.count() > 0 })
	if remoteMode() { // the remote capture is told by core: a real 409 module_off, while its job is still running
		e.off.Store(true)
		waitFor(t, "the source to close on the 409, before the job is cancelled", func() bool { return e.src.closes() == 1 })
		e.off.Store(false)
	}
	gate.set(false)
	sched.ModuleChanged("sensor-passive", false)
	waitFor(t, "the source to close", func() bool { return e.src.closes() == 1 })
	n := e.sink.count()
	pause(t, 80*time.Millisecond)
	if e.sink.count() != n || len(e.src.opens()) != 1 {
		t.Error("the capture kept working after the module was turned off")
	}
	if list, _ := e.svc.Status(t.Context()); list[0].Name == "" {
		t.Error("data of a disabled module must stay readable")
	}
	cancel()
	<-done
}

type switchGate struct {
	mu sync.Mutex
	on map[string]bool
}

func (g *switchGate) Enabled(id string) bool { g.mu.Lock(); defer g.mu.Unlock(); return g.on[id] }
func (g *switchGate) set(v bool)             { g.mu.Lock(); defer g.mu.Unlock(); g.on["sensor-passive"] = v }

func nopLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

// MigrationsUsePrefix: DATA_MODEL rule, checked by effect.
func TestMigrationsUsePrefix(t *testing.T) {
	storetest.AssertMigrationsUsePrefix(t, "sensor-passive", sp.Migrations, "sp_", storetest.Migration{Module: "core", FS: core.Migrations})
}

// SYS-5: turning the module off and on many times, and moving the capture, leaves no goroutine behind. Not
// parallel: runtime.NumGoroutine counts the whole process.
func TestContract_NoGoroutineLeakAcrossSwitches(t *testing.T) {
	e := newEnv(t, frames(), true)
	e.setInterface("eth0", false)
	gate := &switchGate{on: map[string]bool{}}
	sched := jobs.New(nopLog(), gate, nil)
	if err := sched.Add(jobs.Job{Module: "sensor-passive", Name: "capture", Every: 10 * time.Millisecond, Run: e.job()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); sched.Run(ctx) }()
	pause(t, 50*time.Millisecond)
	base := runtime.NumGoroutine()
	for i := range 20 {
		prev := len(e.src.opens())
		gate.set(true)
		sched.ModuleChanged("sensor-passive", true)
		waitFor(t, "open", func() bool { return len(e.src.opens()) > prev })
		if i%3 == 0 {
			e.setInterface("eth1", true)
			waitFor(t, "reopen 1", func() bool { return len(e.src.opens()) > prev+1 })
			e.setInterface("eth0", false)
			waitFor(t, "reopen 2", func() bool { return len(e.src.opens()) > prev+2 })
		}
		gate.set(false)
		start := time.Now()
		sched.ModuleChanged("sensor-passive", false)
		waitFor(t, "close", func() bool { return e.src.closes() == len(e.src.opens()) })
		if d := time.Since(start); d > waitBound {
			t.Errorf("stop took %v", d)
		}
	}
	pause(t, 100*time.Millisecond)
	if e.rem != nil { // the link's connections are idle, not leaked: close them before counting
		e.rem.client.CloseIdleConnections()
		e.rem.link.Server.CloseClientConnections()
		pause(t, 200*time.Millisecond)
	}
	runtime.GC()
	if after := runtime.NumGoroutine(); after > base+1 {
		buf := make([]byte, 1<<16)
		t.Errorf("leak: %d -> %d\n%s", base, after, buf[:runtime.Stack(buf, true)])
	}
	cancel()
	<-done
}

// H1: one valid but over-long host name must not stop the others from being recorded.
func TestContract_LongHostnameDoesNotPoisonTheBatch(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 20)
	zero, bcast := netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255")
	fr := []pktgen.Frame{
		{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP)},
		{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.Printer, pktgen.PrinterIP, pktgen.MAC{}, pktgen.RouterIP)},
		{At: pktgen.T0, Data: pktgen.UDPFrame(pktgen.Bcast, pktgen.Phone, zero, bcast, 68, 67,
			pktgen.DHCP(1, pktgen.Phone, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{Type: 1, Hostname: long}))},
	}
	e := newEnv(t, map[string][]pktgen.Frame{"eth0": fr}, true)
	e.setInterface("eth0", false)
	e.run()
	waitFor(t, "all three devices", func() bool { return len(e.devices()) == 3 })
	if d := e.device(pktgen.Phone.String()); d == nil || d.Hostname == nil || len(*d.Hostname) > 200 {
		t.Errorf("the phone: %+v", d)
	}
}

// sensor-protocol 5.5: an item the inventory refuses is dropped alone; the rest of its batch is recorded.
func TestContract_OneRefusedItemDoesNotBlindTheBatch(t *testing.T) {
	t.Parallel()
	zero, bcast := netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255")
	fr := []pktgen.Frame{
		{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP)},
		{At: pktgen.T0, Data: pktgen.UDPFrame(pktgen.Bcast, pktgen.Phone, zero, bcast, 68, 67,
			pktgen.DHCP(1, pktgen.Phone, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{Type: 1, Hostname: "refused-name"}))},
		{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.Printer, pktgen.PrinterIP, pktgen.MAC{}, pktgen.RouterIP)},
	}
	e := newEnv(t, map[string][]pktgen.Frame{"eth0": fr}, true, withReject("refused-name"))
	e.setInterface("eth0", false)
	e.run()
	waitFor(t, "the two good devices and the phone's MAC", func() bool { return len(e.devices()) == 3 })
	for _, o := range e.observations() {
		if o.Value == "refused-name" {
			t.Error("the refused observation was recorded")
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// Dropped packets are summarised in the log, once while the numbers do not change (no spam).
func TestContract_DropSummaryIsLoggedOnceWhileUnchanged(t *testing.T) {
	t.Parallel()
	var buf syncBuffer
	e := newEnv(t, map[string][]pktgen.Frame{"eth1": pktgen.Malformed()}, true,
		withLog(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})), withSummaryEvery(20*time.Millisecond), withSinglePass())
	e.setInterface("eth1", true)
	e.run()
	waitFor(t, "the summary", func() bool { return strings.Contains(buf.String(), "packets dropped or ignored") })
	// A slow machine can spread the frames over several intervals (one summary per change): wait until the
	// counters stop moving, then ten more intervals with the same counters must log nothing.
	last, stable := buf.String(), time.Now()
	waitFor(t, "stable counters", func() bool {
		if cur := buf.String(); cur != last {
			last, stable = cur, time.Now()
		}
		return time.Since(stable) > 100*time.Millisecond
	})
	n := strings.Count(buf.String(), "packets dropped or ignored")
	pause(t, 200*time.Millisecond)
	if m := strings.Count(buf.String(), "packets dropped or ignored"); m != n {
		t.Errorf("%d summaries after the counters stopped changing, want %d:\n%s", m, n, buf.String())
	}
	if !strings.Contains(buf.String(), "malformed_arp") {
		t.Errorf("the summary has no counters:\n%s", buf.String())
	}
}

// A capture that cannot be opened is retried with a growing pause, not every few seconds forever.
func TestContract_FailingOpenBacksOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil, true)
	e.src.fail = true
	e.setInterface("eth0", false)
	start := time.Now()
	e.run()
	// RetryEvery is 20 ms. Four attempts take at least 20+40+80 = 140 ms with a doubling pause and only 60 ms with a
	// constant one. A loaded machine only makes it slower, so the lower bound cannot fail by chance.
	waitFor(t, "four attempts", func() bool {
		e.src.mu.Lock()
		defer e.src.mu.Unlock()
		return e.src.tries >= 4
	})
	if d := time.Since(start); d < 140*time.Millisecond {
		t.Errorf("four attempts in %v, want at least 140 ms (20, 40, 80 ms pauses)", d)
	}
}
