package inventory_test

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

var allKinds = []string{"printer", "camera", "nvr", "nas", "ap", "iot"}

func okSettings(ranges ...string) inventory.SettingsInput {
	if ranges == nil {
		ranges = []string{}
	}
	return inventory.SettingsInput{Settings: inventory.Settings{
		LANRanges:    ranges,
		Active:       inventory.ActiveWindow{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "23:00", To: "05:00", Rate: 50, Exclusions: []string{}},
		FragileKinds: allKinds, RegularScanKinds: []string{},
	}}
}

// confirmScope turns active scanning on for the ranges with the attestation ticked.
func (e *env) confirmScope(ranges ...string) {
	e.t.Helper()
	in := okSettings(ranges...)
	in.Active.Enabled, in.ScopeConfirmed = true, true
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil {
		e.t.Fatalf("SaveSettings: %v", err)
	}
}

func TestContract_INV6_NetworkRanges(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	save := func(ranges ...string) error {
		_, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", okSettings(ranges...))
		return err
	}
	bad := []struct {
		name   string
		ranges []string
		code   string
	}{
		{"no prefix is never guessed (D-32)", []string{"192.168.18.0"}, "no_prefix"},
		{"public range", []string{"8.8.8.0/24"}, "public_range"},
		{"a range that straddles the private block", []string{"172.0.0.0/8"}, "public_range"},
		{"100/8 outside the shared address space (D-461)", []string{"100.128.0.0/24"}, "public_range"},
		{"just below the shared address space", []string{"100.63.0.0/16"}, "public_range"},
		{"wider than the shared address space", []string{"100.0.0.0/8"}, "public_range"},
		{"overlap, same start", []string{"192.168.10.0/24", "192.168.10.0/25"}, "overlap_range"},
		{"overlap, nested", []string{"10.0.0.0/8", "10.1.2.0/24"}, "overlap_range"},
		{"not a CIDR", []string{"banana"}, "bad_cidr"},
		{"IPv6", []string{"fd00::/8"}, "bad_cidr"},
		{"leading zero", []string{"192.168.010.0/24"}, "bad_cidr"},
		{"too many", func() []string {
			var r []string
			for i := range 17 {
				r = append(r, "10."+string(rune('0'+i/10))+string(rune('0'+i%10))+".0.0/16")
			}
			return r
		}(), "too_many_ranges"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) { wantAPIError(t, save(c.ranges...), 400, c.code) })
	}
	t.Run("host bits are reduced to the network and reported, as the mock does", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			in, want []string
			adjusted []inventory.Adjustment
			code     string
		}{
			{"host bits", []string{" 192.168.18.5/24 "}, []string{"192.168.18.0/24"}, []inventory.Adjustment{{From: "192.168.18.5/24", To: "192.168.18.0/24"}}, ""},
			{"keeps the typed prefix length", []string{"10.1.2.3/25"}, []string{"10.1.2.0/25"}, []inventory.Adjustment{{From: "10.1.2.3/25", To: "10.1.2.0/25"}}, ""},
			{"a duplicate that collapses after masking", []string{"192.168.18.0/24", "192.168.18.77/24"}, []string{"192.168.18.0/24"}, []inventory.Adjustment{{From: "192.168.18.77/24", To: "192.168.18.0/24"}}, ""},
			{"an overlap only found after masking", []string{"192.168.18.0/24", "192.168.18.130/25"}, nil, nil, "overlap_range"},
			{"no host bits, nothing adjusted", []string{"192.168.18.0/24"}, []string{"192.168.18.0/24"}, []inventory.Adjustment{}, ""},
			{"no prefix is still refused", []string{"192.168.18.5"}, nil, nil, "no_prefix"},
			{"a public range is refused after masking", []string{"8.8.8.9/24"}, nil, nil, "public_range"},
			{"a shared address space range is local (RFC 6598, D-461)", []string{"100.65.254.0/24", "100.64.0.0/16"}, []string{"100.65.254.0/24", "100.64.0.0/16"}, []inventory.Adjustment{}, ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := newEnv(t)
				got, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", okSettings(tc.in...))
				if tc.code != "" {
					wantAPIError(t, err, 400, tc.code)
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(got.LANRanges, tc.want) || !slices.Equal(got.Adjusted, tc.adjusted) {
					t.Fatalf("ranges %v adjusted %v, want %v / %v", got.LANRanges, got.Adjusted, tc.want, tc.adjusted)
				}
				if st, _ := e.svc.Settings(e.ctx()); !slices.Equal(st.LANRanges, tc.want) {
					t.Fatalf("stored %v", st.LANRanges)
				}
			})
		}
	})
	// exclusions stay strict (the mock refuses host bits there)
	exIn := okSettings("192.168.10.0/24")
	exIn.Active.Exclusions = []string{"192.168.10.5/28"}
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", exIn); err == nil {
		t.Fatal("an exclusion with host bits was accepted")
	}
	// the prefix the person typed is kept (a /25 stays a /25)
	if err := save("192.168.18.0/25", "10.0.0.0/8", "172.16.0.0/12"); err != nil {
		t.Fatal(err)
	}
	st, _ := e.svc.Settings(e.ctx())
	if strings.Join(st.LANRanges, ",") != "192.168.18.0/25,10.0.0.0/8,172.16.0.0/12" {
		t.Fatalf("ranges = %v", st.LANRanges)
	}
	// 16 ranges are fine
	var sixteen []string
	for i := range 16 {
		sixteen = append(sixteen, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16).String())
	}
	if err := save(sixteen...); err != nil {
		t.Fatalf("16 ranges: %v", err)
	}
	// a failed save changes nothing
	if err := save("8.8.8.0/24"); err == nil {
		t.Fatal("public range accepted")
	}
	if st, _ := e.svc.Settings(e.ctx()); len(st.LANRanges) != 16 {
		t.Fatalf("ranges after a failed save = %v", st.LANRanges)
	}
}

func TestContract_INV7_ActiveScanNeedsScopeAndWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	with := func(f func(*inventory.SettingsInput)) error {
		in := okSettings("192.168.10.0/24")
		f(&in)
		_, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in)
		return err
	}
	on := func(in *inventory.SettingsInput) { in.Active.Enabled, in.ScopeConfirmed = true, true }
	cases := []struct {
		name string
		edit func(*inventory.SettingsInput)
		code string
	}{
		{"no attestation", func(in *inventory.SettingsInput) { in.Active.Enabled = true }, "scope_not_confirmed"},
		{"no range", func(in *inventory.SettingsInput) { on(in); in.LANRanges = []string{} }, "no_ranges"},
		{"no day", func(in *inventory.SettingsInput) { on(in); in.Active.Days = []int{} }, "no_days"},
		{"day 0", func(in *inventory.SettingsInput) { on(in); in.Active.Days = []int{0} }, "bad_days"},
		{"day 8", func(in *inventory.SettingsInput) { on(in); in.Active.Days = []int{8} }, "bad_days"},
		{"from = to", func(in *inventory.SettingsInput) { on(in); in.Active.From, in.Active.To = "22:00", "22:00" }, "bad_window"},
		{"bad time", func(in *inventory.SettingsInput) { on(in); in.Active.From = "25:00" }, "bad_time"},
		{"rate 0", func(in *inventory.SettingsInput) { on(in); in.Active.Rate = 0 }, "bad_rate"},
		{"rate 1001", func(in *inventory.SettingsInput) { on(in); in.Active.Rate = 1001 }, "bad_rate"},
		{"exclusion with host bits", func(in *inventory.SettingsInput) { on(in); in.Active.Exclusions = []string{"192.168.10.5/28"} }, "bad_exclusion"},
		{"exclusion garbage", func(in *inventory.SettingsInput) { on(in); in.Active.Exclusions = []string{"printer"} }, "bad_exclusion"},
		{"unknown kind", func(in *inventory.SettingsInput) { in.FragileKinds = []string{"toaster"} }, "bad_kinds"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { wantAPIError(t, with(c.edit), 400, c.code) })
	}
	// 1 and 7, a window across midnight, rate 1 and 1000 are all valid
	for _, rate := range []int{1, 1000} {
		if err := with(func(in *inventory.SettingsInput) {
			on(in)
			in.Active.Rate = rate
			in.Active.Days = []int{7, 1, 1}
			in.Active.Exclusions = []string{"192.168.10.10", "192.168.10.0/28"}
		}); err != nil {
			t.Fatalf("rate %d: %v", rate, err)
		}
	}
	st, _ := e.svc.Settings(e.ctx())
	if !st.Active.Enabled || st.ScopeConfirmedAt == nil || st.ScopeConfirmedBy == nil || *st.ScopeConfirmedBy != "admin@acme.example" {
		t.Fatalf("settings = %+v, want enabled with the attestation recorded (who, when)", st)
	}
	if strings.Join(strings.Fields(strings.Trim(strings.ReplaceAll(strings.Trim(strings.Join(intsToStrings(st.Active.Days), " "), " "), "  ", " "), " ")), ",") != "1,7" {
		t.Fatalf("days = %v, want sorted and unique", st.Active.Days)
	}
	// regular_scan_kinds is cut down to fragile_kinds
	if err := with(func(in *inventory.SettingsInput) {
		in.FragileKinds = []string{"nas"}
		in.RegularScanKinds = []string{"nas", "camera"}
	}); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.svc.Settings(e.ctx()); strings.Join(st.RegularScanKinds, ",") != "nas" {
		t.Fatalf("regular_scan_kinds = %v", st.RegularScanKinds)
	}
	// turning scanning off needs no attestation, and drops it
	if err := with(func(_ *inventory.SettingsInput) {}); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.svc.Settings(e.ctx()); st.Active.Enabled || st.ScopeConfirmedAt != nil {
		t.Fatalf("settings = %+v", st)
	}
}

func intsToStrings(in []int) []string {
	var out []string
	for _, v := range in {
		out = append(out, strconv.Itoa(v))
	}
	return out
}

func TestContract_INV8_FragileDevicesAreScannedOnceGently(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("192.168.10.0/24")
	e.record(obs(netip.MustParseAddr("192.168.10.40"), macA, observe.Kind, "nas", observe.Agent, 0.9))
	e.record(obs(netip.MustParseAddr("192.168.10.41"), macB, observe.Kind, "pc", observe.Agent, 0.9))
	nas, pc := e.idByMAC(macA), e.idByMAC(macB)
	policy := func(id string) inventory.ScanDecision {
		t.Helper()
		d, err := e.svc.ScanPolicy(e.ctx(), id)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if !e.detail(nas).Asset.Fragile || e.detail(pc).Asset.Fragile {
		t.Fatal("fragile flags follow the type setting")
	}
	if d := policy(pc); !d.Allowed || d.Rate != 50 || d.Reason != inventory.ReasonOK {
		t.Fatalf("a regular device = %+v", d)
	}
	// first sight: one scan at the lowest speed
	if d := policy(nas); !d.Allowed || d.Rate != 1 || d.Reason != inventory.ReasonFirstGentleScan {
		t.Fatalf("a fragile device the first time = %+v", d)
	}
	if err := e.svc.MarkFirstScan(e.ctx(), nas); err != nil {
		t.Fatal(err)
	}
	if e.detail(nas).Asset.FirstScanAt == nil {
		t.Fatal("first_scan_at not set")
	}
	// after that: passive only
	if d := policy(nas); d.Allowed || d.Reason != inventory.ReasonFragilePassiveOnly {
		t.Fatalf("after the first scan = %+v", d)
	}
	patch := func(rs string) {
		t.Helper()
		if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", nas, inventory.Patch{RegularScan: &rs}); err != nil {
			t.Fatal(err)
		}
	}
	patch("allow")
	if d := policy(nas); !d.Allowed || d.Rate != 50 {
		t.Fatalf("regular_scan=allow = %+v", d)
	}
	// the type setting allows regular scans for NAS ...
	in := okSettings("192.168.10.0/24")
	in.Active.Enabled, in.ScopeConfirmed, in.RegularScanKinds = true, true, []string{"nas"}
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil {
		t.Fatal(err)
	}
	patch("follow")
	if d := policy(nas); !d.Allowed {
		t.Fatalf("follow with the type allowed = %+v", d)
	}
	// ... but never on this device beats the type setting
	patch("never")
	if d := policy(nas); d.Allowed || d.Reason != inventory.ReasonFragilePassiveOnly {
		t.Fatalf("never = %+v", d)
	}
	// fragile=true by hand makes a PC fragile; the flag survives later settings changes
	tr := true
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", pc, inventory.Patch{Fragile: &tr}); err != nil {
		t.Fatal(err)
	}
	if d := policy(pc); d.Rate != 1 || d.Reason != inventory.ReasonFirstGentleScan {
		t.Fatalf("fragile by hand = %+v", d)
	}
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil {
		t.Fatal(err)
	}
	if !e.detail(pc).Asset.Fragile {
		t.Fatal("a manual fragile flag was reset by the settings")
	}
	// changing the fragile kinds moves the devices that were not set by hand
	in.FragileKinds = []string{"camera"}
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil {
		t.Fatal(err)
	}
	if e.detail(nas).Asset.Fragile {
		t.Fatal("the NAS stayed fragile after NAS left the fragile kinds")
	}
}

func TestContract_POST3_ScanPolicyAndInScope(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := e.ctx()
	ip := netip.MustParseAddr
	// nothing is in scope before any range is configured
	if ok, _ := e.svc.InScope(ctx, ip("192.168.10.5")); ok {
		t.Fatal("in scope with no ranges")
	}
	in := okSettings("192.168.10.0/24", "10.1.0.0/16")
	in.Active.Enabled, in.ScopeConfirmed = true, true
	in.Active.Exclusions = []string{"192.168.10.10", "10.1.5.0/24"}
	if _, err := e.svc.SaveSettings(ctx, "admin@acme.example", in); err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{
		"192.168.10.5": true, "192.168.10.10": false, "10.1.2.3": true, "10.1.5.77": false, "10.2.0.1": false, "8.8.8.8": false, "192.168.11.1": false,
	} {
		if got, _ := e.svc.InScope(ctx, ip(addr)); got != want {
			t.Errorf("InScope(%s) = %v, want %v", addr, got, want)
		}
	}
	if got, _ := e.svc.InScope(ctx, ip("::ffff:192.168.10.5")); !got {
		t.Error("an IPv4-mapped address should be treated as IPv4")
	}
	e.record(obs(ip("192.168.10.20"), macA, observe.Kind, "pc", observe.Agent, 0.9))
	e.record(obs(ip("192.168.10.10"), macB, observe.Kind, "pc", observe.Agent, 0.9))
	if d, _ := e.svc.ScanPolicy(ctx, e.idByMAC(macA)); !d.Allowed {
		t.Fatalf("in scope = %+v", d)
	}
	if d, _ := e.svc.ScanPolicy(ctx, e.idByMAC(macB)); d.Allowed || d.Reason != inventory.ReasonOutOfScope {
		t.Fatalf("excluded = %+v", d)
	}
	// scanning off or scope not confirmed: nothing is allowed
	in.Active.Enabled, in.ScopeConfirmed = false, false
	if _, err := e.svc.SaveSettings(ctx, "admin@acme.example", in); err != nil {
		t.Fatal(err)
	}
	if d, _ := e.svc.ScanPolicy(ctx, e.idByMAC(macA)); d.Allowed || d.Reason != inventory.ReasonScanningOff {
		t.Fatalf("scanning off = %+v", d)
	}
	if _, err := e.svc.ScanPolicy(ctx, "a-nope"); err == nil {
		t.Fatal("no error for an unknown device")
	}
	// a device with no IP cannot be scanned
	e.record(obsv("aa:bb:cc:00:00:09", observe.Kind, "pc", observe.Agent, 0.9))
	if d, _ := e.svc.ScanPolicy(ctx, e.idByMAC("aa:bb:cc:00:00:09")); d.Allowed || d.Reason != inventory.ReasonNoIP {
		t.Fatalf("no IP = %+v", d)
	}
}

func TestContract_POST5_SettingsKeepTheAttestationWhileTheRangesDoNotChange(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	in := okSettings("192.168.10.0/24", "10.0.0.0/8")
	in.Active.Enabled, in.ScopeConfirmed = true, true
	first, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(e.ev.named(inventory.EventSettingsChanged)); n != 1 {
		t.Fatalf("%d settings events", n)
	}
	e.tick(time.Hour)
	// same ranges in another order, another admin: attestation (when, who) stays
	in.LANRanges = []string{"10.0.0.0/8", "192.168.10.0/24"}
	in.Active.Rate = 10
	again, err := e.svc.SaveSettings(e.ctx(), "other-admin@acme.example", in)
	if err != nil {
		t.Fatal(err)
	}
	if *again.ScopeConfirmedAt != *first.ScopeConfirmedAt || *again.ScopeConfirmedBy != "admin@acme.example" {
		t.Fatalf("attestation changed: %v %v", *again.ScopeConfirmedAt, *again.ScopeConfirmedBy)
	}
	// a new range needs a new attestation, by the new admin, at the new time
	e.tick(time.Hour)
	in.LANRanges = []string{"10.0.0.0/8", "192.168.10.0/24", "172.16.0.0/16"}
	third, err := e.svc.SaveSettings(e.ctx(), "other-admin@acme.example", in)
	if err != nil {
		t.Fatal(err)
	}
	if *third.ScopeConfirmedAt == *first.ScopeConfirmedAt || *third.ScopeConfirmedBy != "other-admin@acme.example" {
		t.Fatalf("attestation = %v by %v", *third.ScopeConfirmedAt, *third.ScopeConfirmedBy)
	}
	if n := len(e.ev.named(inventory.EventSettingsChanged)); n != 3 {
		t.Fatalf("%d settings events, want one per save", n)
	}
	if !has(e.auditActions(), "inventory.settings") {
		t.Fatalf("no audit row: %v", e.auditActions())
	}
}

func TestSettingsIgnoreTheClientsAttestationFields(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	bogusAt, bogusBy := "2001-01-01T00:00:00.000Z", "someone@else.example"
	in := okSettings("192.168.10.0/24")
	in.ScopeConfirmedAt, in.ScopeConfirmedBy = &bogusAt, &bogusBy
	got, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in)
	if err != nil || got.ScopeConfirmedAt != nil || got.ScopeConfirmedBy != nil {
		t.Fatalf("unconfirmed: %+v, %v", got.Settings, err)
	}
	in.ScopeConfirmed, in.Active.Enabled = true, true
	got, err = e.svc.SaveSettings(e.ctx(), "admin@acme.example", in)
	if err != nil || *got.ScopeConfirmedAt != "2026-11-09T10:00:00.000Z" || *got.ScopeConfirmedBy != "admin@acme.example" {
		t.Fatalf("confirmed: %+v, %v", got.Settings, err)
	}
}

// D-45, D-84 (H1): a device whose kind is unknown may be fragile, so its first scan is the gentle one; after it
// the device stays passive-only until its kind is set, then it follows the rules of its kind.
func TestContract_INV8_UnclassifiedDevicesAreScannedOnceGently(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("192.168.10.0/24")
	e.record(obs(netip.MustParseAddr("192.168.10.50"), macA, observe.Vendor, "Acme", observe.Passive, 0.5))
	id := e.idByMAC(macA)
	if k := e.detail(id).Asset.Kind; k != "unknown" {
		t.Fatalf("kind = %q, the test needs an unclassified device", k)
	}
	policy := func() inventory.ScanDecision {
		t.Helper()
		d, err := e.svc.ScanPolicy(e.ctx(), id)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := policy(); !d.Allowed || d.Rate != 1 || d.Reason != inventory.ReasonFirstGentleScan {
		t.Fatalf("an unclassified device the first time = %+v", d)
	}
	if err := e.svc.MarkFirstScan(e.ctx(), id); err != nil {
		t.Fatal(err)
	}
	if d := policy(); d.Allowed || d.Reason != inventory.ReasonUnclassifiedPassiveOnly {
		t.Fatalf("an unclassified device after its gentle scan = %+v", d)
	}
	pc := "pc"
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{Kind: &pc}); err != nil {
		t.Fatal(err)
	}
	// "pc" is in allKinds of okSettings, so it is fragile by type; take it out so the person's classification
	// means "not fragile"
	in := okSettings("192.168.10.0/24")
	in.Active.Enabled, in.ScopeConfirmed = true, true
	in.FragileKinds = []string{"printer"}
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil {
		t.Fatal(err)
	}
	if d := policy(); !d.Allowed || d.Rate != 50 || d.Reason != inventory.ReasonOK {
		t.Fatalf("classified as not fragile = %+v", d)
	}
	allow := "allow"
	e.record(obs(netip.MustParseAddr("192.168.10.51"), macB, observe.Vendor, "Acme", observe.Passive, 0.5))
	other := e.idByMAC(macB)
	if err := e.svc.MarkFirstScan(e.ctx(), other); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", other, inventory.Patch{RegularScan: &allow}); err != nil {
		t.Fatal(err)
	}
	if d, _ := e.svc.ScanPolicy(e.ctx(), other); !d.Allowed || d.Reason != inventory.ReasonOK {
		t.Fatalf("regular_scan=allow on an unclassified device = %+v", d)
	}
}

// M2: ProtectedIPs lists, by address, what a sweep must not probe: the box, devices declared by hand, devices
// with regular_scan=never, and fragile or unclassified devices after their gentle scan; not a fragile device that
// has not had its gentle scan, nor an ordinary device.
func TestContract_INV8_ProtectedIPs(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("192.168.10.0/24")
	ip := netip.MustParseAddr
	if _, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette-hq", IP: "192.168.10.2"}); err != nil {
		t.Fatal(err)
	}
	e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.10.3"})
	e.record(obs(ip("192.168.10.40"), macA, observe.Kind, "nas", observe.Agent, 0.9)) // fragile, gentle scan done
	e.record(obs(ip("192.168.10.41"), macB, observe.Kind, "nas", observe.Agent, 0.9)) // fragile, not scanned yet
	e.record(obs(ip("192.168.10.42"), "aa:bb:cc:00:00:42", observe.Kind, "pc", observe.Agent, 0.9))
	e.record(obs(ip("192.168.10.43"), "aa:bb:cc:00:00:43", observe.Kind, "pc", observe.Agent, 0.9))       // regular_scan=never
	e.record(obs(ip("192.168.10.44"), "aa:bb:cc:00:00:44", observe.Vendor, "Acme", observe.Passive, 0.5)) // unclassified, gentle scan done
	e.record(obs(ip("192.168.10.45"), "aa:bb:cc:00:00:45", observe.Vendor, "Acme", observe.Passive, 0.5)) // unclassified, not scanned yet
	for _, id := range []string{e.idByMAC(macA), e.idByMAC("aa:bb:cc:00:00:44")} {
		if err := e.svc.MarkFirstScan(e.ctx(), id); err != nil {
			t.Fatal(err)
		}
	}
	never := "never"
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", e.idByMAC("aa:bb:cc:00:00:43"), inventory.Patch{RegularScan: &never}); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.ProtectedIPs(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	var have []string
	for _, a := range got {
		have = append(have, a.String())
	}
	slices.Sort(have)
	want := []string{"192.168.10.2", "192.168.10.3", "192.168.10.40", "192.168.10.43", "192.168.10.44"}
	if !slices.Equal(have, want) {
		t.Fatalf("protected = %v\nwant       %v", have, want)
	}
}
