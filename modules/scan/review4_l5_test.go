package scan

import "testing"

// L5: the product text from feeds (a feed is untrusted, SYS-6) is stored as one plain line: no control, format or
// bidi characters.
func TestReview4_L5_TheProductIsStoredAsPlainText(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	ev := NewKEV{CVE: "CVE-2024-3400", Vendor: "Palo\xe2\x80\xaeAlto\x00", Product: "PAN-OS\n\t<b>x</b>\xe2\x81\xa6", HasTemplate: true}
	if err := r.svc.OnNewKEV(r.ctx(), ev); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := r.db.Reader().QueryRowContext(r.ctx(), `SELECT product FROM scan_event`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "PaloAlto PAN-OS <b>x</b>" {
		t.Fatalf("product %q", got)
	}
}
