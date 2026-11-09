package findings

import (
	"errors"
	"strings"
	"testing"
)

func mustCPE(t testing.TB, s string) CPE {
	t.Helper()
	c, err := ParseCPE(s)
	if err != nil {
		t.Fatalf("ParseCPE(%q): %v", s, err)
	}
	return c
}

func TestParseCPE(t *testing.T) {
	t.Parallel()
	c := mustCPE(t, `cpe:2.3:a:Apache:http_server:2.4.57:*:*:-:*:*:*:*`)
	if c.Part != (Attr{Value, "a"}) || c.Vendor != (Attr{Value, "apache"}) || c.Product.Value != "http_server" {
		t.Fatalf("identity attrs wrong: %+v", c)
	}
	if c.Version.Value != "2.4.57" || c.Update.Kind != Any || c.Edition.Kind != Any || c.Language.Kind != NA {
		t.Fatalf("version/ANY/NA wrong: %+v", c)
	}
	if got := c.String(); got != `cpe:2.3:a:apache:http_server:2.4.57:*:*:-:*:*:*:*` {
		t.Fatalf("String() = %q", got)
	}
}

func TestParseCPE_Escaping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		product string // canonical Value of the product attribute
		literal string // unquoted text
	}{
		{`cpe:2.3:a:v:c\+\+_lib:1:*:*:*:*:*:*:*`, `c\+\+_lib`, `c++_lib`},
		{`cpe:2.3:a:v:big-ip:1:*:*:*:*:*:*:*`, `big-ip`, `big-ip`},
		{`cpe:2.3:a:v:big\-ip:1:*:*:*:*:*:*:*`, `big-ip`, `big-ip`},
		{`cpe:2.3:a:v:a\:b:1:*:*:*:*:*:*:*`, `a\:b`, `a:b`},
		{`cpe:2.3:a:v:\-:1:*:*:*:*:*:*:*`, `\-`, `-`}, // literal hyphen is not NA
		{`cpe:2.3:a:v:\*:1:*:*:*:*:*:*:*`, `\*`, ``},  // quoted star is not a wildcard (no literal text because Literal rejects wildcard chars)
		{`cpe:2.3:a:v:.net_framework:1:*:*:*:*:*:*:*`, `.net_framework`, `.net_framework`},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			c := mustCPE(t, tt.in)
			if c.Product.Kind != Value || c.Product.Value != tt.product {
				t.Fatalf("product = %+v, want Value %q", c.Product, tt.product)
			}
			if lit, ok := c.Product.Literal(); tt.literal != "" && (!ok || lit != tt.literal) {
				t.Fatalf("Literal() = %q,%v want %q", lit, ok, tt.literal)
			}
			if back := mustCPE(t, c.String()); back != c {
				t.Fatalf("round trip changed: %+v -> %+v", c, back)
			}
		})
	}
}

func TestParseCPE_Invalid(t *testing.T) {
	t.Parallel()
	bad := []string{
		"",
		"cpe:2.3:a:v:p",                       // too few
		"cpe:2.3:a:v:p:1:*:*:*:*:*:*:*:*",     // too many
		"cpe:2.2:a:v:p:1:*:*:*:*:*:*:*",       // version
		"cpe:/a:v:p:1",                        // 2.2 URI form
		"cpe:2.3:x:v:p:1:*:*:*:*:*:*:*",       // part
		"cpe:2.3:a::p:1:*:*:*:*:*:*:*",        // empty attribute
		"cpe:2.3:a:v:p:1:*:*:*:*:*:*:\\",      // trailing backslash
		`cpe:2.3:a:v:p\a:1:*:*:*:*:*:*:*`,     // backslash before letter
		`cpe:2.3:a:v:p!:1:*:*:*:*:*:*:*`,      // unquoted special
		`cpe:2.3:a:v:a*b:1:*:*:*:*:*:*:*`,     // wildcard inside
		"cpe:2.3:a:v:p q:1:*:*:*:*:*:*:*",     // space
		"cpe:2.3:a:v:p\u00e9:1:*:*:*:*:*:*:*", // non-ASCII
		"cpe:2.3:a:v:p:1:*:*:*:*:*:*:\x00",    // control char
		"cpe:2.3:a:v:" + strings.Repeat("a", 2000) + ":1:*:*:*:*:*:*:*", // too long
	}
	for _, s := range bad {
		if _, err := ParseCPE(s); !errors.Is(err, ErrInvalidCPE) {
			t.Errorf("ParseCPE(%.40q) err = %v, want ErrInvalidCPE", s, err)
		}
	}
}

func TestCPE_Matches(t *testing.T) {
	t.Parallel()
	sw := `cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*`
	tests := []struct {
		name, cfg, target string
		want              bool
	}{
		{"exact", sw, sw, true},
		{"case", `cpe:2.3:a:Apache:HTTP_Server:2.4.57:*:*:*:*:*:*:*`, sw, true},
		{"any version", `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`, sw, true},
		{"other version", `cpe:2.3:a:apache:http_server:2.4.56:*:*:*:*:*:*:*`, sw, false},
		{"other vendor", `cpe:2.3:a:nginx:http_server:*:*:*:*:*:*:*:*`, sw, false},
		{"prefix wildcard", `cpe:2.3:a:apache:http_*:*:*:*:*:*:*:*:*`, sw, true},
		{"suffix wildcard on version", `cpe:2.3:a:apache:http_server:2.4.*:*:*:*:*:*:*:*`, sw, true},
		{"suffix wildcard miss", `cpe:2.3:a:apache:http_server:2.5.*:*:*:*:*:*:*:*`, sw, false},
		{"single char wildcard", `cpe:2.3:a:apache:http_serve?:*:*:*:*:*:*:*:*`, sw, true},
		{"NA config vs ANY target", `cpe:2.3:a:apache:http_server:2.4.57:-:*:*:*:*:*:*`, sw, false},
		{"NA config vs NA target", `cpe:2.3:a:apache:http_server:2.4.57:-:*:*:*:*:*:*`, `cpe:2.3:a:apache:http_server:2.4.57:-:*:*:*:*:*:*`, true},
		{"ANY config vs NA target", sw, `cpe:2.3:a:apache:http_server:2.4.57:-:*:*:*:*:*:*`, true},
		{"value config vs NA target", `cpe:2.3:a:apache:http_server:2.4.57:beta:*:*:*:*:*:*`, `cpe:2.3:a:apache:http_server:2.4.57:-:*:*:*:*:*:*`, false},
		{"value config vs ANY target", `cpe:2.3:a:apache:http_server:2.4.57:beta:*:*:*:*:*:*`, sw, false},
		{"value config vs target wildcard", `cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*`, `cpe:2.3:a:apache:http_*:2.4.57:*:*:*:*:*:*:*`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := mustCPE(t, tt.cfg).Matches(mustCPE(t, tt.target)); got != tt.want {
				t.Fatalf("Matches = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCPE_SameProduct(t *testing.T) {
	t.Parallel()
	cfg := mustCPE(t, `cpe:2.3:a:apache:http_server:2.4.56:beta:*:*:*:*:*:*`)
	if !cfg.SameProduct(mustCPE(t, `cpe:2.3:a:apache:http_server:9.9:*:*:*:*:*:*:*`)) {
		t.Fatal("same vendor/product with other version must be the same product")
	}
	if cfg.SameProduct(mustCPE(t, `cpe:2.3:a:apache:tomcat:2.4.56:*:*:*:*:*:*:*`)) {
		t.Fatal("different product matched")
	}
	if cfg.SameProduct(mustCPE(t, `cpe:2.3:o:apache:http_server:2.4.56:*:*:*:*:*:*:*`)) {
		t.Fatal("different part matched")
	}
}

func FuzzParseCPE(f *testing.F) {
	for _, s := range []string{
		`cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*`,
		`cpe:2.3:a:v:c\+\+_lib:1:*:*:*:-:*:*:*`,
		`cpe:2.3:a:v:\-:1:*:*:*:*:*:*:*`,
		`cpe:2.3:a:v:a\:b:1.*:*:*:*:*:*:*`,
		`cpe:2.3:a:v:??p*:1:*:*:*:*:*:*:*`,
		`cpe:2.3:a:v:p:1:*:*:*:*:*:*:\`,
		"cpe:2.3:",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, err := ParseCPE(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidCPE) {
				t.Fatalf("error does not wrap ErrInvalidCPE: %v", err)
			}
			return
		}
		back, err := ParseCPE(c.String())
		if err != nil {
			t.Fatalf("canonical form %q does not parse: %v", c.String(), err)
		}
		if back != c {
			t.Fatalf("round trip changed %+v -> %+v", c, back)
		}
		if !c.Matches(c) && !strings.ContainsAny(c.String(), "*?") {
			t.Fatalf("a literal CPE must match itself: %q", c.String())
		}
		_ = c.Matches(back)
		_ = c.SameProduct(back)
	})
}
