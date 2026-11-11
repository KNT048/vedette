package main

import (
	"testing"
)

// auth-oidc in the real wiring (SYS-5, INV-4, PRE-3): off by default, so its routes do not exist and the sign-in page shows no SSO
// button; on and saved, the button appears and the configuration reads back with the secret's last 4 only.
func TestWiringAuthOIDC(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	if c, v := s.do("GET", "/core/auth-options", "", ""); c != 200 || v["oidc"] != false {
		t.Fatalf("auth-options: %d %v", c, v)
	}
	for _, r := range [][2]string{{"GET", "/core/oidc"}, {"POST", "/auth/oidc/start"}, {"POST", "/auth/oidc/callback"}} {
		if c, _ := s.do(r[0], r[1], "admin", `{"code":"c","state":"s","binding":"b"}`); c != 404 {
			t.Errorf("%s %s with the module off: %d", r[0], r[1], c)
		}
	}
	s.setModule("auth-oidc", true)
	if c, v := s.do("POST", "/auth/oidc/start", "", ""); c != 400 || at(v, "error", "code") != "oidc_off" {
		t.Fatalf("start before a save: %d %v", c, v)
	}
	c, v := s.do("GET", "/core/oidc", "admin", "")
	if c != 200 || v["scopes"] != "openid email profile" || v["default_role"] != nil || v["sso_users"] != float64(0) {
		t.Fatalf("defaults: %d %v", c, v)
	}
	if c, _ := s.do("GET", "/core/oidc", "operator", ""); c != 403 {
		t.Fatalf("operator: %d", c)
	}
	body := `{"issuer":"https://idp.example/realms/main/","client_id":"vedette","client_secret":"a-long-secret-9876","scopes":"openid email","groups_claim":"groups","default_role":null,"role_map":[{"group":"ops","role":"operator"}]}`
	c, v = s.do("PUT", "/core/oidc", "admin", body)
	if c != 200 || v["issuer"] != "https://idp.example/realms/main" || v["secret_last4"] != "9876" || v["client_secret"] != nil {
		t.Fatalf("save: %d %v", c, v)
	}
	if c, v := s.do("GET", "/core/auth-options", "", ""); c != 200 || v["oidc"] != true {
		t.Fatalf("auth-options after a save: %d %v", c, v)
	}
	s.setModule("auth-oidc", false)
	if c, v := s.do("GET", "/core/auth-options", "", ""); v["oidc"] != false {
		t.Fatalf("auth-options with the module off again: %d %v", c, v)
	}
}
