package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

func TestUsers_ListCreateAndPatch(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	r := admin.get("/core/users")
	wantOK(t, r, 200)
	items := r.JSON["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("users = %s", r.Raw)
	}
	first := items[0].(map[string]any)
	if first["email"] != "admin@acme.example" || first["role"] != "admin" || first["disabled"] != false || first["twofa"] != false || first["twofa_method"] != nil || first["last_login"] == nil {
		t.Fatalf("admin = %v", first)
	}
	if strings.Contains(r.Raw, "argon2") || strings.Contains(r.Raw, "password") {
		t.Fatal("a password hash is in the list")
	}

	c := admin.post("/core/users", map[string]any{"name": " Bob Op ", "email": " Bob@Acme.Example ", "role": "operator"})
	wantOK(t, c, 201)
	user := c.JSON["user"].(map[string]any)
	temp := c.str("temp_password")
	if user["name"] != "Bob Op" || user["email"] != "bob@acme.example" || user["role"] != "operator" || user["disabled"] != false || user["last_login"] != nil || len(temp) != 20 {
		t.Fatalf("created = %s", c.Raw)
	}
	// The temporary password is shown once: nothing else returns it, and it signs Bob in.
	if strings.Contains(admin.get("/core/users").Raw, temp) || strings.Contains(w.logs.String(), temp) {
		t.Fatal("the temporary password leaked after creation")
	}
	bob := w.client()
	wantOK(t, bob.post("/auth/login", map[string]any{"email": "bob@acme.example", "password": temp}), 200)
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'user.create' AND target = 'bob@acme.example' AND user = 'admin@acme.example'"); n != 1 {
		t.Fatal("no user.create audit row by the administrator")
	}

	wantStatus(t, admin.post("/core/users", map[string]any{"name": "Bob", "email": "BOB@acme.example", "role": "viewer"}), 409, "duplicate")
	wantStatus(t, admin.post("/core/users", map[string]any{"name": "", "email": "x@acme.example", "role": "viewer"}), 400, "invalid_name")
	wantStatus(t, admin.post("/core/users", map[string]any{"name": "X", "email": "nope", "role": "viewer"}), 400, "invalid_email")
	wantStatus(t, admin.post("/core/users", map[string]any{"name": "X", "email": "x@acme.example", "role": "root"}), 400, "invalid")

	id := user["id"].(string)
	p := admin.patch("/core/users/"+id, map[string]any{"role": "admin"})
	wantOK(t, p, 200)
	if p.JSON["user"].(map[string]any)["role"] != "admin" {
		t.Fatalf("patch = %s", p.Raw)
	}
	wantOK(t, admin.patch("/core/users/"+id, map[string]any{"disabled": true}), 200)
	wantStatus(t, w.client().post("/auth/login", map[string]any{"email": "bob@acme.example", "password": temp}), 403, "disabled")
	wantOK(t, admin.patch("/core/users/"+id, map[string]any{"disabled": false, "role": "viewer"}), 200)
	wantStatus(t, admin.patch("/core/users/u-nope", map[string]any{"disabled": true}), 404, "not_found")
	wantStatus(t, admin.patch("/core/users/"+id, map[string]any{"role": "root"}), 400, "invalid")
	for _, a := range []string{"user.role", "user.disable", "user.enable"} {
		if w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = ?", a) == 0 {
			t.Errorf("no %s audit row", a)
		}
	}
}

// INV-7 over HTTP.
func TestContract_INV7_HTTPUserRules(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	var adminID string
	for _, it := range admin.get("/core/users").JSON["items"].([]any) {
		adminID = it.(map[string]any)["id"].(string)
	}
	wantStatus(t, admin.patch("/core/users/"+adminID, map[string]any{"disabled": true}), 400, "self_disable")
	wantStatus(t, admin.patch("/core/users/"+adminID, map[string]any{"role": "viewer"}), 400, "last_admin")
	wantStatus(t, admin.post("/core/users/"+adminID+"/2fa/reset", nil), 400, "self_reset")

	second := admin.post("/core/users", map[string]any{"name": "Two", "email": "two@acme.example", "role": "admin"})
	wantOK(t, second, 201)
	secondID := second.JSON["user"].(map[string]any)["id"].(string)
	// With a second administrator the first may step down; and the second is then the last.
	wantOK(t, admin.patch("/core/users/"+adminID, map[string]any{"role": "viewer"}), 200)
	two := w.client()
	wantOK(t, two.post("/auth/login", map[string]any{"email": "two@acme.example", "password": second.str("temp_password")}), 200)
	wantStatus(t, two.patch("/core/users/"+secondID, map[string]any{"disabled": true}), 400, "self_disable")
	wantStatus(t, two.patch("/core/users/"+secondID, map[string]any{"role": "operator"}), 400, "last_admin")
	// The demoted administrator is a viewer now: every admin route refuses them (the role is read on each request).
	wantStatus(t, admin.get("/core/users"), 403, "forbidden")

	// A reset ends every session of the user and the temporary password is shown once.
	phone := w.client()
	wantOK(t, phone.post("/auth/login", map[string]any{"email": "admin@acme.example", "password": authtest.Password}), 200)
	r := two.post("/core/users/"+adminID+"/reset-password", nil)
	wantOK(t, r, 200)
	temp := r.str("temp_password")
	if len(temp) != 20 || strings.Contains(w.logs.String(), temp) {
		t.Fatalf("reset = %s", r.Raw)
	}
	wantStatus(t, phone.get("/me"), 401, "unauthenticated")
	wantStatus(t, admin.get("/me"), 401, "unauthenticated")
	wantStatus(t, w.client().login("admin@acme.example"), 400, "invalid_credentials")
	wantOK(t, w.client().post("/auth/login", map[string]any{"email": "admin@acme.example", "password": temp}), 200)
	wantStatus(t, two.post("/core/users/u-nope/reset-password", nil), 404, "not_found")
	var hash string
	if err := w.env.DB.Reader().QueryRowContext(t.Context(), "SELECT password_hash FROM core_user WHERE id = ?", adminID).Scan(&hash); err != nil || !strings.HasPrefix(hash, "$argon2id$") || strings.Contains(hash, temp) {
		t.Fatalf("stored password: %q %v", hash, err)
	}
}

func TestUsers_ResetTwoFA(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	bobC := admin.post("/core/users", map[string]any{"name": "Bob", "email": "bob@acme.example", "role": "viewer"})
	wantOK(t, bobC, 201)
	bobID := bobC.JSON["user"].(map[string]any)["id"].(string)
	wantStatus(t, admin.post("/core/users/"+bobID+"/2fa/reset", nil), 409, "not_on")
	wantStatus(t, admin.post("/core/users/u-nope/2fa/reset", nil), 404, "not_found")

	bob := w.client()
	wantOK(t, bob.post("/auth/login", map[string]any{"email": "bob@acme.example", "password": bobC.str("temp_password")}), 200)
	start := bob.post("/core/account/2fa/start", map[string]any{"password": bobC.str("temp_password")})
	wantOK(t, start, 200)
	wantOK(t, bob.post("/core/account/2fa/confirm", map[string]any{"code": auth.TOTPCode(decodeBase32(t, start.str("secret")), auth.TOTPStep(w.env.Clock.Now()))}), 200)
	w.env.Clock.Advance(time.Minute)
	found := false
	for _, it := range admin.get("/core/users").JSON["items"].([]any) {
		if m := it.(map[string]any); m["email"] == "bob@acme.example" {
			found = m["twofa_method"] == "app" && m["twofa"] == true
		}
	}
	if !found {
		t.Fatal("the list does not show Bob's two-step method")
	}
	wantOK(t, admin.post("/core/users/"+bobID+"/2fa/reset", nil), 200)
	wantStatus(t, bob.get("/me"), 401, "unauthenticated") // every session of that user ended
	wantOK(t, w.client().post("/auth/login", map[string]any{"email": "bob@acme.example", "password": bobC.str("temp_password")}), 200)
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'user.2fa_reset' AND target = 'bob@acme.example' AND detail LIKE 'was authenticator app%'"); n != 1 {
		t.Fatal("no user.2fa_reset audit row")
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_secret WHERE purpose = 'core_user_totp'"); n != 0 {
		t.Fatalf("%d TOTP keys left after the reset", n)
	}
}

// A mutation by an administrator whose session was ended (here: by their own password change elsewhere)
// is refused whole.
func TestUsers_ActorIsRecheckedForEveryAdminWrite(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	b := admin.post("/core/users", map[string]any{"name": "Bob", "email": "bob@acme.example", "role": "viewer"})
	wantOK(t, b, 201)
	stale := w.client()
	for k, v := range admin.jar {
		stale.jar[k] = v
	}
	other := w.client()
	wantOK(t, other.login("admin@acme.example"), 200)
	wantOK(t, other.post("/core/account/password", map[string]any{"current": authtest.Password, "next": "a brand new long password"}), 200)
	for name, r := range map[string]reply{
		"create":   stale.post("/core/users", map[string]any{"name": "C", "email": "c@acme.example", "role": "viewer"}),
		"patch":    stale.patch("/core/users/"+b.JSON["user"].(map[string]any)["id"].(string), map[string]any{"disabled": true}),
		"general":  stale.putGeneral(map[string]any{"name": "Evil Co", "timezone": "UTC"}),
		"export":   stale.get("/core/audit/export"),
		"audit":    stale.get("/core/audit"),
		"users":    stale.get("/core/users"),
		"password": stale.post("/core/users/"+b.JSON["user"].(map[string]any)["id"].(string)+"/reset-password", nil),
	} {
		if r.Code != 401 || r.code() != "unauthenticated" {
			t.Errorf("%s with an ended session = %d %s", name, r.Code, r.Raw)
		}
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_user"); n != 2 {
		t.Fatalf("users = %d", n)
	}
}
