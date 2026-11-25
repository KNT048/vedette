package notify_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// The box keeps only the fields a provider uses, and a saved secret only with the sign-in method it was saved for.
func TestEmailProviderFieldsAndSecretFollowTheSignInMethod(t *testing.T) {
	e := newEnv(t)
	save := func(f map[string]string, secret string) (notify.Channel, error) {
		return e.svc.SaveChannel(e.ctx(), "admin@acme.example", channel.Email, notify.ChannelInput{Enabled: true, MinSeverity: notify.High, Secret: secret, Fields: f})
	}
	ms := map[string]string{"provider": "microsoft365", "host": "smtp.office365.com", "port": "587", "security": "starttls", "username": "alerts@acme.example",
		"tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011db47", "client_id": "0a1b2c3d-4e5f-6789-abcd-ef0123456789", "from": "alerts@acme.example", "to": "it@acme.example"}
	c, err := save(ms, "Abc8Q~client.secret_value-123")
	if err != nil {
		t.Fatal(err)
	}
	if c.Fields["tenant_id"] == "" || c.Fields["client_id"] == "" || c.Fields["provider"] != "microsoft365" || *c.SecretLast4 != "••••" {
		t.Fatalf("fields %v", c.Fields)
	}
	// The same method keeps the saved client secret.
	if _, err := save(ms, ""); err != nil {
		t.Fatal(err)
	}
	// Another method needs its own secret: the client secret is not a password.
	gmail := map[string]string{"provider": "gmail", "host": "smtp.gmail.com", "port": "587", "security": "starttls", "username": "me@gmail.com",
		"tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011db47", "from": "me@gmail.com", "to": "it@acme.example"}
	_, err = save(gmail, "")
	wantCode(t, err, 400, "secret_required")
	if c, err = save(gmail, "abcd efgh ijkl mnop"); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Fields["tenant_id"]; ok {
		t.Errorf("a Microsoft field kept for Gmail: %v", c.Fields)
	}
	// Postmark's username is its server token: never kept as a field.
	pm := map[string]string{"provider": "postmark", "host": "smtp.postmarkapp.com", "port": "587", "security": "starttls", "username": "1a2b3c4d-token",
		"from": "alerts@acme.example", "to": "it@acme.example"}
	if c, err = save(pm, "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Fields["username"]; ok {
		t.Errorf("Postmark username kept: %v", c.Fields)
	}
	bad := map[string]string{"provider": "hotmail", "host": "smtp.acme.example", "port": "587", "security": "starttls", "username": "a", "from": "alerts@acme.example", "to": "it@acme.example"}
	_, err = save(bad, "pw")
	wantCode(t, err, 400, "bad_provider")
	ms["tenant_id"] = "../../evil"
	_, err = save(ms, "Abc8Q~client.secret_value-123")
	wantCode(t, err, 400, "bad_tenant_id")
}

// A saved secret is only ever sent to the sign-in method, server and port it was saved for. A save with "No encryption"
// in between does not carry a client secret over to a password login: that save deletes the secret.
func TestEmailSecretIsBoundToMethodServerAndPort(t *testing.T) {
	e := newEnv(t)
	save := func(f map[string]string, secret string) (notify.Channel, error) {
		return e.svc.SaveChannel(e.ctx(), "admin@acme.example", channel.Email, notify.ChannelInput{Enabled: true, MinSeverity: notify.High, Secret: secret, Fields: f})
	}
	ms := map[string]string{"provider": "microsoft365", "host": "smtp.office365.com", "port": "587", "security": "starttls", "username": "alerts@acme.example",
		"tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011db47", "client_id": "0a1b2c3d-4e5f-6789-abcd-ef0123456789", "from": "alerts@acme.example", "to": "it@acme.example"}
	if _, err := save(ms, "Abc8Q~client.secret_value-123"); err != nil {
		t.Fatal(err)
	}
	// step 1: Custom SMTP without encryption on an internal relay needs no secret; the client secret is deleted, not kept
	none := map[string]string{"provider": "custom", "host": "192.168.1.25", "port": "25", "security": "none", "from": "alerts@acme.example", "to": "it@acme.example"}
	c, err := save(none, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.SecretLast4 != nil {
		t.Fatalf("the client secret survived a change of method: last4 %q", *c.SecretLast4)
	}
	// step 2: STARTTLS with a password login has nothing to send
	tls := map[string]string{"provider": "custom", "host": "smtp.attacker.example", "port": "587", "security": "starttls", "username": "x", "from": "alerts@acme.example", "to": "it@acme.example"}
	_, err = save(tls, "")
	wantCode(t, err, 400, "secret_required")

	// A password saved for one server is not sent to another server or port.
	if _, err := save(tls, "pass-for-attacker"); err != nil {
		t.Fatal(err)
	}
	for _, mod := range []func(map[string]string){
		func(f map[string]string) { f["host"] = "smtp.other.example" },
		func(f map[string]string) { f["port"] = "2525" },
	} {
		f := map[string]string{}
		for k, v := range tls {
			f[k] = v
		}
		mod(f)
		_, err := save(f, "")
		wantCode(t, err, 400, "secret_required")
	}
	// The same server, port and method keep it (other fields may change); the host is compared without case.
	tls["to"], tls["host"] = "director@acme.example", "SMTP.Attacker.example"
	if c, err = save(tls, ""); err != nil || c.SecretLast4 == nil {
		t.Fatalf("same server: %v %v", err, c.SecretLast4)
	}
	// A host error still shows first: the admin fixes the server before being asked for the secret.
	tls["host"] = "169.254.169.254"
	_, err = save(tls, "")
	wantCode(t, err, 400, "bad_host")
	// The Microsoft 365 preset never sends its token anywhere but smtp.office365.com.
	ms["host"] = "smtp.attacker.example"
	_, err = save(ms, "Abc8Q~client.secret_value-123")
	wantCode(t, err, 400, "bad_host")
}

// The Microsoft Graph preset keeps its tenant and client IDs, binds its client secret to Graph, and a test message goes to
// graph.microsoft.com sendMail (no SMTP server is involved).
func TestEmailGraphPresetSavesAndSendsThroughGraph(t *testing.T) {
	var hosts []string
	rt := roundTrip(func(r *http.Request, form url.Values) (int, string) {
		hosts = append(hosts, r.URL.Host+r.URL.Path)
		if r.URL.Host == "login.microsoftonline.com" {
			if form.Get("scope") != "https://graph.microsoft.com/.default" || form.Get("client_secret") != "Gr8Q~graph.client_secret-456" {
				return 400, `{"error":"invalid_request"}`
			}
			return 200, `{"token_type":"Bearer","expires_in":3599,"access_token":"graph-token"}`
		}
		if r.URL.Host == "graph.microsoft.com" && r.URL.Path == "/v1.0/users/alerts@acme.example/sendMail" && r.Header.Get("Authorization") == "Bearer graph-token" {
			return 202, ""
		}
		return 404, `{"error":{"code":"ResourceNotFound"}}`
	})
	e := newEnv(t, func(c *notify.Config) { c.HTTPClient = &http.Client{Transport: rt} })
	g := map[string]string{"provider": "microsoft-graph", "host": "graph.microsoft.com", "port": "443", "security": "ssl", "username": "alerts@acme.example",
		"tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011db47", "client_id": "0a1b2c3d-4e5f-6789-abcd-ef0123456789", "from": "alerts@acme.example", "to": "it@acme.example"}
	in := notify.ChannelInput{Enabled: true, MinSeverity: notify.High, Secret: "Gr8Q~graph.client_secret-456", Fields: g} //nolint:gosec // G101: a test value, not a credential
	c, err := e.svc.SaveChannel(e.ctx(), "admin@acme.example", channel.Email, in)
	if err != nil {
		t.Fatal(err)
	}
	if c.Fields["tenant_id"] == "" || c.Fields["client_id"] == "" || c.Fields["secret_for"] != "microsoft_graph graph.microsoft.com:443" {
		t.Fatalf("fields %v", c.Fields)
	}
	res, err := e.svc.TestChannel(e.ctx(), "admin@acme.example", channel.Email)
	if err != nil || !res.OK {
		t.Fatalf("test = %+v, %v (requests %v)", res, err, hosts)
	}
	if len(hosts) != 2 || hosts[1] != "graph.microsoft.com/v1.0/users/alerts@acme.example/sendMail" {
		t.Errorf("requests %v", hosts)
	}
	// The SMTP app preset's client secret is bound elsewhere: switching to it needs the secret again.
	g["provider"], g["host"], g["port"], g["security"] = "microsoft365", "smtp.office365.com", "587", "starttls"
	_, err = e.svc.SaveChannel(e.ctx(), "admin@acme.example", channel.Email, notify.ChannelInput{Enabled: true, MinSeverity: notify.High, Fields: g})
	wantCode(t, err, 400, "secret_required")
}
