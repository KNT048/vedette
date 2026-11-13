package notify_test

import (
	"testing"

	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// D-449: the box keeps only the fields a provider uses, and a saved secret only with the sign-in method it was saved for.
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
	if c.Fields["tenant_id"] == "" || c.Fields["client_id"] == "" || c.Fields["provider"] != "microsoft365" || *c.SecretLast4 != "-123" {
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
