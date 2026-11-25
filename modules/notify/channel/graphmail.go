package channel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/knt048/vedette/core/secrets"
)

// Microsoft Graph sendMail with an app-only token: the "Microsoft Graph (app, client secret)" preset. The admin registers an app,
// gives it the application permission Mail.Send of Microsoft Graph with admin consent, and creates a client secret; Vedette gets a
// token with the client credentials grant (scope https://graph.microsoft.com/.default, smtpauth.go) and posts the message as MIME to
// /v1.0/users/<mailbox>/sendMail. No SMTP AUTH and no Exchange Online PowerShell step are involved.
//
// The host is fixed: only the tenant (checked by NewEmail) and the mailbox (an email address, path-escaped) come from the
// configuration, so no configuration sends the token elsewhere. Like the token requests, the request goes through
// EmailConfig.HTTPClient without redirects (tokenClient) and does not pass the connect-time address check.
const (
	graphHost    = "graph.microsoft.com"
	graphSendURL = "https://" + graphHost + "/v1.0/users/%s/sendMail"
	// maxGraphBody is the most Graph accepts in one request (4 MB); the base64 of the MIME message must fit.
	maxGraphBody = 4 << 20
	maxGraphAns  = 64 << 10
)

var graphCodeRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.]{0,63}$`)

// deliverGraph sends the RFC 5322 message raw through Microsoft Graph. A refusal is a *SignInError with a fixed sentence (Graph's
// message text is never shown or logged: it can name tenant internals); 429 is a *RateLimitError.
func (e *emailSender) deliverGraph(ctx context.Context, raw []byte) error {
	ctx, cancel := context.WithTimeout(ctx, emailTimeout)
	defer cancel()
	tok, key, err := e.token(ctx) // the token first: Graph is never called without one
	if err != nil {
		return err
	}
	body := base64.StdEncoding.EncodeToString(raw)
	if len(body) > maxGraphBody {
		return &SignInError{Msg: "The message is larger than Microsoft Graph accepts (4 MB), so it was not sent."}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf(graphSendURL, url.PathEscape(e.cfg.Username)), strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: email: graph request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain") // Graph reads a text/plain body of sendMail as base64 MIME
	req.Header.Set("Authorization", "Bearer "+tok.Reveal())
	hide := []secrets.Value{tok, e.cfg.Password}
	status, ans, err := doLimit(e.client, Email, req, maxGraphAns, hide...)
	var rl *RateLimitError
	switch {
	case errors.As(err, &rl):
		return err
	case err != nil && status == 0 && ctx.Err() != nil:
		return fmt.Errorf("notify: email: graph: %s", transportReason(ctx.Err(), nil))
	case err != nil && status == 0:
		return &SignInError{Msg: "Vedette could not reach Microsoft Graph (" + graphHost + "). Check the box's internet access and DNS."}
	case status == http.StatusAccepted || status == http.StatusOK:
		return nil
	}
	var a struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	code := ""
	if json.Unmarshal(ans, &a) == nil && graphCodeRE.MatchString(a.Error.Code) {
		code = a.Error.Code
	}
	if status == http.StatusUnauthorized && code != "NoPermissionsInAccessToken" {
		e.tokens.drop(key) // a refused token is not used again
	}
	return &SignInError{Msg: e.graphRefusal(status, code)}
}

// graphRefusal is the sentence for a refusal of Graph sendMail, by Graph's error code (never its message).
func (e *emailSender) graphRefusal(status int, code string) string {
	switch code {
	case "ErrorAccessDenied", "AccessDenied", "Authorization_RequestDenied", "NoPermissionsInAccessToken", "ErrorAccessDeniedException":
		return "Microsoft Graph denied sending as " + e.cfg.Username + ". In the app registration, add the application permission Mail.Send " +
			"(Microsoft Graph, Application, not Delegated) and grant admin consent; if your admin limited the app to some mailboxes " +
			"(application access policy or RBAC for Applications), include this one."
	case "ErrorSendAsDenied":
		return "Microsoft Graph refused the sender email " + e.cfg.From + ": the mailbox " + e.cfg.Username + " may not send as it. " +
			"Use the mailbox address as the sender email, or give the mailbox Send As permission for that address."
	case "ErrorInvalidUser", "ResourceNotFound", "MailboxNotEnabledForRESTAPI", "ErrorNonExistentMailbox", "Request_ResourceNotFound":
		return "Microsoft Graph cannot find the mailbox " + e.cfg.Username + " in this tenant, or it has no Exchange Online mailbox (license). " +
			"Check the mailbox address."
	case "InvalidAuthenticationToken":
		return "Microsoft Graph refused the sign-in token. Check the tenant ID, the client ID and the client secret of the app registration."
	}
	if status == http.StatusNotFound {
		return "Microsoft Graph cannot find the mailbox " + e.cfg.Username + " in this tenant. Check the mailbox address."
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return fmt.Sprintf("Microsoft Graph refused to send (HTTP %d%s). Check that the app registration has the application permission "+
			"Mail.Send with admin consent, and the tenant ID, the client ID and the client secret.", status, codeSuffix(code))
	}
	return fmt.Sprintf("Microsoft Graph did not accept the message (HTTP %d%s). Try again later; if it keeps failing, send a test from the Email channel.", status, codeSuffix(code))
}
