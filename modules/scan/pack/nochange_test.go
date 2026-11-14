package pack

import (
	"encoding/base64"
	"strings"
	"testing"
)

// D-528: the text rule every template file passes, in the builder and in the worker.
func TestNoChangeText(t *testing.T) {
	t.Parallel()
	ok := "id: x\nhttp:\n  - raw:\n      - |\n        POST /login HTTP/1.1\n        Host: {{Hostname}}\n\n        a=b\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n" +
		"    matchers:\n      - type: word\n        words:\n          - \"Reset password\"\n"
	if err := NoChangeText([]byte(ok)); err != nil {
		t.Fatalf("a POST check refused: %v", err)
	}
	for name, body := range map[string]string{
		"a PUT raw":          strings.Replace(ok, "POST /login", "PUT /login", 1),
		"a PATCH method":     strings.Replace(ok, "method: GET", "method: patch", 1),
		"a DELETE raw":       strings.Replace(ok, "POST /login", "DELETE /x", 1),
		"an @Host":           strings.Replace(ok, "      - |\n", "      - |\n        @Host: https://login.microsoftonline.com:443\n", 1),
		"a method override":  strings.Replace(ok, "Host: {{Hostname}}", "Host: {{Hostname}}\n        X-HTTP-Method-Override: DELETE", 1),
		"_method=PUT":        strings.Replace(ok, "a=b", "_method=PUT&a=b", 1),
		"into outfile":       strings.Replace(ok, "a=b", "q=1 INTO OUTFILE '/var/www/x.php'", 1),
		"xp_cmdshell":        strings.Replace(ok, "a=b", "q=1;exec xp_cmdshell 'whoami'", 1),
		"file_put_contents":  strings.Replace(ok, "a=b", "c=file_put_contents('x.php','y')", 1),
		"a multipart upload": strings.Replace(ok, "a=b", "Content-Type: multipart/form-data; boundary=b\n--b\nContent-Disposition: form-data; name=\"f\"; filename=\"x.php\"", 1),
		"gopher":             strings.Replace(ok, "a=b", "url=gopher://127.0.0.1:6379/_SET", 1),
	} {
		if NoChangeText([]byte(body)) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestChangeInRequest(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		part string
		post bool
		want bool
	}{
		{"action=arm_shortcode_form_ajax_action&user_pass=x&arm_action=change-password", true, true},
		{"POST /api/changePw HTTP/1.1", true, true},
		{"POST /wp-admin/admin-ajax.php?action=stm_lms_register HTTP/1.1", true, true},
		{"POST /api/v1/users/signup HTTP/1.1", true, true},
		{"POST /service/v1/createUser HTTP/1.1", true, true},
		{"POST /eonapi/createEonUser?username=admin HTTP/1.1", true, true},
		{"{{BaseURL}}/Admin/Access/Setup/Default.aspx?Action=createadministrator&adminusername=x", false, true},
		{"GET /wp-admin/admin-post.php?do_reset_wordpress=1 HTTP/1.1", false, true},
		{"GET /footprints/servicedesk/passwordreset/request/ HTTP/1.1", false, false}, // a GET shows the form
		{"{{BaseURL}}/osm/REGISTER.cmd", false, false},
		{"cg_create_user_data_csv=true", true, false}, // an export, not a user
		{"X-FCCK-REGISTER: SYSINFO", true, false},
		{"q=1';INSERT INTO DOCTERA_USERS VALUES('a')--", false, true},
		{"q=1%27%3BINSERT%20INTO%20t%20VALUES(1)", false, true},
		{"q=1;UPDATE+users+SET+admin=1", false, true},
		{"q=1 UNION SELECT 1,2", false, false},
		{"proto=;ls>/usr/local/lyx/web/x;", false, true},
		{"param=1; $(ls>/www/x);", false, true},
		{"echo \"eA==\" | base64 -d > /usr/local/out", false, true},
		{"{{BaseURL}}/a/%3Cimg%20src=x%20onerror=alert(document.domain)%3E/filename", false, false}, // XSS, not a shell
		{"{{BaseURL}}/{{s}}\"><img src=a onerror=alert(1)>/..CFIDE/x.cfm", false, false},
	} {
		if got := ChangeInRequest(c.part, c.post) != ""; got != c.want {
			t.Errorf("%q (post %t): change %t, want %t", c.part, c.post, got, c.want)
		}
	}
}

func TestThirdPartyURL(t *testing.T) {
	t.Parallel()
	b64 := base64.StdEncoding.EncodeToString([]byte("http://abc.interact.sh/x"))
	for part, third := range map[string]bool{
		"{{BaseURL}}/proxy?url=https://raw.githubusercontent.com/x":     true,
		"{{BaseURL}}/r?dest=http://interact.sh":                         true,
		"{{BaseURL}}/BlobHandler.ashx?Url=" + b64:                       true,
		"{{BaseURL}}/a?u=http://127.0.0.1:8080/":                        false,
		"{{BaseURL}}/a?u=http://localhost/":                             false,
		"{{BaseURL}}/a?u=http://169.254.169.254/latest/meta-data/":      false,
		"[{\"url\":\"http://[::ffff:127.0.0.1]:3000/health\"}]":         false,
		"{{BaseURL}}/a?u=http://192.168.1.25/rest":                      false,
		"{{BaseURL}}/a?u=http://test":                                   false,
		"{{BaseURL}}/a?u=https://idp.example.com/sso":                   false,
		"{{RootURL}}/x?next={{BaseURL}}/y":                              false,
		"{{BaseURL}}/x?FORWARD_URL=http://oast.me%EF%BF%BD@localhost":   true, // review kev r1 H-2: the userinfo a parser may take for the host
		"{{BaseURL}}/x?u=http://admin:secret@127.0.0.1/":                false,
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/">`: false,
		`<a xmlns:asy="http://www.bea.com/async/AsyncResponseService">`: false,
		`SOAPAction: "http://tempuri.org/IService/Get"`:                 false,
	} {
		if got := ThirdPartyURL(part) != ""; got != third {
			t.Errorf("%q: third party %t, want %t", part, got, third)
		}
	}
}
