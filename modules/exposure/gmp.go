package exposure

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// A minimal client of the Greenbone Management Protocol (GMP, XML over the gvmd unix socket) for the optional deep scan
// (S-EXP-2, CONTRACT INV-25, D-563). It speaks only the commands the scan needs: authenticate, get_feeds and get_configs
// (readiness), create/modify_config, get_port_lists, create_target, create_task, start_task, get_tasks, get_reports, stop_task and
// the deletes that clean up after a scan. gvmd is a separate program in Greenbone's own containers; nothing of it is linked here.
//
// Every answer is untrusted input (rules/security.md): one answer is at most a few MiB (gmpMaxAnswer, gmpMaxReport), it is parsed
// strictly into the fields the scan reads (encoding/xml expands no external entity and reads only UTF-8), a status that is not 2xx
// is an error, and an id that is not a UUID is refused before it is put into the next command.

// Fixed objects of a Greenbone Community Edition install (its feed's data objects).
const (
	gmpFullAndFast = "daba56c8-73ec-11df-a475-002264764cea" // scan config "Full and fast"
	gmpIANATCP     = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5" // port list "All IANA assigned TCP"
	gmpOpenVAS     = "08b69003-5fc2-4037-a479-93b440211c73" // scanner "OpenVAS Default"

	// gbObjectPrefix starts the name of every target and task Vedette creates, so a scan can find and remove its own leftovers.
	gbObjectPrefix = "vedette-scan-"
	// gmpBruteOID is the feed's "Options for Brute Force NVTs" (family Settings): its checkboxes "Disable brute force checks" and
	// "Disable default account checks" set the KB keys that credential tests in other families read, so turning the families off
	// alone does not stop them (D-563 review r1 M2).
	gmpBruteOID = "1.3.6.1.4.1.25623.1.0.103697"
	// gmpGlobalOID is the feed's "Global variable settings" (family Settings): its checkbox "Enable generic web application scanning"
	// turns on the generic SQL injection and XSS fuzzing of the web application tests; the testing terms cover it (D-566).
	gmpGlobalOID = "1.3.6.1.4.1.25623.1.0.12288"
	// GreenbonePortList is the name of the port list the scan uses.
	GreenbonePortList = "All IANA assigned TCP"
	// GreenboneMinQoD is the lowest quality of detection a result is read with (Greenbone's own default filter is 70).
	GreenboneMinQoD = 70

	gmpMaxAnswer  = 1 << 20 // bytes of an answer other than a report
	gmpMaxReport  = 8 << 20 // bytes of a report; a bigger one is refused, never cut
	gmpCmdTimeout = 2 * time.Minute
	gmpMaxResults = 2000 // results a report may hold before it is refused
	gmpMaxCVEs    = 50   // CVE ids kept per result
	gmpMaxName    = 200
	gmpMaxText    = 400
)

// gmpDisruptiveFamilies are the families of "Full and fast" that guess passwords, log in with default accounts or try to crash a
// service: on only with the disruptive tick of the testing terms (D-566).
var gmpDisruptiveFamilies = []string{"Brute force attacks", "Default Accounts", "Denial of Service"}

// gmpCheckbox is one checkbox of an NVT's preferences that Vedette's config must hold before a task starts: set on every scan and
// read back (fail closed). Its id is read from gvmd.
type gmpCheckbox struct {
	oid, name, value string
}

// gbLevel is one of Vedette's two scan configs, each a copy of "Full and fast" of its own (D-566): which disruptive families are
// on, safe_checks and the checkboxes. A level never changes into the other: each has its config, found by name.
type gbLevel struct {
	name       string // the config's name in Greenbone
	text       string // what it does, for the check line and the probe log
	disruptive bool   // the disruptive families on
	safeChecks string // "yes" or "no"
	prefs      []gmpCheckbox
}

// The two levels (D-566): the deep scan of accepted testing terms, and the deep scan with the disruptive tick.
var (
	gbDeep = gbLevel{
		name: "vedette-deep-full-and-fast", disruptive: false, safeChecks: "yes",
		text: "Full and fast, every non-disruptive check (active ones and generic web scanning included); safe checks on",
		prefs: []gmpCheckbox{
			{gmpBruteOID, "Disable brute force checks", "yes"},
			{gmpBruteOID, "Disable default account checks", "yes"},
			{gmpGlobalOID, "Enable generic web application scanning", "yes"},
		},
	}
	gbDisruptive = gbLevel{
		name: "vedette-disruptive-full-and-fast", disruptive: true, safeChecks: "no",
		text: "Full and fast, every check (brute force, default accounts and denial of service included); safe checks off",
		prefs: []gmpCheckbox{
			{gmpBruteOID, "Disable brute force checks", "no"},
			{gmpBruteOID, "Disable default account checks", "no"},
			{gmpGlobalOID, "Enable generic web application scanning", "yes"},
		},
	}
)

// levelOf is the config of a scan mode; only a Full mode reaches Greenbone.
func levelOf(m ScanMode) gbLevel {
	if m.Disruptive {
		return gbDisruptive
	}
	return gbDeep
}

// GMPLogin is the GMP user and password the host created for Vedette when it set Greenbone up (kept in core/secrets, never logged).
type GMPLogin struct {
	User     string
	Password string // handed over by the host, never stored or logged by this package
}

// The errors of the GMP client. ErrGMPBad is an answer this client does not read (too big, not XML of the expected shape, an id that
// is not a UUID): the scan says it could not read Greenbone's answer and never reads it as "nothing found".
var (
	ErrGMPBad      = errors.New("exposure: unreadable GMP answer")
	errGMPNotFound = errors.New("exposure: GMP: not found")
	errGMPAuth     = errors.New("exposure: GMP: authentication failed")
	// errGMPSlow: gvmd did not answer within the command's deadline. It is slow, not unreadable (review r1 M3).
	errGMPSlow = errors.New("exposure: GMP: no answer in time")
)

// gmpStatusError is a GMP answer with a status that is not 2xx; Text is gvmd's status_text, clipped and printable.
type gmpStatusError struct {
	Cmd, Status, Text string
}

func (e *gmpStatusError) Error() string {
	return fmt.Sprintf("exposure: GMP %s: %s %s", e.Cmd, e.Status, e.Text)
}

var gmpUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// gmpConn is one GMP session over a connection from GreenboneHost.Dial.
type gmpConn struct {
	conn net.Conn
}

// capReader reads at most n bytes and then fails, so an answer over the cap is an error and not a cut document.
type capReader struct {
	r io.Reader
	n int64
}

var errGMPTooBig = errors.New("exposure: GMP answer over the size cap")

func (c *capReader) Read(p []byte) (int, error) {
	if c.n <= 0 {
		return 0, errGMPTooBig
	}
	if int64(len(p)) > c.n {
		p = p[:c.n]
	}
	n, err := c.r.Read(p)
	c.n -= int64(n)
	return n, err
}

// do sends one command and reads its one answer into v (nil: only the status is read). The answer must be the element
// "<cmd>_response" with a 2xx status; it returns the answer's id attribute (the id of what a create made). A cancelled ctx closes
// the wait at once.
func (g *gmpConn) do(ctx context.Context, cmd, body string, limit int64, v any) (string, error) {
	if err := g.conn.SetDeadline(time.Now().Add(gmpCmdTimeout)); err != nil {
		return "", fmt.Errorf("exposure: GMP %s: %w", cmd, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = g.conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if _, err := io.WriteString(g.conn, body); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			err = errGMPSlow
		}
		return "", ctxOr(ctx, fmt.Errorf("exposure: GMP %s: sending: %w", cmd, err))
	}
	id, err := decodeGMP(&capReader{r: g.conn, n: limit}, cmd, v)
	if err != nil {
		return "", ctxOr(ctx, err)
	}
	return id, nil
}

func ctxOr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// decodeGMP reads exactly one answer element of command cmd from r into v and checks its status (fail closed): nothing but an
// XML declaration, comments and white space may come before it (a DOCTYPE is refused), and its name must be "<cmd>_response".
func decodeGMP(r io.Reader, cmd string, v any) (string, error) {
	bad := func(err error) (string, error) { return "", gmpReadErr(cmd, err) }
	dec := xml.NewDecoder(r)
	dec.Strict = true
	for {
		tok, err := dec.Token()
		if err != nil {
			return bad(err)
		}
		switch t := tok.(type) {
		case xml.ProcInst, xml.Comment:
			continue
		case xml.CharData:
			if len(strings.TrimSpace(string(t))) == 0 {
				continue
			}
		case xml.StartElement:
			return finishGMP(dec, t, cmd, v)
		}
		return "", fmt.Errorf("%w: %s: unexpected content before the answer", ErrGMPBad, cmd)
	}
}

func finishGMP(dec *xml.Decoder, start xml.StartElement, cmd string, v any) (string, error) {
	if start.Name.Local != cmd+"_response" || start.Name.Space != "" {
		return "", fmt.Errorf("%w: %s answered with <%s>", ErrGMPBad, cmd, clipText(start.Name.Local, 40))
	}
	attr := map[string]string{}
	for _, a := range start.Attr {
		attr[a.Name.Local] = a.Value
	}
	var err error
	if v == nil {
		err = dec.Skip()
	} else {
		err = dec.DecodeElement(v, &start)
	}
	if err != nil {
		return "", gmpReadErr(cmd, err)
	}
	st := attr["status"]
	switch {
	case len(st) == 3 && st[0] == '2':
		return attr["id"], nil
	case st == "400" && cmd == "authenticate", st == "401", st == "403":
		return "", errGMPAuth
	case st == "404":
		return "", errGMPNotFound
	case len(st) == 3 && (st[0] == '4' || st[0] == '5'):
		return "", &gmpStatusError{Cmd: cmd, Status: st, Text: plainText(attr["status_text"], 160)}
	}
	return "", fmt.Errorf("%w: %s status %q", ErrGMPBad, cmd, clipText(st, 10))
}

// gmpReadErr sorts an error met while reading an answer: a deadline is errGMPSlow, anything else ErrGMPBad.
func gmpReadErr(cmd string, err error) error {
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return fmt.Errorf("%w: %s", errGMPSlow, cmd)
	case errors.Is(err, errGMPTooBig):
		return fmt.Errorf("%w: %s answer over the size cap", ErrGMPBad, cmd)
	}
	return fmt.Errorf("%w: %s: %w", ErrGMPBad, cmd, err)
}

// esc is text put into a command, escaped for XML.
func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// id refuses an id from an answer that is not a UUID before it goes into a command.
func gmpID(s, what string) (string, error) {
	if !gmpUUID.MatchString(s) {
		return "", fmt.Errorf("%w: %s id %q", ErrGMPBad, what, clipText(s, 40))
	}
	return s, nil
}

func (g *gmpConn) authenticate(ctx context.Context, l GMPLogin) error {
	_, err := g.do(ctx, "authenticate", "<authenticate><credentials><username>"+esc(l.User)+"</username><password>"+esc(l.Password)+"</password></credentials></authenticate>", gmpMaxAnswer, nil)
	return err
}

type gmpFeeds struct {
	Feeds []struct {
		Type    string    `xml:"type"`
		Syncing *struct{} `xml:"currently_syncing"`
	} `xml:"feed"`
}

type gmpConfig struct {
	ID       string      `xml:"id,attr"`
	Name     string      `xml:"name"`
	Owner    string      `xml:"owner>name"`
	Families []gmpFamily `xml:"families>family"`
}

// gmpFamily is one family of a config; NVTCount is how many of its tests the config selects ("" when gvmd gave no count).
type gmpFamily struct {
	Name     string `xml:"name"`
	NVTCount string `xml:"nvt_count"`
}

// on says the config selects tests of the family: listed, with a count that is not 0.
func (f gmpFamily) on() bool { return strings.TrimSpace(f.NVTCount) != "0" }

type gmpConfigs struct {
	Configs []gmpConfig `xml:"config"`
}

// readiness says whether Greenbone can scan: its feeds are not syncing and the "Full and fast" config is there (the feed's data
// objects are loaded). loading is true while the first feed load (about 2 hours) or a feed update runs.
func (g *gmpConn) readiness(ctx context.Context) (loading bool, err error) {
	var f gmpFeeds
	if _, err := g.do(ctx, "get_feeds", "<get_feeds/>", gmpMaxAnswer, &f); err != nil {
		return false, err
	}
	if len(f.Feeds) == 0 {
		return true, nil
	}
	for _, x := range f.Feeds {
		if x.Syncing != nil {
			return true, nil
		}
	}
	var c gmpConfigs
	switch _, err := g.do(ctx, "get_configs", `<get_configs config_id="`+gmpFullAndFast+`"/>`, gmpMaxAnswer, &c); {
	case errors.Is(err, errGMPNotFound):
		return true, nil
	case err != nil:
		return false, err
	}
	return !slices.ContainsFunc(c.Configs, func(x gmpConfig) bool { return x.ID == gmpFullAndFast }), nil
}

// levelConfig returns the id of Vedette's config of one level, creating it once as a copy of "Full and fast" (reused by name only
// when the GMP user owns it), and on every scan puts back and reads back what the level needs, so a half-made or edited copy is put
// right (fail closed): the disruptive families on or off, safe_checks, and the checkboxes of "Options for Brute Force NVTs" and
// "Global variable settings" (D-566). A config used by a task Vedette did not start cannot be changed: that is said, and nothing
// starts.
func (g *gmpConn) levelConfig(ctx context.Context, user string, lv gbLevel) (string, error) {
	var full gmpConfigs
	if _, err := g.do(ctx, "get_configs", `<get_configs config_id="`+gmpFullAndFast+`" families="1"/>`, gmpMaxAnswer, &full); err != nil {
		return "", err
	}
	if len(full.Configs) != 1 || full.Configs[0].ID != gmpFullAndFast || len(full.Configs[0].Families) == 0 {
		return "", fmt.Errorf("%w: the Full and fast config has no families", ErrGMPBad)
	}
	var mine gmpConfigs
	if _, err := g.do(ctx, "get_configs", `<get_configs filter="name=`+lv.name+` rows=-1"/>`, gmpMaxAnswer, &mine); err != nil {
		return "", err
	}
	id, foreign := "", false
	for _, c := range mine.Configs {
		if c.Name != lv.name {
			continue
		}
		if c.Owner != user {
			foreign = true
			continue
		}
		id = c.ID
		break
	}
	if id == "" && foreign {
		return "", &Unavailable{Reason: "a scan config named " + lv.name + " belongs to another Greenbone user, so Vedette did not use it. Rename or delete it in Greenbone."}
	}
	if id == "" {
		var err error
		if id, err = g.do(ctx, "create_config", "<create_config><copy>"+gmpFullAndFast+"</copy><name>"+lv.name+
			"</name><comment>Vedette: "+esc(lv.text)+".</comment></create_config>", gmpMaxAnswer, nil); err != nil {
			return "", err
		}
	}
	if _, err := gmpID(id, "config"); err != nil {
		return "", err
	}
	var sel strings.Builder
	sel.WriteString(`<modify_config config_id="` + id + `"><family_selection><growing>1</growing>`)
	kept := 0
	for _, f := range full.Configs[0].Families {
		name := strings.TrimSpace(f.Name)
		if name == "" || (!lv.disruptive && slices.Contains(gmpDisruptiveFamilies, name)) {
			continue
		}
		kept++
		sel.WriteString("<family><name>" + esc(name) + "</name><all>1</all><growing>1</growing></family>")
	}
	if kept == 0 {
		return "", fmt.Errorf("%w: no family left to scan with", ErrGMPBad)
	}
	sel.WriteString("</family_selection></modify_config>")
	if err := g.modifyConfig(ctx, lv.name, sel.String()); err != nil {
		return "", err
	}
	if err := g.modifyConfig(ctx, lv.name, `<modify_config config_id="`+id+`"><preference><name>safe_checks</name><value>`+
		base64.StdEncoding.EncodeToString([]byte(lv.safeChecks))+`</value></preference></modify_config>`); err != nil {
		return "", err
	}
	if err := g.levelPrefs(ctx, id, lv); err != nil {
		return "", err
	}
	return id, g.readBack(ctx, id, lv)
}

// readBack checks the families and safe_checks of the config after they were set (D-566): a disruptive family on in the deep config,
// or off in the disruptive one, or safe_checks not as set, starts nothing.
func (g *gmpConn) readBack(ctx context.Context, id string, lv gbLevel) error {
	var got gmpConfigs
	if _, err := g.do(ctx, "get_configs", `<get_configs config_id="`+id+`" families="1"/>`, gmpMaxAnswer, &got); err != nil {
		return err
	}
	if len(got.Configs) != 1 || got.Configs[0].ID != id {
		return fmt.Errorf("%w: get_configs did not answer about Vedette's config", ErrGMPBad)
	}
	for _, f := range gmpDisruptiveFamilies {
		on := slices.ContainsFunc(got.Configs[0].Families, func(x gmpFamily) bool { return strings.TrimSpace(x.Name) == f && x.on() })
		if on != lv.disruptive {
			return &Unavailable{Reason: "Greenbone did not keep the family \"" + f + "\" " + onOff(lv.disruptive) + " in Vedette's scan config " + lv.name + ", so nothing was started."}
		}
	}
	var p gmpPrefs
	if _, err := g.do(ctx, "get_preferences", `<get_preferences config_id="`+id+`" preference="safe_checks"/>`, gmpMaxAnswer, &p); err != nil {
		return err
	}
	if x, ok := p.find("safe_checks"); !ok || strings.TrimSpace(x.Value) != lv.safeChecks {
		return &Unavailable{Reason: "Greenbone did not keep safe checks " + onOff(lv.safeChecks == "yes") + " in Vedette's scan config " + lv.name + ", so nothing was started."}
	}
	return nil
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// modifyConfig sends one modify_config; gvmd's refusal because a task uses the config is said as such (review r1 M4).
func (g *gmpConn) modifyConfig(ctx context.Context, name, body string) error {
	_, err := g.do(ctx, "modify_config", body, gmpMaxAnswer, nil)
	var se *gmpStatusError
	if errors.As(err, &se) && strings.Contains(strings.ToLower(se.Text), "in use") {
		return &Unavailable{Reason: "Greenbone's scan config " + name + " is used by a task Vedette did not start, so its settings could not be set again and nothing was started. Delete that task in Greenbone."}
	}
	return err
}

type gmpPref struct {
	ID     string `xml:"id"`
	Name   string `xml:"name"`
	HRName string `xml:"hr_name"`
	Type   string `xml:"type"`
	Value  string `xml:"value"`
}

type gmpPrefs struct {
	Prefs []gmpPref `xml:"preference"`
}

func (p gmpPrefs) find(name string) (gmpPref, bool) {
	for _, x := range p.Prefs {
		if strings.TrimSpace(x.Name) == name || strings.TrimSpace(x.HRName) == name {
			return x, true
		}
	}
	return gmpPref{}, false
}

var gmpPrefID = regexp.MustCompile(`^[0-9]{1,4}$`)

// levelPrefs sets each checkbox of the level in the config and reads them back. Its id is read from gvmd and it is sent in the form
// modify_config takes for an NVT preference ("<oid>:<id>:checkbox:<name>"). One missing from the feed, not a checkbox, or not kept:
// fail closed, nothing starts.
func (g *gmpConn) levelPrefs(ctx context.Context, config string, lv gbLevel) error {
	prefs := func(oid string) (gmpPrefs, error) {
		var p gmpPrefs
		_, err := g.do(ctx, "get_preferences", `<get_preferences nvt_oid="`+oid+`" config_id="`+config+`"/>`, gmpMaxAnswer, &p)
		return p, err
	}
	for _, oid := range []string{gmpBruteOID, gmpGlobalOID} {
		before, err := prefs(oid)
		if err != nil {
			return err
		}
		for _, c := range lv.prefs {
			if c.oid != oid {
				continue
			}
			x, ok := before.find(c.name)
			if !ok || strings.TrimSpace(x.Type) != "checkbox" || !gmpPrefID.MatchString(strings.TrimSpace(x.ID)) {
				return &Unavailable{Reason: "Greenbone's feed has no \"" + c.name + "\" option, so Vedette cannot set its scan config as the testing terms say; nothing was started."}
			}
			full := oid + ":" + strings.TrimSpace(x.ID) + ":checkbox:" + c.name
			if err := g.modifyConfig(ctx, lv.name, `<modify_config config_id="`+config+`"><preference><nvt oid="`+oid+`"/><name>`+esc(full)+`</name><value>`+
				base64.StdEncoding.EncodeToString([]byte(c.value))+`</value></preference></modify_config>`); err != nil {
				return err
			}
		}
		after, err := prefs(oid)
		if err != nil {
			return err
		}
		for _, c := range lv.prefs {
			if c.oid != oid {
				continue
			}
			if x, ok := after.find(c.name); !ok || strings.TrimSpace(x.Value) != c.value {
				return &Unavailable{Reason: "Greenbone did not keep \"" + c.name + "\" " + onOff(c.value == "yes") + " in Vedette's scan config " + lv.name + ", so nothing was started."}
			}
		}
	}
	return nil
}

type gmpPortLists struct {
	Lists []struct {
		ID   string `xml:"id,attr"`
		Name string `xml:"name"`
	} `xml:"port_list"`
}

// portList checks that the predefined "All IANA assigned TCP" list is there under its fixed id.
func (g *gmpConn) portList(ctx context.Context) (string, error) {
	var p gmpPortLists
	if _, err := g.do(ctx, "get_port_lists", `<get_port_lists port_list_id="`+gmpIANATCP+`"/>`, gmpMaxAnswer, &p); err != nil {
		return "", err
	}
	if len(p.Lists) != 1 || p.Lists[0].ID != gmpIANATCP || p.Lists[0].Name != GreenbonePortList {
		return "", fmt.Errorf("%w: the port list %q is not there", ErrGMPBad, GreenbonePortList)
	}
	return gmpIANATCP, nil
}

// createTarget makes the target of one scan: exactly the one address, the port list, alive test "Consider Alive" (the box's own
// IP may not answer ping from inside).
func (g *gmpConn) createTarget(ctx context.Context, name, ip, portList string) (string, error) {
	id, err := g.do(ctx, "create_target", "<create_target><name>"+esc(name)+"</name><hosts>"+esc(ip)+`</hosts><port_list id="`+portList+
		`"/><alive_tests>Consider Alive</alive_tests></create_target>`, gmpMaxAnswer, nil)
	if err != nil {
		return "", err
	}
	return gmpID(id, "target")
}

func (g *gmpConn) createTask(ctx context.Context, name, target, config string) (string, error) {
	id, err := g.do(ctx, "create_task", "<create_task><name>"+esc(name)+`</name><comment>Started by Vedette (external exposure, optional deep scan).</comment><config id="`+
		config+`"/><target id="`+target+`"/><scanner id="`+gmpOpenVAS+`"/></create_task>`, gmpMaxAnswer, nil)
	if err != nil {
		return "", err
	}
	return gmpID(id, "task")
}

type gmpStarted struct {
	ReportID string `xml:"report_id"`
}

func (g *gmpConn) startTask(ctx context.Context, task string) (string, error) {
	var s gmpStarted
	if _, err := g.do(ctx, "start_task", `<start_task task_id="`+task+`"/>`, gmpMaxAnswer, &s); err != nil {
		return "", err
	}
	return gmpID(strings.TrimSpace(s.ReportID), "report")
}

type gmpTasks struct {
	Tasks []struct {
		ID       string `xml:"id,attr"`
		Status   string `xml:"status"`
		Progress string `xml:"progress"`
	} `xml:"task"`
}

// The task states gvmd reports that end a scan.
const (
	gmpDone = "Done"
)

var gmpTaskStates = []string{"New", "Requested", "Queued", "Running", "Stop Requested", "Stopped", "Done", "Interrupted", "Processing", "Delete Requested", "Ultimate Delete Requested"}

// taskStatus is one poll of the task: its state (one of gvmd's words) and progress (-1 when gvmd gives none).
func (g *gmpConn) taskStatus(ctx context.Context, task string) (string, int, error) {
	var t gmpTasks
	if _, err := g.do(ctx, "get_tasks", `<get_tasks task_id="`+task+`"/>`, gmpMaxAnswer, &t); err != nil {
		return "", 0, err
	}
	if len(t.Tasks) != 1 || t.Tasks[0].ID != task {
		return "", 0, fmt.Errorf("%w: get_tasks did not answer about the task", ErrGMPBad)
	}
	st := strings.TrimSpace(t.Tasks[0].Status)
	if !slices.Contains(gmpTaskStates, st) {
		return "", 0, fmt.Errorf("%w: task state %q", ErrGMPBad, clipText(st, 30))
	}
	p, err := strconv.Atoi(strings.TrimSpace(t.Tasks[0].Progress))
	if err != nil || p < -1 || p > 100 {
		p = -1
	}
	return st, p, nil
}

// report reads the results of a finished task with QoD at least GreenboneMinQoD, levels high, medium and low (log notes are not read).
func (g *gmpConn) report(ctx context.Context, report, ip string) ([]GreenboneRow, int, error) {
	r := &gmpReport{}
	if _, err := g.do(ctx, "get_reports", `<get_reports report_id="`+report+`" details="1" ignore_pagination="1" filter="min_qod=`+
		strconv.Itoa(GreenboneMinQoD)+` levels=hml apply_overrides=0 rows=-1 first=1 sort-reverse=severity"/>`, gmpMaxReport, r); err != nil {
		return nil, 0, err
	}
	return parseGMPReport(r, report, ip)
}

// cleanup stops (when running) and deletes the task with its report and the target: the scan is over or was stopped, and gvmd
// must not keep scanning or keep one target and task per scan. It returns what failed ("stop_task: …"), for the log, the audit
// row and the page.
func (g *gmpConn) cleanup(ctx context.Context, task, target string, running bool) []string {
	var failed []string
	try := func(cmd, body string) {
		if _, err := g.do(ctx, cmd, body, gmpMaxAnswer, nil); err != nil {
			failed = append(failed, cmd+": "+clipText(err.Error(), 160))
		}
	}
	if task != "" {
		if running {
			try("stop_task", `<stop_task task_id="`+task+`"/>`)
		}
		try("delete_task", `<delete_task task_id="`+task+`" ultimate="1"/>`)
	}
	if target != "" {
		try("delete_target", `<delete_target target_id="`+target+`" ultimate="1"/>`)
	}
	return failed
}

type gmpObjects struct {
	Tasks []struct {
		ID     string `xml:"id,attr"`
		Name   string `xml:"name"`
		Owner  string `xml:"owner>name"`
		Status string `xml:"status"`
	} `xml:"task"`
	Targets []struct {
		ID    string `xml:"id,attr"`
		Name  string `xml:"name"`
		Owner string `xml:"owner>name"`
	} `xml:"target"`
}

// The task states in which gvmd may still be scanning.
var gmpActive = []string{"Requested", "Queued", "Running", "Stop Requested", "Processing"}

// errGBStillStopping: an earlier task of Vedette's is still being stopped, so a new one does not start (it would run beside it).
var errGBStillStopping = &Unavailable{Reason: "an earlier Greenbone scan of Vedette is still stopping, so a new one was not started. Try again in a few minutes."}

// leftovers stops and deletes the tasks and targets an earlier scan of Vedette's left behind (a stop that failed, a restart of the
// box in the middle of a scan), owned by user and named with gbObjectPrefix, before a new task starts: Vedette never leaves a task
// of its own running beside a new one. A task that could not be stopped or deleted is an error and nothing new starts; a target that
// could not be deleted is only said.
func (g *gmpConn) leftovers(ctx context.Context, user string) (problems []string, err error) {
	var o gmpObjects
	if _, err := g.do(ctx, "get_tasks", `<get_tasks filter="name~`+gbObjectPrefix+` rows=-1"/>`, gmpMaxAnswer, &o); err != nil {
		return nil, err
	}
	for _, t := range o.Tasks {
		id, idErr := gmpID(t.ID, "task")
		if idErr != nil || t.Owner != user || !strings.HasPrefix(t.Name, gbObjectPrefix) {
			continue
		}
		st := strings.TrimSpace(t.Status)
		if slices.Contains(gmpActive, st) && st != "Stop Requested" {
			if _, err := g.do(ctx, "stop_task", `<stop_task task_id="`+id+`"/>`, gmpMaxAnswer, nil); err != nil {
				return problems, fmt.Errorf("stopping the earlier task %s: %w", id, err)
			}
		}
		if _, err := g.do(ctx, "delete_task", `<delete_task task_id="`+id+`" ultimate="1"/>`, gmpMaxAnswer, nil); err != nil {
			if slices.Contains(gmpActive, st) {
				return problems, errGBStillStopping
			}
			return problems, fmt.Errorf("deleting the earlier task %s: %w", id, err)
		}
		problems = append(problems, "an earlier task of Vedette's ("+st+") was removed before this scan")
	}
	o = gmpObjects{}
	if _, err := g.do(ctx, "get_targets", `<get_targets filter="name~`+gbObjectPrefix+` rows=-1"/>`, gmpMaxAnswer, &o); err != nil {
		return problems, err
	}
	for _, t := range o.Targets {
		id, idErr := gmpID(t.ID, "target")
		if idErr != nil || t.Owner != user || !strings.HasPrefix(t.Name, gbObjectPrefix) {
			continue
		}
		if _, err := g.do(ctx, "delete_target", `<delete_target target_id="`+id+`" ultimate="1"/>`, gmpMaxAnswer, nil); err != nil {
			problems = append(problems, "an earlier target of Vedette's could not be deleted: "+clipText(err.Error(), 160))
		}
	}
	return problems, nil
}

// ---- the report (untrusted) ----

type gmpReport struct {
	Report []struct {
		ID    string `xml:"id,attr"`
		Inner struct {
			ID      string      `xml:"id,attr"`
			Results *gmpResults `xml:"results"`
		} `xml:"report"`
	} `xml:"report"`
}

type gmpResults struct {
	Result []gmpResult `xml:"result"`
}

type gmpResult struct {
	Name string `xml:"name"`
	Host struct {
		Text string `xml:",chardata"`
	} `xml:"host"`
	Port string `xml:"port"`
	NVT  struct {
		OID      string   `xml:"oid,attr"`
		Name     string   `xml:"name"`
		Solution string   `xml:"solution"`
		Refs     []gmpRef `xml:"refs>ref"`
	} `xml:"nvt"`
	Severity *string `xml:"severity"`
	QoD      *string `xml:"qod>value"`
}

var (
	gmpPort = regexp.MustCompile(`^[A-Za-z0-9-]{1,16}/[A-Za-z0-9-]{1,16}$`)
	gmpOID  = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,15}$`)
)

// parseGMPReport turns a get_reports answer into rows. It is strict and fails closed (ErrGMPBad): not exactly one report with the
// asked id, no results list, more than gmpMaxResults results, or a result without a number as its severity (0 to 10) and QoD
// (0 to 100). A result of another host is dropped (the target held one address), one below GreenboneMinQoD too (whatever the filter
// did). Text is plain, printable and clipped; a port that is not "22/tcp" or "general/tcp" is ""; CVE ids are checked, without
// repeats, at most gmpMaxCVEs. It returns the rows and how many results the report held.
func parseGMPReport(r *gmpReport, report, ip string) ([]GreenboneRow, int, error) {
	if len(r.Report) != 1 || r.Report[0].ID != report || r.Report[0].Inner.Results == nil {
		return nil, 0, fmt.Errorf("%w: get_reports did not answer with the one report asked for", ErrGMPBad)
	}
	res := r.Report[0].Inner.Results.Result
	if len(res) > gmpMaxResults {
		return nil, 0, fmt.Errorf("%w: more than %d results", ErrGMPBad, gmpMaxResults)
	}
	rows := []GreenboneRow{}
	for _, x := range res {
		if x.Severity == nil || x.QoD == nil {
			return nil, 0, fmt.Errorf("%w: a result without severity or QoD", ErrGMPBad)
		}
		sev, err := strconv.ParseFloat(strings.TrimSpace(*x.Severity), 64)
		if err != nil || sev < -3 || sev > 10 { // gvmd marks log/false-positive/error results with 0, -1, -3
			return nil, 0, fmt.Errorf("%w: severity %q", ErrGMPBad, clipText(*x.Severity, 20))
		}
		qod, err := strconv.Atoi(strings.TrimSpace(*x.QoD))
		if err != nil || qod < 0 || qod > 100 {
			return nil, 0, fmt.Errorf("%w: QoD %q", ErrGMPBad, clipText(*x.QoD, 20))
		}
		if strings.TrimSpace(x.Host.Text) != ip || qod < GreenboneMinQoD || sev <= 0 {
			continue
		}
		name := plainText(x.NVT.Name, gmpMaxName)
		if name == "" {
			name = plainText(x.Name, gmpMaxName)
		}
		row, ok := cleanGreenboneRow(GreenboneRow{IP: ip, Severity: sev, Name: name, Port: strings.TrimSpace(x.Port), QoD: qod, OID: strings.TrimSpace(x.NVT.OID),
			Solution: plainText(x.NVT.Solution, gmpMaxText), CVEs: gmpCVEs(x.NVT.Refs)})
		if !ok {
			return nil, 0, fmt.Errorf("%w: a result without a name", ErrGMPBad)
		}
		rows = append(rows, row)
	}
	return rows, len(res), nil
}

type gmpRef struct {
	Type string `xml:"type,attr"`
	ID   string `xml:"id,attr"`
}

func gmpCVEs(refs []gmpRef) []string {
	out := []string{}
	for _, r := range refs {
		id := strings.ToUpper(strings.TrimSpace(r.ID))
		if strings.EqualFold(r.Type, "cve") && cveID.MatchString(id) && !slices.Contains(out, id) && len(out) < gmpMaxCVEs {
			out = append(out, id)
		}
	}
	return out
}
