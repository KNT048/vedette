package core

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/archive"
)

// Restore from a backup file on a new box, and the decryption key that goes with it (S-CORE-1, D-518). The first-run page
// uploads the .tar.gz downloaded from Settings -> Data (step 1, POST /core/setup/restore/upload): core reads it as untrusted
// bytes (host/archive, the host's own rules), stages the database in snapshots/<id>/ with upload.json and NO snapshot.json,
// opens it read-only to check it and says what it holds. Step 2 (POST /core/setup/restore) checks the key file against the
// backup's secrets, writes the key and snapshot.json, so the staged upload becomes a snapshot of the host contract
// (host-api 6.11), and has the host import it with backup.create {manual}; then the restore is the one of Settings -> Data
// (startRestore, D-377): a snapshot of the fresh box becomes pre_restore and is put back when the restored data does not
// start. No second restore mechanism and no new host command. Both steps need the setup code and are refused once setup is
// done. The box keeps one upload at a time: a new upload replaces the older one, and the start-up sweep removes one that
// was never restored (snapshotMaxAge).
const (
	maxUploadBytes = 4 << 30 // ponytail: 4 GiB of backup; raise it when a box's backups grow past it
	uploadTimeout  = 30 * time.Minute
	uploadMaxAge   = time.Hour
	uploadMetaFile = "upload.json"
	setupActor     = "setup" // the audit user of the first-run restore: nobody is signed in yet

	codeNotABackup    = "not_a_backup"
	codeUploadUnknown = "upload_unknown"
	codeInvalidKey    = "invalid_key"
	codeWrongKey      = "wrong_key"
	codeKeyUnreadable = "key_unreadable"
)

// BodyLimits is the request cap of the backup upload above the server default (operationId -> bytes). cmd/vedette hands it
// to server.Config through moduleWiring.BodyLimits.
var BodyLimits = map[string]int64{"core_post_core_setup_restore_upload": maxUploadBytes}

var sqliteMagic = []byte("SQLite format 3\x00")

func notABackup(msg string) *apierr.Error { return apierr.New(400, codeNotABackup, msg) }

func uploadUnknown() *apierr.Error {
	return apierr.New(404, codeUploadUnknown, "The uploaded backup is no longer on the box (an upload is kept for an hour). Upload it again.")
}

// uploadMeta is upload.json: when the backup was made (its manifest) and when it was uploaded.
type uploadMeta struct {
	CreatedAt  time.Time `json:"created_at"`
	UploadedAt time.Time `json:"uploaded_at"`
}

// upload is a backup staged in snapshots/<id>/.
type upload struct {
	snapshot
	meta uploadMeta
}

func (u upload) db() string { return filepath.Join(u.dir, snapshotDBFile) }

// errKeyInside: an archive that carries a key is not a file Download backup makes (INV-6); the host keeps those on the box.
var errKeyInside = errors.New("core: the archive holds a key")

// stageUpload reads an uploaded backup archive from r into a new snapshots/<id>/: the manifest is checked, the database is
// written as vedette.db (0600, exactly the size its header declares, refused before a byte is written when the disk has less
// than twice that free), and upload.json last. A failure leaves nothing behind.
func (s *snapshotter) stageUpload(ctx context.Context, r io.Reader) (up upload, err error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return upload{}, fmt.Errorf("core: snapshot directory: %w", err)
	}
	id, err := newSnapshotID()
	if err != nil {
		return upload{}, err
	}
	dir := filepath.Join(s.dir, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return upload{}, fmt.Errorf("core: snapshot directory: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	var man archive.Manifest
	var haveMan, haveDB bool
	err = archive.Read(r, func(name string, mr io.Reader, n int64) error {
		switch name {
		case archive.MemberManifest:
			b, err := io.ReadAll(mr)
			if err != nil {
				return err //nolint:wrapcheck // stageUpload maps read errors
			}
			if int64(len(b)) != n {
				return fmt.Errorf("%w: the manifest is cut short", archive.ErrArchive)
			}
			if man, err = archive.ParseManifest(b); err != nil {
				return fmt.Errorf("%w: %s", archive.ErrArchive, err.Error())
			}
			if man.IncludesSecrets {
				return errKeyInside
			}
			haveMan = true
		case archive.MemberDB:
			if !haveMan {
				return fmt.Errorf("%w: the manifest must come first", archive.ErrArchive)
			}
			if n == 0 {
				return fmt.Errorf("%w: the database is empty", archive.ErrArchive)
			}
			if free, ferr := s.free(s.dir); ferr == nil && free < 2*uint64(n) { //nolint:gosec // n is non-negative (archive.Read)
				return errLowDisk
			}
			f, err := os.OpenFile(filepath.Join(dir, snapshotDBFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // a fixed name inside the directory made above
			if err != nil {
				return fmt.Errorf("core: stage the upload: %w", err)
			}
			c, err := io.Copy(f, mr)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err //nolint:wrapcheck // stageUpload maps read errors
			}
			if c != n {
				return fmt.Errorf("%w: the database is cut short", archive.ErrArchive)
			}
			haveDB = true
		case archive.MemberKey:
			return errKeyInside
		}
		return nil
	})
	var tooBig *http.MaxBytesError
	switch {
	case err == nil && !haveDB:
		return upload{}, notABackup("This file has no database in it. Choose the .tar.gz file that Download backup saved.")
	case err == nil:
	case errors.As(err, &tooBig):
		return upload{}, apierr.TooLarge()
	case errors.Is(err, errLowDisk):
		return upload{}, apierr.New(409, CodeLowDisk, "The box has less free disk space than twice the size of this backup's database.")
	case errors.Is(err, errKeyInside):
		return upload{}, notABackup("This file holds a decryption key, so it is not a file Download backup saved. Upload the backup and the key file separately.")
	case ctx.Err() != nil:
		return upload{}, ctx.Err() //nolint:wrapcheck // the request is over
	default: // a damaged or cut file, or a read of the upload that broke off
		return upload{}, notABackup("This file is not a Vedette backup, or it is damaged or cut short. Choose the .tar.gz file that Download backup saved.")
	}
	created, err := time.Parse(time.RFC3339, man.CreatedAt)
	if err != nil { // ParseManifest already checked it
		return upload{}, notABackup("This file is not a Vedette backup.")
	}
	meta := uploadMeta{CreatedAt: created.UTC(), UploadedAt: s.now().UTC()}
	b, err := json.Marshal(meta)
	if err != nil {
		return upload{}, fmt.Errorf("core: stage the upload: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, uploadMetaFile), b, 0o600); err != nil {
		return upload{}, fmt.Errorf("core: stage the upload: %w", err)
	}
	return upload{snapshot: snapshot{ID: id, dir: dir}, meta: meta}, nil
}

// openUpload finds the staged upload id: its upload.json, younger than uploadMaxAge, and no snapshot.json yet.
func (s *snapshotter) openUpload(id string) (upload, error) {
	if !snapshotIDRE.MatchString(id) {
		return upload{}, uploadUnknown()
	}
	dir := filepath.Join(s.dir, id)
	if _, err := os.Lstat(filepath.Join(dir, snapshotMetaFile)); err == nil {
		return upload{}, uploadUnknown()
	}
	b, err := os.ReadFile(filepath.Join(dir, uploadMetaFile)) //nolint:gosec // id matched snapshotIDRE
	if err != nil || len(b) > 4096 {
		return upload{}, uploadUnknown()
	}
	var m uploadMeta
	if err := json.Unmarshal(b, &m); err != nil || s.now().Sub(m.UploadedAt) > uploadMaxAge {
		return upload{}, uploadUnknown()
	}
	return upload{snapshot: snapshot{ID: id, dir: dir}, meta: m}, nil
}

// dropUploads removes every staged upload: the box keeps one at a time, and none once setup is done.
func (s *snapshotter) dropUploads() {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.IsDir() && snapshotIDRE.MatchString(e.Name()) {
			s.dropUpload(e.Name())
		}
	}
}

// dropUpload removes the staged upload id: a directory of ours with upload.json and no snapshot.json (one being imported is
// left to its own request).
func (s *snapshotter) dropUpload(id string) {
	dir := filepath.Join(s.dir, id)
	if _, err := os.Lstat(filepath.Join(dir, snapshotMetaFile)); err == nil {
		return
	}
	if _, err := os.Lstat(filepath.Join(dir, uploadMetaFile)); err == nil {
		_ = os.RemoveAll(dir)
	}
}

// seal turns the staged upload into a snapshot of the host contract: the key (when given) and snapshot.json, written last.
func (s *snapshotter) seal(up upload, key []byte, schema string) error {
	if key != nil {
		f, err := os.OpenFile(filepath.Join(up.dir, snapshotKeyFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("core: write the key: %w", err)
		}
		_, err = f.Write(key)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("core: write the key: %w", err)
		}
	}
	return s.writeMeta(up.ID, schema, key != nil)
}

// inspection is what a staged backup holds, read from its database.
type inspection struct {
	schema           string
	org              string
	users            int
	twofaUsers       int
	adminsWithoutKey int
	secrets          int // rows of core_secret checked (at most 10000)
	opened           int // of those, how many key opens; 0 without a key
}

// inspectBackup opens the staged database read-only (immutable: SQLite writes nothing, not even a -wal; trusted_schema off:
// nothing in the file's schema runs a function) and checks it is a Vedette database this software can run: SQLite's
// quick_check, no module newer than live (409 schema_newer), an organization that finished setup. With key it counts the
// secrets the key opens. The file is untrusted: only counts and the organization name come out of it.
func inspectBackup(ctx context.Context, path, live string, key []byte, reference func(context.Context, string) (map[string]string, error)) (inspection, error) {
	var ins inspection
	damaged := notABackup("The database in this backup is damaged. Choose another backup.")
	f, err := os.Open(path) //nolint:gosec // a staged upload's fixed name
	if err != nil {
		return ins, fmt.Errorf("core: open the upload: %w", err)
	}
	head := make([]byte, len(sqliteMagic))
	_, err = io.ReadFull(f, head)
	_ = f.Close()
	if err != nil || !bytes.Equal(head, sqliteMagic) {
		return ins, notABackup("This file is not a Vedette backup: it holds no database.")
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Set("immutable", "1")
	q.Add("_pragma", "query_only(1)")
	q.Add("_pragma", "trusted_schema(0)")
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}).String())
	if err != nil {
		return ins, fmt.Errorf("core: open the upload: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	var check string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&check); err != nil || check != "ok" {
		return ins, damaged
	}
	if ins.schema, err = store.SchemaVersionsOf(ctx, db); err != nil || !strings.Contains(","+ins.schema, ",core=") || !archive.ValidSchema(ins.schema) {
		return ins, notABackup("This file is not a Vedette backup.")
	}
	if schemaNewer(ins.schema, live) {
		return ins, apierr.New(409, api.CodeSchemaNewer, "This backup was made by a newer Vedette. Install that version (or a later one) on this box first, then restore.")
	}
	// Triggers and views run on the live box once it is restored: a file changed at rest could plant one (a hidden account made
	// administrator again at every sign-in) or drop one (the append-only audit log). Only the ones Vedette's own migrations make
	// at these versions are accepted, with their exact text.
	got, err := store.SchemaObjectsOf(ctx, db)
	if err != nil {
		return ins, damaged
	}
	want, err := reference(ctx, ins.schema)
	if err != nil {
		return ins, err
	}
	if !maps.Equal(got, want) {
		return ins, notABackup("The database in this backup was changed: its triggers or views are not the ones Vedette makes. Choose another backup.")
	}
	org, err := coredb.New(db).GetOrg(ctx)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && org.SetupComplete == 0) {
		return ins, notABackup("This backup is of a box that was never set up, so there is nothing in it to restore.")
	}
	if err != nil {
		return ins, damaged
	}
	ins.org = cutAtRune(org.Name, 80)
	// An account made by SSO (column since core migration 10) cannot sign in without the key either: the provider's client
	// secret is one of the secrets.
	sso := ""
	var n int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM pragma_table_info('core_user') WHERE name = 'sso_issuer'").Scan(&n); err == nil && n > 0 {
		sso = " AND sso_issuer IS NULL"
	}
	err = db.QueryRowContext(ctx, `SELECT count(*), coalesce(sum(twofa_method IS NOT NULL), 0), coalesce(sum(role = 'admin' AND twofa_method IS NULL`+sso+`), 0)
		FROM core_user WHERE disabled = 0`).Scan(&ins.users, &ins.twofaUsers, &ins.adminsWithoutKey)
	if err != nil {
		return ins, damaged
	}
	if key == nil {
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM core_secret").Scan(&ins.secrets); err != nil {
			return ins, damaged
		}
		return ins, nil
	}
	st, err := secrets.New(key)
	if err != nil {
		return ins, apierr.New(400, codeInvalidKey, "This is not a Vedette decryption key file.")
	}
	if ins.opened, ins.secrets, err = st.CountOpenable(ctx, db); err != nil {
		return ins, damaged
	}
	return ins, nil
}

// schemaObjects is what this software's migrations make at schema ("module=version,..."): the triggers, views and virtual
// tables an uploaded database must have, no more and no fewer (INV-38). It migrates a scratch database in a private temporary
// directory with the migrations the purge rebuilds a fresh install from (HandlersConfig.Schema, in the order they run), and
// removes it. Without them nothing matches and every upload is refused.
func (h *OSHandlers) schemaObjects(ctx context.Context, schema string) (map[string]string, error) {
	at := map[string]int64{}
	for p := range strings.SplitSeq(schema, ",") {
		if m, v, ok := strings.Cut(p, "="); ok {
			at[m], _ = strconv.ParseInt(v, 10, 64)
		}
	}
	dir, err := os.MkdirTemp("", "vedette-schema-")
	if err != nil {
		return nil, fmt.Errorf("core: schema reference: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	db, err := store.Open(ctx, filepath.Join(dir, "schema.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		return nil, err //nolint:wrapcheck // store's error names what failed
	}
	defer func() { _ = db.Close() }()
	for _, m := range h.setup.schema {
		if v, ok := at[strings.ReplaceAll(m.Module, "-", "_")]; ok {
			if err := store.MigrateTo(ctx, db, m.Module, m.FS, v); err != nil {
				return nil, err //nolint:wrapcheck // store's error names the module
			}
		}
	}
	return store.SchemaObjectsOf(ctx, db.Reader()) //nolint:wrapcheck // store's error names what failed
}

// schemaNewer reports whether backup ("module=version,...") has a module at a higher version than live, or one live does
// not have (the host's own early check, host/ops schemaNewer).
func schemaNewer(backup, live string) bool {
	have := map[string]int{}
	for p := range strings.SplitSeq(live, ",") {
		if m, v, ok := strings.Cut(p, "="); ok {
			have[m], _ = strconv.Atoi(v)
		}
	}
	for p := range strings.SplitSeq(backup, ",") {
		m, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		n, _ := strconv.Atoi(v)
		if old, ok := have[m]; !ok || n > old {
			return true
		}
	}
	return false
}

// ---- POST /core/setup/restore/upload ----

// CorePostCoreSetupRestoreUpload implements POST /core/setup/restore/upload (public, setup code): step 1 of the first-run
// restore. The body is the archive; it is read only after the setup code was accepted, with a read deadline long enough
// for a large file.
func (h *OSHandlers) CorePostCoreSetupRestoreUpload(ctx context.Context, req oas.CorePostCoreSetupRestoreUploadReq, params oas.CorePostCoreSetupRestoreUploadParams) (*oas.CorePostCoreSetupRestoreUploadOK, error) {
	if err := h.needHost(); err != nil {
		return nil, err
	}
	if !h.setup.firstRun.TryLock() { // held to the end: setup cannot finish meanwhile (D-518)
		return nil, firstRunBusy()
	}
	defer h.setup.firstRun.Unlock()
	if err := h.setup.CheckSetupCode(ctx, params.XSetupCode.Or("")); err != nil {
		return nil, err
	}
	if x, ok := server.ExchangeFrom(ctx); ok {
		if err := http.NewResponseController(x.W).SetReadDeadline(time.Now().Add(uploadTimeout)); err != nil { // the server's 60 s is for requests, not files
			h.log.WarnContext(ctx, "core: the upload keeps the server's read timeout; a large backup may be cut", "error", err)
		}
	}
	live, err := h.db.SchemaVersions(ctx)
	if err != nil {
		return nil, err
	}
	h.snaps.dropUploads()
	up, err := h.snaps.stageUpload(ctx, req.Data)
	if err != nil {
		return nil, err
	}
	ins, err := inspectBackup(ctx, up.db(), live, nil, h.schemaObjects)
	if err != nil {
		up.remove()
		return nil, err
	}
	id := up.ID
	time.AfterFunc(uploadMaxAge, func() { h.snaps.dropUpload(id) }) // not kept past the hour step 2 accepts it for
	c := caller{Principal: server.Principal{Email: setupActor}}
	if err := h.record(ctx, c, false, "data.restore_upload", "backup", "backup of "+up.meta.CreatedAt.Format(time.RFC3339)); err != nil {
		up.remove()
		return nil, err
	}
	return &oas.CorePostCoreSetupRestoreUploadOK{
		ID: up.ID, CreatedAt: up.meta.CreatedAt, Org: ins.org, Users: ins.users, TwofaUsers: ins.twofaUsers,
		AdminsWithoutKey: ins.adminsWithoutKey, Secrets: ins.secrets,
	}, nil
}

// ---- POST /core/setup/restore ----

// CorePostCoreSetupRestore implements POST /core/setup/restore (public, setup code, 202): step 2. Everything that can be
// refused is refused before the host is asked: the key's shape and that it opens the backup's secrets, the confirmation
// without a key, an update or restore running. Then the host imports the upload and the restore starts (startRestore).
func (h *OSHandlers) CorePostCoreSetupRestore(ctx context.Context, req *oas.CorePostCoreSetupRestoreReq) (*oas.CorePostCoreSetupRestoreAccepted, error) {
	if err := h.needHost(); err != nil {
		return nil, err
	}
	if !h.setup.firstRun.TryLock() { // held to the end: setup cannot finish while this imports and starts the restore (D-518)
		return nil, firstRunBusy()
	}
	defer h.setup.firstRun.Unlock()
	if err := h.setup.CheckSetupCode(ctx, req.SetupCode); err != nil {
		return nil, err
	}
	var key []byte
	if k := strings.TrimSpace(req.Key.Or("")); k != "" {
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(b) != secrets.KeySize {
			return nil, apierr.New(400, codeInvalidKey, "This is not a Vedette decryption key file: the key file is the 32-byte file that Download decryption key saved.")
		}
		key = b
	}
	up, err := h.snaps.openUpload(req.UploadID)
	if err != nil {
		return nil, err
	}
	live, err := h.db.SchemaVersions(ctx)
	if err != nil {
		return nil, err
	}
	ins, err := inspectBackup(ctx, up.db(), live, key, h.schemaObjects)
	if err != nil {
		return nil, err
	}
	if ins.secrets == 0 {
		// Nothing to check the key against: an unchecked file never becomes the box's master key. The box keeps its own and
		// the page says so. (A key that opens some secrets but not all is right: rows a keyless restore left, like an old box
		// CA, stay sealed under another key by design, D-351.)
		key = nil
	}
	switch {
	case key != nil && ins.secrets > 0 && ins.opened == 0:
		return nil, apierr.New(400, codeWrongKey, "This key does not open the saved secrets of this backup. Choose the key file of the box the backup comes from.")
	case key == nil && ins.secrets > 0 && !req.ConfirmWithoutKey.Or(false):
		return nil, apierr.New(409, codeConfirmReq, "Without the decryption key the saved secrets are lost and users with two-step sign-in cannot sign in. Add the key file, or confirm to restore without it.")
	}
	if done, err := h.setup.SetupDone(ctx); err != nil { // the first-run lock keeps setup from finishing; said again before the import
		return nil, err
	} else if done {
		return nil, alreadySetup()
	}
	if h.busy(ctx) || h.restoreRunning(ctx) { // asked again under lockRestore below; refused here before the host copies the upload
		return nil, apierr.New(409, codeBusy, "An update or a restore is running. Wait for it to finish, then restore.")
	}
	if err := h.snaps.seal(up, key, ins.schema); err != nil {
		up.remove()
		return nil, h.snapshotFailure(ctx, err)
	}
	c := caller{Principal: server.Principal{Email: setupActor}}
	b := api.Backup{CreatedAt: up.meta.CreatedAt}
	keep := false
	detail := "backup of " + up.meta.CreatedAt.Format(time.RFC3339) + ", without the key"
	if key != nil {
		detail = "backup of " + up.meta.CreatedAt.Format(time.RFC3339) + ", with the key"
	}
	err = h.act(ctx, c, false, "data.restore_import", "backup", detail, func(id, actor string) error {
		label := "Uploaded backup of " + up.meta.CreatedAt.Format("2006-01-02 15:04") // labelRE of the host: letters, digits, space, : and -
		run, err := h.host.BackupCreate(ctx, api.BackupCreateArgs{Kind: "manual", IncludeSecrets: key != nil, Label: label, Snapshot: up.ID}, id, actor)
		if err != nil {
			var found, known bool
			if run, found, known = h.recoverRun(ctx, err, api.CmdBackupCreate, id); !found {
				keep = !known // the host may be reading it: the start-up sweep removes it later
				return notTaken(ctx, h.log, err, run)
			}
		}
		if run, err = waitRun(ctx, h.log, h.host, run, 16*time.Minute); err != nil {
			return err
		}
		var res api.BackupResult
		if err := json.Unmarshal(run.Result, &res); err != nil || res.BackupID == "" {
			h.log.ErrorContext(ctx, "core: backup run without a usable result", "run", run.RunID)
			return apierr.New(502, CodeHostError, "The operating system helper could not do this. The details are in the box log.")
		}
		b.BackupID = res.BackupID
		return nil
	})
	if keep {
		time.AfterFunc(uploadMaxAge, up.remove) // the host may still read it: gone after the hour, before the start-up sweep
	} else {
		up.remove() // the host copied it, or the import failed: either way an upload is not used twice
	}
	if err != nil {
		return nil, err
	}
	// The restore locks are taken only now: the import may wait up to 16 minutes, and an update must answer busy meanwhile, not
	// wait. The first-run lock already keeps a second upload or restore out.
	unlock, err := h.lockRestore(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	rec, err := h.startRestore(ctx, c, false, b)
	if err != nil {
		return nil, err
	}
	return &oas.CorePostCoreSetupRestoreAccepted{Status: oas.CorePostCoreSetupRestoreAcceptedStatus(rec.view().Status), Error: oas.NilString{Null: true}}, nil
}

// ---- GET /core/setup/restore ----

// CoreGetCoreSetupRestore implements GET /core/setup/restore (public): the first-run restore while setup is open, only its
// status and the sentence of how it ended. A restore that succeeded brought an organization that finished setup, so once
// setup is done the answer is done, whoever finished it: it tells nobody more than GET /setup does.
func (h *OSHandlers) CoreGetCoreSetupRestore(ctx context.Context) (oas.NilCoreGetCoreSetupRestoreOK, error) {
	if done, err := h.setup.SetupDone(ctx); err != nil {
		return oas.NilCoreGetCoreSetupRestoreOK{}, err
	} else if done {
		return oas.NilCoreGetCoreSetupRestoreOK{Value: oas.CoreGetCoreSetupRestoreOK{Status: oas.CoreGetCoreSetupRestoreOKStatusDone, Error: oas.NilString{Null: true}}}, nil
	}
	if err := h.needHost(); err != nil {
		return oas.NilCoreGetCoreSetupRestoreOK{}, err
	}
	rec, err := h.restoreLatest(ctx)
	if err != nil {
		return oas.NilCoreGetCoreSetupRestoreOK{}, err
	}
	if rec == nil {
		return oas.NilCoreGetCoreSetupRestoreOK{Null: true}, nil
	}
	v := rec.view()
	out := oas.CoreGetCoreSetupRestoreOK{Status: oas.CoreGetCoreSetupRestoreOKStatus(v.Status), Error: oas.NilString{Null: true}}
	if v.Error != nil {
		out.Error = oas.NewNilString(*v.Error)
	}
	return oas.NilCoreGetCoreSetupRestoreOK{Value: out}, nil
}

// ---- POST /core/data/key ----

// CorePostCoreDataKey implements POST /core/data/key (admin): the master key file, to keep apart from the backups (D-518).
// Step-up as for a restore: the current password, then a fresh two-step code when it is on; then one audit row. The bytes
// go only into this response: never a log line, never another response.
func (h *OSHandlers) CorePostCoreDataKey(ctx context.Context, req *oas.CorePostCoreDataKeyReq) (oas.CorePostCoreDataKeyOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return oas.CorePostCoreDataKeyOK{}, err
	}
	if err := h.auth.VerifyOwnPassword(ctx, c.ID, req.Password, "Wrong password. The password is needed to download the decryption key."); err != nil {
		return oas.CorePostCoreDataKeyOK{}, err
	}
	if u, err := h.auth.GetUser(ctx, c.ID); err != nil {
		return oas.CorePostCoreDataKeyOK{}, fmt.Errorf("core: read user: %w", err)
	} else if u.TwofaMethod != "" {
		if _, err := h.auth.VerifyTwoStep(ctx, c.ID, req.Code.Or(""), "core.data_key", "Download the decryption key"); err != nil {
			return oas.CorePostCoreDataKeyOK{}, err
		}
	}
	unreadable := apierr.New(409, codeKeyUnreadable, "The decryption key file cannot be read on this box. The details are in the box log.")
	if h.keyPath == "" {
		return oas.CorePostCoreDataKeyOK{}, unreadable
	}
	key, err := secrets.LoadKeyFile(h.keyPath)
	if err != nil {
		h.log.ErrorContext(ctx, "core: the key file cannot be read for its download", "error", err) // the error names the path, never the bytes
		return oas.CorePostCoreDataKeyOK{}, unreadable
	}
	if err := h.record(ctx, c, true, "data.key_download", "decryption key", ""); err != nil {
		return oas.CorePostCoreDataKeyOK{}, err
	}
	if x, ok := server.ExchangeFrom(ctx); ok {
		hd := x.W.Header()
		hd.Set("Content-Disposition", `attachment; filename="vedette-key-`+h.now().UTC().Format("2006-01-02")+`.key"`)
		hd.Set("Content-Length", strconv.Itoa(len(key)))
	}
	return oas.CorePostCoreDataKeyOK{Data: bytes.NewReader(key)}, nil
}
