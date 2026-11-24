package core

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette"
	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/archive"
)

// Restore from a backup file on a new box, and the decryption key that goes with it (S-CORE-1). The first-run page
// uploads the .tar.gz downloaded from Settings -> Data (step 1, POST /core/setup/restore/upload): core reads it as untrusted
// bytes (host/archive, the host's own rules), stages the database in snapshots/<id>/ with upload.json and NO snapshot.json,
// opens it read-only to check it and says what it holds. Step 2 (POST /core/setup/restore) checks the key file against the
// backup's secrets, writes the key and snapshot.json, so the staged upload becomes a snapshot of the host contract
// (host-api 6.11), and has the host import it with backup.create {manual}; then the restore is the one of Settings -> Data
// (startRestore): a snapshot of the fresh box becomes pre_restore and is put back when the restored data does not
// start. No second restore mechanism and no new host command. Both steps need the setup code and are refused once setup is
// done. The box keeps one upload at a time: a new upload replaces the older one, and the start-up sweep removes one that
// was never restored (snapshotMaxAge).
const (
	maxUploadBytes = 4 << 30 // ponytail: 4 GiB of backup; raise it when a box's backups grow past it
	uploadTimeout  = 30 * time.Minute
	uploadMaxAge   = time.Hour
	uploadMetaFile = "upload.json"
	// uploadKeyFile is the decryption key a password-protected upload carried (0600), kept with the staged upload until step 2
	// seals it as the snapshot's vedette.key; removed with the upload.
	uploadKeyFile = "upload.key"
	setupActor    = "setup" // the audit user of the first-run restore: nobody is signed in yet

	codeNotABackup    = "not_a_backup"
	codeUploadUnknown = "upload_unknown"
	codeInvalidKey    = "invalid_key"
	codeWrongKey      = "wrong_key"
	codeKeyUnreadable = "key_unreadable"
)

// BodyLimits is the request cap of the backup upload above the server default (operationId -> bytes). cmd/vedette hands it
// to server.Config through moduleWiring.BodyLimits.
var BodyLimits = map[string]int64{"core_post_core_setup_restore_upload": maxUploadBytes, "core_post_core_data_restore_upload": maxUploadBytes}

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
	key  []byte // the decryption key the file carried (upload.key); nil when it carried none
}

func (u upload) db() string { return filepath.Join(u.dir, snapshotDBFile) }

// errKeyInside: an archive that carries a key in the host's own place (after the database) is not a file Download backup
// makes (INV-6); the host keeps those on the box. A password-protected download carries its key in front, inside the
// encryption (splitKeyMember), never here.
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
	up := upload{snapshot: snapshot{ID: id, dir: dir}, meta: m}
	if key, err := secrets.LoadKeyFile(filepath.Join(dir, uploadKeyFile)); err == nil {
		up.key = key
	} else if !errors.Is(err, fs.ErrNotExist) { // step 1 wrote it 0600 and 32 bytes: anything else is not ours
		return upload{}, uploadUnknown()
	}
	return up, nil
}

// keepKey writes the key a password-protected upload carried next to its database (0600, a new file).
func (u *upload) keepKey(key []byte) error {
	f, err := os.OpenFile(filepath.Join(u.dir, uploadKeyFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("core: stage the key: %w", err)
	}
	_, err = f.Write(key)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("core: stage the key: %w", err)
	}
	u.key = key
	return nil
}

// dropKey removes the staged key: not needed (the backup holds no secret to open), or sealed as the snapshot's own copy.
func (u *upload) dropKey() {
	if u.key != nil {
		_ = os.Remove(filepath.Join(u.dir, uploadKeyFile))
		u.key = nil
	}
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
// The key the upload carried leaves its staging name: the snapshot's vedette.key is the one copy the host reads.
func (s *snapshotter) seal(up upload, key []byte, schema string) error {
	up.dropKey()
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

// liveSchema is what a backup is compared with: the live database's migration versions, its schema epoch and the migration
// files it applied (every database this build started on has both: they are this build's files).
type liveSchema struct {
	versions string                   // "module=version,..."
	epoch    int64                    // the row of store.EpochTable
	stamped  bool                     // the live database has that row
	files    map[store.FileKey]string // store.FilesTable
	recorded bool                     // the live database has that table
}

func (h *OSHandlers) liveSchema(ctx context.Context) (liveSchema, error) {
	var l liveSchema
	var err error
	if l.versions, err = h.db.SchemaVersions(ctx); err != nil {
		return l, err //nolint:wrapcheck // store's error names what failed
	}
	if l.epoch, l.stamped, err = store.EpochOf(ctx, h.db.Reader()); err != nil {
		return l, err //nolint:wrapcheck // store's error names what failed
	}
	l.files, l.recorded, err = store.AppliedFilesOf(ctx, h.db.Reader())
	return l, err //nolint:wrapcheck // store's error names what failed
}

// inspectBackup opens the staged database read-only (immutable: SQLite writes nothing, not even a -wal; trusted_schema off:
// nothing in the file's schema runs a function) and checks it is a Vedette database this software can run: SQLite's
// quick_check, the schema epoch and the applied migration files of live (a backup of a pre-release build is refused: this
// build would not start on it), no module newer than live (409 schema_newer), an organization that finished setup. With key it counts
// the secrets the key opens. The file is untrusted: only counts and the organization name come out of it.
func inspectBackup(ctx context.Context, path string, live liveSchema, key []byte, reference func(context.Context, string) (map[string]string, error)) (inspection, error) {
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
	preRelease := notABackup("This backup was made by a pre-release build of Vedette, which this version cannot restore. Choose a backup made by this version.")
	if e, ok, err := store.EpochOf(ctx, db); err != nil {
		return ins, damaged
	} else if ok != live.stamped || e != live.epoch {
		return ins, preRelease
	}
	// A backup of an earlier release of the same epoch applied fewer files, each the same as this build's; core migrates it up
	// after the restore. A file that differs (or a backup from before the files were recorded) is one core would refuse to start on.
	if live.recorded {
		files, ok, err := store.AppliedFilesOf(ctx, db)
		if err != nil {
			return ins, damaged
		}
		if !ok {
			return ins, preRelease
		}
		for k, sum := range files {
			if mine, there := live.files[k]; there && mine != sum {
				return ins, preRelease
			}
		}
	}
	if schemaNewer(ins.schema, live.versions) {
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
	if !h.setup.firstRun.TryLock() { // held to the end: setup cannot finish meanwhile
		return nil, firstRunBusy()
	}
	defer h.setup.firstRun.Unlock()
	if err := h.setup.CheckSetupCode(ctx, params.XSetupCode.Or("")); err != nil {
		return nil, err
	}
	h.longRead(ctx)
	live, err := h.liveSchema(ctx)
	if err != nil {
		return nil, err
	}
	up, ins, err := h.stageChecked(ctx, req.Data, params.XBackupPassword.Or(""), live)
	if err != nil {
		return nil, err
	}
	c := caller{Principal: server.Principal{Email: setupActor}}
	if err := h.recordUpload(ctx, c, false, up); err != nil {
		return nil, err
	}
	return &oas.CorePostCoreSetupRestoreUploadOK{
		ID: up.ID, CreatedAt: up.meta.CreatedAt, Org: ins.org, Users: ins.users, TwofaUsers: ins.twofaUsers,
		AdminsWithoutKey: ins.adminsWithoutKey, Secrets: ins.secrets, KeyIncluded: up.key != nil,
	}, nil
}

// stageChecked reads an uploaded file (plain, or password-protected with the password of X-Backup-Password) into a staged
// upload and checks it against live (inspectBackup); the key a protected file carried is kept only when it opens some of the
// backup's secrets. The box keeps one upload at a time: an older one is removed first. A refusal leaves nothing behind.
func (h *OSHandlers) stageChecked(ctx context.Context, body io.Reader, passwordHeader string, live liveSchema) (upload, inspection, error) {
	data, key, err := h.openBackupUpload(ctx, body, passwordHeader)
	if err != nil {
		return upload{}, inspection{}, err
	}
	defer clear(key)
	h.snaps.dropUploads()
	up, err := h.snaps.stageUpload(ctx, data)
	if err != nil {
		return upload{}, inspection{}, err
	}
	ins, err := inspectBackup(ctx, up.db(), live, key, h.schemaObjects)
	if err != nil {
		up.remove()
		return upload{}, inspection{}, err
	}
	if key != nil && ins.secrets > 0 && ins.opened > 0 {
		// The key a protected file carries is checked as a key file is in step 2: it is kept only when it opens some of the
		// backup's secrets. One that opens none (a box restored without its key that has sealed nothing since, or a file
		// changed by hand) and one with no secret to check it against are not kept: the box keeps its own key, and the page
		// says what is lost and takes a key file as for a file without one. An unchecked key never becomes the master key.
		if err := up.keepKey(key); err != nil {
			up.remove()
			return upload{}, inspection{}, h.snapshotFailure(ctx, err)
		}
	}
	return up, ins, nil
}

// recordUpload removes the staged upload after the hour step 2 accepts it for and audits data.restore_upload.
func (h *OSHandlers) recordUpload(ctx context.Context, c caller, admin bool, up upload) error {
	id := up.ID
	time.AfterFunc(uploadMaxAge, func() { h.snaps.dropUpload(id) }) // not kept past the hour step 2 accepts it for
	if err := h.record(ctx, c, admin, "data.restore_upload", "backup", "backup of "+up.meta.CreatedAt.Format(time.RFC3339)); err != nil {
		up.remove()
		return err
	}
	return nil
}

// openBackupUpload is the archive of an upload: the body itself, or a password-protected file (age) opened with the password
// of X-Backup-Password while it is read, so only the plain archive reaches the staging (nothing encrypted is stored). A
// protected file without a password is 409 password_required; a wrong password is 400 wrong_backup_password and counts as
// a guess on the setup-code limit of the caller's address (BeginSetupAttempt, given back when the password is right): the
// upload already needs the setup code, scrypt costs about a second per try, and the limit keeps guessing online slower
// than guessing on a copy of the file. A plain file with a password is taken as it is (the password protects nothing).
// A protected file's key member (splitKeyMember) is taken off the front: key is the decryption key it carried, nil for a
// plain file or a protected one without it. A plain file never yields a key: its archive is read by host/archive's rules,
// which refuse anything in front of the manifest.
func (h *OSHandlers) openBackupUpload(ctx context.Context, body io.Reader, header string) (_ io.Reader, key []byte, _ error) {
	br := bufio.NewReaderSize(body, maxAgeHeader)
	if !isAgeFile(br) {
		return br, nil, nil
	}
	password, err := backupPasswordHeader(header)
	if err != nil {
		return nil, nil, err
	}
	if password == "" {
		return nil, nil, passwordRequired()
	}
	_, ip, err := exchange(ctx)
	if err != nil {
		return nil, nil, err
	}
	refund, err := h.auth.BeginSetupAttempt(ip)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // 429 rate_limited as for the setup code
	}
	r, err := decryptBackup(br, password)
	if ae, ok := apierr.As(err); ok && ae.Code == codeWrongBackupPassword {
		return nil, nil, err // a wrong guess keeps its count
	}
	refund() // the right password, or a file that is not one to guess at
	if errors.Is(err, errAgeNotPassword) {
		return nil, nil, notABackup("This file is encrypted with a key, not with a password, so it is not a file Download backup saved.")
	}
	if err != nil {
		return nil, nil, err
	}
	plain := bufio.NewReaderSize(r, maxKeyMember)
	if key, err = splitKeyMember(plain); err != nil {
		return nil, nil, notABackup("The decryption key inside this backup is damaged. Choose the file that Download backup saved.")
	}
	return plain, key, nil
}

// ---- POST /core/setup/restore ----

// uploadKey is the key a staged upload is restored with, chosen and checked by chooseUploadKey before anything changes.
type uploadKey struct {
	key    []byte // sealed with the snapshot, so the host imports the backup with it; nil = the box keeps its own key
	words  string // for the data.restore_import detail: "with the key", "with this box's key", ...
	schema string // the backup's migration versions ("module=version,...")
}

// keyFile is the key file of a request (base64), nil when none was given; 400 invalid_key when it is not 32 bytes.
func keyFile(keyB64 string) ([]byte, error) {
	k := strings.TrimSpace(keyB64)
	if k == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != secrets.KeySize {
		return nil, apierr.New(400, codeInvalidKey, "This is not a Vedette decryption key file: the key file is the 32-byte file that Download decryption key saved.")
	}
	return b, nil
}

// chooseUploadKey checks the key a staged upload is restored with, before the host is asked anything: the key file of the
// request (given, from keyFile: 400 wrong_key when it opens none of the backup's secrets), else the key
// the protected file carried (key_included), else, with ownKey, this box's own key when it opens them (a backup of this box:
// the box keeps its key). Without any of them a backup with secrets needs confirmWithoutKey (409 confirm_required). A backup
// with no secret has nothing to check a key against: an unchecked file never becomes the box's master key, so none is used.
// (A key that opens some secrets but not all is right: rows a keyless restore left, like an old box CA, stay sealed under
// another key by design.)
func (h *OSHandlers) chooseUploadKey(ctx context.Context, up upload, given []byte, confirmWithoutKey, ownKey bool) (uploadKey, error) {
	live, err := h.liveSchema(ctx)
	if err != nil {
		return uploadKey{}, err
	}
	check := func(key []byte) (inspection, error) { return inspectBackup(ctx, up.db(), live, key, h.schemaObjects) }
	switch {
	case given != nil:
		ins, err := check(given)
		switch {
		case err != nil:
			return uploadKey{}, err
		case ins.secrets == 0:
			return uploadKey{words: "without the key (the backup holds no saved secret)", schema: ins.schema}, nil
		case ins.opened == 0:
			return uploadKey{}, apierr.New(400, codeWrongKey, "This key does not open the saved secrets of this backup. Choose the key file of the box the backup comes from.")
		}
		return uploadKey{key: given, words: "with the key", schema: ins.schema}, nil
	case up.key != nil:
		ins, err := check(up.key)
		if err != nil {
			return uploadKey{}, err
		}
		if ins.secrets == 0 {
			return uploadKey{words: "without the key (the backup holds no saved secret)", schema: ins.schema}, nil
		}
		return uploadKey{key: up.key, words: "with the key inside the protected backup", schema: ins.schema}, nil
	}
	ins, err := check(nil)
	if err != nil {
		return uploadKey{}, err
	}
	if ins.secrets == 0 {
		return uploadKey{words: "without the key (the backup holds no saved secret)", schema: ins.schema}, nil
	}
	if ownKey && h.boxKeyOpens(ctx, up, live) {
		return uploadKey{words: "with this box's key", schema: ins.schema}, nil
	}
	if !confirmWithoutKey {
		return uploadKey{}, apierr.New(409, codeConfirmReq, "Without the decryption key the saved secrets are lost and users with two-step sign-in cannot sign in. Add the key file, or confirm to restore without it.")
	}
	return uploadKey{words: "without the key", schema: ins.schema}, nil
}

// boxKeyOpens reports whether this box's own key opens some of the staged backup's secrets: a backup of this box restores
// with them and the box keeps its key. A key file that cannot be read opens nothing.
func (h *OSHandlers) boxKeyOpens(ctx context.Context, up upload, live liveSchema) bool {
	own, err := h.loadKey()
	if err != nil {
		h.log.WarnContext(ctx, "core: the key file cannot be read to check an uploaded backup", "error", err) // the error names the path, never the bytes
		return false
	}
	defer clear(own)
	ins, err := inspectBackup(ctx, up.db(), live, own, h.schemaObjects)
	return err == nil && ins.secrets > 0 && ins.opened > 0
}

// importUpload has the host import the staged upload as a manual backup (with the chosen key, if any) and answers it, ready
// for startRestore. The upload is removed once the host copied it or the import failed; one the host may still be reading
// goes after the hour. extra ends the data.restore_import detail.
func (h *OSHandlers) importUpload(ctx context.Context, c caller, admin bool, up upload, k uploadKey, extra string) (api.Backup, error) {
	if err := h.snaps.seal(up, k.key, k.schema); err != nil {
		up.remove()
		return api.Backup{}, h.snapshotFailure(ctx, err)
	}
	b := api.Backup{CreatedAt: up.meta.CreatedAt}
	keep := false
	err := h.act(ctx, c, admin, "data.restore_import", "backup", "backup of "+up.meta.CreatedAt.Format(time.RFC3339)+", "+k.words+extra, func(id, actor string) error {
		// labelRE of the host: letters, digits, space, : and - (no comma). Before first-run setup the restored organization's
		// zone is not known yet (a fresh box has only the default), so the time is UTC and says so.
		label := "Uploaded backup of " + orgtime.ISODay(up.meta.CreatedAt, time.UTC) + " " + orgtime.ClockZone(up.meta.CreatedAt, time.UTC)
		run, kept, err := h.startBackup(ctx, api.BackupCreateArgs{Kind: "manual", IncludeSecrets: k.key != nil, Label: label, Snapshot: up.ID}, id, actor)
		if err != nil {
			keep = kept // the host may be reading it: the start-up sweep removes it later
			return err
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
		return api.Backup{}, err
	}
	return b, nil
}

// CorePostCoreSetupRestore implements POST /core/setup/restore (public, setup code, 202): step 2. Everything that can be
// refused is refused before the host is asked: the key's shape and that it opens the backup's secrets, the confirmation
// without a key, an update or restore running. Then the host imports the upload and the restore starts (startRestore).
func (h *OSHandlers) CorePostCoreSetupRestore(ctx context.Context, req *oas.CorePostCoreSetupRestoreReq) (*oas.CorePostCoreSetupRestoreAccepted, error) {
	if err := h.needHost(); err != nil {
		return nil, err
	}
	if !h.setup.firstRun.TryLock() { // held to the end: setup cannot finish while this imports and starts the restore
		return nil, firstRunBusy()
	}
	defer h.setup.firstRun.Unlock()
	if err := h.setup.CheckSetupCode(ctx, req.SetupCode); err != nil {
		return nil, err
	}
	if !req.AcceptTerms.Or(false) { // a new operator takes the box over: the same terms as setup
		return nil, termsNotAccepted()
	}
	given, err := keyFile(req.Key.Or(""))
	if err != nil {
		return nil, err
	}
	up, err := h.snaps.openUpload(req.UploadID)
	if err != nil {
		return nil, err
	}
	k, err := h.chooseUploadKey(ctx, up, given, req.ConfirmWithoutKey.Or(false), false)
	if err != nil {
		return nil, err
	}
	if done, err := h.setup.SetupDone(ctx); err != nil { // the first-run lock keeps setup from finishing; said again before the import
		return nil, err
	} else if done {
		return nil, alreadySetup()
	}
	if h.busy(ctx) || h.restoreRunning(ctx) { // asked again under lockRestore below; refused here before the host copies the upload
		return nil, apierr.New(409, codeBusy, "An update or a restore is running. Wait for it to finish, then restore.")
	}
	c := caller{Principal: server.Principal{Email: setupActor}}
	// The acceptance is said here, in the fresh database the pre_restore backup keeps; the restored database gets its
	// terms.accepted row from the marker file when the run is settled there (settleRestore, settleRestoreAtStart).
	accepted := firstRunTerms{Version: vedette.TermsVersion(), At: h.now().UTC()}
	b, err := h.importUpload(ctx, c, false, up, k, ", terms of use "+accepted.Version+" accepted")
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
	if err := h.writeTermsMarker(accepted); err != nil {
		return nil, err
	}
	rec, err := h.startRestore(ctx, c, false, b)
	if err != nil {
		h.dropTermsMarker()
		return nil, err
	}
	return &oas.CorePostCoreSetupRestoreAccepted{Status: oas.CorePostCoreSetupRestoreAcceptedStatus(rec.view().Status), Error: oas.NilString{Null: true}}, nil
}

// ---- the terms accepted before a first-run restore ----

const (
	termsMarkerFile = "first-run-terms.json"
	// termsMarkerMaxAge: a marker older than this belongs to a restore that never came back (the host restores within
	// restoreTimeout); it is dropped at start-up, not settled.
	termsMarkerMaxAge = 2 * time.Hour
)

// firstRunTerms is the marker file: the version shown and when it was accepted. It lives next to the database, not in it,
// because the restore replaces the database; the restored one records it when the run is settled there.
type firstRunTerms struct {
	Version string    `json:"version"`
	At      time.Time `json:"at"`
}

func (h *OSHandlers) writeTermsMarker(t firstRunTerms) error {
	b, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("core: encode the terms marker: %w", err)
	}
	tmp := h.termsMarker + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("core: write the terms marker: %w", err)
	}
	if err := os.Rename(tmp, h.termsMarker); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("core: write the terms marker: %w", err)
	}
	return nil
}

// termsVersionRE is the shape of vedette.TermsVersion: the Version date (or "undated") and 8 hex digits.
var termsVersionRE = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}|undated)\.[0-9a-f]{8}$`)

// readTermsMarker is the marker, ok false when there is none or it cannot be trusted: at most 4 KiB, a version of the
// shape core writes, a time within the last termsMarkerMaxAge and not in the future (validated at the edge: the file sits
// on disk, and a bad one falls back rather than reaching the database and the audit log).
func (h *OSHandlers) readTermsMarker() (firstRunTerms, bool) {
	var t firstRunTerms
	if h.termsMarker == "" {
		return t, false
	}
	b, err := os.ReadFile(h.termsMarker)
	if err != nil || len(b) > 4096 || json.Unmarshal(b, &t) != nil || !termsVersionRE.MatchString(t.Version) {
		return firstRunTerms{}, false
	}
	if now := h.now(); t.At.IsZero() || t.At.After(now) || now.Sub(t.At) > termsMarkerMaxAge {
		return firstRunTerms{}, false
	}
	return t, true
}

func (h *OSHandlers) dropTermsMarker() {
	if h.termsMarker != "" {
		if err := os.Remove(h.termsMarker); err != nil && !errors.Is(err, fs.ErrNotExist) {
			h.log.Warn("core: could not remove the terms marker", "error", err)
		}
	}
}

// firstRunRestorePending reports whether a first-run restore left its terms marker, young enough to settle; an older one
// is dropped (its content is checked when it is used).
func (h *OSHandlers) firstRunRestorePending() bool {
	fi, err := os.Stat(h.termsMarker)
	if err != nil {
		return false
	}
	if time.Since(fi.ModTime()) > termsMarkerMaxAge { // the file's own age
		h.dropTermsMarker()
		return false
	}
	return true
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

// ---- restore from a file on a set-up box: POST /core/data/restore/upload and /core/data/restore/file ----

// fileBusy is the answer while another restore from a file is being checked or imported on this box.
func fileBusy() *apierr.Error {
	return apierr.New(409, codeBusy, "Another backup file is being checked or restored. Wait for it to finish.")
}

// longRead gives the request a read deadline long enough for a large file (the server's 60 s is for requests, not files).
func (h *OSHandlers) longRead(ctx context.Context) {
	if x, ok := server.ExchangeFrom(ctx); ok {
		if err := http.NewResponseController(x.W).SetReadDeadline(time.Now().Add(uploadTimeout)); err != nil {
			h.log.WarnContext(ctx, "core: the upload keeps the server's read timeout; a large backup may be cut", "error", err)
		}
	}
}

// CorePostCoreDataRestoreUpload implements POST /core/data/restore/upload (admin): step 1 of a restore from a downloaded file
// on a box that is set up, as the first-run upload (stageChecked: the same file checks, password and carried key) behind an
// administrator's session instead of the setup code. Nothing on the box changes but the staged upload; box_key says whether
// this box's own key opens the backup's secrets (a backup of this box), so the page asks for no key file then.
func (h *OSHandlers) CorePostCoreDataRestoreUpload(ctx context.Context, req oas.CorePostCoreDataRestoreUploadReq, params oas.CorePostCoreDataRestoreUploadParams) (*oas.CorePostCoreDataRestoreUploadOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	if !h.fileMu.TryLock() {
		return nil, fileBusy()
	}
	defer h.fileMu.Unlock()
	if h.busy(ctx) || h.restoreRunning(ctx) {
		return nil, apierr.New(409, codeBusy, "An update or a restore is running. Wait for it to finish, then restore.")
	}
	h.longRead(ctx)
	live, err := h.liveSchema(ctx)
	if err != nil {
		return nil, err
	}
	up, ins, err := h.stageChecked(ctx, req.Data, params.XBackupPassword.Or(""), live)
	if err != nil {
		return nil, err
	}
	boxKey := up.key == nil && ins.secrets > 0 && h.boxKeyOpens(ctx, up, live)
	if err := h.recordUpload(ctx, c, true, up); err != nil {
		return nil, err
	}
	return &oas.CorePostCoreDataRestoreUploadOK{
		ID: up.ID, CreatedAt: up.meta.CreatedAt, Org: ins.org, Users: ins.users, TwofaUsers: ins.twofaUsers,
		AdminsWithoutKey: ins.adminsWithoutKey, Secrets: ins.secrets, KeyIncluded: up.key != nil, BoxKey: boxKey,
	}, nil
}

// CorePostCoreDataRestoreFile implements POST /core/data/restore/file (admin, 202): step 2, the restore of the uploaded file
// as the restore of a kept backup. Everything that can be refused is refused before anything changes, in this order: the
// confirmation, the key file's shape, the upload, the key (chooseUploadKey, with this box's own key as a choice), an update
// or restore running, then the step-up of a restore (the current password, a fresh two-step code). A refusal keeps the
// upload, so the next try needs no new upload. Then the host imports it (importUpload) and the restore starts
// (startRestore: the copy of the current data first, kept as pre_restore and put back when the restored data does not start).
func (h *OSHandlers) CorePostCoreDataRestoreFile(ctx context.Context, req *oas.CorePostCoreDataRestoreFileReq) (*oas.CorePostCoreDataRestoreFileAccepted, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	if v, ok := req.ConfirmDataLoss.Get(); !ok || !v {
		return nil, apierr.New(409, codeConfirmReq, "Restoring replaces everything written since the backup. Confirm to go on.")
	}
	given, err := keyFile(req.Key.Or(""))
	if err != nil {
		return nil, err
	}
	if !h.fileMu.TryLock() {
		return nil, fileBusy()
	}
	defer h.fileMu.Unlock()
	up, err := h.snaps.openUpload(req.UploadID)
	if err != nil {
		return nil, err
	}
	k, err := h.chooseUploadKey(ctx, up, given, req.ConfirmWithoutKey.Or(false), true)
	if err != nil {
		return nil, err
	}
	if h.busy(ctx) || h.restoreRunning(ctx) { // asked again under lockRestore below; refused here before the host copies the upload
		return nil, apierr.New(409, codeBusy, "An update or a restore is running. Wait for it to finish, then restore.")
	}
	// Step-up as for the restore of a kept backup: the current password, counted against the re-auth limiter, then a fresh
	// two-step code when it is on.
	if err := h.auth.VerifyOwnPassword(ctx, c.ID, req.Password, "Wrong password. The password is needed to restore a backup."); err != nil {
		return nil, err
	}
	if u, err := h.auth.GetUser(ctx, c.ID); err != nil {
		return nil, fmt.Errorf("core: read user: %w", err)
	} else if u.TwofaMethod != "" {
		loc, err := h.location(ctx)
		if err != nil {
			h.log.WarnContext(ctx, "core: reading the organization time zone failed; the restore summary uses UTC", "error", err)
			loc = time.UTC
		}
		if _, err := h.auth.VerifyTwoStep(ctx, c.ID, req.Code.Or(""), "core.data_restore", "Restore the backup file from "+orgtime.StampZone(up.meta.CreatedAt, loc)); err != nil {
			return nil, err
		}
	}
	b, err := h.importUpload(ctx, c, true, up, k, "")
	if err != nil {
		return nil, err
	}
	unlock, err := h.lockRestore(ctx) // only now: the import may wait up to 16 minutes, and an update must answer busy meanwhile, not wait
	if err != nil {
		return nil, err
	}
	defer unlock()
	rec, err := h.startRestore(ctx, c, true, b)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePostCoreDataRestoreFileAccepted](rec.view())
}

// ---- POST /core/data/key ----

// CorePostCoreDataKey implements POST /core/data/key (admin): the master key file, to keep apart from the backups.
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
	key, err := h.loadKey()
	if err != nil {
		h.log.ErrorContext(ctx, "core: the key file cannot be read for its download", "error", err) // the error names the path, never the bytes
		return oas.CorePostCoreDataKeyOK{}, apierr.New(409, codeKeyUnreadable, "The decryption key file cannot be read on this box. The details are in the box log.")
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

// loadKey reads the master key file (0600, 32 bytes): for its own download and for the inside of a password-protected backup,
// nothing else. The bytes go only where the caller puts them; an error names the path, never the bytes.
func (h *OSHandlers) loadKey() ([]byte, error) {
	if h.keyPath == "" {
		return nil, errors.New("core: no key file is configured")
	}
	return secrets.LoadKeyFile(h.keyPath) //nolint:wrapcheck // secrets names the file and what is wrong with it
}
