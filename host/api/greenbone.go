package api

// The OpenVAS commands (Greenbone Community Edition, docs/specs/host-api.md §6.16, D-529, FULL-2): vedette-host runs Greenbone's official
// compose project (deploy/greenbone) under its own project name, hands gvmd's socket to core and sets the GMP login core keeps.

// Names of the commands.
const (
	// CmdGreenboneUp makes sure the compose provider is installed and the podman API socket runs, starts the project (the first time it
	// pulls about 9 GB of images and the feed) with the GMP login for gvmd, and checks that gvmd, ospd-openvas, pg-gvm and redis run.
	CmdGreenboneUp = "greenbone.up"
	// CmdGreenboneDown stops the project and keeps its volumes; it first cancels an up or a feed update that runs.
	CmdGreenboneDown = "greenbone.down"
	// CmdGreenboneSyncFeed is Greenbone's feed update: pull the seven feed data images, then start those services again.
	CmdGreenboneSyncFeed = "greenbone.sync_feed"
)

// Refusal and failure codes of the OpenVAS commands (spec §6.16).
const (
	// CodeGreenboneNoProvider: this OS release has no compose provider package Vedette knows, or the one installed is too old.
	CodeGreenboneNoProvider = "greenbone_no_provider"
	// CodeGreenboneFailed: a step failed (podman, compose, the login); the message says which and the host log has the rest.
	CodeGreenboneFailed = "greenbone_failed"
	// CodeGreenboneCancelled: greenbone.down stopped this up or feed update.
	CodeGreenboneCancelled = "greenbone_cancelled"
)

// GreenboneSocketDir is where gvmd's socket directory lives on the host, and core's view of it (core's unit mounts its parent
// GreenboneRunDir at the same path). GreenboneSocket is the socket core dials.
const (
	GreenboneRunDir    = "/run/vedette-greenbone"
	GreenboneSocketDir = GreenboneRunDir + "/gvmd"
	GreenboneSocket    = GreenboneSocketDir + "/gvmd.sock"
	// GreenboneUser is the GMP user Vedette signs in as: the admin user Greenbone's gvmd image creates.
	GreenboneUser = "admin"
)

// GreenboneUpArgs are the args of greenbone.up. Password is the GMP password core generated and keeps in core/secrets (48 lower-case
// hex characters); the host hands it to gvmd at every up as a file only root and gvmd read, so gvmd creates its admin user with it,
// and sets it again in the background on a volume that keeps another one (host-api §6.16, D-590). The server's audit line redacts it
// by its key and records only a digest of the args.
type GreenboneUpArgs struct {
	Password string `json:"password"`
}
