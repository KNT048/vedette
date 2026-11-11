package reports

import (
	"testing"

	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

func TestMigrationsUsePrefix(t *testing.T) {
	t.Parallel()
	storetest.AssertMigrationsUsePrefix(t, "reports", Migrations, "rep_", storetest.Migration{Module: "core", FS: core.Migrations})
}
