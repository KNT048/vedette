package agentintake

import (
	"cmp"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/core/productid"
)

// SQL Server's own version. SQL Server setup writes one Uninstall entry for a whole release, "Microsoft SQL Server 2022
// (64-bit)", without a DisplayVersion (or with the build it was installed with): osquery's programs and Wazuh's packages give it as
// it is, the row maps to CISA's "Microsoft | SQL Server" and findings had to ask a person for a version the machine knows. Two
// sources, in order (the first also replaces a version the entry states; the second only fills one it lacks):
//
//  1. The instance's setup registry, HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL<n>.<instance>\Setup, value PatchLevel: the
//     build installed, cumulative and security updates included (Microsoft, "Determine version information of SQL Server components
//     and client tools": "Patchlevel indicates the current build ..., Version usually shows the original version"). The programs query
//     reads it with the list (programsQuery), so the value and the list always come in one snapshot. Several instances of one release
//     give the lowest build: the umbrella row stands for all of them, and the lowest one is affected by everything a higher one is.
//  2. Without it (Wazuh, an agent whose config predates the setup-registry query), the release's own components from the same list ("SQL Server 2022
//     Database Engine Services", "… Common Files", "Browser for SQL Server 2022", ...), only when the Database Engine is one of them
//     and every one of them with a build of the release's major gives the same build of the release ("16.0.1000.6"). Components that
//     disagree (an update that changed some of them, a service pack's "13.2.5026.0") leave the row without a version, as before.
//     A cumulative update installs as a patch of the components' packages; their DisplayVersion may stay at the build they were
//     installed with (RTM), so this source can only be lower than the machine's build: findings then over-reports what a later
//     update fixed, the safe side, and the registry source replaces it as soon as the agent reports it.
//
// With the registry's build, the release's other rows that the product catalogue maps to the same product (the RsFx Driver: "Microsoft SQL Server 2022
// RsFx Driver", 16.0.1000.6 after any update) keep their own name instead: their version is a component's, not the release's, and would
// keep the CVEs an update fixed open.

// sqlUmbrellaRE is the release's own Uninstall entry; the capture is the release ("2022", "2008 R2").
var sqlUmbrellaRE = regexp.MustCompile(`^Microsoft SQL Server (20[0-9]{2}(?: R2)?) \((?:64|32)-bit\)$`)

// sqlReleaseRE finds the release a component's name belongs to ("SQL Server 2022 Common Files", "Browser for SQL Server 2022").
var sqlReleaseRE = regexp.MustCompile(`\bSQL Server (20[0-9]{2}(?: R2)?)\b`)

// sqlFamilies is the first two parts of the builds of each release (Microsoft's build lists: 2022 is 16.0.x.y, 2008 R2 10.50.x.y).
var sqlFamilies = map[string]string{"2008": "10.0", "2008 R2": "10.50", "2012": "11.0", "2014": "12.0", "2016": "13.0", "2017": "14.0",
	"2019": "15.0", "2022": "16.0", "2025": "17.0"}

// sqlSetupKeyRE is an instance's Setup key as osquery's registry table gives it: MSSQL<major>[_<minor>].<instance> ("MSSQL16.MSSQLSERVER",
// "MSSQL10_50.SQLEXPRESS"). Analysis and Reporting Services (MSAS, MSRS) are other keys.
var sqlSetupKeyRE = regexp.MustCompile(`(?i)^HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL([1-9][0-9]?)(?:_([0-9]{1,2}))?\.[^\\]{1,64}\\Setup$`)

// sqlBuildRE is a SQL Server build: four numbers ("16.0.4135.4").
var sqlBuildRE = regexp.MustCompile(`^[1-9][0-9]?\.[0-9]{1,2}\.[0-9]{1,5}\.[0-9]{1,5}$`)

// componentConfidence is the confidence of a release version read from its components: below a version the machine stated.
const componentConfidence = 0.9

// sqlVersion is the version a release's umbrella row takes; registry says it is the setup registry's.
type sqlVersion struct {
	version    string
	confidence float64
	registry   bool
}

// sqlVersions holds the version of each release ("2022") the list has an umbrella row of.
type sqlVersions map[string]sqlVersion

// sqlUmbrella says whether name is a release's own Uninstall entry, and which release.
func sqlUmbrella(name string) (string, bool) {
	m := sqlUmbrellaRE.FindStringSubmatch(name)
	if m == nil {
		return "", false
	}
	_, ok := sqlFamilies[m[1]]
	return m[1], ok
}

// sqlServerVersions reads the version of each release the programs rows have an umbrella row of: the setup registry's, else the
// components'. A release with neither is left out.
func sqlServerVersions(rows []row) sqlVersions {
	out := sqlVersions{}
	for _, r := range rows {
		if rel, ok := sqlUmbrella(r["name"]); ok && r["reg_key"] == "" {
			out[rel] = sqlVersion{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	patch := sqlPatchLevels(rows)
	for rel := range out {
		if v, ok := patch[sqlFamilies[rel]]; ok {
			out[rel] = sqlVersion{version: v, confidence: softwareConfidence, registry: true}
		} else if v, ok := sqlComponents(rows, rel); ok {
			out[rel] = sqlVersion{version: v, confidence: componentConfidence}
		} else {
			delete(out, rel)
		}
	}
	return out
}

// sqlPatchLevels is the lowest PatchLevel of each family ("16.0") among the setup values of the rows, each a build of its key's own
// family (MSSQL16 gives 16.0.x.y only). Values that do not fit are not read.
func sqlPatchLevels(rows []row) map[string]string {
	out := map[string]string{}
	for _, r := range rows {
		m := sqlSetupKeyRE.FindStringSubmatch(r["reg_key"])
		if m == nil || !sqlBuildRE.MatchString(r["version"]) {
			continue
		}
		fam := m[1] + "." + cmp.Or(m[2], "0")
		if !strings.HasPrefix(r["version"], fam+".") {
			continue
		}
		if old, ok := out[fam]; !ok || compareBuild(r["version"], old) < 0 {
			out[fam] = r["version"]
		}
	}
	return out
}

// sqlComponents is the build every component of the release in the rows gives, when they agree and the Database Engine is one of
// them. Components are the rows whose name names the release (not its umbrella rows) with a build of the release's major; one of
// another family of that major (a service pack's 13.2.x of release 13.0) is a disagreement.
func sqlComponents(rows []row, rel string) (string, bool) {
	fam := sqlFamilies[rel]
	major, _, _ := strings.Cut(fam, ".")
	var build string
	engine := false
	for _, r := range rows {
		name, v := r["name"], r["version"]
		if r["reg_key"] != "" || !sqlBuildRE.MatchString(v) || !strings.HasPrefix(v, major+".") {
			continue
		}
		if _, umbrella := sqlUmbrella(name); umbrella || !slices.ContainsFunc(sqlReleaseRE.FindAllStringSubmatch(name, -1), func(m []string) bool { return m[1] == rel }) {
			continue
		}
		if !strings.HasPrefix(v, fam+".") || build != "" && v != build {
			return "", false
		}
		build = v
		engine = engine || strings.HasSuffix(name, "SQL Server "+rel+" Database Engine Services")
	}
	return build, build != "" && engine
}

// authoritative says whether a row the product catalogue maps to p is a component of a release whose umbrella row took the setup registry's version:
// such a row keeps its own name (its version is a component's).
func (s sqlVersions) authoritative(name string, p productid.Product) bool {
	if p.Vendor != "Microsoft" || p.Product != "SQL Server" {
		return false
	}
	for _, m := range sqlReleaseRE.FindAllStringSubmatch(name, -1) {
		if v, ok := s[m[1]]; ok && v.registry {
			return true
		}
	}
	return false
}

// sqlUmbrellaFirst is the programs rows with SQL Server's release rows first, the rest in their order: a release row that took its
// components' build shares its product and build with the RsFx Driver, and the merged row then keeps the release's name.
func sqlUmbrellaFirst(rows []row) []row {
	out := make([]row, 0, len(rows))
	for pass := range 2 {
		for _, r := range rows {
			if _, umbrella := sqlUmbrella(r["name"]); umbrella == (pass == 0) {
				out = append(out, r)
			}
		}
	}
	return out
}

// compareBuild orders two builds that sqlBuildRE accepts, number by number.
func compareBuild(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := range min(len(as), len(bs)) {
		x, _ := strconv.Atoi(as[i])
		y, _ := strconv.Atoi(bs[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return len(as) - len(bs)
}
