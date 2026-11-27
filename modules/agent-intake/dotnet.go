package agentintake

import (
	"regexp"

	"github.com/knt048/vedette/core/productid"
)

// .NET's installed runtimes. Each .NET shared framework (Microsoft.NETCore.App, Microsoft.AspNetCore.App,
// Microsoft.WindowsDesktop.App) is installed per version side by side, and a vulnerability is fixed in the framework's own version.
// The Uninstall list does not say which are installed: the host and its resolver ("Microsoft .NET Host FX Resolver - 6.0.16") keep
// the version of the runtime that installed them after that runtime is gone, and a hosting bundle's entry names several frameworks.
// The runtime installers register each installed version under
// HKLM\SOFTWARE\[WOW6432Node\]dotnet\Setup\InstalledVersions\<arch>\sharedfx\<framework>, one value named by the version (for every
// runtime an installer put there, the frameworks `dotnet --list-runtimes` prints). The programs query reads those values
// with the list (programsQuery); each version of each framework the product catalogue names (its "windows" names) is a row under the
// framework's name, and the Uninstall entries of the same products then keep their own names. Without those values (Wazuh, an agent on
// an older config) the runtimes' own Uninstall entries give the rows, as the catalogue maps them.

// dotnetFxKeyRE is a shared framework's key as osquery's registry table gives it; the captures are the architecture and the framework.
var dotnetFxKeyRE = regexp.MustCompile(`(?i)^HKEY_LOCAL_MACHINE\\SOFTWARE\\(?:WOW6432Node\\)?dotnet\\Setup\\InstalledVersions\\(x64|x86|arm64)\\sharedfx\\([A-Za-z][A-Za-z0-9.]{0,63})$`)

// dotnetVersionRE is a framework version as the installers name the value: "8.0.19", a preview's "10.0.0-rc.2.25502.107".
var dotnetVersionRE = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}(?:-[0-9A-Za-z.]{1,40})?$`)

// fxVersion is one installed framework version.
type fxVersion struct {
	display, version string
	p                productid.Product
}

// fxVersions is what the registered framework versions of one programs list give: their rows, and the keys of their products.
type fxVersions struct {
	rows     []fxVersion
	products map[string]bool
}

// dotnetFrameworks reads the registered framework versions of the programs rows; a framework the catalogue does not name, a value
// that is no version and a key of another place give nothing.
func dotnetFrameworks(rows []row) fxVersions {
	out := fxVersions{products: map[string]bool{}}
	for _, r := range rows {
		m := dotnetFxKeyRE.FindStringSubmatch(r["reg_key"])
		if m == nil || !dotnetVersionRE.MatchString(r["version"]) {
			continue
		}
		p, ok := productid.Resolve(productid.Windows, m[2], "", "")
		if !ok {
			continue
		}
		out.rows = append(out.rows, fxVersion{display: m[2] + " " + r["version"] + " (" + m[1] + ")", version: r["version"], p: p})
		out.products[p.Key] = true
	}
	return out
}
