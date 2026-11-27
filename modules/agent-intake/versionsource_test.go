package agentintake

import (
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// fxRow is a row of the programs query's .NET arm: one installed version of a shared framework, as the installer registers it.
func fxRow(view, arch, framework, version string) row {
	return row{"name": "", "version": version, "publisher": "", "install_date": "",
		"reg_key": `HKEY_LOCAL_MACHINE\SOFTWARE\` + view + `dotnet\Setup\InstalledVersions\` + arch + `\sharedfx\` + framework}
}

// arpDotnet is the .NET part of a Windows PC's programs list: runtimes, the host resolver of an older runtime, a desktop runtime and
// ASP.NET Core's shared framework, each its own Uninstall entry.
func arpDotnet() []row {
	r := func(name, version string) row {
		return row{"name": name, "version": version, "publisher": "Microsoft Corporation", "install_date": "20260301", "reg_key": ""}
	}
	return []row{
		r("Microsoft .NET Runtime - 6.0.25 (x64)", "48.100.4028"),
		r("Microsoft .NET Host FX Resolver - 6.0.16 (x64)", "48.67.58427"),
		r("Microsoft .NET Host - 8.0.19 (x64)", "64.76.37566"),
		r("Microsoft .NET Runtime - 8.0.14 (x64)", "64.56.29490"),
		r("Microsoft .NET Host FX Resolver - 10.0.1 (x64)", "80.4.44025"),
		r("Microsoft Windows Desktop Runtime - 8.0.0 (x64)", "64.0.5329"),
		r("Microsoft ASP.NET Core 8.0.19 Shared Framework (x64)", "8.0.19.25372"),
	}
}

// productRows is the rows of mapPackages for one product, as "display version".
func productRows(items []observe.Software, product string) []string {
	var out []string
	for _, s := range items {
		if s.Vendor == "Microsoft" && s.Product == product {
			out = append(out, s.Display+" "+s.Version)
		}
	}
	slices.Sort(out)
	return out
}

// Without the installer's registration of the shared frameworks (Wazuh, an agent on an older config), the runtimes' own Uninstall
// entries give .NET; the host and its resolver are not the runtime (their version is the runtime that installed them, which may be
// gone): they keep their own name.
func TestDotnet_UninstallEntriesGiveTheRuntimesNotTheHost(t *testing.T) {
	t.Parallel()
	items, _ := mapPackages(map[string][]row{"programs": arpDotnet()}, maxRows)
	if got, want := productRows(items, ".NET"), []string{
		"Microsoft .NET Runtime - 6.0.25 (x64) 6.0.25", "Microsoft .NET Runtime - 8.0.14 (x64) 8.0.14", "Microsoft Windows Desktop Runtime - 8.0.0 (x64) 8.0.0",
	}; !slices.Equal(got, want) {
		t.Fatalf(".NET rows %q, want %q", got, want)
	}
	for _, s := range items {
		if strings.Contains(s.Display, "Host") && (s.Vendor != "Microsoft Corporation" || s.KevKeys != nil) {
			t.Fatalf("a host row maps to a product: %+v", s)
		}
	}
}

// With the registration (HKLM\SOFTWARE[\WOW6432Node]\dotnet\Setup\InstalledVersions\<arch>\sharedfx\<framework>, one value per installed
// version, what `dotnet --list-runtimes` lists), each framework version is its own row under the framework's name. An Uninstall entry
// of the same version is the same row (shown with the framework's name); every other entry still gives its row: a runtime entry the
// registry does not list (6.0.16) and a hosting bundle (ASP.NET Core Module, with CVEs of its own) are never dropped, as a missed
// version is worse than one too many. A value that is no version and a key of another place are no rows.
func TestDotnet_SharedFrameworksGiveTheRuntimes(t *testing.T) {
	t.Parallel()
	rows := with([]row{
		fxRow("WOW6432Node\\", "x64", "Microsoft.NETCore.App", "6.0.25"),
		fxRow("WOW6432Node\\", "x64", "Microsoft.NETCore.App", "8.0.19"),
		fxRow("WOW6432Node\\", "x64", "Microsoft.NETCore.App", "10.0.1"),
		fxRow("WOW6432Node\\", "x64", "Microsoft.WindowsDesktop.App", "8.0.0"),
		fxRow("WOW6432Node\\", "x86", "Microsoft.NETCore.App", "8.0.14"),
		fxRow("", "x64", "Microsoft.NETCore.App", "8.0.19"), // the same version in the 64-bit view: one row
		fxRow("WOW6432Node\\", "x64", "Microsoft.AspNetCore.App", "8.0.19"),
		fxRow("WOW6432Node\\", "x64", "Microsoft.AspNetCore.App", "6.0.25"),
		fxRow("WOW6432Node\\", "x64", "Microsoft.NETCore.App", "(Default)"),
		fxRow("WOW6432Node\\", "x64", "Contoso.Plugin.App", "1.0.0"),
		{"name": "", "version": "6.0.16", "reg_key": `HKEY_LOCAL_MACHINE\SOFTWARE\Contoso\sharedfx\Microsoft.NETCore.App`},
	}, with(arpDotnet(),
		row{"name": "Microsoft .NET Runtime - 6.0.16 (x64)", "version": "48.67.58427", "publisher": "Microsoft Corporation"},
		row{"name": "Microsoft .NET 6.0.36 - Windows Server Hosting", "version": "6.0.36.24516", "publisher": "Microsoft Corporation"})...)
	items, dropped := mapPackages(map[string][]row{"programs": rows}, maxRows)
	if dropped != 0 {
		t.Fatalf("%d dropped", dropped)
	}
	if got, want := productRows(items, ".NET"), []string{
		"Microsoft .NET Runtime - 6.0.16 (x64) 6.0.16", "Microsoft.NETCore.App 10.0.1 (x64) 10.0.1", "Microsoft.NETCore.App 6.0.25 (x64) 6.0.25",
		"Microsoft.NETCore.App 8.0.14 (x86) 8.0.14", "Microsoft.NETCore.App 8.0.19 (x64) 8.0.19", "Microsoft.WindowsDesktop.App 8.0.0 (x64) 8.0.0",
	}; !slices.Equal(got, want) {
		t.Fatalf(".NET rows %q, want %q", got, want)
	}
	if got, want := productRows(items, "ASP.NET Core"), []string{
		"Microsoft .NET 6.0.36 - Windows Server Hosting 6.0.36", "Microsoft.AspNetCore.App 6.0.25 (x64) 6.0.25", "Microsoft.AspNetCore.App 8.0.19 (x64) 8.0.19",
	}; !slices.Equal(got, want) {
		t.Fatalf("ASP.NET Core rows %q, want %q", got, want)
	}
	for _, s := range items {
		if strings.HasPrefix(s.Version, "HKEY") || s.Display == "" || strings.Contains(s.Display, "Contoso") {
			t.Fatalf("a registry value became a software row: %+v", s)
		}
	}
}

// SQL Server: the instance's PatchLevel is the build that runs, also when the release's Uninstall entry states a version of its own
// (the build it was installed with).
func TestSQLServer_SetupRegistryWinsOverTheUninstallEntry(t *testing.T) {
	t.Parallel()
	rows := with([]row{setupRow("MSSQL16.MSSQLSERVER", "16.0.4135.4")}, labSQL()...)
	rows[1]["version"] = "16.0.1000.6" // the umbrella row
	got := sqlRows(t, rows)
	if len(got) != 1 || got[0].Display != "Microsoft SQL Server 2022 (64-bit)" || got[0].Version != "16.0.4135.4" {
		t.Fatalf("SQL Server rows %+v", got)
	}
}

// A vendor's word before the release in the version a program reports is catalogue data (version_prefix): AnyDesk's Uninstall
// entry says "ad 9.7.6".
func TestPrograms_VendorPrefixOfTheVersion(t *testing.T) {
	t.Parallel()
	items, _ := mapPackages(map[string][]row{"programs": {
		{"name": "AnyDesk", "version": "ad 9.7.6", "publisher": "AnyDesk Software GmbH"},
		{"name": "Notepad++ (64-bit x64)", "version": "ad 8.6"}, // another product's version keeps its text
	}}, maxRows)
	if items[0].Product != "AnyDesk" || items[0].Version != "9.7.6" {
		t.Fatalf("AnyDesk %+v", items[0])
	}
	if items[1].Version != "ad 8.6" {
		t.Fatalf("other %+v", items[1])
	}
}
