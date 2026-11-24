package main

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	agentintake "github.com/knt048/vedette/modules/agent-intake"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// A distribution kernel on a machine that installed a kernel update and has not restarted yet. Ubuntu and Debian name every
// kernel's packages after its ABI (linux-headers-7.0.0-43-generic, linux-headers-6.12.48+deb13-amd64), so the previous kernel's
// headers, modules and tools stay installed next to the new kernel's under names of their own, all built from the kernel's source
// package ("linux"), the package the distributions' security data lists kernel CVEs under.
type kernelShape struct {
	name    string
	os      string
	running string // uname -r
	feed    string // the feed of the security rows ("ubuntu-osv", "debian-tracker")
	distro  string // the feeds' distribution id and release of the security rows
	release string
	fixed   string // the release the distribution fixed every kernel CVE of the shape in: the installed, not yet running kernel
	pkgs    []agentintake.DebPackage
}

// ubuntuKernelShape is an Ubuntu 26.04 box that runs 7.0.0-43-generic with the 7.0.0-44 packages installed (restart pending), and
// keeps every 7.0.0-43 package of the running kernel next to its 7.0.0-44 twin.
func ubuntuKernelShape() kernelShape {
	p := func(name, version, source string) agentintake.DebPackage {
		return agentintake.DebPackage{Name: name, Version: version, Source: source}
	}
	var pkgs []agentintake.DebPackage
	for _, abi := range []string{"43", "44"} {
		v := "7.0.0-" + abi + "." + abi
		k := "7.0.0-" + abi
		pkgs = append(pkgs,
			p("linux-image-"+k+"-generic", v, "linux-signed"),
			p("linux-modules-"+k+"-generic", v, "linux"),
			p("linux-headers-"+k, v, "linux"),
			p("linux-headers-"+k+"-generic", v, "linux"),
			p("linux-tools-"+k, v, "linux"),
			p("linux-tools-"+k+"-generic", v, "linux"),
			// the out-of-tree modules of the same kernel come from a source package of their own
			p("linux-main-modules-zfs-"+k+"-generic", v, "linux-restricted-modules"))
	}
	pkgs = append(pkgs,
		p("linux-generic", "7.0.0.44.44", "linux-meta"),
		p("linux-image-generic", "7.0.0.44.44", "linux-meta"),
		p("linux-headers-generic", "7.0.0.44.44", "linux-meta"),
		p("linux-libc-dev", "7.0.0-44.44", "linux"),
		p("linux-tools-common", "7.0.0-44.44", "linux"),
		p("linux-firmware", "20260319.git1a2b3c4d-0ubuntu1", ""),
		p("linux-base", "4.12", ""),
		p("openssh-server", "1:10.2p1-2ubuntu3.9", "openssh"),
		p("openssh-client", "1:10.2p1-2ubuntu3.9", "openssh"))
	return kernelShape{name: "ubuntu", os: "Ubuntu 26.04.1 LTS", running: "7.0.0-43-generic", feed: "ubuntu-osv", distro: "ubuntu", release: "26.04", fixed: "7.0.0-44.44", pkgs: pkgs}
}

// debianKernelShape is a Debian 13 box that runs 6.12.48+deb13-amd64 with 6.12.57+deb13-amd64 installed (restart pending). Debian's
// signed images come from linux-signed-amd64, whose own version differs from the image's (dpkg names it in the Source column).
func debianKernelShape() kernelShape {
	p := func(name, version, source string) agentintake.DebPackage {
		return agentintake.DebPackage{Name: name, Version: version, Source: source}
	}
	var pkgs []agentintake.DebPackage
	for _, up := range []string{"6.12.48", "6.12.57"} {
		v, abi := up+"-1", up+"+deb13"
		pkgs = append(pkgs,
			p("linux-image-"+abi+"-amd64", v, "linux-signed-amd64 ("+up+"+1)"),
			p("linux-headers-"+abi+"-amd64", v, "linux"),
			p("linux-headers-"+abi+"-common", v, "linux"),
			p("linux-kbuild-"+abi, v, "linux"))
	}
	pkgs = append(pkgs,
		p("linux-image-amd64", "6.12.57-1", "linux-signed-amd64 (6.12.57+1)"),
		p("linux-headers-amd64", "6.12.57-1", "linux"),
		p("linux-libc-dev", "6.12.57-1", "linux"),
		p("linux-base", "4.12", ""),
		p("openssh-server", "1:10.0p1-7+deb13u1", "openssh"))
	return kernelShape{name: "debian", os: "Debian GNU/Linux 13 (trixie)", running: "6.12.48+deb13-amd64", feed: "debian-tracker", distro: "debian", release: "13", fixed: "6.12.57-1", pkgs: pkgs}
}

// kernelCVEs is the number of kernel CVEs of the count: the Ubuntu box of the test round had 139 open on its running kernel.
const kernelCVEs = 139

// TestCount_DistributionKernelFindings measures the class on both box shapes: the open findings the box's own package list gives
// for kernel CVEs the distribution fixed in the installed, not yet running kernel, by software line, and the fix they name. The
// right answer is one finding per CVE (on the running kernel's line) whose fix is the restart into the installed kernel.
// Before the fix: Ubuntu 834 findings on 6 lines (Kernel and the 7.0.0-43 headers, modules and tools), 695 of them "install
// linux-…-7.0.0-43 7.0.0-44.44" and 139 with no fix; Debian 139 on a Kernel line that read the not yet running 6.12.57 image, every
// one "cannot tell" with no fix.
func TestCount_DistributionKernelFindings(t *testing.T) {
	t.Parallel()
	for _, shape := range []kernelShape{ubuntuKernelShape(), debianKernelShape()} {
		t.Run(shape.name, func(t *testing.T) {
			t.Parallel()
			b := newKernelBox(t, shape, nil)
			b.install(shape.running)
			lines, fixes, total := b.open()
			t.Logf("%s: %d open findings for %d kernel CVEs; by line %v; by fix %v", shape.name, total, kernelCVEs, lines, fixes)
			if total != kernelCVEs || len(lines) != 1 || lines["Kernel"] != kernelCVEs {
				t.Errorf("%s: %d open findings on %d lines %v, want %d on the running kernel's line", shape.name, total, len(lines), lines, kernelCVEs)
			}
			if want := string(findings.FixRestart) + " " + shape.fixed; fixes[want] != total {
				t.Errorf("%s: fixes %v, want every finding to name %q", shape.name, fixes, want)
			}
		})
	}
}

// After the restart into the installed kernel every kernel finding closes by itself, as an update the device got; a CVE fixed only
// in a kernel that is not installed yet stays, once, with the release to install.
func TestDistributionKernelRestartClosesAndAnUpdateStays(t *testing.T) {
	t.Parallel()
	shape := ubuntuKernelShape()
	later := "CVE-2026-99001"
	b := newKernelBox(t, shape, map[string]string{later: "7.0.0-45.45"})
	b.install(shape.running)
	lines, fixes, total := b.open()
	if total != kernelCVEs+1 || lines["Kernel"] != total || fixes["distro_update 7.0.0-45.45"] != 1 || fixes["restart 7.0.0-44.44"] != kernelCVEs {
		t.Fatalf("before the restart: %d open, by line %v, by fix %v", total, lines, fixes)
	}
	b.install("7.0.0-44-generic")
	lines, fixes, total = b.open()
	if total != 1 || lines["Kernel"] != 1 || fixes["distro_update 7.0.0-45.45"] != 1 {
		t.Fatalf("after the restart: %d open, by line %v, by fix %v", total, lines, fixes)
	}
	recs, err := b.s.d.Findings.List(t.Context(), b.id)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.CVE != later && (r.Status != findings.StatusPatched || r.Row.Via != findings.ViaVersionMoved || r.Row.FromVersion != "7.0.0-43.43" || r.Row.ToVersion != "7.0.0-44.44") {
			t.Fatalf("%s after the restart: %+v", r.CVE, r.Row)
		}
	}
}

// kernelBox is a box of a kernel shape on the binary's wiring, with the shape's kernel CVEs (every one fixed in shape.fixed) and extra
// CVEs fixed in other releases of the kernel's source package.
type kernelBox struct {
	t     *testing.T
	s     *stack
	shape kernelShape
	id    string
}

func newKernelBox(t *testing.T, shape kernelShape, extra map[string]string) *kernelBox {
	t.Helper()
	s := newStack(t)
	ctx := t.Context()
	fixes := map[string]string{}
	for i := range kernelCVEs {
		fixes[fmt.Sprintf("CVE-2026-%d", 90001+i)] = shape.fixed
	}
	for cve, fixed := range extra {
		fixes[cve] = fixed
	}
	added := time.Now().AddDate(0, -1, 0)
	for cve, fixed := range fixes {
		s.kevAdded(cve, "Linux", "Kernel", added)
		err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES (?, ?, ?, 'linux', ?, 'fixed', ?)`,
				shape.feed, shape.distro, shape.release, cve, fixed)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	id, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "boxanna", OS: shape.os})
	if err != nil {
		t.Fatal(err)
	}
	return &kernelBox{t: t, s: s, shape: shape, id: id}
}

// install stores the shape's packages as the box's own list (mapped like vedette-host's dpkg list) with running as the running
// kernel, and runs the findings job.
func (b *kernelBox) install(running string) {
	b.t.Helper()
	pkgs := make([]agentintake.DebPackage, len(b.shape.pkgs))
	for i, p := range b.shape.pkgs {
		p.Kernel = running
		pkgs[i] = p
	}
	sw, _ := agentintake.MapDebPackages(pkgs)
	items := make([]inventory.SoftwareItem, len(sw))
	for i, x := range sw {
		items[i] = inventory.SoftwareItem{Display: x.Display, Vendor: x.Vendor, Product: x.Product, Version: x.Version, KevKeys: x.KevKeys, Confidence: 1,
			Packaged: x.Packaged, PkgVersion: x.PkgVersion, PkgSource: x.PkgSource}
	}
	ctx := b.t.Context()
	if err := b.s.d.Inventory.UpsertSoftware(ctx, b.id, items, "box"); err != nil {
		b.t.Fatal(err)
	}
	if err := findingsJobs(*b.s.d)[0].Run(ctx); err != nil {
		b.t.Fatal(err)
	}
}

// open counts the box's open findings by software line and by fix ("<kind> <version>").
func (b *kernelBox) open() (lines, fixes map[string]int, total int) {
	b.t.Helper()
	recs, err := b.s.d.Findings.List(b.t.Context(), b.id)
	if err != nil {
		b.t.Fatal(err)
	}
	names, err := softwareNames(b.s, b.id)
	if err != nil {
		b.t.Fatal(err)
	}
	lines, fixes = map[string]int{}, map[string]int{}
	for _, r := range recs {
		if !r.Row.Open() {
			continue
		}
		total++
		lines[names[r.SoftwareID]]++
		fixes[strings.TrimSpace(string(r.Row.Fix.Kind)+" "+r.Row.Fix.Version)]++
	}
	return lines, fixes, total
}

// softwareNames is the display name of each software line of the device, by id.
func softwareNames(s *stack, asset string) (map[string]string, error) {
	lines, err := s.d.Inventory.SoftwareLines(s.t.Context(), asset)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(lines))
	for _, l := range lines {
		out[l.ID] = l.Display
	}
	return out, nil
}
