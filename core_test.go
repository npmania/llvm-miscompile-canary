package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 0 {
		if _, ok := isWrapperArgv0(os.Args[0]); ok {
			os.Exit(runWrapperMain(os.Args))
		}
		if len(os.Args) > 1 && os.Args[1] == "reduce-check" {
			err := cmdReduceCheck(context.Background(), os.Args[2:], os.Stderr)
			if err != nil {
				if !errors.Is(err, errNotInteresting) {
					fmt.Fprintf(os.Stderr, "lmc: %v\n", err)
				}
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func TestPlatformAndFlags(t *testing.T) {
	cases := []struct {
		plat   string
		prof   string
		wantC  []string
		wantLD []string
		darwin bool
	}{
		{platLinuxX86, profDistroO2, []string{"-O2"}, nil, false},
		{platLinuxX86, profReleaseLTO, []string{"-O3", "-flto=thin", "-march=x86-64-v3"}, []string{"-O3", "-flto=thin", "-Wl,--thinlto-jobs=4", "-march=x86-64-v3"}, false},
		{platLinuxARM64, profReleaseLTO, []string{"-O3", "-flto=thin", "-mcpu=neoverse-v1"}, []string{"-O3", "-flto=thin", "-Wl,--thinlto-jobs=4", "-mcpu=neoverse-v1"}, false},
		{platLinuxRISCV64, profDistroO2, []string{"-O2"}, nil, false},
		{platLinuxRISCV64, profReleaseLTO, []string{"-O3", "-flto=thin", "-march=rva23u64"}, []string{"-O3", "-flto=thin", "-Wl,--thinlto-jobs=4", "-march=rva23u64"}, false},
		{platLinuxRISCV64, profDiagSan, []string{"-O1", "-g", "-fsanitize=undefined", "-fno-sanitize-recover=undefined"}, []string{"-fsanitize=undefined", "-fno-sanitize-recover=undefined"}, false},
		{platDarwinARM, profReleaseLTO, []string{"-O3", "-flto=thin", "-mcpu=apple-m1"}, []string{"-O3", "-flto=thin", "-Wl,--thinlto-jobs=4", "-mcpu=apple-m1"}, true},
		{platLinuxX86, profDiagO0, []string{"-O0"}, nil, false},
		{platLinuxX86, profDiagSan, []string{"-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=address,undefined"}, []string{"-fsanitize=address,undefined", "-fno-sanitize-recover=address,undefined"}, false},
	}
	for _, tc := range cases {
		spec, err := lookupPlatform(tc.plat)
		if err != nil {
			t.Fatalf("lookupPlatform(%q): %v", tc.plat, err)
		}
		if spec.IsDarwin != tc.darwin {
			t.Fatalf("%s IsDarwin = %v, want %v", tc.plat, spec.IsDarwin, tc.darwin)
		}
		gotC, err := profileCompilerFlags(tc.prof, spec)
		if err != nil || !slices.Equal(gotC, tc.wantC) {
			t.Fatalf("%s/%s compiler flags = %v (%v), want %v", tc.plat, tc.prof, gotC, err, tc.wantC)
		}
		if gotLD := profileLinkerFlags(tc.prof, spec); !slices.Equal(gotLD, tc.wantLD) {
			t.Fatalf("%s/%s linker flags = %v, want %v", tc.plat, tc.prof, gotLD, tc.wantLD)
		}
	}
	if _, err := lookupPlatform("freebsd-amd64"); err == nil {
		t.Fatal("expected error for unsupported platform")
	}
	if !slices.Equal(conservativeFlags(), []string{"-fno-strict-aliasing", "-fwrapv", "-ftrivial-auto-var-init=zero"}) {
		t.Fatalf("unexpected conservativeFlags: %v", conservativeFlags())
	}
	rvSpec, err := lookupPlatform(platLinuxRISCV64)
	if err != nil {
		t.Fatal(err)
	}
	if got := irCompileFlags(rvSpec, profReleaseLTO, &toolchain{}); !slices.Equal(got, []string{"--target=riscv64-linux-gnu", "-O3", "-march=rva23u64", "-Wno-error"}) {
		t.Fatalf("irCompileFlags(riscv64/lto) = %v", got)
	}
	if !hasSanitizerReport("ubsan: signed-integer-overflow") || !hasSanitizerReport("err\nubsan: type-mismatch") {
		t.Fatal("expected hasSanitizerReport to match ubsan minimal output")
	}
	if hasSanitizerReport("/tmp/work/asan-ubsan: build error") {
		t.Fatal("hasSanitizerReport false-positived on asan-ubsan workdir path")
	}
	repro := generateReproScript(&incident{ID: "rv-1", GoodSHA: "aaaa", BadSHA: "bbbb", CulpritPass: "instcombine", CulpritPassIndex: 5, Affected: []affected{{Package: "lua", Platform: platLinuxRISCV64}}})
	if !strings.Contains(repro, `"$CLANG" --target=riscv64-linux-gnu -O2 -x ir`) {
		t.Fatalf("repro script missing riscv64 target:\n%s", repro)
	}
}

func TestResolveToolchain(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	auxDir := filepath.Join(dir, "aux")
	sdkDir := filepath.Join(dir, "MacOSX.sdk")
	for _, d := range []string{binDir, auxDir, sdkDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mkBin := func(d, name string) string {
		p := filepath.Join(d, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mkBin(binDir, "clang")
	mkBin(binDir, "clang++")
	mkBin(binDir, "ld.lld")
	mkBin(binDir, "ld64.lld")
	mkBin(auxDir, "opt")
	mkBin(auxDir, "alive-tv")

	tcLinux, err := resolveToolchain(platLinuxX86, binDir, auxDir, "", "", "")
	if err != nil {
		t.Fatalf("linux toolchain: %v", err)
	}
	if filepath.Base(tcLinux.Linker) != "ld.lld" || filepath.Base(tcLinux.Opt) != "opt" || filepath.Base(tcLinux.AliveTV) != "alive-tv" {
		t.Fatalf("unexpected linux toolchain: %+v", tcLinux)
	}

	tcDarwin, err := resolveToolchain(platDarwinARM, binDir, auxDir, "", "", sdkDir)
	if err != nil {
		t.Fatalf("darwin toolchain: %v", err)
	}
	if filepath.Base(tcDarwin.Linker) != "ld64.lld" || tcDarwin.SDKRoot != sdkDir {
		t.Fatalf("unexpected darwin toolchain: %+v", tcDarwin)
	}
}

func TestWrapperProbeAndPlan(t *testing.T) {
	if isCXX, ok := isWrapperArgv0("/tmp/bin/clang++"); !ok || !isCXX {
		t.Fatalf("expected clang++ wrapper, got isCXX=%v ok=%v", isCXX, ok)
	}
	if _, ok := isWrapperArgv0("/tmp/bin/lmc"); ok {
		t.Fatal("lmc should not be treated as wrapper")
	}

	baseCfg := wrapConfig{
		RealCC: "/fake/clang", RealCXX: "/fake/clang++", Linker: "/fake/ld.lld",
		Platform: platLinuxX86, Profile: profReleaseLTO, SaveLTOTemps: true,
	}

	for _, probeArgs := range [][]string{
		{"-v"},
		{"-dumpmachine"},
		{"-print-resource-dir"},
		{"-E", "foo.c"},
		{"-c", "conftest.c", "-o", "conftest.o"},
		{"-c", "/tmp/CMakeTmp/test.c"},
	} {
		p, err := planWrap(baseCfg, false, "/work", probeArgs)
		if err != nil || p.mode != "probe" || !slices.Equal(p.fullArgs, probeArgs) {
			t.Fatalf("probe %v -> mode=%q args=%v err=%v", probeArgs, p.mode, p.fullArgs, err)
		}
	}

	pCompile, err := planWrap(baseCfg, false, "/work", []string{"-c", "a.c", "-o", "a.o"})
	if err != nil {
		t.Fatal(err)
	}
	if pCompile.mode != "compile" || !slices.Contains(pCompile.fullArgs, "-O3") ||
		!slices.Contains(pCompile.fullArgs, "-flto=thin") || !slices.Contains(pCompile.fullArgs, "-Wno-error") ||
		!slices.Contains(pCompile.extraEnv, "SOURCE_DATE_EPOCH=0") {
		t.Fatalf("unexpected compile plan: %+v", pCompile)
	}

	pLinkELF, err := planWrap(baseCfg, false, "/work", []string{"a.o", "-o", "/work/app"})
	if err != nil {
		t.Fatal(err)
	}
	if pLinkELF.mode != "link" || !slices.Contains(pLinkELF.fullArgs, "-Wl,--save-temps") ||
		!slices.Contains(pLinkELF.fullArgs, "-Wl,--thinlto-jobs=4") || !slices.Contains(pLinkELF.fullArgs, "--ld-path=/fake/ld.lld") {
		t.Fatalf("unexpected ELF link plan: %+v", pLinkELF)
	}

	darwinCfg := baseCfg
	darwinCfg.Platform = platDarwinARM
	darwinCfg.Linker = "/fake/ld64.lld"
	darwinCfg.SDKRoot = "/fake/MacOSX.sdk"
	pLinkDarwin, err := planWrap(darwinCfg, true, "/work", []string{"a.o", "-o", "/work/app"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pLinkDarwin.fullArgs, "-Wl,-save-temps") ||
		!slices.Contains(pLinkDarwin.fullArgs, "-Wl,-object_path_lto,/work/app.lto.d") ||
		!slices.Contains(pLinkDarwin.fullArgs, "-isysroot") ||
		pLinkDarwin.ltoTempsDir != "/work/app.lto.d" {
		t.Fatalf("unexpected Darwin link plan: %+v", pLinkDarwin)
	}

	rvCfg := baseCfg
	rvCfg.Platform = platLinuxRISCV64
	pRVHelp, err := planWrap(rvCfg, false, "/work", []string{"--help"})
	if err != nil || pRVHelp.mode != "probe" || !slices.Equal(pRVHelp.fullArgs, []string{"--help"}) {
		t.Fatalf("riscv64 --help probe = %+v (%v)", pRVHelp, err)
	}
	pRVProbeCompile, err := planWrap(rvCfg, false, "/work", []string{"-c", "conftest.c", "-o", "conftest.o"})
	if err != nil || pRVProbeCompile.mode != "probe" || !slices.Contains(pRVProbeCompile.fullArgs, "--target=riscv64-linux-gnu") || slices.Contains(pRVProbeCompile.fullArgs, "--ld-path=/fake/ld.lld") {
		t.Fatalf("riscv64 compile probe = %+v (%v)", pRVProbeCompile, err)
	}
	pRVProbeLink, err := planWrap(rvCfg, false, "/work", []string{"-v", "CMakeCCompilerABI.c", "-o", "cmTC"})
	if err != nil || pRVProbeLink.mode != "probe" || !slices.Contains(pRVProbeLink.fullArgs, "--target=riscv64-linux-gnu") || !slices.Contains(pRVProbeLink.fullArgs, "--ld-path=/fake/ld.lld") {
		t.Fatalf("riscv64 link probe = %+v (%v)", pRVProbeLink, err)
	}
	pRVProbeWl, err := planWrap(rvCfg, false, "/work", []string{"-Wl,--version"})
	if err != nil || pRVProbeWl.mode != "probe" || !slices.Contains(pRVProbeWl.fullArgs, "--target=riscv64-linux-gnu") || !slices.Contains(pRVProbeWl.fullArgs, "--ld-path=/fake/ld.lld") {
		t.Fatalf("riscv64 -Wl,--version probe = %+v (%v)", pRVProbeWl, err)
	}
	pRVProbeXLinker, err := planWrap(rvCfg, false, "/work", []string{"-Xlinker", "--version"})
	if err != nil || pRVProbeXLinker.mode != "probe" || !slices.Contains(pRVProbeXLinker.fullArgs, "--target=riscv64-linux-gnu") || !slices.Contains(pRVProbeXLinker.fullArgs, "--ld-path=/fake/ld.lld") {
		t.Fatalf("riscv64 -Xlinker --version probe = %+v (%v)", pRVProbeXLinker, err)
	}
	pRVProbeCompileWl, err := planWrap(rvCfg, false, "/work", []string{"-c", "-Wl,--gc-sections", "conftest.c"})
	if err != nil || pRVProbeCompileWl.mode != "probe" || !slices.Contains(pRVProbeCompileWl.fullArgs, "--target=riscv64-linux-gnu") || slices.Contains(pRVProbeCompileWl.fullArgs, "--ld-path=/fake/ld.lld") {
		t.Fatalf("riscv64 compile+Wl probe = %+v (%v)", pRVProbeCompileWl, err)
	}
	pRVExplicitTarget, err := planWrap(rvCfg, false, "/work", []string{"--target=riscv64-linux-gnu", "-c", "conftest.c"})
	if err != nil || !slices.Equal(pRVExplicitTarget.fullArgs, []string{"--target=riscv64-linux-gnu", "-c", "conftest.c"}) {
		t.Fatalf("riscv64 explicit target probe = %+v (%v)", pRVExplicitTarget, err)
	}
	pRVExplicitLD, err := planWrap(rvCfg, false, "/work", []string{"--ld-path", "/custom/ld", "conftest.c", "-o", "conftest"})
	if err != nil || slices.Contains(pRVExplicitLD.fullArgs, "--ld-path=/fake/ld.lld") || !slices.Contains(pRVExplicitLD.fullArgs, "--target=riscv64-linux-gnu") {
		t.Fatalf("riscv64 explicit --ld-path probe = %+v (%v)", pRVExplicitLD, err)
	}
	pRVCompile, err := planWrap(rvCfg, false, "/work", []string{"-c", "a.c", "-o", "a.o"})
	if err != nil || pRVCompile.mode != "compile" || !slices.Contains(pRVCompile.fullArgs, "--target=riscv64-linux-gnu") || !slices.Contains(pRVCompile.fullArgs, "-march=rva23u64") {
		t.Fatalf("riscv64 compile = %+v (%v)", pRVCompile, err)
	}
	pRVLink, err := planWrap(rvCfg, false, "/work", []string{"a.o", "-o", "/work/app"})
	if err != nil || pRVLink.mode != "link" || !slices.Contains(pRVLink.fullArgs, "--target=riscv64-linux-gnu") || !slices.Contains(pRVLink.fullArgs, "--ld-path=/fake/ld.lld") {
		t.Fatalf("riscv64 link = %+v (%v)", pRVLink, err)
	}

	rvSpec, err := lookupPlatform(platLinuxRISCV64)
	if err != nil {
		t.Fatal(err)
	}
	if crossTimeout(rvSpec, 10*time.Minute) != 30*time.Minute {
		t.Fatalf("crossTimeout(riscv64) = %v, want 30m", crossTimeout(rvSpec, 10*time.Minute))
	}
	if hostSpec, err := resolvePlatform(""); err == nil && crossTimeout(hostSpec, 10*time.Minute) != 10*time.Minute {
		t.Fatalf("crossTimeout(host) = %v, want 10m", crossTimeout(hostSpec, 10*time.Minute))
	}
	rvWork := t.TempDir()
	ws, err := (&runner{LMCBin: "/bin/sh"}).wireWorkspace(rvWork, filepath.Join(rvWork, "src"), runConfig{
		Spec: rvSpec, Profile: profDistroO2, TC: &toolchain{Spec: rvSpec, Clang: "/fake/clang", ClangXX: "/fake/clang++", Linker: "/fake/ld.lld"},
	})
	if err != nil {
		t.Fatalf("wireWorkspace(riscv64): %v", err)
	}
	tcFile := filepath.Join(rvWork, "cross.cmake")
	tcRaw, err := os.ReadFile(tcFile)
	if err != nil || !strings.Contains(string(tcRaw), "CMAKE_SYSTEM_PROCESSOR riscv64") ||
		!strings.Contains(string(tcRaw), "CMAKE_C_COMPILER_TARGET riscv64-linux-gnu") ||
		!strings.Contains(string(tcRaw), "BROTLI_WRAPPER_LD_PREFIX") {
		t.Fatalf("cross.cmake = %q (%v)", string(tcRaw), err)
	}
	if !slices.Contains(ws.Env, "CMAKE_TOOLCHAIN_FILE="+tcFile) || !slices.Contains(ws.Env, "QEMU_CPU=rva23u64") {
		t.Fatalf("missing cross env in ws.Env")
	}
}

func TestWrapperCaptureAndStripFlags(t *testing.T) {
	dir := t.TempDir()
	fakeCC := filepath.Join(dir, "fake-clang")
	script := `#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; continue; fi
  shift
done
[ -n "$out" ] && printf 'ok\n' > "$out"
exit 0
`
	if err := os.WriteFile(fakeCC, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	manDir := filepath.Join(dir, "manifest")
	capDir := filepath.Join(dir, "cap")
	cfg := wrapConfig{
		RealCC: fakeCC, RealCXX: fakeCC, Platform: platLinuxX86, Profile: profDistroO2,
		ManifestDir: manDir, CaptureTU: "foo.c", CaptureOutDir: capDir,
	}
	var stdout, stderr bytes.Buffer
	code, err := runWrapper(context.Background(), "clang", []string{"-c", "foo.c", "-o", filepath.Join(dir, "foo.o")}, dir, os.Environ(), cfg, nil, &stdout, &stderr)
	if err != nil || code != 0 {
		t.Fatalf("runWrapper code=%d err=%v stderr=%s", code, err, stderr.String())
	}
	recs, err := readCompileRecs(manDir)
	if err != nil || len(recs) != 1 {
		t.Fatalf("compile recs = %v, err=%v", recs, err)
	}
	if !fileExists(recs[0].PreprocessedPath) || !fileExists(recs[0].BitcodePath) {
		t.Fatalf("missing capture artifacts: %+v", recs[0])
	}

	got := stripFlags([]string{"-I", "/inc", "-D", "X=1", "-isysroot", "/sdk", "-flto=thin", "--ld-path=/ld", "--ld-path", "/ld2", "-fuse-ld=lld", "-mllvm", "-opt-bisect-limit=9", "-frandom-seed=123", "-c", "foo.c", "-o", "foo.o"},
		stripMode|stripOutput|stripInclude|stripHost|stripLink|stripLTO|stripOptBisect|stripSources, dir)
	if !slices.Equal(got, []string{"-D", "X=1"}) {
		t.Fatalf("stripFlags = %v, want [-D X=1]", got)
	}
}

func TestStoreRoundTripAndMerge(t *testing.T) {
	dir := t.TempDir()
	st, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	rec := sweep{
		LLVMCommit:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		StartedAt:   t0,
		CompletedAt: t0,
		Results: []pkgResult{
			{Package: "zlib", Platform: platLinuxX86, Profile: profDistroO2, Status: statusPass},
		},
	}
	if _, err := saveSweep(dir, &rec); err != nil {
		t.Fatal(err)
	}
	recordSweep(st, rec, nil)
	if err := saveState(dir, st); err != nil {
		t.Fatal(err)
	}

	inc1 := &incident{
		ID: "inc-1", Status: incidentOpen, Confidence: confNeedsReview,
		GoodSHA:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BadSHA:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CulpritSHA:  "cccccccccccccccccccccccccccccccccccccccc",
		CulpritPass: "InstCombinePass",
		Affected:    []affected{{Package: "zlib", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	if _, err := mergeIncident(dir, inc1); err != nil {
		t.Fatal(err)
	}
	inc2 := &incident{
		ID: "inc-2", Status: incidentOpen, Confidence: confConfirmed,
		GoodSHA: inc1.GoodSHA, BadSHA: inc1.BadSHA, CulpritSHA: inc1.CulpritSHA,
		AliveTVStatus: aliveMiscompile, AliveTVOutput: "mismatch",
		Affected: []affected{{Package: "zlib", Platform: platDarwinARM, Profile: profReleaseLTO, TestID: "t1"}},
	}
	merged, err := mergeIncident(dir, inc2)
	if err != nil {
		t.Fatal(err)
	}
	if merged.ID != "inc-1" || merged.Confidence != confConfirmed || len(merged.Affected) != 2 || merged.AliveTVStatus != aliveMiscompile {
		t.Fatalf("unexpected merged incident: %+v", merged)
	}
	reloaded, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.goodSHAFor("zlib", platLinuxX86, profDistroO2) != rec.LLVMCommit {
		t.Fatalf("unexpected LastGoodByTarget: %+v", reloaded.LastGoodByTarget)
	}
	if !slices.Equal(reloaded.ActiveIncidentIDs, []string{"inc-1"}) {
		t.Fatalf("unexpected ActiveIncidentIDs: %v", reloaded.ActiveIncidentIDs)
	}
}

func TestCorpusFetchUnpackAndValidate(t *testing.T) {
	dir := t.TempDir()
	tbPath, sum := makeTestTarGz(t, dir, map[string]string{
		"demo-1.0/hello.txt": "hello\n",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, tbPath)
	}))
	defer srv.Close()

	corpusDir := filepath.Join(dir, "corpus")
	pkgDir := filepath.Join(corpusDir, "demo")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	yamlText := fmt.Sprintf(`name: demo
category: "Crypto & Bignum"
repo: owner/demo
version: "1.0"
url: %s/demo.tar.gz
sha256: %s
strip_components: 1
lang: c
timeout_min: 5
smoke_test: t1
platforms:
  - linux-x86_64
  - darwin-arm64
description: demo pkg
cmake:
  flags:
    - -DBUILD_TESTING=ON
ctest: {}
`, srv.URL, sum)
	if err := os.WriteFile(filepath.Join(pkgDir, "recipe.yaml"), []byte(yamlText), 0o644); err != nil {
		t.Fatal(err)
	}

	recipes, err := validateCorpus(corpusDir, 1)
	if err != nil || len(recipes) != 1 || recipes[0].CMake == nil || recipes[0].CTest == nil {
		t.Fatalf("validateCorpus failed: %v, recipes=%v", err, recipes)
	}

	cached, err := fetchSource(context.Background(), recipes[0], filepath.Join(dir, "cache"), "", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "unpacked")
	if err := unpackSource(context.Background(), cached, dst, 1); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "hello.txt"))
	if err != nil || string(got) != "hello\n" {
		t.Fatalf("unpacked content = %q (%v)", string(got), err)
	}

	if err := checkNoAssembler("build.sh", "nasm -f elf64 a.asm\n"); err == nil {
		t.Fatal("expected checkNoAssembler to reject nasm")
	}
	if err := checkNoAssembler("build.sh", "# nasm comment\ncmake -DENABLE_ASM=OFF\n"); err != nil {
		t.Fatalf("unexpected checkNoAssembler error: %v", err)
	}
}

func TestCorpusRunnerCMakeAndCTest(t *testing.T) {
	if _, err := exec.LookPath("cmake"); err != nil {
		t.Skip("cmake not in PATH")
	}
	tc, err := resolveToolchain("", "", "", "", "", "")
	if err != nil {
		t.Skipf("no host toolchain: %v", err)
	}
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cmakeLists := `cmake_minimum_required(VERSION 3.16)
project(mini C)
enable_testing()
add_executable(mini_test main.c)
add_test(NAME pass_case COMMAND mini_test ok)
add_test(NAME fail_case COMMAND mini_test bad)
`
	mainC := `#include <string.h>
int main(int argc, char **argv) { return (argc > 1 && strcmp(argv[1], "ok") == 0) ? 0 : 1; }
`
	if err := os.WriteFile(filepath.Join(srcDir, "CMakeLists.txt"), []byte(cmakeLists), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.c"), []byte(mainC), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := &recipe{
		Name: "mini", Version: "1.0", Lang: "c", TimeoutMin: 5, SmokeTest: "pass_case",
		Platforms: []string{tc.Spec.ID}, Dir: filepath.Join(dir, "recipe"),
		CMake: &cmakeSpec{},
		CTest: &ctestSpec{},
	}
	r := &runner{Jobs: 2}
	ws, bOut, err := r.build(context.Background(), runConfig{
		Recipe: rec, Spec: tc.Spec, Profile: profDistroO2, TC: tc, WorkDir: filepath.Join(dir, "work"), SrcDir: srcDir,
	})
	if err != nil || !bOut.Passed {
		t.Fatalf("cmake build failed: err=%v out=%s", err, bOut.Output)
	}
	if one := r.testOne(context.Background(), rec, ws, "pass_case", nil, time.Minute); !one.Passed {
		t.Fatalf("ctest pass_case failed: %s", one.Output)
	}
	tOut, fails := r.testAll(context.Background(), rec, ws, nil, time.Minute)
	if tOut.Passed || !slices.Equal(fails, []string{"fail_case"}) {
		t.Fatalf("ctest testAll passed=%v fails=%v out=%s", tOut.Passed, fails, tOut.Output)
	}

	shPkg := filepath.Join(dir, "shpkg")
	if err := os.MkdirAll(shPkg, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"build.sh":    "#!/bin/sh\necho built > \"$BUILD_DIR/marker\"\n",
		"test_all.sh": "#!/bin/sh\ntest -f \"$BUILD_DIR/marker\" && echo FAIL_ID: sh_case && exit 1\n",
		"test_one.sh": "#!/bin/sh\ntest \"$1\" = sh_case\n",
	} {
		if err := os.WriteFile(filepath.Join(shPkg, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	shRec := &recipe{Name: "shpkg", Version: "1.0", Lang: "c", TimeoutMin: 5, SmokeTest: "sh_case", Platforms: []string{tc.Spec.ID}, Dir: shPkg}
	ws2, bOut2, err := r.build(context.Background(), runConfig{
		Recipe: shRec, Spec: tc.Spec, Profile: profDistroO2, TC: tc, WorkDir: filepath.Join(dir, "work-sh"), SrcDir: srcDir,
	})
	if err != nil || !bOut2.Passed {
		t.Fatalf("sh build failed: err=%v out=%s", err, bOut2.Output)
	}
	if tOut2, fails2 := r.testAll(context.Background(), shRec, ws2, nil, time.Minute); tOut2.Passed || !slices.Equal(fails2, []string{"sh_case"}) {
		t.Fatalf("sh testAll passed=%v fails=%v", tOut2.Passed, fails2)
	}
	if one2 := r.testOne(context.Background(), shRec, ws2, "sh_case", nil, time.Minute); !one2.Passed {
		t.Fatalf("sh testOne failed: %s", one2.Output)
	}
}

func TestCLISubcommands(t *testing.T) {
	dir := t.TempDir()
	corpusDir := filepath.Join(dir, "corpus")
	for _, tc := range []struct {
		name  string
		plats string
	}{
		{"beta", "[linux-x86_64, darwin-arm64]"},
		{"alpha", "[linux-x86_64, linux-riscv64]"},
	} {
		p := filepath.Join(corpusDir, tc.name)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		y := fmt.Sprintf("name: %s\ncategory: \"Crypto & Bignum\"\nrepo: a/b\nversion: \"1\"\nurl: https://example.com/a.tgz\nsha256: %s\nlang: c\ntimeout_min: 5\nsmoke_test: s\nplatforms: %s\ndescription: d\ncmake: {}\nctest: {}\n",
			tc.name, strings.Repeat("a", 64), tc.plats)
		if err := os.WriteFile(filepath.Join(p, "recipe.yaml"), []byte(y), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var out, errBuf bytes.Buffer
	if code := runCLI(context.Background(), []string{"lmc", "validate-corpus", "-corpus", corpusDir, "-require", "2"}, &out, &errBuf); code != 0 {
		t.Fatalf("validate-corpus failed (%d): %s", code, errBuf.String())
	}

	out.Reset()
	if code := runCLI(context.Background(), []string{"lmc", "corpus-matrix", "-corpus", corpusDir}, &out, &errBuf); code != 0 {
		t.Fatalf("corpus-matrix failed (%d): %s", code, errBuf.String())
	}
	var names []string
	if err := json.Unmarshal(out.Bytes(), &names); err != nil || !slices.Equal(names, []string{"alpha", "beta"}) {
		t.Fatalf("corpus-matrix = %q (%v)", out.String(), err)
	}

	out.Reset()
	if code := runCLI(context.Background(), []string{"lmc", "corpus-matrix", "-corpus", corpusDir, "-include"}, &out, &errBuf); code != 0 {
		t.Fatalf("corpus-matrix -include failed (%d): %s", code, errBuf.String())
	}
	var incMat struct {
		Include []struct {
			Package    string `json:"package"`
			Platform   string `json:"platform"`
			Runner     string `json:"runner"`
			TCPlatform string `json:"tc_platform"`
		} `json:"include"`
	}
	if err := json.Unmarshal(out.Bytes(), &incMat); err != nil || len(incMat.Include) != 4 {
		t.Fatalf("corpus-matrix -include = %q (%v)", out.String(), err)
	}
	if incMat.Include[1].Package != "alpha" || incMat.Include[1].Platform != platLinuxRISCV64 ||
		incMat.Include[1].Runner != "ubuntu-24.04" || incMat.Include[1].TCPlatform != platLinuxX86 {
		t.Fatalf("unexpected riscv64 include row: %+v", incMat.Include[1])
	}
	if incMat.Include[3].Package != "beta" || incMat.Include[3].Platform != platDarwinARM ||
		incMat.Include[3].Runner != "macos-latest" || incMat.Include[3].TCPlatform != platDarwinARM {
		t.Fatalf("unexpected darwin include row: %+v", incMat.Include[3])
	}

	fakeAlive := filepath.Join(dir, "alive-tv")
	if err := os.WriteFile(fakeAlive, []byte("#!/bin/sh\necho \"Transformation doesn't verify!\"\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	beforeLL := filepath.Join(dir, "before.ll")
	afterLL := filepath.Join(dir, "after.ll")
	_ = os.WriteFile(beforeLL, []byte("define i32 @f() { ret i32 0 }\n"), 0o644)
	_ = os.WriteFile(afterLL, []byte("define i32 @f() { ret i32 1 }\n"), 0o644)

	incPath := filepath.Join(dir, "inc.json")
	inc := incident{ID: "i1", Status: incidentOpen, Confidence: confNeedsReview}
	if err := writeJSONAtomic(incPath, &inc); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errBuf.Reset()
	if code := runCLI(context.Background(), []string{"lmc", "alive-check", "-alive-tv", fakeAlive, "-before", beforeLL, "-after", afterLL, "-inc", incPath}, &out, &errBuf); code != 0 {
		t.Fatalf("alive-check failed (%d): %s", code, errBuf.String())
	}
	var updated incident
	if err := readJSON(incPath, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.AliveTVStatus != aliveMiscompile || updated.Confidence != confConfirmed {
		t.Fatalf("unexpected alive-check incident: %+v", updated)
	}

	storeDir := filepath.Join(dir, "store")
	if code := runCLI(context.Background(), []string{"lmc", "merge-incident", "-store", storeDir, "-inc", incPath}, &out, &errBuf); code != 0 {
		t.Fatalf("merge-incident failed (%d): %s", code, errBuf.String())
	}
	fragsDir := filepath.Join(dir, "frags")
	if err := writeResultFragment(filepath.Join(fragsDir, "alpha.json"), []pkgResult{
		{Package: "alpha", Platform: platLinuxX86, Profile: profDistroO2, Status: statusPass},
	}); err != nil {
		t.Fatal(err)
	}
	siteOut := filepath.Join(dir, "site")
	regOut := filepath.Join(dir, "regs.json")
	if code := runCLI(context.Background(), []string{
		"lmc", "aggregate", "-frags", fragsDir, "-store", storeDir,
		"-sha", strings.Repeat("d", 40), "-corpus", corpusDir, "-out", siteOut, "-reg-out", regOut,
	}, &out, &errBuf); code != 0 {
		t.Fatalf("aggregate failed (%d): %s", code, errBuf.String())
	}
	if !fileExists(filepath.Join(siteOut, "index.html")) || !fileExists(regOut) {
		t.Fatal("aggregate did not write site and regressions")
	}
	if code := runCLI(context.Background(), []string{"lmc", "sync-issues", "-store", storeDir, "-dry-run", "-quiet"}, &out, &errBuf); code != 0 {
		t.Fatalf("sync-issues -dry-run failed (%d): %s", code, errBuf.String())
	}
}

func makeTestTarGz(t *testing.T, dir string, files map[string]string) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "test.tar.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(buf.Bytes())
	return p, hex.EncodeToString(h[:])
}
