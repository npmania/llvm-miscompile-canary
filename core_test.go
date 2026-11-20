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
	if !hasSanitizerReport("foo.c:42:10: runtime error: signed integer overflow") ||
		!hasSanitizerReport("<unknown>: runtime error: shift exponent 40 is too large") ||
		!hasSanitizerReport("0x100040: runtime error: load of null pointer") {
		t.Fatal("expected hasSanitizerReport to match UBSan runtime error formats")
	}
	if hasSanitizerReport("/tmp/work/asan-ubsan: build error") ||
		hasSanitizerReport("lua: runtime error: stack overflow") {
		t.Fatal("hasSanitizerReport false-positived on non-sanitizer output")
	}
	repro := generateReproScript(&incident{ID: "rv-1", GoodSHA: "aaaa", BadSHA: "bbbb", CulpritPass: "instcombine", CulpritPassIndex: 5, Affected: []affected{{Package: "lua", Platform: platLinuxRISCV64}}})
	if !strings.Contains(repro, `"$CLANG" --target=riscv64-linux-gnu -O2 -x ir`) ||
		!strings.Contains(repro, `"$CLANG" --target=riscv64-linux-gnu -O0 -x ir`) ||
		strings.Contains(repro, "-opt-bisect-limit=5") {
		t.Fatalf("unexpected distro-O2 repro script:\n%s", repro)
	}
	reproLTO := generateReproScript(&incident{ID: "rv-2", GoodSHA: "aaaa", BadSHA: "bbbb", CulpritPass: "gvn", CulpritPassIndex: 9, Affected: []affected{{Package: "zstd", Platform: platLinuxRISCV64, Profile: profReleaseLTO}}})
	if !strings.Contains(reproLTO, `"$CLANG" --target=riscv64-linux-gnu -O3 -march=rva23u64 -x ir`) ||
		!strings.Contains(reproLTO, `"$CLANG" --target=riscv64-linux-gnu -O0 -march=rva23u64 -x ir`) ||
		strings.Contains(reproLTO, "-opt-bisect-limit=") {
		t.Fatalf("unexpected release-lto repro script:\n%s", reproLTO)
	}
	id1 := buildIncidentID("zstd", platLinuxX86, profDistroO2, "t1", "11111111", "aaaaaaaa")
	id2 := buildIncidentID("zstd", platDarwinARM, profReleaseLTO, "t1", "11111111", "aaaaaaaa")
	id3 := buildIncidentID("zstd", platLinuxX86, profReleaseLTO, "t1", "11111111", "aaaaaaaa")
	if id1 == id2 || id1 == id3 || id2 == id3 {
		t.Fatalf("incident IDs collided: %q %q %q", id1, id2, id3)
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

	got := stripFlags([]string{"-I", "/inc", "-isystem-after", "/after", "-include-pch", "a.pch", "-includefoo.h", "-imacrosbar.h", "-D", "X=1", "-isysroot", "/sdk", "-flto=thin", "--ld-path=/ld", "--ld-path", "/ld2", "-fuse-ld=lld", "-Xlinker", "-z", "-order_file", "ord.txt", "-opt-record-file", "rec.yaml", "-Xassembler", "--noexecstack", "--param", "max=1", "-mllvm", "-opt-bisect-limit=9", "-frandom-seed=123", "-c", "foo.c", "-o", "foo.o"},
		stripMode|stripOutput|stripInclude|stripHost|stripLink|stripLTO|stripOptBisect|stripSources, dir)
	want := []string{"-D", "X=1", "-order_file", "ord.txt", "-opt-record-file", "rec.yaml", "-Xassembler", "--noexecstack", "--param", "max=1"}
	if !slices.Equal(got, want) {
		t.Fatalf("stripFlags = %v, want %v", got, want)
	}

	for _, f := range []string{"-objc", "-object", "-object-file-name", "-object-file-name=x.o", "-order_file", "-objc-isystem", "-objcxx-isystem", "-opt-record-file", "-opt-record-passes", "-opt-record-format", "-opt-record-file=x"} {
		if isAttachedOutputFlag(f) {
			t.Fatalf("isAttachedOutputFlag(%q) = true, want false", f)
		}
	}
	if !isAttachedOutputFlag("-ofoo.o") || !isAttachedOutputFlag("-o/tmp/a.o") {
		t.Fatal("expected attached -o flags to match")
	}

	arDir := filepath.Join(dir, "libs")
	if err := os.MkdirAll(arDir, 0o755); err != nil {
		t.Fatal(err)
	}
	libFoo := filepath.Join(arDir, "libfoo.a")
	libBar := filepath.Join(arDir, "libbar.a")
	_ = os.WriteFile(libFoo, []byte("!<arch>\n"), 0o644)
	_ = os.WriteFile(libBar, []byte("!<arch>\n"), 0o644)
	flPath := filepath.Join(dir, "objs.list")
	_ = os.WriteFile(flPath, []byte("x.o\ny.o\n"), 0o644)
	rspPath := filepath.Join(dir, "link.rsp")
	_ = os.WriteFile(rspPath, []byte("z.o -force_load "+libBar+"\n"), 0o644)

	parsed := parseClangArgs(dir, []string{"-Wl,@" + rspPath, "-Wl,-filelist," + flPath, "-L", arDir, "-lfoo", "-o", "app"})
	if !parsed.hasResponseFile || !parsed.hasFilelist || len(parsed.objectFiles) != 3 ||
		!slices.Contains(parsed.archiveFiles, libFoo) || !slices.Contains(parsed.archiveFiles, libBar) {
		t.Fatalf("unexpected parsed link args: %+v", parsed)
	}

	pWlRsp, err := planWrap(wrapConfig{RealCC: fakeCC, Platform: platLinuxX86, Profile: profDistroO2}, false, dir, []string{"-Wl,@missing.rsp", "-o", "app"})
	if err != nil || pWlRsp.mode == "probe" {
		t.Fatalf("planWrap(-Wl,@missing.rsp) = %+v (%v), want non-probe", pWlRsp, err)
	}

	multiMan := filepath.Join(dir, "multi-manifest")
	multiCfg := wrapConfig{RealCC: fakeCC, RealCXX: fakeCC, Platform: platLinuxX86, Profile: profDistroO2, ManifestDir: multiMan}
	if code, err := runWrapper(context.Background(), "clang", []string{"-c", "m1.c", "m2.c"}, dir, os.Environ(), multiCfg, nil, &stdout, &stderr); err != nil || code != 0 {
		t.Fatalf("multi-source runWrapper code=%d err=%v", code, err)
	}
	mRecs, err := readCompileRecs(multiMan)
	if err != nil || len(mRecs) != 2 {
		t.Fatalf("multi-source compile recs = %+v, err=%v", mRecs, err)
	}
	if filepath.Base(mRecs[0].Output) != "m1.o" || filepath.Base(mRecs[1].Output) != "m2.o" ||
		len(mRecs[0].Sources) != 1 || len(mRecs[1].Sources) != 1 ||
		slices.Contains(mRecs[0].FullArgs, "m2.c") || slices.Contains(mRecs[1].FullArgs, "m1.c") {
		t.Fatalf("unexpected multi-source compile recs: %+v", mRecs)
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

func TestReadCTestFailuresFallback(t *testing.T) {
	out := `Test project /tmp/x
    Start 1: ok_case
    Start 2: disabled_case
1/7 Test #1: ok_case ..........................   Passed    0.00 sec
2/7 Test #2: disabled_case ....................***Not Run (Disabled)   0.00 sec
    Start 3: skip_case
3/7 Test #3: skip_case ........................***Skipped   0.00 sec
    Start 4: fail_case
4/7 Test #4: fail_case ........................***Failed    0.00 sec
    Start 5: abort_case
5/7 Test #5: abort_case .......................Subprocess aborted***Exception:   0.00 sec
    Start 6: timeout_case
6/7 Test #6: timeout_case .....................***Timeout   1.00 sec
    Start 7: hang_case
`
	got := readCTestFailures(t.TempDir(), out)
	want := []string{"fail_case", "abort_case", "timeout_case", "hang_case"}
	if !slices.Equal(got, want) {
		t.Fatalf("readCTestFailures fallback = %v, want %v", got, want)
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

func TestCorpusMatrixSharding(t *testing.T) {
	dir := t.TempDir()
	synDir := filepath.Join(dir, "corpus")
	type spec struct {
		name    string
		timeout int
		plats   []string
		version string
		url     string
		sha     string
	}
	specs := []spec{
		{"heavy-a", 30, []string{platLinuxX86, platLinuxARM64, platLinuxRISCV64, platDarwinARM}, "1.0", "https://example.com/heavy-a.tar.gz", strings.Repeat("1", 64)},
		{"heavy-b", 25, []string{platLinuxX86, platLinuxARM64, platLinuxRISCV64, platDarwinARM}, "1.0", "https://example.com/heavy-b.tar.gz", strings.Repeat("2", 64)},
		{"med-a", 20, []string{platLinuxX86, platLinuxARM64, platDarwinARM}, "1.0", "https://example.com/med-a.tar.gz", strings.Repeat("3", 64)},
		{"med-b", 15, []string{platLinuxX86, platLinuxARM64, platDarwinARM}, "1.0", "https://example.com/med-b.tar.gz", strings.Repeat("4", 64)},
		{"med-c", 15, []string{platLinuxX86, platLinuxARM64}, "1.0", "https://example.com/med-c.tar.gz", strings.Repeat("5", 64)},
		{"small-a", 10, []string{platLinuxX86, platLinuxARM64, platLinuxRISCV64, platDarwinARM}, "1.0", "https://example.com/small-a.tar.gz", strings.Repeat("6", 64)},
		{"small-b", 10, []string{platLinuxX86, platDarwinARM}, "1.0", "https://example.com/small-b.tar.gz", strings.Repeat("7", 64)},
	}
	writeRec := func(base string, s spec) {
		t.Helper()
		p := filepath.Join(base, s.name)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		y := fmt.Sprintf("name: %s\ncategory: \"Systems\"\nrepo: a/b\nversion: %q\nurl: %s\nsha256: %s\nlang: c\ntimeout_min: %d\nsmoke_test: s\nplatforms: [%s]\ndescription: d\ncmake: {}\nctest: {}\n",
			s.name, s.version, s.url, s.sha, s.timeout, strings.Join(s.plats, ", "))
		if err := os.WriteFile(filepath.Join(p, "recipe.yaml"), []byte(y), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range specs {
		writeRec(synDir, s)
	}

	for _, badArgs := range [][]string{
		{"lmc", "corpus-matrix", "-corpus", synDir, "-shards", "-1"},
		{"lmc", "corpus-matrix", "-corpus", synDir, "-include", "-shards", "-1"},
		{"lmc", "corpus-matrix", "-corpus", synDir, "-shards", "4"},
	} {
		var out, errBuf bytes.Buffer
		if code := runCLI(context.Background(), badArgs, &out, &errBuf); code == 0 {
			t.Fatalf("%v succeeded unexpectedly: %s", badArgs, out.String())
		}
	}

	runMatrix := func(args ...string) string {
		t.Helper()
		var out, errBuf bytes.Buffer
		argv := append([]string{"lmc", "corpus-matrix"}, args...)
		if code := runCLI(context.Background(), argv, &out, &errBuf); code != 0 {
			t.Fatalf("%v failed (%d): %s", argv, code, errBuf.String())
		}
		return out.String()
	}

	unsharded := runMatrix("-corpus", synDir, "-include")
	zeroShards := runMatrix("-corpus", synDir, "-include", "-shards", "0")
	if unsharded != zeroShards {
		t.Fatalf("-shards 0 diverged from -include:\n%s\nvs\n%s", zeroShards, unsharded)
	}

	emptyDir := filepath.Join(dir, "empty")
	if err := os.MkdirAll(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(runMatrix("-corpus", emptyDir, "-include", "-shards", "4")); got != `{"include":[]}` {
		t.Fatalf("empty sharded matrix = %q, want empty include array", got)
	}

	type shardRow struct {
		Shard      string `json:"shard"`
		Label      string `json:"label"`
		Packages   string `json:"packages"`
		SrcHash    string `json:"src_hash"`
		Platform   string `json:"platform"`
		Runner     string `json:"runner"`
		TCPlatform string `json:"tc_platform"`
	}
	parseShards := func(raw string) []shardRow {
		t.Helper()
		var mat struct {
			Include []shardRow `json:"include"`
		}
		if err := json.Unmarshal([]byte(raw), &mat); err != nil {
			t.Fatalf("unmarshal matrix: %v\n%s", err, raw)
		}
		return mat.Include
	}
	checkHex16 := func(h string) {
		t.Helper()
		if len(h) != 16 || h != strings.ToLower(h) {
			t.Fatalf("invalid src_hash %q", h)
		}
		if _, err := hex.DecodeString(h); err != nil {
			t.Fatalf("non-hex src_hash %q: %v", h, err)
		}
	}

	raw4A := runMatrix("-corpus", synDir, "-include", "-shards", "4")
	raw4B := runMatrix("-corpus", synDir, "-include", "-shards", "4")
	if raw4A != raw4B {
		t.Fatal("sharded corpus-matrix output is not deterministic")
	}
	rows4 := parseShards(raw4A)
	byPlat := map[string][]shardRow{}
	for _, row := range rows4 {
		checkHex16(row.SrcHash)
		byPlat[row.Platform] = append(byPlat[row.Platform], row)
	}
	wantX86 := [][3]string{
		{"01", "heavy-a", "heavy-a"},
		{"02", "heavy-b", "heavy-b"},
		{"03", "shard-03", "med-a,small-a,small-b"},
		{"04", "shard-04", "med-b,med-c"},
	}
	if len(byPlat[platLinuxX86]) != len(wantX86) {
		t.Fatalf("x86 shards = %+v, want %d", byPlat[platLinuxX86], len(wantX86))
	}
	for i, w := range wantX86 {
		got := byPlat[platLinuxX86][i]
		if got.Shard != w[0] || got.Label != w[1] || got.Packages != w[2] {
			t.Fatalf("x86 shard[%d] = %+v, want %v", i, got, w)
		}
	}
	wantRV := [][3]string{
		{"01", "heavy-a", "heavy-a"},
		{"02", "heavy-b", "heavy-b"},
		{"03", "small-a", "small-a"},
	}
	if len(byPlat[platLinuxRISCV64]) != len(wantRV) {
		t.Fatalf("rv64 shards = %+v, want %d", byPlat[platLinuxRISCV64], len(wantRV))
	}
	for i, w := range wantRV {
		got := byPlat[platLinuxRISCV64][i]
		if got.Shard != w[0] || got.Label != w[1] || got.Packages != w[2] {
			t.Fatalf("rv64 shard[%d] = %+v, want %v", i, got, w)
		}
	}
	for i := 0; i < 4; i++ {
		if rows4[i].Shard != "01" || rows4[i].Label != "heavy-a" {
			t.Fatalf("row[%d] = %+v, want shard 01 heavy-a first", i, rows4[i])
		}
	}

	baseRec := &recipe{Name: "p", Version: "1.0", URL: "https://example.com/p-1.0.tar.gz", SHA256: strings.Repeat("a", 64)}
	otherRec := &recipe{Name: "q", Version: "2.0", URL: "https://example.com/q-2.0.tar.gz", SHA256: strings.Repeat("b", 64)}
	h0 := shardSrcHash([]*recipe{baseRec, otherRec})
	checkHex16(h0)
	if hRev := shardSrcHash([]*recipe{otherRec, baseRec}); hRev != h0 {
		t.Fatalf("shardSrcHash depended on input order: %q vs %q", h0, hRev)
	}
	for name, mut := range map[string]*recipe{
		"version": {Name: baseRec.Name, Version: "1.1", URL: baseRec.URL, SHA256: baseRec.SHA256},
		"url":     {Name: baseRec.Name, Version: baseRec.Version, URL: "https://example.com/p-1.0.tar.xz", SHA256: baseRec.SHA256},
		"sha256":  {Name: baseRec.Name, Version: baseRec.Version, URL: baseRec.URL, SHA256: strings.Repeat("c", 64)},
	} {
		if got := shardSrcHash([]*recipe{mut, otherRec}); got == h0 {
			t.Fatalf("shardSrcHash did not change when %s changed", name)
		}
	}

	rows2 := parseShards(runMatrix("-corpus", synDir, "-include", "-shards", "2"))
	seen2 := map[string]int{}
	platCounts2 := map[string]int{}
	for _, row := range rows2 {
		if row.Packages == "" {
			t.Fatalf("empty shard in fallback: %+v", row)
		}
		platCounts2[row.Platform]++
		for _, pkg := range strings.Split(row.Packages, ",") {
			seen2[row.Platform+"|"+pkg]++
		}
	}
	for _, plat := range []string{platLinuxX86, platLinuxARM64, platLinuxRISCV64, platDarwinARM} {
		if platCounts2[plat] != 2 {
			t.Fatalf("fallback shards=2 count for %s = %d, want 2", plat, platCounts2[plat])
		}
	}
	for _, s := range specs {
		for _, plat := range s.plats {
			if seen2[plat+"|"+s.name] != 1 {
				t.Fatalf("fallback shards=2 coverage for (%s, %s) = %d, want 1", plat, s.name, seen2[plat+"|"+s.name])
			}
		}
	}

	rowsClamp := parseShards(runMatrix("-corpus", synDir, "-include", "-shards", "20"))
	clampByPlat := map[string]int{}
	for _, row := range rowsClamp {
		pkgs := strings.Split(row.Packages, ",")
		if len(pkgs) != 1 || row.Packages == "" || row.Label != row.Packages {
			t.Fatalf("clamped shard not single-pkg: %+v", row)
		}
		clampByPlat[row.Platform]++
	}
	wantPlatCounts := map[string]int{}
	for _, s := range specs {
		for _, plat := range s.plats {
			wantPlatCounts[plat]++
		}
	}
	for plat, want := range wantPlatCounts {
		if clampByPlat[plat] != want {
			t.Fatalf("clamped shards for %s = %d, want %d", plat, clampByPlat[plat], want)
		}
	}

	realRecipes, err := loadCorpus("corpus")
	if err != nil {
		t.Fatalf("loadCorpus: %v", err)
	}
	realRows := parseShards(runMatrix("-corpus", "corpus", "-include", "-shards", "12"))
	if len(realRows) != 48 || len(realRows) > 256 {
		t.Fatalf("real corpus sharded matrix count = %d, want 48", len(realRows))
	}
	realCovered := map[string]int{}
	realShardKeys := map[string]bool{}
	hashByShard := map[string]string{}
	soloSeen := map[string]int{}
	soloNames := []string{"duckdb", "z3", "binaryen", "cpython", "ffmpeg"}
	for idx, row := range realRows {
		checkHex16(row.SrcHash)
		if idx < 20 && (row.Shard < "01" || row.Shard > "05") {
			t.Fatalf("realRows[%d] = %+v, want solo heavy shards 01..05 in first 20 jobs", idx, row)
		}
		sk := row.Platform + "|" + row.Shard
		if realShardKeys[sk] {
			t.Fatalf("duplicate (platform, shard) key %s", sk)
		}
		realShardKeys[sk] = true
		if prev, ok := hashByShard[row.Shard]; ok && prev != row.SrcHash {
			t.Fatalf("shard %s src_hash mismatch across platforms: %q vs %q", row.Shard, prev, row.SrcHash)
		}
		hashByShard[row.Shard] = row.SrcHash
		pkgs := strings.Split(row.Packages, ",")
		if len(pkgs) == 0 || row.Packages == "" {
			t.Fatalf("empty shard row: %+v", row)
		}
		if len(pkgs) == 1 && slices.Contains(soloNames, pkgs[0]) {
			if row.Label != pkgs[0] {
				t.Fatalf("solo shard label = %q, want %q", row.Label, pkgs[0])
			}
			soloSeen[pkgs[0]]++
		}
		for _, pkg := range pkgs {
			realCovered[row.Platform+"|"+pkg]++
		}
	}
	for _, name := range soloNames {
		if soloSeen[name] != 4 {
			t.Fatalf("solo recipe %s appeared solo on %d platforms, want 4", name, soloSeen[name])
		}
	}
	wantRealPairs := map[string]bool{}
	for _, r := range realRecipes {
		for _, plat := range r.Platforms {
			k := plat + "|" + r.Name
			wantRealPairs[k] = true
			if realCovered[k] != 1 {
				t.Fatalf("real corpus coverage for (%s, %s) = %d, want 1", plat, r.Name, realCovered[k])
			}
		}
	}
	if len(realCovered) != len(wantRealPairs) {
		t.Fatalf("real corpus covered %d pairs, want %d", len(realCovered), len(wantRealPairs))
	}
}

func TestSweepCancelAndIncrementalFlush(t *testing.T) {
	dir := t.TempDir()
	tcDir := filepath.Join(dir, "tc")
	if err := os.MkdirAll(tcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"clang", "clang++", "ld.lld"} {
		if err := os.WriteFile(filepath.Join(tcDir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tbPath, sum := makeTestTarGz(t, dir, map[string]string{
		"pkg-1.0/ok.txt": "ok\n",
	})
	startedPath := filepath.Join(dir, "p2.started")
	corpusDir := filepath.Join(dir, "corpus")
	writePkg := func(name, buildScript string) {
		t.Helper()
		p := filepath.Join(corpusDir, name)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		y := fmt.Sprintf("name: %s\ncategory: \"Systems\"\nrepo: a/b\nversion: \"1.0\"\nurl: file://%s\nsha256: %s\nstrip_components: 1\nlang: c\ntimeout_min: 5\nsmoke_test: s\nplatforms: [linux-x86_64]\ndescription: d\n",
			name, tbPath, sum)
		if err := os.WriteFile(filepath.Join(p, "recipe.yaml"), []byte(y), 0o644); err != nil {
			t.Fatal(err)
		}
		for fn, body := range map[string]string{
			"build.sh":    buildScript,
			"test_all.sh": "#!/bin/sh\nexit 0\n",
			"test_one.sh": "#!/bin/sh\nexit 0\n",
		} {
			if err := os.WriteFile(filepath.Join(p, fn), []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	writePkg("p1", "#!/bin/sh\nexit 0\n")
	writePkg("p2", fmt.Sprintf("#!/bin/sh\ntouch '%s'\nsleep 30\n", startedPath))

	fragDir := filepath.Join(dir, "frags")
	fragPath := filepath.Join(fragDir, "shard-linux-x86_64-01.json")
	workDir := filepath.Join(dir, "work")
	cacheDir := filepath.Join(dir, "cache")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		var out, errBuf bytes.Buffer
		errCh <- cmdSweep(ctx, []string{
			"-corpus", corpusDir, "-pkg", "p1,p2", "-plat", platLinuxX86,
			"-prof", profDistroO2, "-tc", tcDir, "-dir", workDir, "-cache", cacheDir, "-frag", fragPath,
		}, &out, &errBuf)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for !fileExists(startedPath) {
		select {
		case err := <-errCh:
			t.Fatalf("cmdSweep exited before p2 started: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("timed out waiting for p2 build to start")
		}
		time.Sleep(10 * time.Millisecond)
	}

	mid, err := readResultFragments(fragDir)
	if err != nil || len(mid) != 1 || mid[0].Package != "p1" || mid[0].Status != statusPass {
		cancel()
		t.Fatalf("incremental flush before cancel = %+v (err=%v), want 1 pass for p1", mid, err)
	}

	cancel()
	var sweepErr error
	select {
	case sweepErr = <-errCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for cmdSweep after cancel")
	}
	if !errors.Is(sweepErr, context.Canceled) {
		t.Fatalf("cmdSweep err = %v, want context.Canceled", sweepErr)
	}
	after, err := readResultFragments(fragDir)
	if err != nil || len(after) != 1 || after[0].Package != "p1" || after[0].Status != statusPass {
		t.Fatalf("fragment after cancel = %+v (err=%v), want only p1 pass", after, err)
	}
	if _, err := os.Stat(filepath.Join(workDir, "p2-linux-x86_64-distro-O2")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled p2 work dir was not cleaned up (stat err=%v)", err)
	}

	preCanceled, preCancel := context.WithCancel(context.Background())
	preCancel()
	fragPath2 := filepath.Join(dir, "frags2", "shard.json")
	var out2, errBuf2 bytes.Buffer
	err2 := cmdSweep(preCanceled, []string{
		"-corpus", corpusDir, "-pkg", "p1", "-plat", platLinuxX86,
		"-prof", profDistroO2, "-tc", tcDir, "-dir", workDir, "-cache", cacheDir, "-frag", fragPath2,
	}, &out2, &errBuf2)
	if !errors.Is(err2, context.Canceled) {
		t.Fatalf("pre-canceled cmdSweep err = %v, want context.Canceled", err2)
	}
	if fileExists(fragPath2) {
		t.Fatal("pre-canceled cmdSweep should not create fragment file")
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
