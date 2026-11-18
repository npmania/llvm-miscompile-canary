package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBisectFirstFail(t *testing.T) {
	cases := []struct {
		name    string
		n       int
		badFrom int
		skip    map[int]bool
		want    int
	}{
		{name: "single", n: 1, badFrom: 0, want: 0},
		{name: "two-first", n: 2, badFrom: 0, want: 0},
		{name: "two-second", n: 2, badFrom: 1, want: 1},
		{name: "middle", n: 9, badFrom: 5, want: 5},
		{name: "last", n: 9, badFrom: 8, want: 8},
		{name: "skip-before", n: 9, badFrom: 5, skip: map[int]bool{3: true}, want: 5},
		{name: "skip-adjacent", n: 9, badFrom: 5, skip: map[int]bool{4: true}, want: 5},
		{name: "skip-mid-culprit-left", n: 9, badFrom: 3, skip: map[int]bool{4: true}, want: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bisectFirstFail(tc.n, func(i int) (bool, error) {
				if tc.skip[i] {
					return false, errBisectSkip
				}
				return i >= tc.badFrom, nil
			})
			if err != nil {
				t.Fatalf("bisectFirstFail: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseBisectOutput(t *testing.T) {
	raw := strings.Join([]string{
		"BISECT: running pass (1) annotation2metadata on [module]",
		"BISECT: running pass (5) sroa on compute_val",
		"BISECT: running pass (18) inline on (compute_val, helper_fn)",
		"BISECT: running pass (38) licm on loop %<unnamed loop> in function compute_val",
		"BISECT: running pass (117) loop-data-prefetch on function (backend_fn)",
		"BISECT: running pass (118) Loop Strength Reduction on loop",
		"BISECT: running pass (172) machine-outliner on module (/tmp/a.c)",
	}, "\n")
	entries := parseBisectOutput(raw)
	if len(entries) != 7 {
		t.Fatalf("got %d entries, want 7", len(entries))
	}
	want := []string{"", "compute_val", "compute_val", "compute_val", "backend_fn", "backend_fn", ""}
	for i, w := range want {
		if entries[i].Func != w {
			t.Errorf("entries[%d].Func = %q, want %q", i, entries[i].Func, w)
		}
	}
}

func TestUnifiedDiff(t *testing.T) {
	ctx := context.Background()
	before := "define i32 @foo(i32 %x) {\nentry:\n  %add = add nsw i32 %x, 1\n  ret i32 %add\n}\n"
	after := "define i32 @foo(i32 %x) {\nentry:\n  %add = add nsw i32 %x, 99\n  ret i32 %add\n}\n"
	if d := unifiedDiff(ctx, "a.ll", before, "b.ll", before); d != "" {
		t.Fatalf("expected empty diff, got %q", d)
	}
	d := unifiedDiff(ctx, "before.ll", before, "after.ll", after)
	delIdx := strings.Index(d, "-  %add = add nsw i32 %x, 1")
	addIdx := strings.Index(d, "+  %add = add nsw i32 %x, 99")
	if !strings.Contains(d, "--- before.ll") || delIdx < 0 || addIdx < 0 || delIdx > addIdx {
		t.Fatalf("unexpected diff:\n%s", d)
	}
}

func makeBadClang(t *testing.T, dir, name, realClang string, triggerPass int) string {
	t.Helper()
	script := fmt.Sprintf(`#!/bin/sh
set -eu
is_culprit=0
limit=-1
prev=""
for arg in "$@"; do
  case "$arg" in
    *culprit.c) is_culprit=1 ;;
    -opt-bisect-limit=*) limit="${arg#-opt-bisect-limit=}" ;;
  esac
  if [ "$prev" = "-mllvm" ]; then
    case "$arg" in -opt-bisect-limit=*) limit="${arg#-opt-bisect-limit=}" ;; esac
  fi
  prev="$arg"
done
if [ "$is_culprit" -eq 1 ] && { [ "$limit" -lt 0 ] || [ "$limit" -ge %d ]; }; then
  exec %s -DBUGGY_PASS=1 "$@"
fi
exec %s "$@"
`, triggerPass, shQuote(realClang), shQuote(realClang))
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeSixTUs(t *testing.T, srcDir string) {
	t.Helper()
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"tu0.c": "int f0(int x) { return x + 1; }\n",
		"tu1.c": "int f1(int x) { return x + 2; }\n",
		"tu2.c": "int f2(int x) { return x + 3; }\n",
		"culprit.c": `__attribute__((noinline)) int target_calc(int x) {
    int acc = 0;
    for (int i = 0; i < x; i++) acc += (i * 3) + 1;
#ifdef BUGGY_PASS
    return acc ^ 0x55;
#else
    return acc;
#endif
}
`,
		"tu4.c": "int f4(int x) { return x + 4; }\n",
		"main.c": `extern int f0(int); extern int f1(int); extern int f2(int); extern int target_calc(int); extern int f4(int);
int main(void) {
    if (f0(1) + f1(1) + f2(1) + f4(1) != 14) return 2;
    return target_calc(4) == 22 ? 0 : 1;
}
`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(srcDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func buildMultiTU(t *testing.T, spec platformSpec, prof string, tc *toolchain, srcDir, workDir string, useArchive bool) (buildDir, manifestDir, appBin string) {
	t.Helper()
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	buildDir, manifestDir, wrapDir := filepath.Join(workDir, "build"), filepath.Join(workDir, "manifest"), filepath.Join(workDir, "wrap")
	if err := mkdirAll(buildDir, manifestDir); err != nil {
		t.Fatal(err)
	}
	if err := setupWrapperDir(wrapDir, selfExe); err != nil {
		t.Fatal(err)
	}
	env := mergeEnv(os.Environ(), wrapEnv(wrapConfig{
		RealCC: tc.Clang, RealCXX: tc.ClangXX, Linker: tc.Linker,
		Platform: spec.ID, Profile: prof, SDKRoot: tc.SDKRoot, ManifestDir: manifestDir,
	}))
	cc := filepath.Join(wrapDir, "clang")

	var objs []string
	for _, s := range []string{"tu0.c", "tu1.c", "tu2.c", "culprit.c", "tu4.c", "main.c"} {
		obj := filepath.Join(buildDir, strings.TrimSuffix(s, ".c")+".o")
		cmd := exec.Command(cc, "-c", filepath.Join(srcDir, s), "-o", obj)
		cmd.Dir, cmd.Env = buildDir, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("compile %s: %v\n%s", s, err, out)
		}
		objs = append(objs, obj)
	}

	appBin = filepath.Join(buildDir, "app")
	var linkArgs []string
	if useArchive {
		arPath := filepath.Join(buildDir, "libunits.a")
		arCmd := exec.Command(tc.Ar, append([]string{"rcs", arPath}, objs[:5]...)...)
		arCmd.Dir = buildDir
		if out, err := arCmd.CombinedOutput(); err != nil {
			t.Fatalf("ar rcs: %v\n%s", err, out)
		}
		linkArgs = []string{objs[5], arPath, "-o", appBin}
	} else {
		linkArgs = append(objs, "-o", appBin)
	}
	linkCmd := exec.Command(cc, linkArgs...)
	linkCmd.Dir, linkCmd.Env = buildDir, env
	if out, err := linkCmd.CombinedOutput(); err != nil {
		t.Fatalf("link app: %v\n%s", err, out)
	}
	return buildDir, manifestDir, appBin
}

func hostToolchainOrSkip(t *testing.T) (platformSpec, *toolchain) {
	t.Helper()
	spec, err := resolvePlatform("")
	if err != nil {
		t.Skipf("unsupported host: %v", err)
	}
	tc, err := resolveToolchain(spec.ID, "", "", "", "", "")
	if err != nil {
		t.Skipf("toolchain unavailable: %v", err)
	}
	return spec, tc
}

func TestObjectAndPassBisect(t *testing.T) {
	spec, goodTC := hostToolchainOrSkip(t)
	const triggerPass = 12
	badTC := *goodTC
	badTC.Clang = makeBadClang(t, t.TempDir(), "bad-clang", goodTC.Clang, triggerPass)

	srcDir := filepath.Join(t.TempDir(), "src")
	writeSixTUs(t, srcDir)

	for _, useArchive := range []bool{false, true} {
		name := "direct"
		if useArchive {
			name = "archive"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			goodB, _, _ := buildMultiTU(t, spec, profDistroO2, goodTC, srcDir, t.TempDir(), useArchive)
			badB, badM, app := buildMultiTU(t, spec, profDistroO2, &badTC, srcDir, t.TempDir(), useArchive)
			testFn := func(ctx context.Context) (bool, string, error) {
				out, err := exec.CommandContext(ctx, app).CombinedOutput()
				return err == nil, string(out), nil
			}
			objRes, err := bisectObjects(ctx, objectBisectOpts{
				Spec: spec, Profile: profDistroO2, GoodTC: goodTC, BadTC: &badTC,
				GoodBuildDir: goodB, BadBuildDir: badB, BadManifestDir: badM,
				ScratchDir: filepath.Join(t.TempDir(), "obj"), Test: testFn,
			})
			if err != nil {
				t.Fatalf("bisectObjects: %v", err)
			}
			if !strings.HasSuffix(objRes.Culprit.SourceFile, "culprit.c") {
				t.Fatalf("SourceFile = %q, want *culprit.c", objRes.Culprit.SourceFile)
			}
			passRes, err := bisectPass(ctx, spec, &badTC, objRes.Culprit, filepath.Join(t.TempDir(), "pass"), objRes.relinkSingle)
			if err != nil {
				t.Fatalf("bisectPass: %v", err)
			}
			if passRes.CulpritPassIndex != triggerPass {
				t.Fatalf("CulpritPassIndex = %d, want %d", passRes.CulpritPassIndex, triggerPass)
			}
			if passRes.PassDiff == "" {
				t.Fatal("expected non-empty PassDiff")
			}
		})
	}
}

func TestThinLTOModuleBisect(t *testing.T) {
	spec, goodTC := hostToolchainOrSkip(t)
	badTC := *goodTC
	badTC.Clang = makeBadClang(t, t.TempDir(), "bad-clang-lto", goodTC.Clang, 10)

	srcDir := filepath.Join(t.TempDir(), "src")
	writeSixTUs(t, srcDir)

	ctx := context.Background()
	goodB, _, _ := buildMultiTU(t, spec, profReleaseLTO, goodTC, srcDir, t.TempDir(), false)
	badB, badM, app := buildMultiTU(t, spec, profReleaseLTO, &badTC, srcDir, t.TempDir(), false)
	testFn := func(ctx context.Context) (bool, string, error) {
		out, err := exec.CommandContext(ctx, app).CombinedOutput()
		return err == nil, string(out), nil
	}

	bcRes, err := bisectObjects(ctx, objectBisectOpts{
		Spec: spec, Profile: profReleaseLTO, GoodTC: goodTC, BadTC: &badTC,
		GoodBuildDir: goodB, BadBuildDir: badB, BadManifestDir: badM,
		ScratchDir: filepath.Join(t.TempDir(), "lto-bc"), Test: testFn,
	})
	if err != nil || !strings.HasSuffix(bcRes.Culprit.SourceFile, "culprit.c") {
		t.Fatalf("ThinLTO bitcode bisect: res=%+v err=%v", bcRes, err)
	}

	natRes, err := bisectObjects(ctx, objectBisectOpts{
		Spec: spec, Profile: profReleaseLTO, GoodTC: goodTC, BadTC: &badTC,
		GoodBuildDir: goodB, BadBuildDir: badB, BadManifestDir: badM,
		ScratchDir: filepath.Join(t.TempDir(), "lto-nat"), ForceNativeLTO: true, Test: testFn,
	})
	if err != nil || !natRes.UsedNativeLTO || !strings.HasSuffix(natRes.Culprit.SourceFile, "culprit.c") {
		t.Fatalf("ThinLTO native bisect: res=%+v err=%v", natRes, err)
	}

	passRes, err := bisectPass(ctx, spec, &badTC, natRes.Culprit, filepath.Join(t.TempDir(), "lto-pass"), natRes.relinkSingle)
	if err != nil || passRes.CulpritPassIndex != 10 {
		t.Fatalf("ThinLTO bisectPass: res=%+v err=%v", passRes, err)
	}
}

func TestCommitBisect(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "llvm")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@e",
			"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@e",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	runGit("init", "-b", "main")
	var shas []string
	for i := range 10 {
		state := "GOOD"
		if i == 4 {
			state = "BROKEN_BUILD"
		} else if i >= 6 {
			state = "MISCOMPILE"
		}
		_ = os.WriteFile(filepath.Join(repo, "v.txt"), []byte(fmt.Sprintf("%s\n%d\n", state, i)), 0o644)
		runGit("add", "v.txt")
		subj := fmt.Sprintf("[Transforms] Commit %d", i)
		if i == 6 {
			subj = "[GVN] Aggressive load coercion"
		}
		runGit("commit", "-m", subj)
		shas = append(shas, runGit("rev-parse", "HEAD"))
	}

	sha, subj, err := bisectCommit(context.Background(), commitBisectOpts{
		LLVMSrcDir: repo, GoodSHA: shas[0], BadSHA: shas[9], WorkDir: filepath.Join(t.TempDir(), "work"),
		buildClang: func(_ context.Context, wt, _, _ string) (string, error) {
			raw, err := os.ReadFile(filepath.Join(wt, "v.txt"))
			if err != nil || strings.HasPrefix(string(raw), "BROKEN_BUILD") {
				return "", errors.New("broken build")
			}
			return filepath.Join(wt, "v.txt"), nil
		},
		testClang: func(_ context.Context, marker, _ string) (bool, string, error) {
			raw, err := os.ReadFile(marker)
			return strings.HasPrefix(string(raw), "GOOD"), "", err
		},
	})
	if err != nil {
		t.Fatalf("bisectCommit: %v", err)
	}
	if sha != shas[6] || subj != "[GVN] Aggressive load coercion" {
		t.Fatalf("got (%s, %q), want (%s, [GVN] Aggressive load coercion)", sha, subj, shas[6])
	}
	if out := runGit("worktree", "list"); strings.Contains(out, "llvm-wt") {
		t.Fatalf("worktree leaked:\n%s", out)
	}
}

func TestAliveTV(t *testing.T) {
	ctx, dir := context.Background(), t.TempDir()
	bIR, aIR := filepath.Join(dir, "before.ll"), filepath.Join(dir, "after.ll")
	_ = os.WriteFile(bIR, []byte("define i32 @f(i32 %x) { ret i32 %x }\n"), 0o644)
	_ = os.WriteFile(aIR, []byte("define i32 @f(i32 %x) { ret i32 poison }\n"), 0o644)

	if r := runAliveTV(ctx, "", bIR, aIR, 5*time.Second); r.Status != formalUnavailable {
		t.Fatalf("got %q, want unavailable", r.Status)
	}
	writeMock := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rMisc := runAliveTV(ctx, writeMock("misc", "echo \"Transformation doesn't verify!\"\nexit 1"), bIR, aIR, 5*time.Second)
	if rMisc.Status != aliveMiscompile || !rMisc.ProvesBug {
		t.Fatalf("got %+v, want miscompile", rMisc)
	}
	rOK := runAliveTV(ctx, writeMock("ok", "echo \"Transformation seems to be correct!\""), bIR, aIR, 5*time.Second)
	if rOK.Status != aliveVerified || rOK.ProvesBug {
		t.Fatalf("got %+v, want verified", rOK)
	}
	rCrash := runAliveTV(ctx, writeMock("crash", "echo \"ERROR: Could not translate\" >&2\nexit 134"), bIR, aIR, 5*time.Second)
	if rCrash.Status != formalUnsupported || rCrash.ProvesBug {
		t.Fatalf("got %+v, want unsupported", rCrash)
	}
}

func TestLLUBI(t *testing.T) {
	ctx, dir := context.Background(), t.TempDir()
	writeMock := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}

	bMain, aMain := filepath.Join(dir, "b_main.ll"), filepath.Join(dir, "a_main.ll")
	_ = os.WriteFile(bMain, []byte("define i32 @main() {\n  ret i32 0\n}\n"), 0o644)
	_ = os.WriteFile(aMain, []byte("define i32 @main() {\n  ret i32 1\n}\n"), 0o644)
	mMain := writeMock("llubi-main", `for a in "$@"; do last="$a"; done
if grep -q "ret i32 0" "$last"; then exit 0; fi
echo "error: Execution of function 'main' resulted in poison return value." >&2
exit 1`)
	if r := runLLUBI(ctx, mMain, bMain, aMain, bMain, aMain, "main", 5*time.Second); r.Status != llubiMismatch || !r.ProvesBug {
		t.Fatalf("main mismatch: got %+v", r)
	}

	bPtr, aPtr := filepath.Join(dir, "b_ptr.ll"), filepath.Join(dir, "a_ptr.ll")
	_ = os.WriteFile(bPtr, []byte("define i32 @eval_win(ptr %a, ptr %b) {\n  ret i32 0\n}\n"), 0o644)
	_ = os.WriteFile(aPtr, []byte("define i32 @eval_win(ptr %a, ptr %b) {\n  ret i32 1\n}\n"), 0o644)
	mPtr := writeMock("llubi-ptr", `echo "warning: passing null values for all arguments" >&2
echo "Immediate UB detected: Invalid memory access via a pointer with nullary provenance." >&2
echo "error: Execution of function 'eval_win' failed." >&2
exit 1`)
	if r := runLLUBI(ctx, mPtr, "", "", bPtr, aPtr, "eval_win", 5*time.Second); r.Status != formalUnsupported || r.ProvesBug {
		t.Fatalf("nullary ptr trap: got %+v", r)
	}

	bSc, aSc := filepath.Join(dir, "b_sc.ll"), filepath.Join(dir, "a_sc.ll")
	_ = os.WriteFile(bSc, []byte("define i32 @scalar_fn(i32 %x) {\n  ret i32 0\n}\n"), 0o644)
	_ = os.WriteFile(aSc, []byte("define i32 @scalar_fn(i32 %x) {\n  ret i32 1\n}\n"), 0o644)
	mSc := writeMock("llubi-sc", `for a in "$@"; do last="$a"; done
echo "warning: passing null values for all arguments" >&2
if grep -q "ret i32 0" "$last"; then exit 0; fi
exit 1`)
	if r := runLLUBI(ctx, mSc, "", "", bSc, aSc, "scalar_fn", 5*time.Second); r.Status != llubiMismatch || !r.ProvesBug {
		t.Fatalf("scalar mismatch: got %+v", r)
	}
}

func TestReduceCheck(t *testing.T) {
	spec, tc := hostToolchainOrSkip(t)
	tmp := t.TempDir()
	goodIR := filepath.Join(tmp, "cand.ll")
	badIR := filepath.Join(tmp, "unrelated.ll")
	_ = os.WriteFile(goodIR, []byte("define i32 @main() {\n  ret i32 0\n}\n"), 0o644)
	_ = os.WriteFile(badIR, []byte("define i32 @main() {\n  ret i32 7\n}\n"), 0o644)

	mockClang := filepath.Join(tmp, "mock-clang")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
limit=-1
prev=""
ir=""
out=""
for a in "$@"; do
  if [ "$prev" = "-mllvm" ]; then
    case "$a" in -opt-bisect-limit=*) limit="${a#-opt-bisect-limit=}" ;; esac
  fi
  if [ "$prev" = "-o" ]; then out="$a"; fi
  case "$a" in *.ll) ir="$a" ;; esac
  prev="$a"
done
if [ "$limit" -ge 5 ] && grep -q "ret i32 0" "$ir"; then
  mod="${out}.mod.ll"
  sed 's/ret i32 0/ret i32 1/' "$ir" > "$mod"
  first=1
  for a in "$@"; do
    if [ "$first" -eq 1 ]; then set --; first=0; fi
    if [ "$a" = "$ir" ]; then set -- "$@" "$mod"; else set -- "$@" "$a"; fi
  done
  exec %s "$@"
fi
exec %s "$@"
`, shQuote(tc.Clang), shQuote(tc.Clang))
	if err := os.WriteFile(mockClang, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	candObj := filepath.Join(tmp, "cand.o")
	appBin := filepath.Join(tmp, "app")
	linkArgs := []string{candObj, "-fuse-ld=" + tc.Linker, "-o", appBin}
	if spec.IsDarwin && tc.SDKRoot != "" {
		linkArgs = append([]string{"-isysroot", tc.SDKRoot}, linkArgs...)
	}
	rs := reduceSpec{
		reduceRelink: reduceRelink{LinkDriver: tc.Clang, LinkDir: tmp, LinkArgs: linkArgs, CandObj: candObj},
		Clang:        mockClang,
		IRFlags:      irCompileFlags(spec, profDistroO2, tc),
		BeforeLim:    4,
		AfterLim:     5,
		TestCmd:      []string{appBin},
		TestDir:      tmp,
		TestEnv:      os.Environ(),
		TimeoutSec:   30,
	}
	specPath := filepath.Join(tmp, "spec.json")
	if err := writeJSONAtomic(specPath, rs); err != nil {
		t.Fatal(err)
	}
	if err := cmdReduceCheck(context.Background(), []string{"-spec", specPath, goodIR}, io.Discard); err != nil {
		t.Fatalf("expected interesting candidate to pass reduce-check, got %v", err)
	}
	if err := cmdReduceCheck(context.Background(), []string{"-spec", specPath, badIR}, io.Discard); !errors.Is(err, errNotInteresting) {
		t.Fatalf("expected errNotInteresting, got %v", err)
	}
}

func makeTarGz(t *testing.T, outPath string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{Name: "pkg-1.0/" + name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func makeTestRecipe(t *testing.T, root, name, tarPath, sha string) *recipe {
	t.Helper()
	pkgDir := filepath.Join(root, name)
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	yamlText := fmt.Sprintf("name: %s\ncategory: Test\nrepo: example/%s\nversion: 1.0.0\nurl: file://%s\nsha256: %s\nlang: c\ntimeout_min: 5\nsmoke_test: check_calc\nplatforms:\n  - linux-x86_64\n  - linux-aarch64\n  - darwin-arm64\ndescription: fixture\n",
		name, name, tarPath, sha)
	_ = os.WriteFile(filepath.Join(pkgDir, "recipe.yaml"), []byte(yamlText), 0o644)
	scripts := map[string]string{
		"build.sh":    "#!/bin/sh\nset -eu\nfor f in a b culprit main; do \"$CC\" -c \"$SRC_DIR/${f}.c\" -o \"$BUILD_DIR/${f}.o\"; done\n\"$CC\" \"$BUILD_DIR/a.o\" \"$BUILD_DIR/b.o\" \"$BUILD_DIR/culprit.o\" \"$BUILD_DIR/main.o\" -o \"$BUILD_DIR/runner\"\n",
		"test_all.sh": "#!/bin/sh\nset -eu\nif ! \"$BUILD_DIR/runner\"; then echo \"FAIL_ID: check_calc\"; exit 1; fi\n",
		"test_one.sh": "#!/bin/sh\nset -eu\n\"$BUILD_DIR/runner\" \"$1\"\n",
	}
	for fn, body := range scripts {
		if err := os.WriteFile(filepath.Join(pkgDir, fn), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r, err := loadRecipe(pkgDir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTriageDrops(t *testing.T) {
	spec, goodTC := hostToolchainOrSkip(t)
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("flaky", func(t *testing.T) {
		tmp := t.TempDir()
		tarPath := filepath.Join(tmp, "flaky.tar.gz")
		counter := filepath.Join(tmp, "counter")
		sha := makeTarGz(t, tarPath, map[string]string{
			"a.c": "int fa(void) { return 1; }\n", "b.c": "int fb(void) { return 2; }\n", "culprit.c": "int fc(void) { return 3; }\n",
			"main.c": fmt.Sprintf("#include <stdio.h>\nint main(void) { FILE *f = fopen(%q, \"a+\"); int c = 0; if (f) { fseek(f, 0, SEEK_END); c = (int)ftell(f); fputc('x', f); fclose(f); } return c == 0 ? 1 : 0; }\n", counter),
		})
		rec := makeTestRecipe(t, filepath.Join(tmp, "corpus"), "flakypkg", tarPath, sha)
		res, err := triage(context.Background(), triageOpts{
			Runner: &runner{CacheDir: filepath.Join(tmp, "cache"), LMCBin: selfExe, Jobs: 2},
			Recipe: rec, Spec: spec, Profile: profDistroO2, GoodTC: goodTC, BadTC: goodTC,
			GoodSHA: "111111111111", BadSHA: "222222222222", TestID: "check_calc", WorkDir: filepath.Join(tmp, "work"),
		})
		if err != nil || !res.Dropped || res.DropReason != "flaky" {
			t.Fatalf("got res=%+v err=%v, want flaky drop", res, err)
		}
	})

	ubFiles := map[string]string{
		"a.c": "int fa(int x) { return x; }\n", "b.c": "int fb(int x) { return x; }\n",
		"culprit.c": "int trigger_ub(int x) { volatile int base = 0x7fffffff; int ovf = base + x;\n#ifdef BAD_MISCOMPILE\nreturn ovf == 0 ? 0 : 99;\n#else\nreturn ovf == 0 ? 0 : 42;\n#endif\n}\n",
		"main.c":    "extern int trigger_ub(int); int main(void) { return trigger_ub(10) == 42 ? 0 : 1; }\n",
	}

	t.Run("upstream-ub-and-clang-rt-fallback", func(t *testing.T) {
		tmp := t.TempDir()
		tarPath := filepath.Join(tmp, "ub.tar.gz")
		rec := makeTestRecipe(t, filepath.Join(tmp, "corpus"), "ubpkg", tarPath, makeTarGz(t, tarPath, ubFiles))
		r := &runner{CacheDir: filepath.Join(tmp, "cache"), LMCBin: selfExe, Jobs: 2}

		writeWrap := func(name, sanBody string) *toolchain {
			p := filepath.Join(tmp, name)
			body := fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do\n  case \"$a\" in\n    -fsanitize=*) %s ;;\n    -O2) exec %s -DBAD_MISCOMPILE=1 \"$@\" ;;\n  esac\ndone\nexec %s \"$@\"\n",
				sanBody, shQuote(goodTC.Clang), shQuote(goodTC.Clang))
			_ = os.WriteFile(p, []byte(body), 0o755)
			tc := *goodTC
			tc.Clang = p
			return &tc
		}

		res, err := triage(context.Background(), triageOpts{
			Runner: r, Recipe: rec, Spec: spec, Profile: profDistroO2, GoodTC: goodTC,
			BadTC:   writeWrap("no-rt", `echo "ld.lld: error: cannot open libclang_rt.asan.a: No such file or directory" >&2; exit 1`),
			GoodSHA: "111111111111", BadSHA: "222222222222", TestID: "check_calc", WorkDir: filepath.Join(tmp, "w1"),
		})
		if err != nil || !res.Dropped || res.DropReason != "upstream_ub" {
			t.Fatalf("missing clang_rt fallback: res=%+v err=%v", res, err)
		}

		_, err = triage(context.Background(), triageOpts{
			Runner: r, Recipe: rec, Spec: spec, Profile: profDistroO2, GoodTC: goodTC,
			BadTC:   writeWrap("broken-san", `echo "error: unrelated compiler flag error" >&2; exit 1`),
			GoodSHA: "111111111111", BadSHA: "222222222222", TestID: "check_calc", WorkDir: filepath.Join(tmp, "w2"),
		})
		if err == nil || !strings.Contains(err.Error(), "without sanitizer trap") {
			t.Fatalf("expected non-sanitizer build error, got %v", err)
		}
	})
}

func TestTriagePipeline(t *testing.T) {
	spec, goodTC := hostToolchainOrSkip(t)
	if _, err := exec.LookPath("zstd"); err != nil {
		t.Skip("zstd unavailable")
	}
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	tarPath := filepath.Join(tmp, "cleanbug.tar.gz")
	sha := makeTarGz(t, tarPath, map[string]string{
		"a.c": "int helper_a(int x) { return x + 10; }\n",
		"b.c": "int helper_b(int x) { return x * 2; }\n",
		"culprit.c": `int unused_dead(int z) { return (z * 7) + 123; }
int compute_kernel(int n) {
    int sum = 0;
    for (int i = 1; i <= n; i++) sum += i;
#ifdef SIM_PASS_BUG
    return sum + 999;
#else
    return sum;
#endif
}
`,
		"main.c": `extern int helper_a(int); extern int helper_b(int); extern int compute_kernel(int);
int main(void) {
    if (helper_a(5) != 15 || helper_b(5) != 10) return 2;
    return compute_kernel(5) == 15 ? 0 : 1;
}
`,
	})
	rec := makeTestRecipe(t, filepath.Join(tmp, "corpus"), "cleanbug", tarPath, sha)

	const bugPass = 14
	badClang := filepath.Join(tmp, "bad-clang")
	qClang := shQuote(goodTC.Clang)
	badScript := fmt.Sprintf(`#!/bin/sh
set -eu
is_c=0; is_ir=0; has_o2=0; limit=-1; prev=""
for a in "$@"; do
  case "$a" in
    *culprit.c) is_c=1 ;;
    -O2) has_o2=1 ;;
    -opt-bisect-limit=*) limit="${a#-opt-bisect-limit=}" ;;
  esac
  if [ "$prev" = "-x" ] && [ "$a" = "ir" ]; then is_ir=1; fi
  if [ "$prev" = "-mllvm" ]; then
    case "$a" in -opt-bisect-limit=*) limit="${a#-opt-bisect-limit=}" ;; esac
  fi
  prev="$a"
done
if [ "$is_c" -eq 1 ] && [ "$has_o2" -eq 1 ] && { [ "$limit" -lt 0 ] || [ "$limit" -ge %d ]; }; then
  exec %s -DSIM_PASS_BUG=1 "$@"
fi
if [ "$is_ir" -eq 1 ] && [ "$has_o2" -eq 1 ] && { [ "$limit" -lt 0 ] || [ "$limit" -ge %d ]; }; then
  ir_file=""; out_obj=""; p2=""
  for a in "$@"; do
    if [ "$p2" = "-o" ]; then out_obj="$a"; fi
    case "$a" in *.ll) ir_file="$a" ;; esac
    p2="$a"
  done
  if [ -n "$ir_file" ] && grep -q "@compute_kernel" "$ir_file"; then
    corrupt="${out_obj}.corrupt.ll"
    sed 's/add nsw i32/sub i32/g; s/add i32/sub i32/g' "$ir_file" > "$corrupt"
    first=1
    for a in "$@"; do
      if [ "$first" -eq 1 ]; then set --; first=0; fi
      if [ "$a" = "$ir_file" ]; then set -- "$@" "$corrupt"; else set -- "$@" "$a"; fi
    done
    exec %s "$@"
  fi
fi
exec %s "$@"
`, bugPass, qClang, bugPass, qClang, qClang)
	if err := os.WriteFile(badClang, []byte(badScript), 0o755); err != nil {
		t.Fatal(err)
	}
	badTC := *goodTC
	badTC.Clang = badClang

	llvmRepo := filepath.Join(tmp, "llvm-repo")
	_ = os.MkdirAll(llvmRepo, 0o755)
	runGit := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", llvmRepo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=D", "GIT_AUTHOR_EMAIL=d@e", "GIT_COMMITTER_NAME=D", "GIT_COMMITTER_EMAIL=d@e")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	runGit("init", "-b", "main")
	var commits []string
	for i := range 5 {
		mode := "GOOD"
		if i >= 3 {
			mode = "BAD"
		}
		_ = os.WriteFile(filepath.Join(llvmRepo, "rev.txt"), []byte(fmt.Sprintf("%s\n%d\n", mode, i)), 0o644)
		runGit("add", "rev.txt")
		subj := fmt.Sprintf("[Pass] Normal %d", i)
		if i == 3 {
			subj = "[InstCombine] Fold loop sum (#249999) by @maintainer fixes llvm/llvm-project#240001"
		}
		runGit("commit", "-m", subj)
		commits = append(commits, runGit("rev-parse", "HEAD"))
	}

	res, err := triage(context.Background(), triageOpts{
		Runner:        &runner{CacheDir: filepath.Join(tmp, "cache"), LMCBin: selfExe, Jobs: 2},
		Recipe:        rec,
		Spec:          spec,
		Profile:       profDistroO2,
		GoodTC:        goodTC,
		BadTC:         &badTC,
		GoodSHA:       commits[0],
		BadSHA:        commits[4],
		WorkDir:       filepath.Join(tmp, "work"),
		BundleDir:     filepath.Join(tmp, "bundles"),
		BundleBaseURL: "https://github.com/npmania/llvm-miscompile-canary/releases/download/incidents",
		LLVMSrcDir:    llvmRepo,
		ReduceMaxIter: 1,
		ReduceTimeout: 20 * time.Second,
		buildClang: func(_ context.Context, wt, _, _ string) (string, error) {
			raw, _ := os.ReadFile(filepath.Join(wt, "rev.txt"))
			if strings.HasPrefix(string(raw), "BAD") {
				return badClang, nil
			}
			return goodTC.Clang, nil
		},
	})
	if err != nil || res.Dropped || res.Incident == nil {
		t.Fatalf("triage: res=%+v err=%v", res, err)
	}
	inc := res.Incident
	if inc.Confidence != confConfirmed || !inc.ASanUBSanClean || !inc.ConservativeFlagIndependent {
		t.Fatalf("unexpected confidence/ub flags: %+v", inc)
	}
	if inc.CulpritTU != "culprit.c" || inc.CulpritPassIndex != bugPass || inc.CulpritSHA != commits[3] {
		t.Fatalf("culprit mismatch: tu=%q pass=%d sha=%s", inc.CulpritTU, inc.CulpritPassIndex, inc.CulpritSHA)
	}
	if err := checkNoCrossRefs(inc.CulpritSubject); err != nil {
		t.Fatalf("CulpritSubject cross-ref: %v", err)
	}
	if err := checkNoCrossRefs(inc.Title); err != nil {
		t.Fatalf("Title cross-ref: %v", err)
	}
	if !strings.Contains(inc.ReducedIR, "@compute_kernel") {
		t.Fatalf("unexpected ReducedIR:\n%s", inc.ReducedIR)
	}

	dec, err := exec.Command("zstd", "-d", "-c", res.BundlePath).Output()
	if err != nil {
		t.Fatalf("zstd -d: %v", err)
	}
	tr := tar.NewReader(bytes.NewReader(dec))
	seen := make(map[string]int64)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		seen[filepath.Base(hdr.Name)] = hdr.Size
	}
	for _, f := range []string{"repro.sh", "standalone_tu.c", "before.ll", "after.ll", "reduced.ll", "summary.json"} {
		if seen[f] == 0 {
			t.Errorf("bundle missing or empty %q (seen=%v)", f, seen)
		}
	}
}
