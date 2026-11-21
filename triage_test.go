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
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestBisectFirstFail(t *testing.T) {
	cases := []struct {
		name    string
		n       int
		badFrom int
		skip    map[int]bool
		want    int
	}{
		{name: "two-second", n: 2, badFrom: 1, want: 1},
		{name: "first-after-base", n: 9, badFrom: 1, want: 1},
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

	if _, err := bisectFirstFail(1, func(int) (bool, error) { return true, nil }); err == nil {
		t.Fatal("expected error for n < 2")
	}
	if _, err := bisectFirstFail(9, func(int) (bool, error) { return false, nil }); err == nil {
		t.Fatal("expected error when all probes pass")
	}
	if _, err := bisectFirstFail(9, func(int) (bool, error) { return true, nil }); err == nil {
		t.Fatal("expected error when all probes fail")
	}
	if _, err := bisectFirstFail(5, func(int) (bool, error) { return false, errBisectSkip }); err == nil {
		t.Fatal("expected error when all probes skip")
	}
	probes := 0
	if _, err := bisectFirstFail(64, func(int) (bool, error) {
		probes++
		return false, errBisectSkip
	}); err == nil || probes > maxBisectConsecSkips {
		t.Fatalf("expected skip-cap error in <= %d probes, got err=%v probes=%d", maxBisectConsecSkips, err, probes)
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
	t.Parallel()
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
			t.Parallel()
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
	t.Parallel()
	spec, goodTC := hostToolchainOrSkip(t)
	badTC := *goodTC
	badTC.Clang = makeBadClang(t, t.TempDir(), "bad-clang-lto", goodTC.Clang, 10)

	srcDir := filepath.Join(t.TempDir(), "src")
	writeSixTUs(t, srcDir)

	for _, useArchive := range []bool{false, true} {
		name := "direct"
		if useArchive {
			name = "archive"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			goodB, _, _ := buildMultiTU(t, spec, profReleaseLTO, goodTC, srcDir, t.TempDir(), useArchive)
			badB, badM, app := buildMultiTU(t, spec, profReleaseLTO, &badTC, srcDir, t.TempDir(), useArchive)
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
		})
	}
}

func TestMultiBinarySetLinkUsesGoodTC(t *testing.T) {
	t.Parallel()
	spec, goodTC := hostToolchainOrSkip(t)
	tmp := t.TempDir()
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	srcDir := filepath.Join(tmp, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(srcDir, "helper.c"), []byte("int main(void) { return 0; }\n"), 0o644)
	_ = os.WriteFile(filepath.Join(srcDir, "a.c"), []byte("int fa(void) { return 1; }\n"), 0o644)
	_ = os.WriteFile(filepath.Join(srcDir, "b.c"), []byte("int fb(void) { return 2; }\n"), 0o644)
	_ = os.WriteFile(filepath.Join(srcDir, "app1.c"), []byte("extern int fa(void); int main(void) { return fa() == 1 ? 0 : 1; }\n"), 0o644)
	_ = os.WriteFile(filepath.Join(srcDir, "app2.c"), []byte("extern int fb(void); int main(void) { return fb() == 2 ? 0 : 1; }\n"), 0o644)

	linkerLog := filepath.Join(tmp, "linker.log")
	goodLinker := filepath.Join(tmp, "good-ld")
	badLinker := filepath.Join(tmp, "bad-ld")
	_ = os.WriteFile(goodLinker, []byte(fmt.Sprintf("#!/bin/sh\necho good >> %s\nexec %s \"$@\"\n", shQuote(linkerLog), shQuote(goodTC.Linker))), 0o755)
	_ = os.WriteFile(badLinker, []byte(fmt.Sprintf("#!/bin/sh\necho bad >> %s\nexec %s \"$@\"\n", shQuote(linkerLog), shQuote(goodTC.Linker))), 0o755)

	gTC := *goodTC
	gTC.Linker = goodLinker
	bTC := *goodTC
	bTC.Linker = badLinker
	badClang := filepath.Join(tmp, "bad-cc")
	_ = os.WriteFile(badClang, []byte(fmt.Sprintf(`#!/bin/sh
for a in "$@"; do
  case "$a" in *b.c) exec %s -DFB_BAD=1 "$@" ;; esac
done
exec %s "$@"
`, shQuote(goodTC.Clang), shQuote(goodTC.Clang))), 0o755)
	bTC.Clang = badClang
	_ = os.WriteFile(filepath.Join(srcDir, "b.c"), []byte("#ifdef FB_BAD\nint fb(void) { return 9; }\n#else\nint fb(void) { return 2; }\n#endif\n"), 0o644)

	buildTwo := func(tc *toolchain, work string, dropHelperObj bool) (string, string, string) {
		bDir, mDir, wDir := filepath.Join(work, "build"), filepath.Join(work, "manifest"), filepath.Join(work, "wrap")
		if err := mkdirAll(bDir, mDir); err != nil {
			t.Fatal(err)
		}
		if err := setupWrapperDir(wDir, selfExe); err != nil {
			t.Fatal(err)
		}
		env := mergeEnv(os.Environ(), wrapEnv(wrapConfig{
			RealCC: tc.Clang, RealCXX: tc.ClangXX, Linker: tc.Linker,
			Platform: spec.ID, Profile: profDistroO2, SDKRoot: tc.SDKRoot, ManifestDir: mDir,
		}))
		cc := filepath.Join(wDir, "clang")
		run := func(args ...string) {
			cmd := exec.Command(cc, args...)
			cmd.Dir, cmd.Env = bDir, env
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("cc %v: %v\n%s", args, err, out)
			}
		}
		for _, f := range []string{"helper", "a", "b", "app1", "app2"} {
			run("-c", filepath.Join(srcDir, f+".c"), "-o", filepath.Join(bDir, f+".o"))
		}
		run(filepath.Join(bDir, "helper.o"), "-o", filepath.Join(bDir, "helper"))
		run(filepath.Join(bDir, "a.o"), filepath.Join(bDir, "app1.o"), "-o", filepath.Join(bDir, "app1"))
		run(filepath.Join(bDir, "b.o"), filepath.Join(bDir, "app2.o"), "-o", filepath.Join(bDir, "app2"))
		if dropHelperObj {
			_ = os.Remove(filepath.Join(bDir, "helper.o"))
		}
		return bDir, mDir, filepath.Join(bDir, "app2")
	}

	goodB, _, _ := buildTwo(&gTC, filepath.Join(tmp, "good"), false)
	badB, badM, app2 := buildTwo(&bTC, filepath.Join(tmp, "bad"), true)
	_ = os.Remove(linkerLog)

	res, err := bisectObjects(context.Background(), objectBisectOpts{
		Spec: spec, Profile: profDistroO2, GoodTC: &gTC, BadTC: &bTC,
		GoodBuildDir: goodB, BadBuildDir: badB, BadManifestDir: badM,
		ScratchDir: filepath.Join(tmp, "scratch"),
		Test: func(ctx context.Context) (bool, string, error) {
			out, err := exec.CommandContext(ctx, app2).CombinedOutput()
			return err == nil, string(out), nil
		},
	})
	if err != nil {
		t.Fatalf("bisectObjects multi-binary: %v", err)
	}
	if !strings.HasSuffix(res.Culprit.SourceFile, "b.c") {
		t.Fatalf("culprit = %q, want *b.c", res.Culprit.SourceFile)
	}
	logRaw, _ := os.ReadFile(linkerLog)
	if !strings.Contains(string(logRaw), "good") {
		t.Fatalf("expected setLink to invoke GoodTC linker, log=%q", string(logRaw))
	}

	_, err = bisectObjects(context.Background(), objectBisectOpts{
		Spec: spec, Profile: profDistroO2, GoodTC: &gTC, BadTC: &bTC,
		GoodBuildDir: goodB, BadBuildDir: badB, BadManifestDir: badM,
		ScratchDir: filepath.Join(tmp, "scratch-fail"),
		Test: func(context.Context) (bool, string, error) {
			return false, "always fails", nil
		},
	})
	if err == nil {
		t.Fatal("expected error when allGood fails on multi-binary package")
	}

	_ = os.Remove(filepath.Join(badB, "helper"))
	_, err = bisectObjects(context.Background(), objectBisectOpts{
		Spec: spec, Profile: profDistroO2, GoodTC: &gTC, BadTC: &bTC,
		GoodBuildDir: goodB, BadBuildDir: badB, BadManifestDir: badM,
		ScratchDir: filepath.Join(tmp, "scratch-missing-1"),
		Test: func(context.Context) (bool, string, error) {
			return false, "always fails", nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "1 manifest outputs missing on disk") {
		t.Fatalf("expected skippedMissing count on allGood fail, got %v", err)
	}

	_ = os.Remove(filepath.Join(badB, "app1"))
	_ = os.Remove(filepath.Join(badB, "app2"))
	_, err = bisectObjects(context.Background(), objectBisectOpts{
		Spec: spec, Profile: profDistroO2, GoodTC: &gTC, BadTC: &bTC,
		GoodBuildDir: goodB, BadBuildDir: badB, BadManifestDir: badM,
		ScratchDir: filepath.Join(tmp, "scratch-missing-all"),
		Test: func(context.Context) (bool, string, error) {
			return true, "ok", nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "3 manifest outputs missing on disk") {
		t.Fatalf("expected skippedMissing count when all manifest outputs missing, got %v", err)
	}
}

func TestCommitBisect(t *testing.T) {
	t.Parallel()
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
			subj = "[GVN] Aggressive load coercion (#249999) by @maintainer fixes llvm/llvm-project#240001"
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
	if sha != shas[6] || subj != "[GVN] Aggressive load coercion (#249999) by @maintainer fixes llvm/llvm-project#240001" {
		t.Fatalf("got (%s, %q), want shas[6]", sha, subj)
	}
	if out := runGit("worktree", "list"); strings.Contains(out, "llvm-project") {
		t.Fatalf("worktree leaked:\n%s", out)
	}

	objRes := &objectBisectResult{Culprit: &compiledObj{BadObj: "culprit.o"}}
	baseOpts := triageOpts{
		LLVMSrcDir: repo, GoodSHA: shas[0], BadSHA: shas[9],
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
	}

	gotSHA, gotSubj, gotCommitErr, gotErr := runTriageCommitBisect(context.Background(), baseOpts, t.TempDir(), objRes)
	if gotErr != nil || gotCommitErr != "" || gotSHA != shas[6] || checkNoCrossRefs(gotSubj) != nil || !strings.Contains(gotSubj, "Aggressive load coercion") {
		t.Fatalf("runTriageCommitBisect ok: sha=%s subj=%q commitErr=%q err=%v", gotSHA, gotSubj, gotCommitErr, gotErr)
	}

	errOpts := baseOpts
	errOpts.buildClang = func(context.Context, string, string, string) (string, error) {
		return "", errors.New("boom")
	}
	gotSHA, _, gotCommitErr, gotErr = runTriageCommitBisect(context.Background(), errOpts, t.TempDir(), objRes)
	if gotErr != nil || gotSHA != "" || gotCommitErr == "" {
		t.Fatalf("runTriageCommitBisect error: sha=%q commitErr=%q err=%v", gotSHA, gotCommitErr, gotErr)
	}

	toOpts := baseOpts
	toOpts.CommitTimeout = 150 * time.Millisecond
	toOpts.buildClang = func(ctx context.Context, _, _, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	gotSHA, _, gotCommitErr, gotErr = runTriageCommitBisect(context.Background(), toOpts, t.TempDir(), objRes)
	if gotErr != nil || gotSHA != "" || !strings.Contains(gotCommitErr, "deadline exceeded") {
		t.Fatalf("runTriageCommitBisect timeout: sha=%q commitErr=%q err=%v", gotSHA, gotCommitErr, gotErr)
	}

	tightCtx, cancelTight := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancelTight()
	called := false
	skipOpts := baseOpts
	skipOpts.buildClang = func(context.Context, string, string, string) (string, error) {
		called = true
		return "", nil
	}
	gotSHA, _, gotCommitErr, gotErr = runTriageCommitBisect(tightCtx, skipOpts, t.TempDir(), objRes)
	if gotErr != nil || called || gotSHA != "" || !strings.Contains(gotCommitErr, "skipped:") {
		t.Fatalf("runTriageCommitBisect tight deadline: called=%v sha=%q commitErr=%q err=%v", called, gotSHA, gotCommitErr, gotErr)
	}

	parentCtx, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	cancelOpts := baseOpts
	cancelOpts.buildClang = func(context.Context, string, string, string) (string, error) {
		cancelParent()
		return "", context.Canceled
	}
	_, _, _, gotErr = runTriageCommitBisect(parentCtx, cancelOpts, t.TempDir(), objRes)
	if !errors.Is(gotErr, context.Canceled) {
		t.Fatalf("runTriageCommitBisect parent cancel: err=%v, want context.Canceled", gotErr)
	}

	ctxCancelBuild, cancelBuild := context.WithCancel(context.Background())
	defer cancelBuild()
	buildCalls := 0
	_, _, err = bisectCommit(ctxCancelBuild, commitBisectOpts{
		LLVMSrcDir: repo, GoodSHA: shas[0], BadSHA: shas[9], WorkDir: filepath.Join(t.TempDir(), "work-cancel-build"),
		buildClang: func(_ context.Context, wt, _, _ string) (string, error) {
			buildCalls++
			if buildCalls == 2 {
				cancelBuild()
				return "", errors.New("interrupted")
			}
			return filepath.Join(wt, "v.txt"), nil
		},
		testClang: func(_ context.Context, marker, _ string) (bool, string, error) {
			raw, err := os.ReadFile(marker)
			return strings.HasPrefix(string(raw), "GOOD"), "", err
		},
	})
	if !errors.Is(err, context.Canceled) || buildCalls != 2 {
		t.Fatalf("cancel in buildClang: err=%v calls=%d, want context.Canceled with calls=2", err, buildCalls)
	}

	ctxCancelTest, cancelTest := context.WithCancel(context.Background())
	defer cancelTest()
	testCalls := 0
	_, _, err = bisectCommit(ctxCancelTest, commitBisectOpts{
		LLVMSrcDir: repo, GoodSHA: shas[0], BadSHA: shas[9], WorkDir: filepath.Join(t.TempDir(), "work-cancel-test"),
		buildClang: func(_ context.Context, wt, _, _ string) (string, error) {
			return filepath.Join(wt, "v.txt"), nil
		},
		testClang: func(_ context.Context, marker, _ string) (bool, string, error) {
			testCalls++
			if testCalls == 2 {
				cancelTest()
				return false, "", nil
			}
			raw, err := os.ReadFile(marker)
			return strings.HasPrefix(string(raw), "GOOD"), "", err
		},
	})
	if !errors.Is(err, context.Canceled) || testCalls != 2 {
		t.Fatalf("cancel in testClang: err=%v calls=%d, want context.Canceled with calls=2", err, testCalls)
	}

	ctxKill, cancelKill := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancelKill()
	start := time.Now()
	_, err = runToolInDirEnv(ctxKill, "sh", []string{"-c", "sleep 30 & wait"}, "", nil)
	if elapsed := time.Since(start); !errors.Is(err, context.DeadlineExceeded) || elapsed >= 2*time.Second {
		t.Fatalf("runToolInDirEnv pgid kill: err=%v elapsed=%v", err, elapsed)
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

	summaryCases := []struct {
		name     string
		out      string
		err      error
		timedOut bool
		want     string
		proves   bool
	}{
		{
			name: "clean-summary",
			out:  "Transformation seems to be correct!\nSummary:\n  2 correct transformations\n  0 incorrect transformations\n  0 failed-to-prove transformations\n  0 Alive2 errors\n",
			want: aliveVerified,
		},
		{
			name: "mixed-correct-and-failed",
			out:  "Transformation seems to be correct!\nSummary:\n  1 correct transformations\n  0 incorrect transformations\n  1 failed-to-prove transformations\n  0 Alive2 errors\n",
			want: formalTimeout,
		},
		{
			name: "mixed-correct-and-error",
			out:  "Transformation seems to be correct!\nSummary:\n  1 correct transformations\n  0 incorrect transformations\n  0 failed-to-prove transformations\n  1 Alive2 errors\n",
			err:  errors.New("exit 1"),
			want: formalUnsupported,
		},
		{
			name: "zero-functions-not-timeout",
			out:  "Summary:\n  0 correct transformations\n  0 incorrect transformations\n  0 failed-to-prove transformations\n  0 Alive2 errors\n",
			want: formalUnsupported,
		},
		{
			name: "error-with-zero-failed-to-prove",
			out:  "ERROR: Unsupported instruction\nSummary:\n  0 correct transformations\n  0 incorrect transformations\n  0 failed-to-prove transformations\n  1 Alive2 errors\n",
			err:  errors.New("exit 1"),
			want: formalUnsupported,
		},
		{
			name: "unknown-exit-0",
			out:  "some unexpected banner",
			want: formalUnsupported,
		},
		{
			name:     "deadline",
			out:      "",
			timedOut: true,
			want:     formalTimeout,
		},
		{
			name:   "summary-incorrect",
			out:    "Summary:\n  0 correct transformations\n  1 incorrect transformations\n  0 failed-to-prove transformations\n  0 Alive2 errors\n",
			want:   aliveMiscompile,
			proves: true,
		},
	}
	for _, tc := range summaryCases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAliveTVOutput(tc.out, tc.err, tc.timedOut)
			if got.Status != tc.want || got.ProvesBug != tc.proves {
				t.Fatalf("parseAliveTVOutput = %+v, want status=%q proves=%v", got, tc.want, tc.proves)
			}
		})
	}

	mixedIR := filepath.Join(dir, "mixed.ll")
	mixedBody := strings.Join([]string{
		"declare void @llvm.dbg.value(metadata, metadata, metadata)",
		"@g = global i32 0",
		"define i32 @single(i32 %x) { ret i32 %x }",
		"define i32 @multi(i32 %x) {",
		"",
		"  ; comment line",
		"  #dbg_value(i32 %x, !1, !DIExpression(), !2)",
		"  call void @llvm.dbg.value(metadata i32 %x, metadata !1, metadata !DIExpression())",
		"  tail call void @llvm.dbg.declare(metadata ptr null, metadata !1, metadata !DIExpression())",
		"entry:",
		"  %y = add i32 %x, 1, !dbg !3",
		"  ret i32 %y",
		"}",
		"!0 = distinct !DICompileUnit(language: DW_LANG_C99)",
		"",
	}, "\n")
	if err := os.WriteFile(mixedIR, []byte(mixedBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := countIRBodyLines(mixedIR); n != 4 {
		t.Fatalf("countIRBodyLines(mixed) = %d, want 4", n)
	}

	trickyIR := filepath.Join(dir, "tricky.ll")
	trickyBody := strings.Join([]string{
		"define { i32, i32 } @pair(i32 %x)",
		"{",
		"  %a = add i32 %x, 1",
		"  %b = add i32 %a, 2",
		"  ret { i32, i32 } zeroinitializer",
		"}",
		"define void @commented() { ; }",
		"  ret void",
		"}",
		`define i32 @"a;b"() {`,
		"  ret i32 0",
		"} ; end",
		"",
	}, "\n")
	if err := os.WriteFile(trickyIR, []byte(trickyBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := countIRBodyLines(trickyIR); n != 5 {
		t.Fatalf("countIRBodyLines(tricky) = %d, want 5", n)
	}
	if !smallerReducedPair(mixedIR, mixedIR, "", "") {
		t.Fatal("smallerReducedPair with empty orig paths = false, want true")
	}
	if !smallerReducedPair(mixedIR, mixedIR, trickyIR, trickyIR) {
		t.Fatal("smallerReducedPair(4 < 5) = false, want true")
	}
	if smallerReducedPair(trickyIR, trickyIR, mixedIR, mixedIR) {
		t.Fatal("smallerReducedPair(5 < 4) = true, want false")
	}
	if smallerReducedPair(mixedIR, mixedIR, mixedIR, mixedIR) {
		t.Fatal("smallerReducedPair(4 < 4) = true, want false")
	}

	var metaHeavy strings.Builder
	metaHeavy.WriteString("declare void @ext()\ndefine i32 @small(i32 %x) {\nentry:\n")
	for i := range 700 {
		fmt.Fprintf(&metaHeavy, "  #dbg_value(i32 %%x, !%d, !DIExpression(), !%d)\n", i, i)
	}
	metaHeavy.WriteString("  %y = add i32 %x, 1\n  ret i32 %y\n}\n")
	for i := range 700 {
		fmt.Fprintf(&metaHeavy, "!%d = !{}\n", i)
	}
	metaHeavyIR := filepath.Join(dir, "meta_heavy.ll")
	if err := os.WriteFile(metaHeavyIR, []byte(metaHeavy.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := countIRBodyLines(metaHeavyIR); n != 3 {
		t.Fatalf("countIRBodyLines(metaHeavy) = %d, want 3", n)
	}
	if r := runAliveTV(ctx, "", metaHeavyIR, aIR, 5*time.Second); r.Status != formalUnavailable {
		t.Fatalf("meta-heavy IR with empty bin = %+v, want unavailable", r)
	}

	var bigBuf strings.Builder
	bigBuf.WriteString("define i32 @big(i32 %x) {\n")
	for i := range maxAliveTVIRBodyLines {
		fmt.Fprintf(&bigBuf, "  %%v%d = add i32 %%x, %d\n", i, i)
	}
	bigBuf.WriteString("  ret i32 %x\n}\n")
	bigIR := filepath.Join(dir, "big.ll")
	if err := os.WriteFile(bigIR, []byte(bigBuf.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := countIRBodyLines(bigIR); n != maxAliveTVIRBodyLines+1 {
		t.Fatalf("countIRBodyLines(big) = %d, want %d", n, maxAliveTVIRBodyLines+1)
	}
	if r := runAliveTV(ctx, "", bigIR, aIR, 5*time.Second); r.Status != formalUnsupported || r.ProvesBug || !strings.Contains(r.Output, "cutoff") {
		t.Fatalf("oversized IR with empty bin = %+v, want unsupported cutoff", r)
	}
	if r := runAliveTV(ctx, writeMock("big-ok", "echo \"Transformation seems to be correct!\""), bigIR, aIR, 5*time.Second); r.Status != formalUnsupported || r.ProvesBug {
		t.Fatalf("oversized IR with mock bin = %+v, want unsupported cutoff", r)
	}

	hugeOutIR := strings.Repeat("  %v = add i32 %x, 1\n", 1200)
	longFail := "define i32 @f(i32 %x) {\n" + hugeOutIR + "  ret i32 %x\n}\nERROR: Value mismatch\nTransformation doesn't verify!\nSummary:\n  1 incorrect transformations\n"
	clipped := clipAliveTVOutput(longFail, 4096)
	if !strings.Contains(clipped, "; ... [omitted IR]") || !strings.Contains(clipped, "ERROR: Value mismatch") || !strings.Contains(clipped, "Transformation doesn't verify!") || len(clipped) > 4096 {
		t.Fatalf("clipAliveTVOutput unexpected len=%d:\n%s", len(clipped), clipped)
	}
	rClip := parseAliveTVOutput(longFail, errors.New("exit 1"), false)
	if rClip.Status != aliveMiscompile || !rClip.ProvesBug || !strings.Contains(rClip.Output, "ERROR: Value mismatch") || !strings.Contains(rClip.Output, "; ... [omitted IR]") {
		t.Fatalf("parseAliveTVOutput clipped = %+v", rClip)
	}
	if h := headText(strings.Repeat("a", 10)+"é", 11); !utf8.ValidString(h) || !strings.HasSuffix(h, "\n...[truncated]") {
		t.Fatalf("headText non-UTF8 or missing suffix: %q", h)
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
	if r := runLLUBI(ctx, mMain, bMain, aMain, bMain, aMain, "main", 5*time.Second); r.Status != llubiMismatch || r.ProvesBug {
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
	if r := runLLUBI(ctx, mSc, "", "", bSc, aSc, "scalar_fn", 5*time.Second); r.Status != llubiMismatch || r.ProvesBug {
		t.Fatalf("scalar mismatch: got %+v", r)
	}

	bEq, aEq := filepath.Join(dir, "b_eq.ll"), filepath.Join(dir, "a_eq.ll")
	_ = os.WriteFile(bEq, []byte("define i32 @eq_fn(ptr %p) {\n  ret i32 0\n}\n"), 0o644)
	_ = os.WriteFile(aEq, []byte("define i32 @eq_fn(ptr %p) {\n  ret i32 0\n}\n"), 0o644)
	mEqNull := writeMock("llubi-eq-null", `echo "warning: passing null values for all arguments" >&2
exit 0`)
	if r := runLLUBI(ctx, mEqNull, "", "", bEq, aEq, "eq_fn", 5*time.Second); r.Status != formalUnsupported || r.ProvesBug || strings.Contains(r.Output, "before_exit=") {
		t.Fatalf("null-arg equivalent: got %+v", r)
	}

	for _, msg := range []string{
		"Unrecognized instruction: %1 = call i32 @ext()",
		"Error: Exceeded maximum number of execution steps.",
		"Error: Maximum stack depth exceeded.",
		"Error: Insufficient stack space.",
		"Error: Insufficient heap space.",
		"Error: Unsupported constant: ptr @g.",
	} {
		if !isLLUBIUnsupported(msg) {
			t.Fatalf("isLLUBIUnsupported(%q) = false, want true", msg)
		}
	}
	if isLLUBIUnsupported("Immediate UB detected: signed integer overflow.") {
		t.Fatal("isLLUBIUnsupported false-positived on Immediate UB")
	}
}

func TestReduceCheck(t *testing.T) {
	t.Parallel()
	spec, tc := hostToolchainOrSkip(t)
	tmp := t.TempDir()
	goodIR := filepath.Join(tmp, "cand.ll")
	badIR := filepath.Join(tmp, "unrelated.ll")
	_ = os.WriteFile(goodIR, []byte("define i32 @main() {\n  ret i32 0\n}\n"), 0o644)
	_ = os.WriteFile(badIR, []byte("define i32 @main() {\n  ret i32 7\n}\n"), 0o644)

	mockClang := filepath.Join(tmp, "mock-clang")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
has_o2=0
prev=""
ir=""
out=""
for a in "$@"; do
  if [ "$a" = "-O2" ]; then has_o2=1; fi
  if [ "$prev" = "-o" ]; then out="$a"; fi
  case "$a" in *.ll) ir="$a" ;; esac
  prev="$a"
done
if [ "$has_o2" -eq 1 ] && grep -q "ret i32 0" "$ir"; then
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
	linkArgs := []string{candObj, linkerFlag(tc.Linker), "-o", appBin}
	if spec.IsDarwin && tc.SDKRoot != "" {
		linkArgs = append([]string{"-isysroot", tc.SDKRoot}, linkArgs...)
	}
	rs := reduceSpec{
		reduceRelink: reduceRelink{LinkDriver: tc.Clang, LinkDir: tmp, LinkArgs: linkArgs, CandObj: candObj},
		BeforeClang:  mockClang,
		AfterClang:   mockClang,
		BeforeFlags:  irO0CompileFlags(spec, profDistroO2, tc),
		AfterFlags:   irCompileFlags(spec, profDistroO2, tc),
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

	rsGoodBad := rs
	rsGoodBad.BeforeClang = tc.Clang
	rsGoodBad.BeforeFlags = irCompileFlags(spec, profDistroO2, tc)
	if !evalReduceCheck(context.Background(), rsGoodBad, goodIR) {
		t.Fatal("expected GoodTC vs BadTC reduce-check to succeed")
	}

	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	recDir := filepath.Join(tmp, "rec")
	if err := os.MkdirAll(recDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recDir, "test_one.sh"), []byte("#!/bin/sh\nexec "+shQuote(appBin)+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &recipe{Name: "redpkg", Dir: recDir}
	badWS := &workspace{BuildDir: tmp, Env: os.Environ(), Spec: spec}
	mockReduce := filepath.Join(tmp, "mock-reduce")
	reduceScript := `#!/bin/sh
set -eu
out=""
in=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then
    out="$a"
  else
    case "$a" in *.ll) in="$a" ;; esac
  fi
  prev="$a"
done
cp "$in" "$out"
`
	if err := os.WriteFile(mockReduce, []byte(reduceScript), 0o755); err != nil {
		t.Fatal(err)
	}
	mockOpt := filepath.Join(tmp, "mock-opt")
	optScript := `#!/bin/sh
set -eu
out=""
in=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then
    out="$a"
  else
    case "$a" in *.ll) in="$a" ;; esac
  fi
  prev="$a"
done
sed 's/ret i32 0/ret i32 1/' "$in" > "$out"
`
	if err := os.WriteFile(mockOpt, []byte(optScript), 0o755); err != nil {
		t.Fatal(err)
	}
	redTC := *tc
	redTC.Clang = mockClang
	redTC.LLVMReduce = mockReduce
	redTC.Opt = mockOpt
	redTC.LLVMExtract = ""

	fullIR := filepath.Join(tmp, "full.ll")
	fullBody := "define i32 @helper(i32 %x) {\n  %a = add i32 %x, 1\n  %b = add i32 %a, 2\n  %c = add i32 %b, 3\n  ret i32 %c\n}\ndefine i32 @main() {\n  ret i32 0\n}\n"
	if err := os.WriteFile(fullIR, []byte(fullBody), 0o644); err != nil {
		t.Fatal(err)
	}
	smallBefore := filepath.Join(tmp, "small_before.ll")
	smallAfter := filepath.Join(tmp, "small_after.ll")
	_ = os.WriteFile(smallBefore, []byte("define i32 @main() {\n  ret i32 0\n}\n"), 0o644)
	_ = os.WriteFile(smallAfter, []byte("define i32 @main() {\n  ret i32 1\n}\n"), 0o644)

	scratchBig := filepath.Join(tmp, "scratch-big")
	if err := os.MkdirAll(scratchBig, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(scratchBig, "reduced_before.ll"), []byte("stale"), 0o644)
	_ = os.WriteFile(filepath.Join(scratchBig, "reduced_after.ll"), []byte("stale"), 0o644)
	makeRelink := func(c string) (reduceRelink, error) {
		args := slices.Clone(linkArgs)
		for i, a := range args {
			if a == candObj {
				args[i] = c
			}
		}
		return reduceRelink{LinkDriver: tc.Clang, LinkDir: tmp, LinkArgs: args, CandObj: c}, nil
	}
	objRes := &objectBisectResult{buildRelink: makeRelink}
	resBig, err := runLLVMReduce(context.Background(), triageOpts{
		Runner: &runner{LMCBin: selfExe}, Recipe: rec, Spec: spec, Profile: profDistroO2, GoodTC: tc, BadTC: &redTC,
	}, badWS, "t1", objRes, &passBisectResult{
		CulpritPass: "instcombine", BeforeFullIRPath: fullIR, BeforeIRPath: smallBefore, AfterIRPath: smallAfter,
	}, scratchBig)
	if err != nil {
		t.Fatalf("runLLVMReduce(larger): %v", err)
	}
	if resBig.ReducedBeforePath != "" || resBig.ReducedAfterPath != "" {
		t.Fatalf("larger reduced pair shadowed smaller before.ll: %+v", resBig)
	}
	if fileExists(filepath.Join(scratchBig, "reduced_before.ll")) || fileExists(filepath.Join(scratchBig, "reduced_after.ll")) {
		t.Fatal("stale or larger reduced_before.ll/reduced_after.ll left on disk")
	}

	largeBefore := filepath.Join(tmp, "large_before.ll")
	largeAfter := filepath.Join(tmp, "large_after.ll")
	_ = os.WriteFile(largeBefore, []byte(fullBody), 0o644)
	_ = os.WriteFile(largeAfter, []byte(strings.ReplaceAll(fullBody, "ret i32 0", "ret i32 1")), 0o644)
	scratchSmall := filepath.Join(tmp, "scratch-small")
	resSmall, err := runLLVMReduce(context.Background(), triageOpts{
		Runner: &runner{LMCBin: selfExe}, Recipe: rec, Spec: spec, Profile: profDistroO2, GoodTC: tc, BadTC: &redTC,
	}, badWS, "t1", objRes, &passBisectResult{
		CulpritPass: "instcombine", BeforeFullIRPath: goodIR, BeforeIRPath: largeBefore, AfterIRPath: largeAfter,
	}, scratchSmall)
	if err != nil {
		t.Fatalf("runLLVMReduce(smaller): %v", err)
	}
	if !fileNonEmpty(resSmall.ReducedBeforePath) || !fileNonEmpty(resSmall.ReducedAfterPath) {
		t.Fatalf("expected verified smaller reduced pair, got %+v", resSmall)
	}
	var smallSpec reduceSpec
	if err := readJSON(filepath.Join(scratchSmall, "reduce_spec.json"), &smallSpec); err != nil {
		t.Fatalf("read scratchSmall reduce_spec.json: %v", err)
	}
	if smallSpec.BeforeClang != tc.Clang || !slices.Contains(smallSpec.BeforeFlags, "-O2") || slices.Contains(smallSpec.BeforeFlags, "-O0") {
		t.Fatalf("expected GoodTC -O2 oracle, got BeforeClang=%q BeforeFlags=%v", smallSpec.BeforeClang, smallSpec.BeforeFlags)
	}

	failClang := filepath.Join(tmp, "fail-clang")
	if err := os.WriteFile(failClang, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	brokenGoodTC := *tc
	brokenGoodTC.Clang = failClang
	for _, tcCase := range []struct {
		name   string
		goodTC *toolchain
	}{
		{"good-exit-1", &brokenGoodTC},
		{"good-nil", nil},
	} {
		sc := filepath.Join(tmp, "scratch-fb-"+tcCase.name)
		if _, err := runLLVMReduce(context.Background(), triageOpts{
			Runner: &runner{LMCBin: selfExe}, Recipe: rec, Spec: spec, Profile: profDistroO2, GoodTC: tcCase.goodTC, BadTC: &redTC,
		}, badWS, "t1", objRes, &passBisectResult{
			CulpritPass: "instcombine", BeforeFullIRPath: goodIR, BeforeIRPath: largeBefore, AfterIRPath: largeAfter,
		}, sc); err != nil {
			t.Fatalf("runLLVMReduce(%s): %v", tcCase.name, err)
		}
		var fbSpec reduceSpec
		if err := readJSON(filepath.Join(sc, "reduce_spec.json"), &fbSpec); err != nil {
			t.Fatalf("read %s reduce_spec.json: %v", tcCase.name, err)
		}
		if fbSpec.BeforeClang != redTC.Clang || !slices.Contains(fbSpec.BeforeFlags, "-O0") {
			t.Fatalf("%s fallback got BeforeClang=%q BeforeFlags=%v", tcCase.name, fbSpec.BeforeClang, fbSpec.BeforeFlags)
		}
	}

	if len(spec.BaselineFlags) == 0 {
		t.Fatal("expected non-empty BaselineFlags on host platform")
	}
	attrIR := filepath.Join(tmp, "attr.ll")
	if err := os.WriteFile(attrIR, []byte("define i32 @main() #0 {\n  ret i32 0\n}\nattributes #0 = { \"target-features\"=\"\" }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mockClangO3 := filepath.Join(tmp, "mock-clang-o3")
	o3Script := fmt.Sprintf(`#!/bin/sh
set -eu
has_o3=0
prev=""
ir=""
out=""
for a in "$@"; do
  if [ "$a" = "-O3" ]; then has_o3=1; fi
  if [ "$prev" = "-o" ]; then out="$a"; fi
  case "$a" in *.ll) ir="$a" ;; esac
  prev="$a"
done
if [ "$has_o3" -eq 1 ] && grep -q "ret i32 0" "$ir"; then
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
	if err := os.WriteFile(mockClangO3, []byte(o3Script), 0o755); err != nil {
		t.Fatal(err)
	}
	mockClangNeedBase := filepath.Join(tmp, "mock-clang-need-base")
	needBaseScript := fmt.Sprintf(`#!/bin/sh
set -eu
has_o3=0
has_base=0
prev=""
ir=""
out=""
for a in "$@"; do
  if [ "$a" = "-O3" ]; then has_o3=1; fi
  if [ "$a" = %s ]; then has_base=1; fi
  if [ "$prev" = "-o" ]; then out="$a"; fi
  case "$a" in *.ll) ir="$a" ;; esac
  prev="$a"
done
if [ "$has_o3" -eq 1 ] && [ "$has_base" -eq 1 ] && grep -q "ret i32 0" "$ir"; then
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
`, shQuote(spec.BaselineFlags[0]), shQuote(tc.Clang), shQuote(tc.Clang))
	if err := os.WriteFile(mockClangNeedBase, []byte(needBaseScript), 0o755); err != nil {
		t.Fatal(err)
	}

	ltoRedTC := redTC
	ltoRedTC.Clang = mockClangO3
	scratchAttr := filepath.Join(tmp, "scratch-lto-attr")
	if _, err := runLLVMReduce(context.Background(), triageOpts{
		Runner: &runner{LMCBin: selfExe}, Recipe: rec, Spec: spec, Profile: profReleaseLTO, GoodTC: tc, BadTC: &ltoRedTC,
	}, badWS, "t1", objRes, &passBisectResult{
		CulpritPass: "instcombine", BeforeFullIRPath: attrIR, BeforeIRPath: largeBefore, AfterIRPath: largeAfter,
	}, scratchAttr); err != nil {
		t.Fatalf("runLLVMReduce(lto-attr): %v", err)
	}
	var attrSpec reduceSpec
	if err := readJSON(filepath.Join(scratchAttr, "reduce_spec.json"), &attrSpec); err != nil {
		t.Fatalf("read scratchAttr reduce_spec.json: %v", err)
	}
	for _, bf := range spec.BaselineFlags {
		if slices.Contains(attrSpec.BeforeFlags, bf) || slices.Contains(attrSpec.AfterFlags, bf) {
			t.Fatalf("expected baseline flag %q stripped for attrIR, got before=%v after=%v", bf, attrSpec.BeforeFlags, attrSpec.AfterFlags)
		}
	}

	scratchNoAttr := filepath.Join(tmp, "scratch-lto-noattr")
	if _, err := runLLVMReduce(context.Background(), triageOpts{
		Runner: &runner{LMCBin: selfExe}, Recipe: rec, Spec: spec, Profile: profReleaseLTO, GoodTC: tc, BadTC: &ltoRedTC,
	}, badWS, "t1", objRes, &passBisectResult{
		CulpritPass: "instcombine", BeforeFullIRPath: goodIR, BeforeIRPath: largeBefore, AfterIRPath: largeAfter,
	}, scratchNoAttr); err != nil {
		t.Fatalf("runLLVMReduce(lto-noattr): %v", err)
	}
	var noAttrSpec reduceSpec
	if err := readJSON(filepath.Join(scratchNoAttr, "reduce_spec.json"), &noAttrSpec); err != nil {
		t.Fatalf("read scratchNoAttr reduce_spec.json: %v", err)
	}
	for _, bf := range spec.BaselineFlags {
		if !slices.Contains(noAttrSpec.BeforeFlags, bf) || !slices.Contains(noAttrSpec.AfterFlags, bf) {
			t.Fatalf("expected baseline flag %q kept for goodIR, got before=%v after=%v", bf, noAttrSpec.BeforeFlags, noAttrSpec.AfterFlags)
		}
	}

	ltoNeedBaseTC := redTC
	ltoNeedBaseTC.Clang = mockClangNeedBase
	scratchNeedBase := filepath.Join(tmp, "scratch-lto-needbase")
	if _, err := runLLVMReduce(context.Background(), triageOpts{
		Runner: &runner{LMCBin: selfExe}, Recipe: rec, Spec: spec, Profile: profReleaseLTO, GoodTC: tc, BadTC: &ltoNeedBaseTC,
	}, badWS, "t1", objRes, &passBisectResult{
		CulpritPass: "instcombine", BeforeFullIRPath: attrIR, BeforeIRPath: largeBefore, AfterIRPath: largeAfter,
	}, scratchNeedBase); err != nil {
		t.Fatalf("runLLVMReduce(lto-needbase): %v", err)
	}
	var needBaseSpec reduceSpec
	if err := readJSON(filepath.Join(scratchNeedBase, "reduce_spec.json"), &needBaseSpec); err != nil {
		t.Fatalf("read scratchNeedBase reduce_spec.json: %v", err)
	}
	for _, bf := range spec.BaselineFlags {
		if !slices.Contains(needBaseSpec.BeforeFlags, bf) || !slices.Contains(needBaseSpec.AfterFlags, bf) {
			t.Fatalf("expected fallback to keep baseline flag %q, got before=%v after=%v", bf, needBaseSpec.BeforeFlags, needBaseSpec.AfterFlags)
		}
	}

	mockGoodNeedBase := filepath.Join(tmp, "mock-good-need-base")
	goodNeedBaseScript := fmt.Sprintf(`#!/bin/sh
set -eu
for a in "$@"; do
  if [ "$a" = %s ]; then exec %s "$@"; fi
done
exit 1
`, shQuote(spec.BaselineFlags[0]), shQuote(tc.Clang))
	if err := os.WriteFile(mockGoodNeedBase, []byte(goodNeedBaseScript), 0o755); err != nil {
		t.Fatal(err)
	}
	goodNeedBaseTC := *tc
	goodNeedBaseTC.Clang = mockGoodNeedBase
	scratchGoodOrder := filepath.Join(tmp, "scratch-lto-good-order")
	if _, err := runLLVMReduce(context.Background(), triageOpts{
		Runner: &runner{LMCBin: selfExe}, Recipe: rec, Spec: spec, Profile: profReleaseLTO, GoodTC: &goodNeedBaseTC, BadTC: &ltoRedTC,
	}, badWS, "t1", objRes, &passBisectResult{
		CulpritPass: "instcombine", BeforeFullIRPath: attrIR, BeforeIRPath: largeBefore, AfterIRPath: largeAfter,
	}, scratchGoodOrder); err != nil {
		t.Fatalf("runLLVMReduce(lto-good-order): %v", err)
	}
	var goodOrderSpec reduceSpec
	if err := readJSON(filepath.Join(scratchGoodOrder, "reduce_spec.json"), &goodOrderSpec); err != nil {
		t.Fatalf("read scratchGoodOrder reduce_spec.json: %v", err)
	}
	if goodOrderSpec.BeforeClang != mockGoodNeedBase || !slices.Contains(goodOrderSpec.BeforeFlags, spec.BaselineFlags[0]) {
		t.Fatalf("expected GoodTC withBase before BadTC -O0 noBase, got BeforeClang=%q BeforeFlags=%v", goodOrderSpec.BeforeClang, goodOrderSpec.BeforeFlags)
	}

	scratchSkew := filepath.Join(tmp, "scratch-lto-skew")
	if _, err := runLLVMReduce(context.Background(), triageOpts{
		Runner: &runner{LMCBin: selfExe}, Recipe: rec, Spec: spec, Profile: profReleaseLTO, GoodTC: &brokenGoodTC, BadTC: &ltoRedTC,
	}, badWS, "t1", objRes, &passBisectResult{
		CulpritPass: "instcombine", BeforeFullIRPath: attrIR, BeforeIRPath: largeBefore, AfterIRPath: largeAfter,
	}, scratchSkew); err != nil {
		t.Fatalf("runLLVMReduce(lto-skew): %v", err)
	}
	var skewSpec reduceSpec
	if err := readJSON(filepath.Join(scratchSkew, "reduce_spec.json"), &skewSpec); err != nil {
		t.Fatalf("read scratchSkew reduce_spec.json: %v", err)
	}
	if skewSpec.BeforeClang != ltoRedTC.Clang || !slices.Contains(skewSpec.BeforeFlags, "-O0") {
		t.Fatalf("expected BadTC -O0 fallback on GoodTC skew, got BeforeClang=%q BeforeFlags=%v", skewSpec.BeforeClang, skewSpec.BeforeFlags)
	}
	for _, bf := range spec.BaselineFlags {
		if slices.Contains(skewSpec.BeforeFlags, bf) || slices.Contains(skewSpec.AfterFlags, bf) {
			t.Fatalf("expected skew fallback to preserve stripped flag %q, got before=%v after=%v", bf, skewSpec.BeforeFlags, skewSpec.AfterFlags)
		}
	}

	noRedTC := redTC
	noRedTC.LLVMReduce = ""
	if _, err := runLLVMReduce(context.Background(), triageOpts{
		Runner: &runner{LMCBin: selfExe}, Recipe: rec, Spec: spec, Profile: profDistroO2, GoodTC: tc, BadTC: &noRedTC,
	}, badWS, "t1", objRes, &passBisectResult{
		CulpritPass: "instcombine", BeforeFullIRPath: goodIR, BeforeIRPath: largeBefore, AfterIRPath: largeAfter,
	}, scratchSmall); err != nil {
		t.Fatalf("runLLVMReduce(fallback): %v", err)
	}
	if fileExists(filepath.Join(scratchSmall, "reduced_before.ll")) || fileExists(filepath.Join(scratchSmall, "reduced_after.ll")) {
		t.Fatal("fallback left stale reduced_before.ll/reduced_after.ll on disk")
	}
}

func TestTriageHelpers(t *testing.T) {
	if !isInterproceduralPass("InlinerPass", "(caller)") ||
		!isInterproceduralPass("PostOrderFunctionAttrsPass", "(foo, bar)") ||
		!isInterproceduralPass("GlobalOptPass", "[module]") ||
		!isInterproceduralPass("AnyModulePass", "([module])") ||
		!isInterproceduralPass("called-value-propagation", "foo") ||
		!isInterproceduralPass("constmerge", "foo") ||
		!isInterproceduralPass("openmp-opt", "foo") ||
		!isInterproceduralPass("rpo-function-attrs", "foo") ||
		!isInterproceduralPass("rel-lookup-table-converter", "foo") ||
		!isInterproceduralPass("SomeCustomCGSCCPass", "(fn)") {
		t.Fatal("expected interprocedural/CGSCC passes to be detected")
	}
	if isInterproceduralPass("InstCombinePass", "foo") || isInterproceduralPass("GVNPass", "function (bar)") {
		t.Fatal("function pass falsely flagged as interprocedural")
	}

	gMem := []arMember{{name: "b.o", path: "/g/b.o"}, {name: "a.o", path: "/g/a.o"}, {name: "x.o", path: "/g/x.o"}}
	bMem := []arMember{{name: "a.o", path: "/b/a.o"}, {name: "b.o", path: "/b/b.o"}, {name: "y.o", path: "/b/y.o"}}
	pair := pairArchiveMembers(gMem, bMem)
	if pair[0] != 1 || pair[1] != 0 || pair[2] != 2 {
		t.Fatalf("pairArchiveMembers = %v, want [1 0 2]", pair)
	}

	cg := tuCodegenFlags([]string{"-O3", "-fPIC", "-mcmodel=large", "-ffp-contract=off", "-Wall", "-fPIC"}, "")
	if len(cg) != 3 || cg[0] != "-fPIC" || cg[1] != "-mcmodel=large" || cg[2] != "-ffp-contract=off" {
		t.Fatalf("tuCodegenFlags = %v", cg)
	}

	tmp := t.TempDir()
	realDir := filepath.Join(tmp, "real")
	linkDir := filepath.Join(tmp, "link")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(evalSymlinksExisting(realDir), "sub", "app.o")
	if rel, ok := relWithinDir(linkDir, target); !ok || rel != filepath.Join("sub", "app.o") {
		t.Fatalf("relWithinDir(%q, %q) = (%q, %v)", linkDir, target, rel, ok)
	}

	if ar, mem := parseResolutionArchive("/tmp/a0000_libfoo.a(culprit.o at 8)"); ar != "/tmp/a0000_libfoo.a" || mem != "culprit.o" {
		t.Fatalf("ELF parseResolutionArchive = (%q, %q)", ar, mem)
	}
	if ar, mem := parseResolutionArchive("/tmp/a0000_libfoo.a(culprit.o)1234"); ar != "/tmp/a0000_libfoo.a" || mem != "culprit.o" {
		t.Fatalf("MachO parseResolutionArchive = (%q, %q)", ar, mem)
	}
	if ar, mem := parseResolutionArchive("/tmp/m0000_main.o"); ar != "" || mem != "" {
		t.Fatalf("direct obj parseResolutionArchive = (%q, %q)", ar, mem)
	}

	rvSpec, err := lookupPlatform(platLinuxRISCV64)
	if err != nil {
		t.Fatal(err)
	}
	x86Spec, err := lookupPlatform(platLinuxX86)
	if err != nil {
		t.Fatal(err)
	}
	armSpec, err := lookupPlatform(platDarwinARM)
	if err != nil {
		t.Fatal(err)
	}
	if got := bisectLLVMTargets(rvSpec, "linux", "amd64"); got != "X86;RISCV" {
		t.Fatalf("bisectLLVMTargets(rv64, linux/amd64) = %q, want X86;RISCV", got)
	}
	if got := bisectLLVMTargets(rvSpec, "linux", "arm64"); got != "RISCV" {
		t.Fatalf("bisectLLVMTargets(rv64, linux/arm64) = %q, want RISCV", got)
	}
	if got := bisectLLVMTargets(x86Spec, "linux", "amd64"); got != "X86" {
		t.Fatalf("bisectLLVMTargets(x86, linux/amd64) = %q, want X86", got)
	}
	if got := bisectLLVMTargets(armSpec, "darwin", "arm64"); got != "AArch64" {
		t.Fatalf("bisectLLVMTargets(darwin-arm64) = %q, want AArch64", got)
	}

	candPath := filepath.Join(tmp, "cand.o")
	restPath := filepath.Join(tmp, "lmc_reduce_rest.o")

	rrAr := reduceRelink{ArOut: filepath.Join(tmp, "lib.a"), ArMembers: []string{"a.o", candPath}, CandObj: candPath}
	gotAr, ok := appendExtraReduceObj(rrAr, restPath, tmp)
	if !ok || !slices.Equal(gotAr.ArMembers, []string{"a.o", candPath, restPath}) || len(rrAr.ArMembers) != 2 {
		t.Fatalf("appendExtraReduceObj(ArMembers) = (%+v, %v), orig=%v", gotAr, ok, rrAr.ArMembers)
	}

	rrDirect := reduceRelink{LinkDir: tmp, CandObj: candPath, LinkArgs: []string{"a.o", candPath, "b.o", "-o", "app"}}
	gotDirect, ok := appendExtraReduceObj(rrDirect, restPath, tmp)
	if !ok || !slices.Equal(gotDirect.LinkArgs, []string{"a.o", candPath, restPath, "b.o", "-o", "app"}) || len(rrDirect.LinkArgs) != 5 {
		t.Fatalf("appendExtraReduceObj(LinkArgs) = (%+v, %v), orig=%v", gotDirect, ok, rrDirect.LinkArgs)
	}

	origFL := filepath.Join(tmp, "objs.filelist")
	if err := os.WriteFile(origFL, []byte("a.o\n"+candPath+"\nb.o\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	flScratch1 := filepath.Join(tmp, "fl1")
	if err := os.MkdirAll(flScratch1, 0o755); err != nil {
		t.Fatal(err)
	}
	rrFL := reduceRelink{LinkDir: tmp, CandObj: candPath, LinkArgs: []string{"-filelist", origFL, "-o", "app"}}
	gotFL, ok := appendExtraReduceObj(rrFL, restPath, flScratch1)
	if !ok || gotFL.LinkArgs[1] != filepath.Join(flScratch1, "filelist_reduce_split.txt") || rrFL.LinkArgs[1] != origFL {
		t.Fatalf("appendExtraReduceObj(-filelist) = (%+v, %v)", gotFL, ok)
	}
	if raw, err := os.ReadFile(gotFL.LinkArgs[1]); err != nil || string(raw) != "a.o\n"+candPath+"\n"+restPath+"\nb.o\n" {
		t.Fatalf("split filelist content = %q (%v)", string(raw), err)
	}

	flScratch2 := filepath.Join(tmp, "fl2")
	if err := os.MkdirAll(flScratch2, 0o755); err != nil {
		t.Fatal(err)
	}
	rrWlFL := reduceRelink{LinkDir: tmp, CandObj: candPath, LinkArgs: []string{"-Wl,-filelist," + origFL, "-o", "app"}}
	gotWlFL, ok := appendExtraReduceObj(rrWlFL, restPath, flScratch2)
	wantWlArg := "-Wl,-filelist," + filepath.Join(flScratch2, "filelist_reduce_split.txt")
	if !ok || gotWlFL.LinkArgs[0] != wantWlArg {
		t.Fatalf("appendExtraReduceObj(-Wl,-filelist) = (%+v, %v), want %q", gotWlFL, ok, wantWlArg)
	}
	if raw, err := os.ReadFile(filepath.Join(flScratch2, "filelist_reduce_split.txt")); err != nil || string(raw) != "a.o\n"+candPath+"\n"+restPath+"\nb.o\n" {
		t.Fatalf("split -Wl,-filelist content = %q (%v)", string(raw), err)
	}

	if d, ok := commitBisectBudget(context.Background(), 0); !ok || d != defaultCommitTimeout {
		t.Fatalf("commitBisectBudget(bg, 0) = (%v, %v), want (%v, true)", d, ok, defaultCommitTimeout)
	}
	if d, ok := commitBisectBudget(context.Background(), 10*time.Minute); !ok || d != 10*time.Minute {
		t.Fatalf("commitBisectBudget(bg, 10m) = (%v, %v), want (10m, true)", d, ok)
	}
	ctx30s, c30s := context.WithTimeout(context.Background(), 30*time.Second)
	defer c30s()
	if d, ok := commitBisectBudget(ctx30s, 200*time.Millisecond); !ok || d != 200*time.Millisecond {
		t.Fatalf("commitBisectBudget(30s, 200ms) = (%v, %v), want (200ms, true)", d, ok)
	}
	ctx10m, c10m := context.WithTimeout(context.Background(), 10*time.Minute)
	defer c10m()
	if d, ok := commitBisectBudget(ctx10m, 90*time.Minute); !ok || d < 4*time.Minute+50*time.Second || d > 5*time.Minute {
		t.Fatalf("commitBisectBudget(10m, 90m) = (%v, %v), want (~5m, true)", d, ok)
	}
	ctx2m, c2m := context.WithTimeout(context.Background(), 2*time.Minute)
	defer c2m()
	if d, ok := commitBisectBudget(ctx2m, 90*time.Minute); ok || d != 0 {
		t.Fatalf("commitBisectBudget(2m, 90m) = (%v, %v), want (0, false)", d, ok)
	}
	ctx100ms, c100ms := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer c100ms()
	if d, ok := commitBisectBudget(ctx100ms, 200*time.Millisecond); ok || d != 0 {
		t.Fatalf("commitBisectBudget(100ms, 200ms) = (%v, %v), want (0, false)", d, ok)
	}

	plainIR := filepath.Join(tmp, "plain.ll")
	cpuIR := filepath.Join(tmp, "cpu.ll")
	featIR := filepath.Join(tmp, "feat.ll")
	_ = os.WriteFile(plainIR, []byte("define i32 @f() {\n  ret i32 0\n}\n"), 0o644)
	_ = os.WriteFile(cpuIR, []byte("attributes #0 = { \"target-cpu\"=\"apple-m1\" }\n"), 0o644)
	_ = os.WriteFile(featIR, []byte("attributes #0 = { \"target-features\"=\"+avx2\" }\n"), 0o644)
	if irHasTargetAttrs(filepath.Join(tmp, "missing.ll")) || irHasTargetAttrs(plainIR) {
		t.Fatal("irHasTargetAttrs false-positived")
	}
	if !irHasTargetAttrs(cpuIR) || !irHasTargetAttrs(featIR) {
		t.Fatal("irHasTargetAttrs missed target-cpu or target-features")
	}

	origFlags := []string{"-O3", "-march=x86-64-v3", "-Wno-error"}
	stripped := withoutBaselineFlags(origFlags, []string{"-march=x86-64-v3"})
	if !slices.Equal(stripped, []string{"-O3", "-Wno-error"}) || !slices.Equal(origFlags, []string{"-O3", "-march=x86-64-v3", "-Wno-error"}) {
		t.Fatalf("withoutBaselineFlags = %v (orig=%v)", stripped, origFlags)
	}
	cloned := withoutBaselineFlags(origFlags, nil)
	cloned[0] = "-O0"
	if origFlags[0] != "-O3" {
		t.Fatalf("withoutBaselineFlags aliased input slice: %v", origFlags)
	}

	confCases := []struct {
		name      string
		spec      platformSpec
		san       bool
		cons      bool
		diagO0    string
		alive     formalResult
		wantASan  bool
		wantConf  string
		wantIssue bool
	}{
		{
			name:      "rv64-ubsan-clean-promotes-likely",
			spec:      platformSpecs[platLinuxRISCV64],
			san:       true,
			cons:      true,
			diagO0:    "pass",
			alive:     formalResult{Status: formalUnsupported},
			wantASan:  false,
			wantConf:  confLikely,
			wantIssue: true,
		},
		{
			name:      "rv64-san-fail-stays-needs-review",
			spec:      platformSpecs[platLinuxRISCV64],
			san:       false,
			cons:      true,
			diagO0:    "pass",
			alive:     formalResult{Status: formalUnsupported},
			wantASan:  false,
			wantConf:  confNeedsReview,
			wantIssue: false,
		},
		{
			name:      "rv64-alive-verified-downgrades-likely",
			spec:      platformSpecs[platLinuxRISCV64],
			san:       true,
			cons:      true,
			diagO0:    "pass",
			alive:     formalResult{Status: aliveVerified},
			wantASan:  false,
			wantConf:  confNeedsReview,
			wantIssue: false,
		},
		{
			name:      "x86-san-clean-likely",
			spec:      platformSpecs[platLinuxX86],
			san:       true,
			cons:      true,
			diagO0:    "pass",
			alive:     formalResult{Status: formalUnsupported},
			wantASan:  true,
			wantConf:  confLikely,
			wantIssue: true,
		},
		{
			name:      "x86-san-fail-needs-review",
			spec:      platformSpecs[platLinuxX86],
			san:       false,
			cons:      true,
			diagO0:    "pass",
			alive:     formalResult{Status: formalUnsupported},
			wantASan:  false,
			wantConf:  confNeedsReview,
			wantIssue: false,
		},
		{
			name:      "x86-alive-verified-needs-review",
			spec:      platformSpecs[platLinuxX86],
			san:       true,
			cons:      true,
			diagO0:    "pass",
			alive:     formalResult{Status: aliveVerified},
			wantASan:  true,
			wantConf:  confNeedsReview,
			wantIssue: false,
		},
		{
			name:      "x86-alive-miscompile-confirmed",
			spec:      platformSpecs[platLinuxX86],
			san:       false,
			cons:      false,
			diagO0:    "test_fail",
			alive:     formalResult{Status: aliveMiscompile, ProvesBug: true},
			wantASan:  false,
			wantConf:  confConfirmed,
			wantIssue: true,
		},
	}
	for _, tc := range confCases {
		gotASan, gotConf := classifyConfidence(tc.spec, tc.san, tc.cons, tc.diagO0, tc.alive)
		if gotASan != tc.wantASan || gotConf != tc.wantConf {
			t.Fatalf("%s: classifyConfidence = (%v, %q), want (%v, %q)", tc.name, gotASan, gotConf, tc.wantASan, tc.wantConf)
		}
		inc := &incident{
			ID:             "inc-" + tc.name,
			Status:         incidentOpen,
			Confidence:     gotConf,
			ASanUBSanClean: gotASan,
			AliveTVStatus:  tc.alive.Status,
			Affected:       []affected{{Package: "zstd", Platform: tc.spec.ID, Profile: profDistroO2, TestID: "t1"}},
		}
		if gotIssue := groupQualifiesForIssue([]*incident{inc}); gotIssue != tc.wantIssue {
			t.Fatalf("%s: groupQualifiesForIssue = %v, want %v", tc.name, gotIssue, tc.wantIssue)
		}
		if tc.spec.ID == platLinuxRISCV64 && tc.wantIssue {
			rows := incidentMetaRows([]*incident{inc}, false, defaultSiteURL)
			var sanVal string
			for _, r := range rows {
				if r[0] == "Sanitizers" {
					sanVal = r[1]
				}
			}
			if sanVal != "`ubsan` clean (asan disabled)" {
				t.Fatalf("%s: Sanitizers row = %q, want ubsan-only warning", tc.name, sanVal)
			}
		}
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
	t.Parallel()
	spec, goodTC := hostToolchainOrSkip(t)
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("flaky", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
		tmp := t.TempDir()
		tarPath := filepath.Join(tmp, "ub.tar.gz")
		rec := makeTestRecipe(t, filepath.Join(tmp, "corpus"), "ubpkg", tarPath, makeTarGz(t, tarPath, ubFiles))
		r := &runner{CacheDir: filepath.Join(tmp, "cache"), LMCBin: selfExe, Jobs: 2}

		writeBadO2 := func(name string) *toolchain {
			p := filepath.Join(tmp, name)
			body := fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = \"-O2\" ]; then exec %s -DBAD_MISCOMPILE=1 \"$@\"; fi\ndone\nexec %s \"$@\"\n",
				shQuote(goodTC.Clang), shQuote(goodTC.Clang))
			_ = os.WriteFile(p, []byte(body), 0o755)
			tc := *goodTC
			tc.Clang = p
			return &tc
		}
		writeGoodSan := func(name, sanBody string) *toolchain {
			p := filepath.Join(tmp, name)
			body := fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do\n  case \"$a\" in\n    -fsanitize=*) %s ;;\n  esac\ndone\nexec %s \"$@\"\n",
				sanBody, shQuote(goodTC.Clang))
			_ = os.WriteFile(p, []byte(body), 0o755)
			tc := *goodTC
			tc.Clang = p
			return &tc
		}
		badO2TC := writeBadO2("bad-o2")

		res, err := triage(context.Background(), triageOpts{
			Runner:  r,
			Recipe:  rec,
			Spec:    spec,
			Profile: profDistroO2,
			GoodTC:  writeGoodSan("no-rt", `echo "ld.lld: error: cannot open libclang_rt.asan.a: No such file or directory" >&2; exit 1`),
			BadTC:   badO2TC,
			GoodSHA: "111111111111",
			BadSHA:  "222222222222",
			TestID:  "check_calc",
			WorkDir: filepath.Join(tmp, "w1"),
		})
		if err != nil || !res.Dropped || res.DropReason != "upstream_ub" {
			t.Fatalf("missing clang_rt fallback: res=%+v err=%v", res, err)
		}

		_, err = triage(context.Background(), triageOpts{
			Runner:  r,
			Recipe:  rec,
			Spec:    spec,
			Profile: profDistroO2,
			GoodTC:  writeGoodSan("broken-san", `echo "error: unrelated compiler flag error" >&2; exit 1`),
			BadTC:   badO2TC,
			GoodSHA: "111111111111",
			BadSHA:  "222222222222",
			TestID:  "check_calc",
			WorkDir: filepath.Join(tmp, "w2"),
		})
		if err == nil || !strings.Contains(err.Error(), "without sanitizer trap") {
			t.Fatalf("expected non-sanitizer build error, got %v", err)
		}
	})

	cleanFiles := map[string]string{
		"a.c": "int fa(int x) { return x; }\n",
		"b.c": "int fb(int x) { return x; }\n",
		"culprit.c": `int calc(int x) {
#if defined(BAD_MISCOMPILE) || defined(FAIL_IN_SAN)
    return x + 99;
#else
    return x + 1;
#endif
}
`,
		"main.c": "extern int calc(int); int main(void) { return calc(5) == 6 ? 0 : 1; }\n",
	}

	t.Run("bad-tc-asan-segv-not-dropped", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		tarPath := filepath.Join(tmp, "clean.tar.gz")
		rec := makeTestRecipe(t, filepath.Join(tmp, "corpus"), "cleansegv", tarPath, makeTarGz(t, tarPath, cleanFiles))
		r := &runner{CacheDir: filepath.Join(tmp, "cache"), LMCBin: selfExe, Jobs: 2}

		badPath := filepath.Join(tmp, "bad-asan-segv")
		badBody := fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do\n  case \"$a\" in\n    -fsanitize=*|-O1) echo \"AddressSanitizer: SEGV on unknown address 0x0\" >&2; exit 1 ;;\n    -O2) exec %s -DBAD_MISCOMPILE=1 \"$@\" ;;\n  esac\ndone\nexec %s \"$@\"\n",
			shQuote(goodTC.Clang), shQuote(goodTC.Clang))
		if err := os.WriteFile(badPath, []byte(badBody), 0o755); err != nil {
			t.Fatal(err)
		}
		badTC := *goodTC
		badTC.Clang = badPath
		badTC.AliveTV, badTC.LLUBI, badTC.LLVMReduce = "", "", ""

		res, err := triage(context.Background(), triageOpts{
			Runner: r, Recipe: rec, Spec: spec, Profile: profDistroO2, GoodTC: goodTC, BadTC: &badTC,
			GoodSHA: "111111111111", BadSHA: "222222222222", TestID: "check_calc", WorkDir: filepath.Join(tmp, "w"),
		})
		if err != nil || res.Dropped || res.Incident == nil {
			t.Fatalf("bad-tc asan segv falsely dropped or errored: res=%+v err=%v", res, err)
		}
		if !res.Incident.ASanUBSanClean || res.Incident.Confidence != confLikely {
			t.Fatalf("expected asan clean + likely, got %+v", res.Incident)
		}
	})

	t.Run("san-test-non-sanitizer-fail", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		tarPath := filepath.Join(tmp, "clean.tar.gz")
		rec := makeTestRecipe(t, filepath.Join(tmp, "corpus"), "sanfail", tarPath, makeTarGz(t, tarPath, cleanFiles))
		r := &runner{CacheDir: filepath.Join(tmp, "cache"), LMCBin: selfExe, Jobs: 2}

		goodPath := filepath.Join(tmp, "good-san-fail")
		goodBody := fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do\n  case \"$a\" in\n    -fsanitize=*) exec %s -DFAIL_IN_SAN=1 \"$@\" ;;\n  esac\ndone\nexec %s \"$@\"\n",
			shQuote(goodTC.Clang), shQuote(goodTC.Clang))
		if err := os.WriteFile(goodPath, []byte(goodBody), 0o755); err != nil {
			t.Fatal(err)
		}
		gTC := *goodTC
		gTC.Clang = goodPath

		badPath := filepath.Join(tmp, "bad-o2")
		badBody := fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = \"-O2\" ]; then exec %s -DBAD_MISCOMPILE=1 \"$@\"; fi\ndone\nexec %s \"$@\"\n",
			shQuote(goodTC.Clang), shQuote(goodTC.Clang))
		if err := os.WriteFile(badPath, []byte(badBody), 0o755); err != nil {
			t.Fatal(err)
		}
		badTC := *goodTC
		badTC.Clang = badPath
		badTC.AliveTV, badTC.LLUBI, badTC.LLVMReduce = "", "", ""

		res, err := triage(context.Background(), triageOpts{
			Runner: r, Recipe: rec, Spec: spec, Profile: profDistroO2, GoodTC: &gTC, BadTC: &badTC,
			GoodSHA: "111111111111", BadSHA: "222222222222", TestID: "check_calc", WorkDir: filepath.Join(tmp, "w"),
		})
		if err != nil || res.Dropped || res.Incident == nil {
			t.Fatalf("non-sanitizer test fail dropped or errored: res=%+v err=%v", res, err)
		}
		if res.Incident.ASanUBSanClean || res.Incident.Confidence != confNeedsReview {
			t.Fatalf("expected ASanUBSanClean=false and needs-review, got %+v", res.Incident)
		}
	})

	t.Run("bad-build-good-fails", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		tarPath := filepath.Join(tmp, "clean.tar.gz")
		rec := makeTestRecipe(t, filepath.Join(tmp, "corpus"), "bothfail", tarPath, makeTarGz(t, tarPath, cleanFiles))
		r := &runner{CacheDir: filepath.Join(tmp, "cache"), LMCBin: selfExe, Jobs: 2}
		failPath := filepath.Join(tmp, "fail-cc")
		_ = os.WriteFile(failPath, []byte("#!/bin/sh\necho 'error: broken both' >&2\nexit 1\n"), 0o755)
		badTC := *goodTC
		badTC.Clang = failPath
		gTC := *goodTC
		gTC.Clang = failPath
		res, err := triage(context.Background(), triageOpts{
			Runner: r, Recipe: rec, Spec: spec, Profile: profDistroO2, GoodTC: &gTC, BadTC: &badTC,
			GoodSHA: "111111111111", BadSHA: "222222222222", TestID: "check_calc", WorkDir: filepath.Join(tmp, "w"),
		})
		if err != nil || !res.Dropped || res.DropReason != "not_regression" {
			t.Fatalf("expected not_regression drop when good also fails build, got res=%+v err=%v", res, err)
		}
	})

	t.Run("bad-build-good-passes-plain-and-ice", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		tarPath := filepath.Join(tmp, "clean.tar.gz")
		rec := makeTestRecipe(t, filepath.Join(tmp, "corpus"), "badbuild", tarPath, makeTarGz(t, tarPath, cleanFiles))
		r := &runner{CacheDir: filepath.Join(tmp, "cache"), LMCBin: selfExe, Jobs: 2}

		plainCC := filepath.Join(tmp, "plain-fail-cc")
		_ = os.WriteFile(plainCC, []byte("#!/bin/sh\necho 'culprit.c:1:2: error: syntax broken' >&2\nexit 1\n"), 0o755)
		plainTC := *goodTC
		plainTC.Clang = plainCC
		resPlain, err := triage(context.Background(), triageOpts{
			Runner: r, Recipe: rec, Spec: spec, Profile: profDistroO2, GoodTC: goodTC, BadTC: &plainTC,
			GoodSHA: "111111111111", BadSHA: "222222222222", TestID: "check_calc", WorkDir: filepath.Join(tmp, "w-plain"),
		})
		if err != nil || resPlain.Dropped || !resPlain.BuildFailed || resPlain.IsICE || resPlain.Incident == nil || resPlain.Incident.Kind != incidentKindBuildFail || !strings.Contains(resPlain.Incident.ErrorExcerpt, "syntax broken") {
			t.Fatalf("unexpected plain build-fail result: res=%+v err=%v", resPlain, err)
		}

		iceCC := filepath.Join(tmp, "ice-fail-cc")
		_ = os.WriteFile(iceCC, []byte("#!/bin/sh\necho 'PLEASE submit a bug report to https://github.com/llvm/llvm-project/issues/' >&2\nexit 1\n"), 0o755)
		iceTC := *goodTC
		iceTC.Clang = iceCC
		resICE, err := triage(context.Background(), triageOpts{
			Runner: r, Recipe: rec, Spec: spec, Profile: profDistroO2, GoodTC: goodTC, BadTC: &iceTC,
			GoodSHA: "111111111111", BadSHA: "222222222222", TestID: "check_calc", WorkDir: filepath.Join(tmp, "w-ice"),
		})
		if err != nil || resICE.Dropped || !resICE.BuildFailed || !resICE.IsICE || resICE.Incident == nil || !strings.Contains(resICE.Incident.Title, "ICE") {
			t.Fatalf("unexpected ICE build-fail result: res=%+v err=%v", resICE, err)
		}
	})

	t.Run("conservative-skipped-on-diag-o0-fail", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		tarPath := filepath.Join(tmp, "clean.tar.gz")
		rec := makeTestRecipe(t, filepath.Join(tmp, "corpus"), "skipcons", tarPath, makeTarGz(t, tarPath, cleanFiles))
		r := &runner{CacheDir: filepath.Join(tmp, "cache"), LMCBin: selfExe, Jobs: 2}

		invLog := filepath.Join(tmp, "inv.log")
		badPath := filepath.Join(tmp, "bad-all-opt")
		badBody := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %s\nexec %s -DBAD_MISCOMPILE=1 \"$@\"\n",
			shQuote(invLog), shQuote(goodTC.Clang))
		if err := os.WriteFile(badPath, []byte(badBody), 0o755); err != nil {
			t.Fatal(err)
		}
		badTC := *goodTC
		badTC.Clang = badPath
		badTC.AliveTV, badTC.LLUBI, badTC.LLVMReduce = "", "", ""

		res, err := triage(context.Background(), triageOpts{
			Runner: r, Recipe: rec, Spec: spec, Profile: profDistroO2, GoodTC: goodTC, BadTC: &badTC,
			GoodSHA: "111111111111", BadSHA: "222222222222", TestID: "check_calc", WorkDir: filepath.Join(tmp, "w"),
		})
		if err != nil || res.Dropped || res.Incident == nil {
			t.Fatalf("unexpected result: res=%+v err=%v", res, err)
		}
		if res.Incident.DiagO0Status != "test_fail" || res.Incident.ConservativeFlagIndependent {
			t.Fatalf("expected DiagO0Status=test_fail and ConservativeFlagIndependent=false: %+v", res.Incident)
		}
		logRaw, _ := os.ReadFile(invLog)
		if strings.Contains(string(logRaw), "-ftrivial-auto-var-init=zero") {
			t.Fatalf("expected conservative build to be skipped when diag-O0 failed, log=\n%s", string(logRaw))
		}
	})
}

func TestTriagePipeline(t *testing.T) {
	t.Parallel()
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
	culpritSrc := `int unused_dead(int z) { return (z * 7) + 123; }
int compute_kernel(int n) {
    int sum = 0;
    for (int i = 1; i <= n; i++) sum += i;
#ifdef SIM_PASS_BUG
    return sum + 999;
#else
    return sum;
#endif
}
`
	sha := makeTarGz(t, tarPath, map[string]string{
		"a.c":       "int helper_a(int x) { return x + 10; }\n",
		"b.c":       "int helper_b(int x) { return x * 2; }\n",
		"culprit.c": culpritSrc,
		"main.c": `extern int helper_a(int); extern int helper_b(int); extern int compute_kernel(int);
int main(void) {
    if (helper_a(5) != 15 || helper_b(5) != 10) return 2;
    return compute_kernel(5) == 15 ? 0 : 1;
}
`,
	})
	rec := makeTestRecipe(t, filepath.Join(tmp, "corpus"), "cleanbug", tarPath, sha)

	probeC := filepath.Join(tmp, "probe_culprit.c")
	if err := os.WriteFile(probeC, []byte(culpritSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	profFlags, err := profileCompilerFlags(profDistroO2, spec)
	if err != nil {
		t.Fatal(err)
	}
	probeArgs := append(crossTargetArgs(spec), profFlags...)
	if spec.IsDarwin && goodTC.SDKRoot != "" {
		probeArgs = append(probeArgs, "-isysroot", goodTC.SDKRoot)
	}
	probeArgs = append(probeArgs, "-S", "-emit-llvm", "-mllvm", "-opt-bisect-limit=-1", probeC, "-o", filepath.Join(tmp, "probe_culprit.ll"))
	var probeOut, probeStderr bytes.Buffer
	probeCmd := exec.Command(goodTC.Clang, probeArgs...)
	probeCmd.Stdout = &probeOut
	probeCmd.Stderr = &probeStderr
	if err := probeCmd.Run(); err != nil {
		t.Fatalf("probe bisect passes: %v\nstdout=%s\nstderr=%s", err, probeOut.String(), probeStderr.String())
	}
	bugPass := 0
	for _, e := range parseBisectOutput(probeStderr.String()) {
		if e.Func == "compute_kernel" && !isInterproceduralPass(e.PassName, e.Target) && e.Index > 1 {
			bugPass = e.Index
			break
		}
	}
	if bugPass == 0 {
		t.Fatalf("no eligible compute_kernel pass found in bisect output:\n%s", probeStderr.String())
	}
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

	t.Run("full-pipeline", func(t *testing.T) {
		t.Parallel()
		res, err := triage(context.Background(), triageOpts{
			Runner:        &runner{CacheDir: filepath.Join(tmp, "cache-main"), LMCBin: selfExe, Jobs: 2},
			Recipe:        rec,
			Spec:          spec,
			Profile:       profDistroO2,
			GoodTC:        goodTC,
			BadTC:         &badTC,
			GoodSHA:       commits[0],
			BadSHA:        commits[4],
			WorkDir:       filepath.Join(tmp, "work-main"),
			BundleDir:     filepath.Join(tmp, "bundles-main"),
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
		wantConf := confLikely
		if inc.AliveTVStatus == aliveMiscompile {
			wantConf = confConfirmed
		} else if inc.AliveTVStatus == aliveVerified {
			wantConf = confNeedsReview
		}
		if inc.Confidence != wantConf || !inc.ASanUBSanClean || !inc.ConservativeFlagIndependent || inc.DiagO0Status != "pass" {
			t.Fatalf("unexpected confidence/ub flags: %+v (want conf=%q)", inc, wantConf)
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
	})

	t.Run("cmd-triage-timeout-flags", func(t *testing.T) {
		t.Parallel()
		writeExec := func(dir, name, target string) {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, name)
			body := fmt.Sprintf("#!/bin/sh\nexec %s \"$@\"\n", shQuote(target))
			if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		goodTCBin := filepath.Join(tmp, "cli-good-bin")
		badTCBin := filepath.Join(tmp, "cli-bad-bin")
		writeExec(goodTCBin, "clang", goodTC.Clang)
		writeExec(goodTCBin, "clang++", goodTC.ClangXX)
		writeExec(goodTCBin, filepath.Base(goodTC.Linker), goodTC.Linker)
		writeExec(badTCBin, "clang", badClang)
		writeExec(badTCBin, "clang++", goodTC.ClangXX)
		writeExec(badTCBin, filepath.Base(goodTC.Linker), goodTC.Linker)

		outJSON := filepath.Join(tmp, "cli-incident.json")
		var cliOut, cliErr bytes.Buffer
		err := cmdTriage(context.Background(), []string{
			"-corpus", filepath.Join(tmp, "corpus"),
			"-pkg", "cleanbug",
			"-plat", spec.ID,
			"-prof", profDistroO2,
			"-good-tc", goodTCBin,
			"-bad-tc", badTCBin,
			"-good", commits[0],
			"-bad", commits[4],
			"-llvm", llvmRepo,
			"-dir", filepath.Join(tmp, "work-cli"),
			"-cache", filepath.Join(tmp, "cache-cli"),
			"-bundle", filepath.Join(tmp, "bundles-cli"),
			"-out", outJSON,
			"-timeout", "4m",
			"-commit-timeout", "90m",
			"-jobs", "2",
		}, &cliOut, &cliErr)
		if err != nil {
			t.Fatalf("cmdTriage: %v\nstderr=%s", err, cliErr.String())
		}
		if !strings.Contains(cliErr.String(), "[triage] commit bisect skipped/failed (continuing with pass bisect):") {
			t.Fatalf("missing commit bisect warning on stderr: %q", cliErr.String())
		}
		var cliInc incident
		if err := readJSON(outJSON, &cliInc); err != nil {
			t.Fatalf("read -out JSON: %v", err)
		}
		if cliInc.CulpritSHA != "" || cliInc.CulpritTU != "culprit.c" || cliInc.CulpritPassIndex != bugPass {
			t.Fatalf("unexpected CLI incident: %+v", cliInc)
		}
	})
}

func TestTriageContextCancel(t *testing.T) {
	t.Parallel()
	spec, tc := hostToolchainOrSkip(t)
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "stub.c"), []byte("int main(void){return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	makeRec := func(name, buildBody, testBody string) *recipe {
		dir := filepath.Join(tmp, "rec-"+name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "build.sh"), []byte("#!/bin/sh\nset -eu\n"+buildBody+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "test_one.sh"), []byte("#!/bin/sh\nset -eu\n"+testBody+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return &recipe{Name: name, Dir: dir, TimeoutMin: 1, SmokeTest: "t1"}
	}

	t.Run("bad-build-deadline", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		rec := makeRec("bad-hang", "sleep 10", "exit 1")
		res, err := triage(ctx, triageOpts{
			Runner: &runner{LMCBin: selfExe, Jobs: 1}, Recipe: rec, Spec: spec, Profile: profDistroO2,
			GoodTC: tc, BadTC: tc, TestID: "t1", SrcDir: srcDir, WorkDir: filepath.Join(tmp, "w-bad-hang"),
		})
		if !errors.Is(err, context.DeadlineExceeded) || res != nil {
			t.Fatalf("bad-build deadline: res=%+v err=%v, want context.DeadlineExceeded", res, err)
		}
	})

	t.Run("good-test-cancel", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		marker := filepath.Join(tmp, "in-good-test")
		done := make(chan struct{})
		go func() {
			defer close(done)
			tk := time.NewTicker(10 * time.Millisecond)
			defer tk.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tk.C:
					if fileExists(marker) {
						cancel()
						return
					}
				}
			}
		}()
		rec := makeRec("good-test-hang", "exit 0", fmt.Sprintf(`case "$BUILD_DIR" in *good-build*) : > %s; sleep 10 ;; *) exit 1 ;; esac`, shQuote(marker)))
		res, err := triage(ctx, triageOpts{
			Runner: &runner{LMCBin: selfExe, Jobs: 1}, Recipe: rec, Spec: spec, Profile: profDistroO2,
			GoodTC: tc, BadTC: tc, TestID: "t1", FlakyAttempts: 1, SrcDir: srcDir, WorkDir: filepath.Join(tmp, "w-good-test-hang"),
		})
		cancel()
		<-done
		if !errors.Is(err, context.Canceled) || res != nil {
			t.Fatalf("good-test cancel: res=%+v err=%v, want context.Canceled", res, err)
		}
	})
}

func writeBadLinkerScript(t *testing.T, path, realLinker string) {
	t.Helper()
	body := fmt.Sprintf(`#!/bin/sh
set -eu
out=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
%s "$@"
case "$out" in
  *diag-o0*) ;;
  *)
    if [ -n "$out" ] && [ -x "$out" ]; then
      printf '#!/bin/sh\nexit 1\n' > "$out"
      chmod 0755 "$out"
    fi
    ;;
esac
`, shQuote(realLinker))
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestLinkerBugIsolationAndCommitBisect(t *testing.T) {
	t.Parallel()
	spec, goodTC := hostToolchainOrSkip(t)
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeSixTUs(t, srcDir)

	goodLinker := filepath.Join(tmp, "good-ld")
	badLinker := filepath.Join(tmp, "bad-ld")
	_ = os.WriteFile(goodLinker, []byte(fmt.Sprintf("#!/bin/sh\nexec %s \"$@\"\n", shQuote(goodTC.Linker))), 0o755)
	writeBadLinkerScript(t, badLinker, goodTC.Linker)

	gTC := *goodTC
	gTC.Linker = goodLinker
	bTC := *goodTC
	bTC.Linker = badLinker

	goodB, _, _ := buildMultiTU(t, spec, profDistroO2, &gTC, srcDir, filepath.Join(tmp, "good-ws"), false)
	badB, badM, appBin := buildMultiTU(t, spec, profDistroO2, &bTC, srcDir, filepath.Join(tmp, "bad-ws"), false)

	objRes, err := bisectObjects(context.Background(), objectBisectOpts{
		Spec: spec, Profile: profDistroO2, GoodTC: &gTC, BadTC: &bTC,
		GoodBuildDir: goodB, BadBuildDir: badB, BadManifestDir: badM,
		ScratchDir: filepath.Join(tmp, "obj-scratch"),
		Test: func(ctx context.Context) (bool, string, error) {
			out, err := exec.CommandContext(ctx, appBin).CombinedOutput()
			return err == nil, string(out), nil
		},
	})
	if err != nil {
		t.Fatalf("bisectObjects linker bug: %v", err)
	}
	if !objRes.IsLinkerBug || objRes.Culprit != nil || objRes.relinkLinker == nil || objRes.TargetLink == nil || objRes.decomp == nil {
		t.Fatalf("expected IsLinkerBug isolation without Culprit, got %+v", objRes)
	}
	if want := filepath.Base(badLinker); objRes.LinkerName != want {
		t.Fatalf("LinkerName = %q, want %q", objRes.LinkerName, want)
	}
	if pass, _, err := objRes.relinkLinker(context.Background(), goodLinker); err != nil || !pass {
		t.Fatalf("relinkLinker(goodLinker) = (%v, %v), want pass", pass, err)
	}
	if pass, _, err := objRes.relinkLinker(context.Background(), badLinker); err != nil || pass {
		t.Fatalf("relinkLinker(badLinker) = (%v, %v), want fail", pass, err)
	}

	repo := filepath.Join(tmp, "llvm")
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
	for i := range 6 {
		state := "GOOD"
		if i >= 3 {
			state = "MISCOMPILE"
		}
		_ = os.WriteFile(filepath.Join(repo, "v.txt"), []byte(fmt.Sprintf("%s\n%d\n", state, i)), 0o644)
		runGit("add", "v.txt")
		subj := fmt.Sprintf("[LLD] Commit %d", i)
		if i == 3 {
			subj = "[LLD][ThinLTO] Drop symbol in dead strip (#250123)"
		}
		runGit("commit", "-m", subj)
		shas = append(shas, runGit("rev-parse", "HEAD"))
	}

	gotSHA, gotSubj, gotCommitErr, gotErr := runTriageCommitBisect(context.Background(), triageOpts{
		LLVMSrcDir: repo, GoodSHA: shas[0], BadSHA: shas[5],
		Spec: spec, GoodTC: &gTC, BadTC: &bTC,
		buildClang: func(_ context.Context, wt, bd, _ string) (string, error) {
			raw, err := os.ReadFile(filepath.Join(wt, "v.txt"))
			if err != nil {
				return "", err
			}
			_ = os.MkdirAll(bd, 0o755)
			midLD := filepath.Join(bd, "mid-ld")
			if strings.HasPrefix(string(raw), "GOOD") {
				_ = os.WriteFile(midLD, []byte(fmt.Sprintf("#!/bin/sh\nexec %s \"$@\"\n", shQuote(goodTC.Linker))), 0o755)
			} else {
				writeBadLinkerScript(t, midLD, goodTC.Linker)
			}
			return midLD, nil
		},
	}, filepath.Join(tmp, "bisect-work"), objRes)
	if gotErr != nil || gotCommitErr != "" || gotSHA != shas[3] || !strings.Contains(gotSubj, "Drop symbol in dead strip") {
		t.Fatalf("runTriageCommitBisect linker bug: sha=%q subj=%q commitErr=%q err=%v", gotSHA, gotSubj, gotCommitErr, gotErr)
	}
}

func TestLinkerBugPipelineBundle(t *testing.T) {
	t.Parallel()
	spec, goodTC := hostToolchainOrSkip(t)
	if _, err := exec.LookPath("zstd"); err != nil {
		t.Skip("zstd unavailable")
	}
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	tarPath := filepath.Join(tmp, "lnkbug.tar.gz")
	sha := makeTarGz(t, tarPath, map[string]string{
		"sub1/dup.c": "int dup_one(void) { return 10; }\n",
		"sub2/dup.c": "int dup_two(void) { return 20; }\n",
		"libsrc.c":   "int lib_fn(void) { return 12; }\n",
		"main.c":     "extern int dup_one(void); extern int dup_two(void); extern int lib_fn(void); int main(void) { return (dup_one() + dup_two() + lib_fn()) == 42 ? 0 : 1; }\n",
	})
	rec := makeTestRecipe(t, filepath.Join(tmp, "corpus"), "lnkbug", tarPath, sha)
	buildScript := fmt.Sprintf(`#!/bin/sh
set -eu
mkdir -p "$BUILD_DIR/sub1" "$BUILD_DIR/sub2"
"$CC" -c "$SRC_DIR/sub1/dup.c" -o "$BUILD_DIR/sub1/dup.o"
"$CC" -c "$SRC_DIR/sub2/dup.c" -o "$BUILD_DIR/sub2/dup.o"
"$CC" -c "$SRC_DIR/libsrc.c" -o "$BUILD_DIR/libsrc.o"
"$CC" -c "$SRC_DIR/main.c" -o "$BUILD_DIR/main.o"
%s rcs "$BUILD_DIR/libhelper.a" "$BUILD_DIR/libsrc.o"
"$CC" "$BUILD_DIR/sub1/dup.o" "$BUILD_DIR/sub2/dup.o" "$BUILD_DIR/main.o" "$BUILD_DIR/libhelper.a" -o "$BUILD_DIR/runner"
`, shQuote(goodTC.Ar))
	if err := os.WriteFile(filepath.Join(rec.Dir, "build.sh"), []byte(buildScript), 0o755); err != nil {
		t.Fatal(err)
	}

	goodLinker := filepath.Join(tmp, "good-ld")
	badLinker := filepath.Join(tmp, "bad-ld")
	_ = os.WriteFile(goodLinker, []byte(fmt.Sprintf("#!/bin/sh\nexec %s \"$@\"\n", shQuote(goodTC.Linker))), 0o755)
	writeBadLinkerScript(t, badLinker, goodTC.Linker)

	gTC := *goodTC
	gTC.Linker = goodLinker
	bTC := *goodTC
	bTC.Linker = badLinker
	bTC.AliveTV, bTC.LLUBI, bTC.LLVMReduce = "", "", ""

	res, err := triage(context.Background(), triageOpts{
		Runner:        &runner{CacheDir: filepath.Join(tmp, "cache"), LMCBin: selfExe, Jobs: 2},
		Recipe:        rec,
		Spec:          spec,
		Profile:       profDistroO2,
		GoodTC:        &gTC,
		BadTC:         &bTC,
		GoodSHA:       "1111111111111111111111111111111111111111",
		BadSHA:        "2222222222222222222222222222222222222222",
		WorkDir:       filepath.Join(tmp, "work"),
		BundleDir:     filepath.Join(tmp, "bundles"),
		FlakyAttempts: 1,
	})
	if err != nil || res.Dropped || res.Incident == nil {
		t.Fatalf("triage linker bug: res=%+v err=%v", res, err)
	}
	inc := res.Incident
	if !inc.IsLinkerBug || inc.Confidence != confLikely || inc.HasReducedIR || inc.CulpritTU != "" || inc.PassDiff != "" {
		t.Fatalf("unexpected linker incident fields: %+v", inc)
	}
	if inc.CulpritPass != filepath.Base(badLinker) || inc.AliveTVStatus != formalUnsupported || inc.LLUBIStatus != formalUnsupported {
		t.Fatalf("unexpected pass/formal status: %+v", inc)
	}

	dec, err := exec.Command("zstd", "-d", "-c", res.BundlePath).Output()
	if err != nil {
		t.Fatalf("zstd -d: %v", err)
	}
	unpackDir := t.TempDir()
	tr := tar.NewReader(bytes.NewReader(dec))
	seen := make(map[string]int64)
	var dupObjs []string
	var hasAr bool
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		raw, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read %s: %v", hdr.Name, err)
		}
		seen[filepath.Base(hdr.Name)] = hdr.Size
		if strings.Contains(hdr.Name, "/inputs/") && strings.HasSuffix(hdr.Name, "_dup.o") {
			dupObjs = append(dupObjs, hdr.Name)
		}
		if strings.Contains(hdr.Name, "/inputs/") && strings.HasSuffix(hdr.Name, "_libhelper.a") {
			hasAr = true
		}
		rel := hdr.Name
		if idx := strings.IndexByte(rel, '/'); idx >= 0 {
			rel = rel[idx+1:]
		}
		dst := filepath.Join(unpackDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, raw, os.FileMode(hdr.Mode)); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"repro.sh", "summary.json", "link.args"} {
		if seen[f] == 0 {
			t.Errorf("bundle missing %q (seen=%v)", f, seen)
		}
	}
	for _, forbid := range []string{"standalone_tu.c", "reduced.ll"} {
		if _, ok := seen[forbid]; ok {
			t.Errorf("linker bug bundle should omit %q", forbid)
		}
	}
	if len(dupObjs) != 2 || !hasAr {
		t.Fatalf("expected 2 disambiguated dup.o files + libhelper.a in bundle, dupObjs=%v hasAr=%v", dupObjs, hasAr)
	}

	runRepro := exec.Command("sh", filepath.Join(unpackDir, "repro.sh"))
	runRepro.Dir = unpackDir
	runRepro.Env = append(os.Environ(),
		"CLANG="+goodTC.Clang,
		"BAD_LD="+badLinker,
		"GOOD_LD="+goodLinker,
	)
	if out, err := runRepro.CombinedOutput(); err != nil {
		t.Fatalf("repro.sh failed: %v\n%s", err, out)
	}
	if err := exec.Command(filepath.Join(unpackDir, "bad.out")).Run(); err == nil {
		t.Fatalf("expected bad.out from repro.sh to fail")
	}
	if err := exec.Command(filepath.Join(unpackDir, "good.out")).Run(); err != nil {
		t.Fatalf("expected good.out from repro.sh to pass: %v", err)
	}

	unitTmp := t.TempDir()
	objA := filepath.Join(unitTmp, "s1", "x.o")
	objB := filepath.Join(unitTmp, "s2", "x.o")
	arPath := filepath.Join(unitTmp, "libfoo.a")
	_ = mkdirAll(filepath.Dir(objA), filepath.Dir(objB))
	_ = os.WriteFile(objA, []byte("OBJ_A_DATA"), 0o644)
	_ = os.WriteFile(objB, []byte("OBJ_B_DATA"), 0o644)
	_ = os.WriteFile(arPath, []byte("AR_DATA"), 0o644)
	decomp := &linkDecomp{
		targetLink: linkRec{
			CWD: unitTmp,
			FullArgs: []string{
				"--sysroot=/host/sysroot", "-B", "/host/bin",
				"-isysroot", "/host/sdk",
				"-Wl,-export_dynamic", "-framework", "CoreFoundation",
				objA, objB, arPath, "-o", "app", "--ld-path=/bad/ld",
			},
		},
		units: []*compiledObj{
			{GoodObj: objA, BadObj: objA},
			{GoodObj: objB, BadObj: objB},
		},
		directIdx: map[string]int{evalSymlinksExisting(objA): 0, evalSymlinksExisting(objB): 1},
		archives:  []archiveGroup{{goodPath: arPath, badPath: arPath}},
	}
	staged, ok := stageLinkerReproInputs(decomp, 1024)
	if !ok {
		t.Fatalf("stageLinkerReproInputs unexpectedly failed")
	}
	var linkArgsRaw string
	for _, e := range staged {
		if e.name == "link.args" {
			linkArgsRaw = string(e.data)
		}
	}
	for _, want := range []string{"-Wl,-export_dynamic", "-framework", "CoreFoundation", "inputs/0000_x.o", "inputs/0001_x.o", "inputs/0002_libfoo.a"} {
		if !strings.Contains(linkArgsRaw, want) {
			t.Errorf("link.args missing %q:\n%s", want, linkArgsRaw)
		}
	}
	for _, forbid := range []string{"/host/sysroot", "/host/bin", "/host/sdk", "/bad/ld"} {
		if strings.Contains(linkArgsRaw, forbid) {
			t.Errorf("link.args leaked host arg %q:\n%s", forbid, linkArgsRaw)
		}
	}
	if _, ok := stageLinkerReproInputs(decomp, 10); ok {
		t.Fatalf("expected stageLinkerReproInputs to reject bundle exceeding maxBytes")
	}
}
