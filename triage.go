package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	formalUnavailable = "unavailable"
	formalUnsupported = "unsupported"
	formalTimeout     = "timeout"

	aliveMiscompile = "miscompile"
	aliveVerified   = "verified"

	llubiMismatch   = "mismatch"
	llubiEquivalent = "equivalent"
	llubiSourceUB   = "source_ub"
)

var (
	errNotInteresting = errors.New("not interesting")
	reUBSanRuntime    = regexp.MustCompile(`(?m)(?::\d+(?::\d+)?|<unknown>|0x[0-9a-fA-F]+|\+0x[0-9a-fA-F]+\)): runtime error: `)
	reAliveCorrect    = regexp.MustCompile(`(?m)^\s*(\d+)\s+correct transformations?\b`)
	reAliveIncorrect  = regexp.MustCompile(`(?m)^\s*(\d+)\s+incorrect transformations?\b`)
	reAliveFailed     = regexp.MustCompile(`(?m)^\s*(\d+)\s+failed-to-prove transformations?\b`)
	reAliveErrors     = regexp.MustCompile(`(?m)^\s*(\d+)\s+Alive2 errors?\b`)
)

type triageOpts struct {
	Runner        *runner
	Recipe        *recipe
	Spec          platformSpec
	Profile       string
	GoodTC, BadTC *toolchain
	GoodSHA       string
	BadSHA        string
	TestID        string
	WorkDir       string
	Tarball       string
	SrcDir        string
	BundleDir     string
	BundleBaseURL string
	LLVMSrcDir    string
	FlakyAttempts int
	TestTimeout   time.Duration
	ReduceMaxIter int
	ReduceTimeout time.Duration
	Jobs          int

	buildClang func(ctx context.Context, wtDir, buildDir, sha string) (string, error)
	testClang  func(ctx context.Context, clangBin, sha string) (bool, string, error)
}

type triageResult struct {
	Dropped     bool      `json:"dropped"`
	DropReason  string    `json:"drop_reason,omitempty"`
	BuildFailed bool      `json:"build_failed,omitempty"`
	IsICE       bool      `json:"is_ice,omitempty"`
	Incident    *incident `json:"incident,omitempty"`
	BundlePath  string    `json:"bundle_path,omitempty"`
}

func triage(ctx context.Context, o triageOpts) (*triageResult, error) {
	if o.Runner == nil || o.Recipe == nil || o.GoodTC == nil || o.BadTC == nil || strings.TrimSpace(o.WorkDir) == "" {
		return nil, errors.New("runner, recipe, good/bad toolchains, and workDir are required")
	}
	if err := os.MkdirAll(o.WorkDir, 0o755); err != nil {
		return nil, err
	}
	absWork := evalSymlinksExisting(o.WorkDir)

	// copy per build since in-tree configure/make recipes dirty $SRC_DIR
	baseSrc := o.SrcDir
	ownCleanSrc := false
	if baseSrc == "" {
		baseSrc = filepath.Join(absWork, "clean-src")
		ownCleanSrc = true
		tb := o.Tarball
		if tb == "" {
			var err error
			if tb, err = fetchSource(ctx, o.Recipe, o.Runner.CacheDir, o.Runner.MirrorBase, nil); err != nil {
				return nil, fmt.Errorf("fetch source: %w", err)
			}
		}
		if err := unpackSource(ctx, tb, baseSrc, o.Recipe.StripComponents); err != nil {
			return nil, fmt.Errorf("unpack source: %w", err)
		}
	} else {
		baseSrc = evalSymlinksExisting(baseSrc)
	}

	buildProfile := func(name, prof string, tc *toolchain, extraC, extraEnv []string, saveLTO bool) (*workspace, runOut, error) {
		dir := filepath.Join(absWork, name)
		src := filepath.Join(dir, "src")
		if err := copyTreeClean(baseSrc, src); err != nil {
			return nil, runOut{}, fmt.Errorf("copy source %s: %w", name, err)
		}
		return o.Runner.build(ctx, runConfig{
			Recipe: o.Recipe, Spec: o.Spec, Profile: prof, TC: tc,
			WorkDir: dir, SrcDir: src, ExtraCFlags: extraC, ExtraEnv: extraEnv, SaveLTOTemps: saveLTO,
		})
	}

	badWS, badOut, err := buildProfile("bad-build", o.Profile, o.BadTC, nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("bad build: %w", err)
	}
	if !badOut.Passed {
		return &triageResult{Dropped: true, BuildFailed: true, IsICE: detectICE(badOut.Output)}, nil
	}

	testID := strings.TrimSpace(o.TestID)
	if testID == "" {
		allOut, failIDs := o.Runner.testAll(ctx, o.Recipe, badWS, nil, o.TestTimeout)
		if allOut.Passed {
			return &triageResult{Dropped: true, DropReason: "flaky"}, nil
		}
		if len(failIDs) > 0 {
			testID = failIDs[0]
		} else {
			testID = o.Recipe.SmokeTest
		}
	}

	attempts := o.FlakyAttempts
	if attempts <= 0 {
		attempts = 3
	}
	for range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if o.Runner.testOne(ctx, o.Recipe, badWS, testID, nil, o.TestTimeout).Passed {
			return &triageResult{Dropped: true, DropReason: "flaky"}, nil
		}
	}

	goodWS, goodOut, err := buildProfile("good-build", o.Profile, o.GoodTC, nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("good build: %w", err)
	}
	if !goodOut.Passed || !o.Runner.testOne(ctx, o.Recipe, goodWS, testID, nil, o.TestTimeout).Passed {
		return &triageResult{Dropped: true, DropReason: "not_regression"}, nil
	}

	diagO0 := "build_fail"
	if o0WS, o0Out, err := buildProfile("diag-o0", profDiagO0, o.BadTC, nil, nil, false); err == nil && o0Out.Passed {
		if o.Runner.testOne(ctx, o.Recipe, o0WS, testID, nil, o.TestTimeout).Passed {
			diagO0 = "pass"
		} else {
			diagO0 = "test_fail"
		}
	}
	_ = os.RemoveAll(filepath.Join(absWork, "diag-o0"))

	sanEnv := sanitizerEnv()
	sanWS, sanOut, err := buildProfile("asan-ubsan", profDiagSan, o.BadTC, nil, sanEnv, false)
	if err != nil {
		return nil, fmt.Errorf("asan/ubsan build: %w", err)
	}
	if !sanOut.Passed && !isCross(o.Spec) && !hasSanitizerReport(sanOut.Output) && isMissingSanitizerRuntime(sanOut.Output) {
		if hostTC, err := resolveToolchain(o.Spec.ID, "", "", "", "", ""); err == nil &&
			hostTC != nil && filepath.Clean(hostTC.Clang) != filepath.Clean(o.BadTC.Clang) {
			if ws, out, err := buildProfile("asan-ubsan-host", profDiagSan, hostTC, nil, sanEnv, false); err == nil {
				sanWS, sanOut = ws, out
			}
		}
	}
	if !sanOut.Passed {
		_ = os.RemoveAll(filepath.Join(absWork, "asan-ubsan"))
		_ = os.RemoveAll(filepath.Join(absWork, "asan-ubsan-host"))
		if hasSanitizerReport(sanOut.Output) {
			return &triageResult{Dropped: true, DropReason: "upstream_ub"}, nil
		}
		return nil, fmt.Errorf("asan/ubsan build failed without sanitizer trap (exit %d): %s", sanOut.ExitCode, tailText(sanOut.Output, 1500))
	}
	// plain assertion failure at -O1 without a sanitizer report means the bug reproduces at -O1
	if sanTest := o.Runner.testOne(ctx, o.Recipe, sanWS, testID, sanEnv, o.TestTimeout); !sanTest.Passed && hasSanitizerReport(sanTest.Output) {
		_ = os.RemoveAll(filepath.Join(absWork, "asan-ubsan"))
		_ = os.RemoveAll(filepath.Join(absWork, "asan-ubsan-host"))
		return &triageResult{Dropped: true, DropReason: "upstream_ub"}, nil
	}
	_ = os.RemoveAll(filepath.Join(absWork, "asan-ubsan"))
	_ = os.RemoveAll(filepath.Join(absWork, "asan-ubsan-host"))

	consWS, consOut, err := buildProfile("conservative", o.Profile, o.BadTC, conservativeFlags(), nil, false)
	if err != nil {
		return nil, fmt.Errorf("conservative build: %w", err)
	}
	consIndep := consOut.Passed && !o.Runner.testOne(ctx, o.Recipe, consWS, testID, nil, o.TestTimeout).Passed
	_ = os.RemoveAll(filepath.Join(absWork, "conservative"))
	if ownCleanSrc {
		_ = os.RemoveAll(baseSrc)
	}

	objRes, err := bisectObjects(ctx, objectBisectOpts{
		Spec: o.Spec, Profile: o.Profile, GoodTC: o.GoodTC, BadTC: o.BadTC,
		GoodBuildDir: goodWS.BuildDir, BadBuildDir: badWS.BuildDir, BadManifestDir: badWS.ManifestDir,
		ScratchDir: filepath.Join(absWork, "object-bisect"),
		Test: func(runCtx context.Context) (bool, string, error) {
			out := o.Runner.testOne(runCtx, o.Recipe, badWS, testID, nil, o.TestTimeout)
			return out.Passed, out.Output, nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("object bisect: %w", err)
	}

	culpritTU := formatCulpritTU(badWS.SrcDir, badWS.BuildDir, objRes.Culprit)
	passDir := filepath.Join(absWork, "pass-bisect")
	passRes, err := bisectPass(ctx, o.Spec, o.BadTC, objRes.Culprit, filepath.Join(passDir, "pass"), objRes.relinkSingle)
	if err != nil {
		return nil, fmt.Errorf("pass bisect: %w", err)
	}

	var aliveRes, llubiRes formalResult
	if passRes.IsCodeGenPass {
		msg := "culprit pass occurs in backend CodeGen after LLVM IR optimization"
		aliveRes, llubiRes = formalResult{Status: formalUnsupported, Output: msg}, formalResult{Status: formalUnsupported, Output: msg}
	} else if passRes.IsInterprocedural {
		aliveRes = formalResult{Status: formalUnsupported, Output: "interprocedural pass not verified with single-function alive-tv"}
		llubiRes = runLLUBI(ctx, o.BadTC.LLUBI, passRes.BeforeFullIRPath, passRes.AfterFullIRPath,
			passRes.BeforeIRPath, passRes.AfterIRPath, passRes.CulpritFunc, 25*time.Second)
	} else {
		aliveRes = runAliveTV(ctx, o.BadTC.AliveTV, passRes.BeforeIRPath, passRes.AfterIRPath, 60*time.Second)
		llubiRes = runLLUBI(ctx, o.BadTC.LLUBI, passRes.BeforeFullIRPath, passRes.AfterFullIRPath,
			passRes.BeforeIRPath, passRes.AfterIRPath, passRes.CulpritFunc, 25*time.Second)
	}

	tuPath, tuName, tuCmd := captureStandaloneTU(ctx, o.Spec, o.Profile, o.BadTC, objRes.Culprit, filepath.Join(passDir, "standalone"))
	reducedPath, reducedIR, err := runLLVMReduce(ctx, o, badWS, testID, objRes, passRes, filepath.Join(passDir, "reduce"))
	if err != nil {
		return nil, fmt.Errorf("llvm-reduce: %w", err)
	}

	conf := confNeedsReview
	if consIndep || aliveRes.ProvesBug || llubiRes.ProvesBug {
		conf = confConfirmed
	}

	var culpritSHA, culpritSubj string
	if strings.TrimSpace(o.LLVMSrcDir) != "" && o.GoodSHA != "" && o.BadSHA != "" {
		cObj := *objRes.Culprit
		if len(cObj.Args) > 0 && cObj.GoodImportBC != "" && o.testClang == nil {
			probeObj := filepath.Join(absWork, "commit-probe-src.o")
			repro := false
			if compileSingleTUWithClang(ctx, o.BadTC.Clang, o.Spec, o.BadTC.SDKRoot, &cObj, probeObj) == nil {
				if pass, _, err := objRes.relinkSingle(ctx, probeObj); err == nil && !pass {
					repro = true
				}
			}
			if !repro {
				// source compile cannot relink or reproduce against ThinLTO peers, bisect from GoodImportBC
				cObj.Args = nil
			}
		}
		sha, subj, err := bisectCommit(ctx, commitBisectOpts{
			LLVMSrcDir: o.LLVMSrcDir, GoodSHA: o.GoodSHA, BadSHA: o.BadSHA,
			WorkDir: filepath.Join(absWork, "commit-bisect"), Spec: o.Spec, Jobs: o.Jobs,
			Culprit: &cObj, SDKRoot: o.BadTC.SDKRoot, RelinkAndTest: objRes.relinkSingle,
			buildClang: o.buildClang, testClang: o.testClang,
		})
		if err != nil {
			return nil, fmt.Errorf("commit bisect: %w", err)
		}
		culpritSHA, culpritSubj = sha, sanitizeText(subj)
	}

	sanFlags, _ := profileCompilerFlags(profDiagSan, o.Spec)
	asanUBSanClean := slices.ContainsFunc(sanFlags, func(f string) bool { return strings.Contains(f, "address") })

	now := time.Now().UTC()
	incID := buildIncidentID(o.Recipe.Name, o.Spec.ID, o.Profile, testID, o.BadSHA, culpritSHA)
	inc := &incident{
		ID:                          incID,
		Title:                       sanitizeText(buildIncidentTitle(o.Recipe.Name, passRes.CulpritPass, passRes.CulpritFunc, culpritTU)),
		Status:                      incidentOpen,
		Confidence:                  conf,
		GoodSHA:                     o.GoodSHA,
		BadSHA:                      o.BadSHA,
		CulpritSHA:                  culpritSHA,
		CulpritSubject:              culpritSubj,
		CulpritTU:                   culpritTU,
		CulpritPass:                 passRes.CulpritPass,
		CulpritPassIndex:            passRes.CulpritPassIndex,
		CulpritFunc:                 passRes.CulpritFunc,
		DiagO0Status:                diagO0,
		ASanUBSanClean:              asanUBSanClean,
		ConservativeFlagIndependent: consIndep,
		AliveTVStatus:               aliveRes.Status,
		AliveTVOutput:               aliveRes.Output,
		LLUBIStatus:                 llubiRes.Status,
		LLUBIOutput:                 llubiRes.Output,
		ReducedIR:                   reducedIR,
		StandaloneReproCmd:          tuCmd,
		PassDiff:                    passRes.PassDiff,
		Affected:                    []affected{{Package: o.Recipe.Name, Version: o.Recipe.Version, Platform: o.Spec.ID, Profile: o.Profile, TestID: testID}},
		CreatedAt:                   now,
		UpdatedAt:                   now,
	}
	if o.BundleBaseURL != "" {
		if strings.HasSuffix(o.BundleBaseURL, ".tar.zst") {
			inc.BundleURL = o.BundleBaseURL
		} else {
			inc.BundleURL = strings.TrimRight(o.BundleBaseURL, "/") + "/reproducer-" + inc.ID + ".tar.zst"
		}
	}

	var bundlePath string
	if strings.TrimSpace(o.BundleDir) != "" {
		if bundlePath, err = packageReproducerBundle(ctx, inc, o.BundleDir, tuPath, tuName, passRes.BeforeIRPath, passRes.AfterIRPath, reducedPath, passRes.BeforeAsmPath, passRes.AfterAsmPath); err != nil {
			return nil, fmt.Errorf("package reproducer bundle: %w", err)
		}
	}
	return &triageResult{Incident: inc, BundlePath: bundlePath}, nil
}

func containsAny(s string, needles []string) bool {
	return slices.ContainsFunc(needles, func(m string) bool { return strings.Contains(s, m) })
}

func hasSanitizerReport(out string) bool {
	if strings.HasPrefix(out, "ubsan: ") || strings.Contains(out, "\nubsan: ") || reUBSanRuntime.MatchString(out) {
		return true
	}
	return containsAny(out, []string{
		"AddressSanitizer:", "UndefinedBehaviorSanitizer:", "LeakSanitizer:", "Sanitizer:",
		"SEGV on unknown address", "heap-buffer-overflow", "stack-buffer-overflow",
		"heap-use-after-free", "stack-use-after-scope", "stack-use-after-return", "global-buffer-overflow",
		"signed integer overflow:", "shift exponent ", "load of misaligned address", "store to misaligned address",
		"member access within null pointer", "null pointer passed as argument", "execution reached an unreachable program point",
	})
}

func isMissingSanitizerRuntime(out string) bool {
	if strings.Contains(out, "clang_rt") {
		return true
	}
	low := strings.ToLower(out)
	return (strings.Contains(low, "asan") || strings.Contains(low, "ubsan")) &&
		containsAny(low, []string{"cannot find", "cannot open", "no such file", "library not found", "file not found"})
}

type formalResult struct {
	Status, Output string
	ProvesBug      bool
}

func runAliveTV(ctx context.Context, bin, beforeIR, afterIR string, timeout time.Duration) formalResult {
	if bin = strings.TrimSpace(bin); bin == "" || !fileExists(bin) || beforeIR == "" || afterIR == "" {
		return formalResult{Status: formalUnavailable}
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(runCtx, bin, "--smt-to=30000", beforeIR, afterIR).CombinedOutput()
	return parseAliveTVOutput(string(out), err, errors.Is(runCtx.Err(), context.DeadlineExceeded))
}

func parseAliveTVOutput(out string, runErr error, timedOut bool) formalResult {
	raw := strings.TrimSpace(out)
	clipped := headText(raw, 4000)
	if timedOut {
		return formalResult{Status: formalTimeout, Output: clipped}
	}

	matchCount := func(re *regexp.Regexp) (int, bool) {
		m := re.FindStringSubmatch(raw)
		if len(m) < 2 {
			return 0, false
		}
		n, err := strconv.Atoi(m[1])
		return n, err == nil
	}
	correct, hasC := matchCount(reAliveCorrect)
	incorrect, hasI := matchCount(reAliveIncorrect)
	failed, hasF := matchCount(reAliveFailed)
	aliveErrs, hasE := matchCount(reAliveErrors)
	hasSummary := hasC || hasI || hasF || hasE

	if incorrect > 0 || containsAny(raw, []string{"Transformation doesn't verify!", "Target is more poisonous than source",
		"Target's return value is more undefined", "Value mismatch", "Mismatch in memory", "Source is more defined than target"}) {
		return formalResult{Status: aliveMiscompile, Output: clipped, ProvesBug: true}
	}
	if hasSummary {
		switch {
		case failed > 0:
			return formalResult{Status: formalTimeout, Output: clipped}
		case aliveErrs > 0:
			return formalResult{Status: formalUnsupported, Output: clipped}
		case correct > 0 && runErr == nil:
			return formalResult{Status: aliveVerified, Output: clipped}
		default:
			return formalResult{Status: formalUnsupported, Output: clipped}
		}
	}
	switch {
	case strings.Contains(raw, "Timeout"):
		return formalResult{Status: formalTimeout, Output: clipped}
	case runErr != nil || containsAny(raw, []string{"ERROR:", "Unsupported ", "unsupported ",
		"Unknown intrinsic", "Failed to parse", "syntax error", "Assertion ", "LLVM ERROR:"}):
		return formalResult{Status: formalUnsupported, Output: clipped}
	case strings.Contains(raw, "Transformation seems to be correct!"):
		return formalResult{Status: aliveVerified, Output: clipped}
	default:
		return formalResult{Status: formalUnsupported, Output: clipped}
	}
}

func runLLUBI(ctx context.Context, bin, beforeFull, afterFull, beforeFunc, afterFunc, culpritFunc string, timeout time.Duration) formalResult {
	if bin = strings.TrimSpace(bin); bin == "" || !fileExists(bin) {
		return formalResult{Status: formalUnavailable}
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}

	inB, inA, entry := beforeFull, afterFull, "main"
	if inB == "" || !irDefinesFunction(inB, "main") {
		switch {
		case culpritFunc != "" && beforeFunc != "" && afterFunc != "" && irDefinesFunction(beforeFunc, culpritFunc):
			inB, inA, entry = beforeFunc, afterFunc, culpritFunc
		case culpritFunc != "" && inB != "" && irDefinesFunction(inB, culpritFunc):
			entry = culpritFunc
		case inB == "":
			inB, inA = beforeFunc, afterFunc
		}
	}
	if inB == "" || inA == "" {
		return formalResult{Status: formalUnavailable}
	}

	bRes := invokeLLUBI(ctx, bin, inB, entry, false, timeout)
	if bRes.timedOut {
		return formalResult{Status: formalTimeout, Output: headText(bRes.output, 2000)}
	}
	if bRes.unsupported {
		return formalResult{Status: formalUnsupported, Output: headText(bRes.output, 2000)}
	}
	if bRes.ubFailed {
		if strings.Contains(bRes.output, "passing null values for all arguments") {
			return formalResult{Status: formalUnsupported, Output: headText(bRes.output, 2000)}
		}
		// re-run with -verbose to separate unmodeled external calls from source UB
		vRes := invokeLLUBI(ctx, bin, inB, entry, true, timeout)
		if isLLUBIUnsupported(vRes.output) || strings.Contains(vRes.output, "passing null values for all arguments") {
			return formalResult{Status: formalUnsupported, Output: headText(vRes.output, 2000)}
		}
		return formalResult{Status: llubiSourceUB, Output: headText(vRes.output, 2000)}
	}

	aRes := invokeLLUBI(ctx, bin, inA, entry, false, timeout)
	if aRes.timedOut {
		return formalResult{Status: formalTimeout, Output: headText(aRes.output, 2000)}
	}
	if aRes.unsupported {
		return formalResult{Status: formalUnsupported, Output: headText(aRes.output, 2000)}
	}
	summary := fmt.Sprintf("entry=%s before_exit=%d after_exit=%d", entry, bRes.exitCode, aRes.exitCode)
	if aRes.output != "" {
		summary += "\n" + aRes.output
	}
	if aRes.ubFailed || aRes.exitCode != bRes.exitCode {
		return formalResult{Status: llubiMismatch, Output: headText(summary, 2000), ProvesBug: true}
	}
	return formalResult{Status: llubiEquivalent, Output: headText(summary, 2000)}
}

type llubiRun struct {
	exitCode                        int
	output                          string
	ubFailed, unsupported, timedOut bool
}

func invokeLLUBI(ctx context.Context, bin, irPath, entry string, verbose bool, timeout time.Duration) llubiRun {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	args := []string{"-deterministic", "-max-steps=2000000", "-entry-function=" + entry}
	if verbose {
		args = append(args, "-verbose")
	}
	raw, err := exec.CommandContext(runCtx, bin, append(args, irPath)...).CombinedOutput()
	out := strings.TrimSpace(string(raw))
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return llubiRun{exitCode: 124, output: out, timedOut: true}
	}
	if isLLUBIUnsupported(out) {
		return llubiRun{exitCode: 1, output: out, unsupported: true}
	}
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return llubiRun{exitCode: 1, output: out, unsupported: true}
		}
		code = exitErr.ExitCode()
	}
	ub := (strings.Contains(out, "Execution of function") && strings.Contains(out, "failed")) ||
		strings.Contains(out, "resulted in poison return value")
	return llubiRun{exitCode: code, output: out, ubFailed: ub}
}

func isLLUBIUnsupported(out string) bool {
	return containsAny(strings.ToLower(out), []string{
		"function not found in module", "must be definition", "failed to initialize global values",
		"failed to parse bitcode", "unsupported instruction", "unsupported intrinsic",
		"unsupported call", "unsupported external", "unsupported constant:",
		"unrecognized instruction:", "calling declaration",
		"declaration function", "external function", "inline asm", "inlineasm",
		"exceeded max steps", "exceeded maximum number of execution steps", "step limit",
		"maximum stack depth exceeded", "insufficient stack space", "insufficient heap space",
	})
}

func irDefinesFunction(irPath, fnName string) bool {
	data, err := os.ReadFile(irPath)
	if err != nil {
		return false
	}
	plain, quoted := "@"+fnName+"(", "@\""+fnName+"\"("
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "define ") && (strings.Contains(line, plain) || strings.Contains(line, quoted)) {
			return true
		}
	}
	return false
}

func captureStandaloneTU(ctx context.Context, spec platformSpec, prof string, badTC *toolchain, culprit *compiledObj, outDir string) (string, string, string) {
	if culprit == nil || badTC == nil || os.MkdirAll(outDir, 0o755) != nil {
		return "", "", ""
	}
	ext, drv := ".c", "clang"
	if culprit.IsCXX {
		ext, drv = ".cpp", "clang++"
	}
	name := "standalone_tu" + ext
	dst := filepath.Join(outDir, name)
	formatCmd := func() string {
		outObj := "standalone_tu.o"
		if len(culprit.CompileRec.RawArgs) > 0 || len(culprit.CompileRec.FullArgs) > 0 {
			return drv + " " + joinFlags(standaloneCompileArgs(culprit.CompileRec, name, outObj, true))
		}
		flags, _ := profileCompilerFlags(prof, spec)
		flags = append(slices.Clone(crossTargetArgs(spec)), flags...)
		return drv + " " + joinFlags(append(flags, "-c", name, "-o", outObj))
	}
	if pre := culprit.CompileRec.PreprocessedPath; pre != "" && fileExists(pre) {
		if info, err := os.Stat(pre); err == nil && info.Size() > 0 && copyFile(pre, dst, 0o644) == nil {
			return dst, name, formatCmd()
		}
	}
	if culprit.SourceFile == "" && len(culprit.Args) == 0 {
		return "", "", ""
	}
	preArgs := append(stripFlags(culprit.Args, stripMode|stripOutput|stripDep|stripLink|stripLTO, culprit.WorkDir), "-E", "-frewrite-includes", "-o", dst)
	if _, err := runToolInDir(ctx, driverFor(badTC, culprit.IsCXX), preArgs, culprit.WorkDir); err != nil {
		return "", "", ""
	}
	return dst, name, formatCmd()
}

type reduceSpec struct {
	reduceRelink
	BeforeClang string   `json:"before_clang"`
	AfterClang  string   `json:"after_clang"`
	BeforeFlags []string `json:"before_flags"`
	AfterFlags  []string `json:"after_flags"`
	TestCmd     []string `json:"test_cmd"`
	TestDir     string   `json:"test_dir"`
	TestEnv     []string `json:"test_env"`
	TimeoutSec  int      `json:"timeout_sec"`
}

func runLLVMReduce(ctx context.Context, o triageOpts, badWS *workspace, testID string, objRes *objectBisectResult, passRes *passBisectResult, scratchDir string) (string, string, error) {
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		return "", "", err
	}
	outIR := filepath.Join(scratchDir, "reduced.ll")
	inputIR := passRes.BeforeFullIRPath
	if !fileExists(inputIR) {
		inputIR = passRes.BeforeIRPath
	}
	if !fileExists(inputIR) {
		return "", "", nil
	}
	fallback := func() (string, string, error) {
		src := passRes.BeforeIRPath
		if !fileExists(src) {
			src = inputIR
		}
		if err := copyFile(src, outIR, 0o644); err != nil {
			return "", "", err
		}
		raw, _ := os.ReadFile(outIR)
		return outIR, headText(string(raw), 32000), nil
	}

	if o.BadTC == nil || o.BadTC.LLVMReduce == "" || !fileExists(o.BadTC.LLVMReduce) || objRes.buildRelink == nil {
		return fallback()
	}
	testCmd, testDir, testEnv := o.Runner.testOneCmd(o.Recipe, badWS, testID, nil)
	if len(testCmd) == 0 {
		return fallback()
	}
	rr, err := objRes.buildRelink(filepath.Join(scratchDir, "cand.o"))
	if err != nil {
		return fallback()
	}

	timeoutSec := int(o.TestTimeout.Seconds())
	if timeoutSec <= 0 {
		timeoutSec = int(crossTimeout(o.Spec, 3*time.Minute).Seconds())
	}

	var tuCG []string
	if objRes.Culprit != nil {
		cgArgs := objRes.Culprit.Args
		if len(cgArgs) == 0 {
			cgArgs = objRes.Culprit.CompileRec.FullArgs
		}
		tuCG = tuCodegenFlags(cgArgs, objRes.Culprit.WorkDir)
	}
	optFlags := append(irCompileFlags(o.Spec, o.Profile, o.BadTC), tuCG...)
	o0Flags := append(irO0CompileFlags(o.Spec, o.Profile, o.BadTC), tuCG...)
	goodOptFlags := optFlags
	if o.GoodTC != nil {
		goodOptFlags = append(irCompileFlags(o.Spec, o.Profile, o.GoodTC), tuCG...)
	}

	type reduceCand struct {
		ir   string
		spec reduceSpec
	}
	makeSpec := func(bClang, aClang string, bFlags, aFlags []string) reduceSpec {
		return reduceSpec{
			reduceRelink: rr, BeforeClang: bClang, AfterClang: aClang,
			BeforeFlags: bFlags, AfterFlags: aFlags,
			TestCmd: testCmd, TestDir: testDir, TestEnv: testEnv, TimeoutSec: timeoutSec,
		}
	}
	var cands []reduceCand
	cands = append(cands, reduceCand{ir: inputIR, spec: makeSpec(o.BadTC.Clang, o.BadTC.Clang, o0Flags, optFlags)})
	if o.GoodTC != nil && o.GoodTC.Clang != "" {
		cands = append(cands, reduceCand{ir: inputIR, spec: makeSpec(o.GoodTC.Clang, o.BadTC.Clang, goodOptFlags, optFlags)})
	}

	var chosenIR string
	var spec reduceSpec
	found := false
	for _, c := range cands {
		if evalReduceCheck(ctx, c.spec, c.ir) {
			chosenIR, spec, found = c.ir, c.spec, true
			break
		}
	}
	if !found && objRes.Culprit != nil {
		preoptIR := filepath.Join(scratchDir, "preopt.ll")
		if _, err := compileCulpritWithBisect(ctx, o.Spec, o.BadTC, objRes.Culprit, 0, "ir", preoptIR, false); err == nil && fileNonEmpty(preoptIR) {
			preCands := []reduceCand{{ir: preoptIR, spec: makeSpec(o.BadTC.Clang, o.BadTC.Clang, o0Flags, optFlags)}}
			if o.GoodTC != nil && o.GoodTC.Clang != "" {
				preCands = append(preCands, reduceCand{ir: preoptIR, spec: makeSpec(o.GoodTC.Clang, o.BadTC.Clang, goodOptFlags, optFlags)})
			}
			for _, c := range preCands {
				if evalReduceCheck(ctx, c.spec, c.ir) {
					chosenIR, spec, found = c.ir, c.spec, true
					break
				}
			}
		}
	}
	if !found {
		return fallback()
	}

	specPath := filepath.Join(scratchDir, "reduce_spec.json")
	if err := writeJSONAtomic(specPath, spec); err != nil {
		return fallback()
	}
	selfExe := o.Runner.LMCBin
	if selfExe == "" {
		if selfExe, err = os.Executable(); err != nil {
			return fallback()
		}
	}
	scriptPath := filepath.Join(scratchDir, "interesting.sh")
	script := fmt.Sprintf("#!/bin/sh\nexec %s reduce-check -spec %s \"$1\"\n", shQuote(selfExe), shQuote(specPath))
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		return fallback()
	}

	maxIter, timeout := o.ReduceMaxIter, o.ReduceTimeout
	if maxIter <= 0 {
		maxIter = 2
	}
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	redCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(redCtx, o.BadTC.LLVMReduce, "-j", "1",
		fmt.Sprintf("--max-pass-iterations=%d", maxIter), "--test="+scriptPath, "-o", outIR, chosenIR)
	cmd.Dir = scratchDir
	setCmdProcessGroup(cmd)
	_ = cmd.Run()

	raw, err := os.ReadFile(outIR)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return fallback()
	}
	return outIR, headText(string(raw), 32000), nil
}

func cmdReduceCheck(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("reduce-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	specPath := fs.String("spec", "", "reduce spec json path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *specPath == "" || fs.NArg() != 1 {
		return errors.New("usage: lmc reduce-check -spec <json> <candidate.ll>")
	}
	var spec reduceSpec
	if err := readJSON(*specPath, &spec); err != nil {
		return err
	}
	if !evalReduceCheck(ctx, spec, fs.Arg(0)) {
		return errNotInteresting
	}
	return nil
}

func evalReduceCheck(ctx context.Context, spec reduceSpec, candIR string) bool {
	step := func(clang string, flags []string) (pass, ok bool) {
		args := append(slices.Clone(flags), "-x", "ir", "-c", candIR, "-o", spec.CandObj)
		if _, err := runToolInDir(ctx, clang, args, ""); err != nil {
			return false, false
		}
		if spec.ArOut != "" && createStaticArchive(ctx, spec.ArTool, spec.RanlibTool, spec.ArOut, spec.ArMembers) != nil {
			return false, false
		}
		if _, err := runToolInDir(ctx, spec.LinkDriver, spec.LinkArgs, spec.LinkDir); err != nil {
			return false, false
		}
		to := time.Duration(spec.TimeoutSec) * time.Second
		if to <= 0 {
			to = 3 * time.Minute
		}
		return runCmd(ctx, spec.TestCmd, spec.TestDir, spec.TestEnv, to).Passed, true
	}
	refPass, ok := step(spec.BeforeClang, spec.BeforeFlags)
	if !ok || !refPass {
		return false
	}
	badPass, ok := step(spec.AfterClang, spec.AfterFlags)
	return ok && !badPass
}

func irCompileFlags(spec platformSpec, prof string, tc *toolchain) []string {
	profFlags, _ := profileCompilerFlags(prof, spec)
	flags := slices.Clone(crossTargetArgs(spec))
	baseLen := len(flags)
	for _, f := range profFlags {
		if !strings.HasPrefix(f, "-flto") {
			flags = append(flags, f)
		}
	}
	if len(flags) == baseLen {
		flags = append(flags, "-O2")
	}
	flags = append(flags, "-Wno-error")
	if spec.IsDarwin && tc != nil && tc.SDKRoot != "" {
		flags = append(flags, "-isysroot", tc.SDKRoot)
	}
	return flags
}

func irO0CompileFlags(spec platformSpec, prof string, tc *toolchain) []string {
	flags := append(slices.Clone(crossTargetArgs(spec)), "-O0")
	if prof == profReleaseLTO {
		flags = append(flags, spec.BaselineFlags...)
	}
	flags = append(flags, "-Wno-error")
	if spec.IsDarwin && tc != nil && tc.SDKRoot != "" {
		flags = append(flags, "-isysroot", tc.SDKRoot)
	}
	return flags
}

func packageReproducerBundle(ctx context.Context, inc *incident, outDir, tuPath, tuName, beforeIR, afterIR, reducedIR, beforeAsm, afterAsm string) (string, error) {
	if inc == nil || inc.ID == "" {
		return "", errors.New("incident with non-empty ID is required")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	zstdBin, err := exec.LookPath("zstd")
	if err != nil {
		return "", fmt.Errorf("zstd binary required: %w", err)
	}
	summary, err := json.MarshalIndent(inc, "", "  ")
	if err != nil {
		return "", err
	}
	summary = append(summary, '\n')

	type entry struct {
		name string
		mode int64
		data []byte
	}
	entries := []entry{
		{name: "repro.sh", mode: 0o755, data: []byte(generateReproScript(inc))},
		{name: "summary.json", mode: 0o644, data: summary},
	}
	if tuPath != "" && fileExists(tuPath) {
		if b, err := os.ReadFile(tuPath); err == nil {
			entries = append(entries, entry{name: firstNonEmpty(tuName, filepath.Base(tuPath)), mode: 0o644, data: b})
		}
	} else {
		entries = append(entries, entry{name: "standalone_tu.c", mode: 0o644, data: []byte("/* Bitcode/LTO module reproduction; see before.ll, after.ll, and reduced.ll */\n")})
	}
	for _, f := range [][2]string{{"before.ll", beforeIR}, {"after.ll", afterIR}, {"reduced.ll", reducedIR}} {
		if f[1] != "" && fileExists(f[1]) {
			b, _ := os.ReadFile(f[1])
			entries = append(entries, entry{name: f[0], mode: 0o644, data: b})
		} else if f[0] == "reduced.ll" {
			entries = append(entries, entry{name: f[0], mode: 0o644})
		}
	}
	for _, f := range [][2]string{{"before.s", beforeAsm}, {"after.s", afterAsm}} {
		if f[1] != "" && fileExists(f[1]) {
			if b, err := os.ReadFile(f[1]); err == nil {
				entries = append(entries, entry{name: f[0], mode: 0o644, data: b})
			}
		}
	}
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.name, b.name) })

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	prefix, epoch := "reproducer-"+inc.ID+"/", time.Unix(0, 0).UTC()
	for _, e := range entries {
		hdr := &tar.Header{Name: prefix + e.name, Mode: e.mode, Size: int64(len(e.data)), ModTime: epoch, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return "", err
		}
		if _, err := tw.Write(e.data); err != nil {
			return "", err
		}
	}
	if err := tw.Close(); err != nil {
		return "", err
	}

	bundlePath := filepath.Join(outDir, "reproducer-"+inc.ID+".tar.zst")
	cmd := exec.CommandContext(ctx, zstdBin, "-q", "-f", "-o", bundlePath)
	cmd.Stdin = bytes.NewReader(tarBuf.Bytes())
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("zstd compress %s: %w (%s)", bundlePath, err, strings.TrimSpace(string(out)))
	}
	return bundlePath, nil
}

func generateReproScript(inc *incident) string {
	oneLine := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	var b strings.Builder
	b.WriteString("#!/bin/sh\nset -eu\n\n")
	fmt.Fprintf(&b, "# %s\n", oneLine(inc.ID))
	if inc.CulpritSHA != "" {
		fmt.Fprintf(&b, "# commit: %s\n", oneLine(inc.CulpritSHA))
	}
	fmt.Fprintf(&b, "# range: %s..%s\n", oneLine(inc.GoodSHA), oneLine(inc.BadSHA))
	if inc.CulpritFunc != "" {
		fmt.Fprintf(&b, "# pass: %s (%d) on %s\n", oneLine(inc.CulpritPass), inc.CulpritPassIndex, oneLine(inc.CulpritFunc))
	} else {
		fmt.Fprintf(&b, "# pass: %s (%d)\n", oneLine(inc.CulpritPass), inc.CulpritPassIndex)
	}
	if inc.StandaloneReproCmd != "" {
		fmt.Fprintf(&b, "# standalone: %s\n", oneLine(inc.StandaloneReproCmd))
	}
	if !inc.ASanUBSanClean && slices.ContainsFunc(inc.Affected, func(a affected) bool { return a.Platform == platLinuxRISCV64 }) {
		b.WriteString("# sanitizers: ubsan only (asan disabled on linux-riscv64)\n")
	}

	prof := profDistroO2
	var spec platformSpec
	if len(inc.Affected) > 0 {
		if inc.Affected[0].Profile != "" {
			prof = inc.Affected[0].Profile
		}
		spec, _ = lookupPlatform(inc.Affected[0].Platform)
	}
	targetFlag := crossTargetFlag(inc.Affected)
	o0Flags := []string{"-O0"}
	optFlags := []string{"-O2"}
	if prof == profReleaseLTO {
		o0Flags = append(o0Flags, spec.BaselineFlags...)
		optFlags = append([]string{"-O3"}, spec.BaselineFlags...)
	}

	b.WriteString("\nCLANG=\"${CLANG:-clang}\"\nALIVE_TV=\"${ALIVE_TV:-alive-tv}\"\n\n")
	fmt.Fprintf(&b, "\"$CLANG\"%s %s -x ir -c reduced.ll -o good.o\n", targetFlag, joinFlags(o0Flags))
	fmt.Fprintf(&b, "\"$CLANG\"%s %s -x ir -c reduced.ll -o bad.o\n", targetFlag, joinFlags(optFlags))
	b.WriteString("\nif [ -s before.ll ] && [ -s after.ll ] && command -v \"$ALIVE_TV\" >/dev/null 2>&1; then\n  \"$ALIVE_TV\" --smt-to=30000 before.ll after.ll || true\nfi\n")
	return b.String()
}

func formatCulpritTU(srcDir, buildDir string, culprit *compiledObj) string {
	if culprit == nil {
		return ""
	}
	if culprit.SourceFile != "" {
		if rel, ok := relWithinDir(srcDir, culprit.SourceFile); ok {
			return filepath.ToSlash(rel)
		}
		return filepath.Base(culprit.SourceFile)
	}
	if culprit.RelPath != "" {
		return filepath.ToSlash(culprit.RelPath)
	}
	if rel, ok := relWithinDir(buildDir, culprit.BadObj); ok {
		return filepath.ToSlash(rel)
	}
	return filepath.Base(culprit.BadObj)
}

func buildIncidentID(pkg, plat, prof, testID, badSHA, culpritSHA string) string {
	short := strings.TrimSpace(firstNonEmpty(culpritSHA, badSHA))
	if len(short) > 8 {
		short = short[:8]
	}
	if short == "" {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", pkg, plat, prof, testID)))
		short = hex.EncodeToString(h[:4])
	}
	parts := []string{firstNonEmpty(sanitizeSlug(pkg), "incident")}
	if s := sanitizeSlug(plat); s != "" {
		parts = append(parts, s)
	}
	if s := sanitizeSlug(prof); s != "" {
		parts = append(parts, s)
	}
	parts = append(parts, sanitizeSlug(short))
	return strings.Join(parts, "-")
}

func buildIncidentTitle(pkg, passName, culpritFunc, culpritTU string) string {
	pass, target := firstNonEmpty(passName, "optimization"), firstNonEmpty(culpritFunc, culpritTU)
	switch {
	case pkg != "" && target != "":
		return fmt.Sprintf("%s: %s in %s", pkg, pass, target)
	case pkg != "":
		return fmt.Sprintf("%s: %s", pkg, pass)
	case target != "":
		return fmt.Sprintf("%s in %s", pass, target)
	default:
		return pass
	}
}

func sanitizeSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func copyTreeClean(srcRoot, dstRoot string) error {
	if err := os.RemoveAll(dstRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dstRoot), 0o755); err != nil {
		return err
	}
	if out, err := exec.Command("cp", "-RPp", filepath.Clean(srcRoot), dstRoot).CombinedOutput(); err != nil {
		return fmt.Errorf("cp %s %s: %w (%s)", srcRoot, dstRoot, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func headText(s string, maxBytes int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxBytes {
		return s
	}
	return s[:maxBytes] + "\n...[truncated]"
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
