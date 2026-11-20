package main

import (
	"archive/tar"
	"bufio"
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

	maxAliveTVIRBodyLines = 600

	defaultCommitTimeout = 90 * time.Minute
	commitReserveMargin  = 5 * time.Minute
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
	CommitTimeout time.Duration
	Jobs          int

	buildClang func(ctx context.Context, wtDir, buildDir, sha string) (string, error)
	testClang  func(ctx context.Context, clangBin, sha string) (bool, string, error)
}

type triageResult struct {
	Dropped         bool      `json:"dropped"`
	DropReason      string    `json:"drop_reason,omitempty"`
	BuildFailed     bool      `json:"build_failed,omitempty"`
	IsICE           bool      `json:"is_ice,omitempty"`
	Incident        *incident `json:"incident,omitempty"`
	BundlePath      string    `json:"bundle_path,omitempty"`
	CommitBisectErr string    `json:"commit_bisect_err,omitempty"`
}

func commitBisectBudget(ctx context.Context, timeout time.Duration) (time.Duration, bool) {
	if timeout <= 0 {
		timeout = defaultCommitTimeout
	}
	dl, ok := ctx.Deadline()
	if !ok {
		return timeout, true
	}
	rem := time.Until(dl)
	reserve := min(commitReserveMargin, timeout)
	avail := rem - reserve
	if avail <= 0 {
		return 0, false
	}
	return min(timeout, avail), true
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
		if err := ctx.Err(); err != nil {
			return nil, runOut{}, err
		}
		dir := filepath.Join(absWork, name)
		src := filepath.Join(dir, "src")
		if err := copyTreeClean(baseSrc, src); err != nil {
			return nil, runOut{}, fmt.Errorf("copy source %s: %w", name, err)
		}
		ws, out, err := o.Runner.build(ctx, runConfig{
			Recipe: o.Recipe, Spec: o.Spec, Profile: prof, TC: tc,
			WorkDir: dir, SrcDir: src, ExtraCFlags: extraC, ExtraEnv: extraEnv, SaveLTOTemps: saveLTO,
		})
		if err == nil && ctx.Err() != nil {
			return nil, runOut{}, ctx.Err()
		}
		return ws, out, err
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
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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
		out := o.Runner.testOne(ctx, o.Recipe, badWS, testID, nil, o.TestTimeout)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if out.Passed {
			return &triageResult{Dropped: true, DropReason: "flaky"}, nil
		}
	}

	goodWS, goodOut, err := buildProfile("good-build", o.Profile, o.GoodTC, nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("good build: %w", err)
	}
	if !goodOut.Passed {
		return &triageResult{Dropped: true, DropReason: "not_regression"}, nil
	}
	goodTest := o.Runner.testOne(ctx, o.Recipe, goodWS, testID, nil, o.TestTimeout)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !goodTest.Passed {
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sanEnv := sanitizerEnv()
	sanWS, sanOut, err := buildProfile("asan-ubsan", profDiagSan, o.GoodTC, nil, sanEnv, false)
	if err != nil {
		return nil, fmt.Errorf("asan/ubsan build: %w", err)
	}
	if !sanOut.Passed && !isCross(o.Spec) && !hasSanitizerReport(sanOut.Output) && isMissingSanitizerRuntime(sanOut.Output) {
		if hostTC, err := resolveToolchain(o.Spec.ID, "", "", "", "", ""); err == nil &&
			hostTC != nil && filepath.Clean(hostTC.Clang) != filepath.Clean(o.GoodTC.Clang) {
			if ws, out, err := buildProfile("asan-ubsan-host", profDiagSan, hostTC, nil, sanEnv, false); err == nil {
				sanWS, sanOut = ws, out
			}
		}
	}
	if err := ctx.Err(); err != nil {
		_ = os.RemoveAll(filepath.Join(absWork, "asan-ubsan"))
		_ = os.RemoveAll(filepath.Join(absWork, "asan-ubsan-host"))
		return nil, err
	}
	if !sanOut.Passed {
		_ = os.RemoveAll(filepath.Join(absWork, "asan-ubsan"))
		_ = os.RemoveAll(filepath.Join(absWork, "asan-ubsan-host"))
		if hasSanitizerReport(sanOut.Output) {
			return &triageResult{Dropped: true, DropReason: "upstream_ub"}, nil
		}
		return nil, fmt.Errorf("asan/ubsan build failed without sanitizer trap (exit %d): %s", sanOut.ExitCode, tailText(sanOut.Output, 1500))
	}
	sanTest := o.Runner.testOne(ctx, o.Recipe, sanWS, testID, sanEnv, o.TestTimeout)
	sanPassed := sanTest.Passed
	_ = os.RemoveAll(filepath.Join(absWork, "asan-ubsan"))
	_ = os.RemoveAll(filepath.Join(absWork, "asan-ubsan-host"))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !sanPassed && hasSanitizerReport(sanTest.Output) {
		return &triageResult{Dropped: true, DropReason: "upstream_ub"}, nil
	}

	consWS, consOut, err := buildProfile("conservative", o.Profile, o.BadTC, conservativeFlags(), nil, false)
	if err != nil {
		return nil, fmt.Errorf("conservative build: %w", err)
	}
	consIndep := consOut.Passed && !o.Runner.testOne(ctx, o.Recipe, consWS, testID, nil, o.TestTimeout).Passed
	_ = os.RemoveAll(filepath.Join(absWork, "conservative"))
	if ownCleanSrc {
		_ = os.RemoveAll(baseSrc)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	runObjTest := func(runCtx context.Context) (bool, string, error) {
		out := o.Runner.testOne(runCtx, o.Recipe, badWS, testID, nil, o.TestTimeout)
		if err := runCtx.Err(); err != nil {
			return false, out.Output, err
		}
		return out.Passed, out.Output, nil
	}
	objRes, err := bisectObjects(ctx, objectBisectOpts{
		Spec: o.Spec, Profile: o.Profile, GoodTC: o.GoodTC, BadTC: o.BadTC,
		GoodBuildDir: goodWS.BuildDir, BadBuildDir: badWS.BuildDir, BadManifestDir: badWS.ManifestDir,
		ScratchDir: filepath.Join(absWork, "object-bisect"),
		Test:       runObjTest,
	})
	if err != nil {
		return nil, fmt.Errorf("object bisect: %w", err)
	}

	passDir := filepath.Join(absWork, "pass-bisect")
	passRes, err := bisectPass(ctx, o.Spec, o.BadTC, objRes.Culprit, filepath.Join(passDir, "pass"), objRes.relinkSingle)
	if o.Profile == profReleaseLTO && !objRes.UsedNativeLTO && (err != nil || passRes.CulpritPassIndex == 0) {
		_, _, _ = objRes.relinkSingle(ctx, objRes.Culprit.BadObj)
		if natObj, natErr := bisectObjects(ctx, objectBisectOpts{
			Spec: o.Spec, Profile: o.Profile, GoodTC: o.GoodTC, BadTC: o.BadTC,
			GoodBuildDir: goodWS.BuildDir, BadBuildDir: badWS.BuildDir, BadManifestDir: badWS.ManifestDir,
			ScratchDir: filepath.Join(absWork, "object-bisect-lto"), ForceNativeLTO: true,
			Test: runObjTest,
		}); natErr == nil && natObj.UsedNativeLTO {
			if natPass, natPassErr := bisectPass(ctx, o.Spec, o.BadTC, natObj.Culprit, filepath.Join(passDir, "pass-lto"), natObj.relinkSingle); natPassErr == nil && (err != nil || natPass.CulpritPassIndex > 0) {
				objRes, passRes, err = natObj, natPass, nil
				_ = os.RemoveAll(filepath.Join(passDir, "pass"))
			} else {
				_ = os.RemoveAll(filepath.Join(passDir, "pass-lto"))
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("pass bisect: %w", err)
	}
	culpritTU := formatCulpritTU(badWS.SrcDir, badWS.BuildDir, objRes.Culprit)

	tuPath, tuName, tuCmd := captureStandaloneTU(ctx, o.Spec, o.Profile, o.BadTC, objRes.Culprit, filepath.Join(passDir, "standalone"))
	redRes, err := runLLVMReduce(ctx, o, badWS, testID, objRes, passRes, filepath.Join(passDir, "reduce"))
	if err != nil {
		return nil, fmt.Errorf("llvm-reduce: %w", err)
	}

	aliveBefore, aliveAfter := passRes.BeforeIRPath, passRes.AfterIRPath
	if redRes.ReducedBeforePath != "" && redRes.ReducedAfterPath != "" {
		aliveBefore, aliveAfter = redRes.ReducedBeforePath, redRes.ReducedAfterPath
	}
	llubiBeforeFunc, llubiAfterFunc := passRes.BeforeIRPath, passRes.AfterIRPath
	if redRes.ReducedBeforePath != "" && redRes.ReducedAfterPath != "" && passRes.CulpritFunc != "" && irDefinesFunction(redRes.ReducedBeforePath, passRes.CulpritFunc) {
		llubiBeforeFunc, llubiAfterFunc = redRes.ReducedBeforePath, redRes.ReducedAfterPath
	}

	var aliveRes, llubiRes formalResult
	if passRes.IsCodeGenPass {
		msg := "culprit pass occurs in backend CodeGen after LLVM IR optimization"
		aliveRes, llubiRes = formalResult{Status: formalUnsupported, Output: msg}, formalResult{Status: formalUnsupported, Output: msg}
	} else if passRes.IsInterprocedural {
		aliveRes = formalResult{Status: formalUnsupported, Output: "interprocedural pass not verified with single-function alive-tv"}
		llubiRes = runLLUBI(ctx, o.BadTC.LLUBI, passRes.BeforeFullIRPath, passRes.AfterFullIRPath,
			llubiBeforeFunc, llubiAfterFunc, passRes.CulpritFunc, 25*time.Second)
	} else {
		aliveRes = runAliveTV(ctx, o.BadTC.AliveTV, aliveBefore, aliveAfter, 60*time.Second)
		llubiRes = runLLUBI(ctx, o.BadTC.LLUBI, passRes.BeforeFullIRPath, passRes.AfterFullIRPath,
			llubiBeforeFunc, llubiAfterFunc, passRes.CulpritFunc, 25*time.Second)
	}

	asanUBSanClean, conf := classifyConfidence(o.Spec, sanPassed, consIndep, diagO0, aliveRes)

	culpritSHA, culpritSubj, commitErr, err := runTriageCommitBisect(ctx, o, absWork, objRes)
	if err != nil {
		return nil, err
	}

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
		IsCodeGenPass:               passRes.IsCodeGenPass,
		CulpritFunc:                 passRes.CulpritFunc,
		DiagO0Status:                diagO0,
		ASanUBSanClean:              asanUBSanClean,
		ConservativeFlagIndependent: consIndep,
		AliveTVStatus:               aliveRes.Status,
		AliveTVOutput:               aliveRes.Output,
		LLUBIStatus:                 llubiRes.Status,
		LLUBIOutput:                 llubiRes.Output,
		ReducedIR:                   redRes.ReducedIR,
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
		if bundlePath, err = packageReproducerBundle(ctx, inc, o.BundleDir, tuPath, tuName, passRes.BeforeIRPath, passRes.AfterIRPath, redRes.ReducedPath, redRes.ReducedBeforePath, redRes.ReducedAfterPath, passRes.BeforeAsmPath, passRes.AfterAsmPath); err != nil {
			return nil, fmt.Errorf("package reproducer bundle: %w", err)
		}
	}
	return &triageResult{Incident: inc, BundlePath: bundlePath, CommitBisectErr: commitErr}, nil
}

func runTriageCommitBisect(ctx context.Context, o triageOpts, absWork string, objRes *objectBisectResult) (culpritSHA, culpritSubj, commitErr string, err error) {
	if strings.TrimSpace(o.LLVMSrcDir) == "" || o.GoodSHA == "" || o.BadSHA == "" || objRes == nil || objRes.Culprit == nil {
		return "", "", "", nil
	}
	if err := ctx.Err(); err != nil {
		return "", "", "", err
	}
	commitDur, ok := commitBisectBudget(ctx, o.CommitTimeout)
	if !ok {
		dl, _ := ctx.Deadline()
		return "", "", fmt.Sprintf("skipped: insufficient remaining time (%s) before triage deadline", max(0, time.Until(dl)).Round(time.Second)), nil
	}
	commitCtx, cancel := context.WithTimeout(ctx, commitDur)
	defer cancel()
	cObj := *objRes.Culprit
	if len(cObj.Args) > 0 && cObj.GoodImportBC != "" && o.testClang == nil && o.BadTC != nil {
		probeObj := filepath.Join(absWork, "commit-probe-src.o")
		repro := false
		if compileSingleTUWithClang(commitCtx, o.BadTC.Clang, o.Spec, o.BadTC.SDKRoot, &cObj, probeObj) == nil {
			if pass, _, err := objRes.relinkSingle(commitCtx, probeObj); err == nil && !pass {
				repro = true
			}
		}
		if !repro {
			// source compile cannot relink or reproduce against ThinLTO peers, bisect from GoodImportBC
			cObj.Args = nil
		}
	}
	if err := commitCtx.Err(); err != nil {
		if ctx.Err() != nil {
			return "", "", "", ctx.Err()
		}
		return "", "", err.Error(), nil
	}
	var sdkRoot string
	if o.BadTC != nil {
		sdkRoot = o.BadTC.SDKRoot
	}
	sha, subj, err := bisectCommit(commitCtx, commitBisectOpts{
		LLVMSrcDir: o.LLVMSrcDir, GoodSHA: o.GoodSHA, BadSHA: o.BadSHA,
		WorkDir: filepath.Join(absWork, "commit-bisect"), Spec: o.Spec, Jobs: o.Jobs,
		Culprit: &cObj, SDKRoot: sdkRoot, RelinkAndTest: objRes.relinkSingle,
		buildClang: o.buildClang, testClang: o.testClang,
	})
	if err != nil {
		if ctx.Err() != nil {
			return "", "", "", ctx.Err()
		}
		return "", "", err.Error(), nil
	}
	return sha, sanitizeText(subj), "", nil
}

func classifyConfidence(spec platformSpec, sanPassed, consIndep bool, diagO0 string, aliveRes formalResult) (bool, string) {
	sanFlags, _ := profileCompilerFlags(profDiagSan, spec)
	asanUBSanClean := sanPassed && slices.ContainsFunc(sanFlags, func(f string) bool { return strings.Contains(f, "address") })
	conf := confNeedsReview
	if aliveRes.ProvesBug {
		conf = confConfirmed
	} else if sanPassed && consIndep && diagO0 == "pass" && aliveRes.Status != aliveVerified {
		conf = confLikely
	}
	return asanUBSanClean, conf
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

func stripIRLineComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\\':
			if inQuote && i+1 < len(line) {
				i++
			}
		case '"':
			inQuote = !inQuote
		case ';':
			if !inQuote {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return strings.TrimSpace(line)
}

func countIRBodyLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	inDef, inFunc := false, false
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		code := stripIRLineComment(line)
		if !inFunc {
			if !inDef {
				if !strings.HasPrefix(code, "define ") {
					continue
				}
				switch {
				case strings.HasSuffix(code, "{"):
					inFunc = true
				case strings.Contains(code, "{") && strings.HasSuffix(code, "}"):
					n++
				default:
					inDef = true
				}
				continue
			}
			if code == "" {
				continue
			}
			switch {
			case strings.HasSuffix(code, "{"):
				inDef, inFunc = false, true
			case strings.Contains(code, "{") && strings.HasSuffix(code, "}"):
				inDef = false
				n++
			}
			continue
		}
		if code == "}" {
			inFunc = false
			continue
		}
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#dbg_") ||
			strings.HasPrefix(line, "call void @llvm.dbg.") || strings.HasPrefix(line, "tail call void @llvm.dbg.") ||
			strings.HasPrefix(line, "musttail call void @llvm.dbg.") || strings.HasPrefix(line, "notail call void @llvm.dbg.") {
			continue
		}
		n++
	}
	return n
}

func smallerReducedPair(redBefore, redAfter, origBefore, origAfter string) bool {
	if origBefore == "" || origAfter == "" || !fileExists(origBefore) || !fileExists(origAfter) {
		return true
	}
	return max(countIRBodyLines(redBefore), countIRBodyLines(redAfter)) < max(countIRBodyLines(origBefore), countIRBodyLines(origAfter))
}

func runAliveTV(ctx context.Context, bin, beforeIR, afterIR string, timeout time.Duration) formalResult {
	if beforeIR != "" && afterIR != "" {
		if n := max(countIRBodyLines(beforeIR), countIRBodyLines(afterIR)); n > maxAliveTVIRBodyLines {
			return formalResult{
				Status: formalUnsupported,
				Output: fmt.Sprintf("IR exceeds alive-tv size cutoff (%d > %d body lines)", n, maxAliveTVIRBodyLines),
			}
		}
	}
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
		return formalResult{Status: llubiMismatch, Output: headText(summary, 2000)}
	}
	if strings.Contains(bRes.output, "passing null values for all arguments") || strings.Contains(aRes.output, "passing null values for all arguments") {
		return formalResult{Status: formalUnsupported, Output: headText(firstNonEmpty(bRes.output, aRes.output), 2000)}
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

type reduceResult struct {
	ReducedPath, ReducedIR, ReducedBeforePath, ReducedAfterPath string
}

func insertIntoFilelist(orig, cwd, candObj, extraObj, dst string) (bool, error) {
	raw, err := os.ReadFile(orig)
	if err != nil {
		return false, err
	}
	candCanon := resolvePath(cwd, candObj)
	var b bytes.Buffer
	inserted := false
	for _, line := range nonEmptyLines(string(raw)) {
		b.WriteString(line)
		b.WriteByte('\n')
		if !inserted && (line == candObj || resolvePath(cwd, line) == candCanon) {
			b.WriteString(extraObj)
			b.WriteByte('\n')
			inserted = true
		}
	}
	if !inserted {
		return false, nil
	}
	if err := os.WriteFile(dst, b.Bytes(), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func appendExtraReduceObj(rr reduceRelink, extraObj, scratchDir string) (reduceRelink, bool) {
	if extraObj == "" {
		return rr, false
	}
	out := rr
	out.LinkArgs = slices.Clone(rr.LinkArgs)
	out.ArMembers = slices.Clone(rr.ArMembers)
	if out.ArOut != "" {
		out.ArMembers = append(out.ArMembers, extraObj)
		return out, true
	}
	if out.CandObj == "" {
		return rr, false
	}
	candCanon := resolvePath(out.LinkDir, out.CandObj)
	for i, a := range out.LinkArgs {
		if a == out.CandObj || (!strings.HasPrefix(a, "-") && resolvePath(out.LinkDir, a) == candCanon) {
			out.LinkArgs = slices.Insert(out.LinkArgs, i+1, extraObj)
			return out, true
		}
	}
	dst := filepath.Join(scratchDir, "filelist_reduce_split.txt")
	for i := 0; i < len(out.LinkArgs); i++ {
		a := out.LinkArgs[i]
		if a == "-filelist" && i+1 < len(out.LinkArgs) {
			if ok, err := insertIntoFilelist(resolvePath(out.LinkDir, out.LinkArgs[i+1]), out.LinkDir, out.CandObj, extraObj, dst); err == nil && ok {
				out.LinkArgs[i+1] = dst
				return out, true
			}
			i++
			continue
		}
		if strings.HasPrefix(a, "-Wl,") {
			toks := strings.Split(a[4:], ",")
			for j := 0; j+1 < len(toks); j++ {
				if toks[j] == "-filelist" {
					if ok, err := insertIntoFilelist(resolvePath(out.LinkDir, toks[j+1]), out.LinkDir, out.CandObj, extraObj, dst); err == nil && ok {
						toks[j+1] = dst
						out.LinkArgs[i] = "-Wl," + strings.Join(toks, ",")
						return out, true
					}
					j++
				}
			}
			continue
		}
		if a == "-Xlinker" && i+3 < len(out.LinkArgs) && out.LinkArgs[i+1] == "-filelist" && out.LinkArgs[i+2] == "-Xlinker" {
			if ok, err := insertIntoFilelist(resolvePath(out.LinkDir, out.LinkArgs[i+3]), out.LinkDir, out.CandObj, extraObj, dst); err == nil && ok {
				out.LinkArgs[i+3] = dst
				return out, true
			}
			i += 3
		}
	}
	return rr, false
}

func runLLVMReduce(ctx context.Context, o triageOpts, badWS *workspace, testID string, objRes *objectBisectResult, passRes *passBisectResult, scratchDir string) (reduceResult, error) {
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		return reduceResult{}, err
	}
	outIR := filepath.Join(scratchDir, "reduced.ll")
	redBefore := filepath.Join(scratchDir, "reduced_before.ll")
	redAfter := filepath.Join(scratchDir, "reduced_after.ll")
	_ = os.Remove(outIR)
	_ = os.Remove(redBefore)
	_ = os.Remove(redAfter)
	inputIR := passRes.BeforeFullIRPath
	if !fileExists(inputIR) {
		inputIR = passRes.BeforeIRPath
	}
	if !fileExists(inputIR) {
		return reduceResult{}, nil
	}
	fallback := func() (reduceResult, error) {
		src := passRes.BeforeIRPath
		if !fileExists(src) {
			src = inputIR
		}
		if err := copyFile(src, outIR, 0o644); err != nil {
			return reduceResult{}, err
		}
		raw, _ := os.ReadFile(outIR)
		return reduceResult{ReducedPath: outIR, ReducedIR: inlineReducedIR(string(raw))}, nil
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
	optNoBase := withoutBaselineFlags(optFlags, o.Spec.BaselineFlags)
	o0NoBase := withoutBaselineFlags(o0Flags, o.Spec.BaselineFlags)
	goodOptNoBase := withoutBaselineFlags(goodOptFlags, o.Spec.BaselineFlags)
	strippedDiffers := !slices.Equal(optNoBase, optFlags) || !slices.Equal(o0NoBase, o0Flags) || !slices.Equal(goodOptNoBase, goodOptFlags)

	type reduceCand struct {
		ir   string
		spec reduceSpec
	}
	makeSpec := func(r reduceRelink, bClang, aClang string, bFlags, aFlags []string) reduceSpec {
		return reduceSpec{
			reduceRelink: r, BeforeClang: bClang, AfterClang: aClang,
			BeforeFlags: bFlags, AfterFlags: aFlags,
			TestCmd: testCmd, TestDir: testDir, TestEnv: testEnv, TimeoutSec: timeoutSec,
		}
	}
	addCands := func(dst []reduceCand, ir string, r reduceRelink) []reduceCand {
		strip := strippedDiffers && irHasTargetAttrs(ir)
		if o.GoodTC != nil && o.GoodTC.Clang != "" {
			if strip {
				dst = append(dst, reduceCand{ir: ir, spec: makeSpec(r, o.GoodTC.Clang, o.BadTC.Clang, goodOptNoBase, optNoBase)})
			}
			dst = append(dst, reduceCand{ir: ir, spec: makeSpec(r, o.GoodTC.Clang, o.BadTC.Clang, goodOptFlags, optFlags)})
		}
		if strip {
			dst = append(dst, reduceCand{ir: ir, spec: makeSpec(r, o.BadTC.Clang, o.BadTC.Clang, o0NoBase, optNoBase)})
		}
		dst = append(dst, reduceCand{ir: ir, spec: makeSpec(r, o.BadTC.Clang, o.BadTC.Clang, o0Flags, optFlags)})
		return dst
	}
	var cands []reduceCand
	if !passRes.IsInterprocedural && passRes.CulpritFunc != "" && o.BadTC.LLVMExtract != "" && fileExists(o.BadTC.LLVMExtract) && fileExists(passRes.BeforeFullIRPath) {
		funcIR := filepath.Join(scratchDir, "culprit_func.ll")
		restIR := filepath.Join(scratchDir, "rest_funcs.ll")
		restObj := filepath.Join(scratchDir, "lmc_reduce_rest.o")
		_, errF := runToolInDir(ctx, o.BadTC.LLVMExtract, []string{"--func=" + passRes.CulpritFunc, "-S", passRes.BeforeFullIRPath, "-o", funcIR}, "")
		_, errR := runToolInDir(ctx, o.BadTC.LLVMExtract, []string{"--delete", "--func=" + passRes.CulpritFunc, "-S", passRes.BeforeFullIRPath, "-o", restIR}, "")
		if errF == nil && errR == nil && fileNonEmpty(funcIR) && fileNonEmpty(restIR) {
			_, errC := runToolInDir(ctx, o.BadTC.Clang, append(slices.Clone(o0Flags), "-x", "ir", "-c", restIR, "-o", restObj), "")
			if errC != nil {
				_, errC = runToolInDir(ctx, o.BadTC.Clang, append(slices.Clone(optFlags), "-x", "ir", "-c", restIR, "-o", restObj), "")
			}
			if errC == nil && fileNonEmpty(restObj) {
				if splitRR, ok := appendExtraReduceObj(rr, restObj, scratchDir); ok {
					cands = addCands(cands, funcIR, splitRR)
				}
			}
		}
	}
	cands = addCands(cands, inputIR, rr)

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
			for _, c := range addCands(nil, preoptIR, rr) {
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
		timeout = 5 * time.Minute
	}
	redCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(redCtx, o.BadTC.LLVMReduce, "-j", "1",
		fmt.Sprintf("--max-pass-iterations=%d", maxIter), "--test="+scriptPath, "-o", outIR, chosenIR)
	cmd.Dir = scratchDir
	setCmdProcessGroup(cmd)
	_ = cmd.Run()

	raw, err := os.ReadFile(outIR)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 || !evalReduceCheck(ctx, spec, outIR) {
		if chosenIR != inputIR && evalReduceCheck(ctx, spec, chosenIR) {
			if err := copyFile(chosenIR, outIR, 0o644); err != nil {
				return fallback()
			}
			raw, err = os.ReadFile(outIR)
			if err != nil || len(bytes.TrimSpace(raw)) == 0 {
				return fallback()
			}
		} else {
			return fallback()
		}
	}

	res := reduceResult{ReducedPath: outIR, ReducedIR: inlineReducedIR(string(raw))}
	passName := strings.TrimSpace(passRes.CulpritPass)
	if !passRes.IsCodeGenPass && o.BadTC.Opt != "" && fileExists(o.BadTC.Opt) && isValidOptPassName(passName) {
		if _, err := runToolInDir(ctx, o.BadTC.Opt, []string{"-passes=" + passName, "-S", outIR, "-o", redAfter}, ""); err == nil && fileNonEmpty(redAfter) {
			afterRaw, readErr := os.ReadFile(redAfter)
			if readErr == nil && cleanIR(string(afterRaw)) != cleanIR(string(raw)) && smallerReducedPair(outIR, redAfter, passRes.BeforeIRPath, passRes.AfterIRPath) {
				beforePass, bOK := runReduceStep(ctx, spec, o.BadTC.Clang, o0Flags, outIR)
				afterPass, aOK := false, false
				if bOK && beforePass {
					afterPass, aOK = runReduceStep(ctx, spec, o.BadTC.Clang, o0Flags, redAfter)
				}
				if bOK && beforePass && aOK && !afterPass && copyFile(outIR, redBefore, 0o644) == nil {
					res.ReducedBeforePath = redBefore
					res.ReducedAfterPath = redAfter
				} else {
					_ = os.Remove(redBefore)
					_ = os.Remove(redAfter)
				}
			} else {
				_ = os.Remove(redAfter)
			}
		} else {
			_ = os.Remove(redAfter)
		}
	}
	return res, nil
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

func runReduceStep(ctx context.Context, spec reduceSpec, clang string, flags []string, candIR string) (pass, ok bool) {
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

func evalReduceCheck(ctx context.Context, spec reduceSpec, candIR string) bool {
	refPass, ok := runReduceStep(ctx, spec, spec.BeforeClang, spec.BeforeFlags, candIR)
	if !ok || !refPass {
		return false
	}
	badPass, ok := runReduceStep(ctx, spec, spec.AfterClang, spec.AfterFlags, candIR)
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

func irHasTargetAttrs(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte(`"target-cpu"=`)) || bytes.Contains(data, []byte(`"target-features"=`))
}

func withoutBaselineFlags(flags, baseline []string) []string {
	out := make([]string, 0, len(flags))
	for _, f := range flags {
		if !slices.Contains(baseline, f) {
			out = append(out, f)
		}
	}
	return out
}

func packageReproducerBundle(ctx context.Context, inc *incident, outDir, tuPath, tuName, beforeIR, afterIR, reducedIR, reducedBeforeIR, reducedAfterIR, beforeAsm, afterAsm string) (string, error) {
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
	for _, f := range [][2]string{{"reduced_before.ll", reducedBeforeIR}, {"reduced_after.ll", reducedAfterIR}} {
		if f[1] != "" && fileNonEmpty(f[1]) {
			if b, err := os.ReadFile(f[1]); err == nil && len(b) > 0 {
				entries = append(entries, entry{name: f[0], mode: 0o644, data: b})
			}
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
	lvl := incidentOptLevel(inc)

	b.WriteString("\nCLANG=\"${CLANG:-clang}\"\n")
	if inc.IsCodeGenPass {
		b.WriteString("LLC=\"${LLC:-llc}\"\n")
	} else {
		b.WriteString("OPT=\"${OPT:-opt}\"\n")
	}
	b.WriteString("ALIVE_TV=\"${ALIVE_TV:-alive-tv}\"\n\n")
	b.WriteString("if [ -s reduced.ll ]; then\n")
	fmt.Fprintf(&b, "  \"$CLANG\"%s %s -x ir -c reduced.ll -o good.o\n", targetFlag, joinFlags(o0Flags))
	fmt.Fprintf(&b, "  \"$CLANG\"%s %s -x ir -c reduced.ll -o bad.o\n", targetFlag, joinFlags(optFlags))
	if inc.IsCodeGenPass {
		fmt.Fprintf(&b, "  if command -v \"$LLC\" >/dev/null 2>&1; then\n    \"$LLC\" %s reduced.ll -o bad.s\n  fi\n", lvl)
	} else if p := sanitizeText(strings.TrimSpace(inc.CulpritPass)); isValidOptPassName(p) {
		fmt.Fprintf(&b, "  if command -v \"$OPT\" >/dev/null 2>&1; then\n    \"$OPT\" -passes=%s -S reduced.ll -o opt_after.ll\n  fi\n", p)
	} else {
		fmt.Fprintf(&b, "  if command -v \"$OPT\" >/dev/null 2>&1; then\n    \"$OPT\" %s -S reduced.ll -o opt_after.ll\n  fi\n", lvl)
	}
	b.WriteString("fi\n\n")
	b.WriteString("if command -v \"$ALIVE_TV\" >/dev/null 2>&1; then\n")
	b.WriteString("  if [ -s reduced_before.ll ] && [ -s reduced_after.ll ]; then\n")
	b.WriteString("    \"$ALIVE_TV\" --smt-to=30000 reduced_before.ll reduced_after.ll || true\n")
	b.WriteString("  elif [ -s before.ll ] && [ -s after.ll ]; then\n")
	b.WriteString("    \"$ALIVE_TV\" --smt-to=30000 before.ll after.ll || true\n")
	b.WriteString("  fi\n")
	b.WriteString("fi\n")
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
