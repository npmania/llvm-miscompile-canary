package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

const maxBisectConsecSkips = 8

var (
	errBisectSkip = errors.New("skip")
	bisectLineRe  = regexp.MustCompile(`^BISECT:\s+running pass \((\d+)\)\s+(.+?)\s+on\s+(.+)$`)
)

func bisectFirstFail(n int, fails func(int) (bool, error)) (int, error) {
	if n < 2 {
		return 0, fmt.Errorf("bisect requires at least 2 points (got %d)", n)
	}
	lo, hi := 0, n-1
	var skipped map[int]bool
	sawGood, sawBad := false, false
	consecSkips := 0
	for lo < hi {
		mid := pickMid(lo, hi, skipped)
		if mid < lo || mid >= hi {
			break
		}
		bad, err := fails(mid)
		if errors.Is(err, errBisectSkip) {
			if skipped == nil {
				skipped = make(map[int]bool)
			}
			skipped[mid] = true
			consecSkips++
			if consecSkips >= maxBisectConsecSkips {
				return 0, fmt.Errorf("bisect aborted after %d consecutive skipped probes", consecSkips)
			}
			continue
		}
		if err != nil {
			return 0, err
		}
		consecSkips = 0
		if bad {
			sawBad = true
			hi = mid
		} else {
			sawGood = true
			lo = mid + 1
		}
	}
	if !sawBad {
		bad, err := fails(hi)
		if errors.Is(err, errBisectSkip) {
			return 0, errors.New("bisect: endpoint skipped and no failing point observed")
		}
		if err != nil {
			return 0, err
		}
		if !bad {
			return 0, errors.New("bisect: all probed points passed")
		}
	}
	if !sawGood {
		return 0, errors.New("bisect: all probed points failed without a passing baseline")
	}
	return hi, nil
}

func pickMid(lo, hi int, skipped map[int]bool) int {
	c := lo + (hi-lo)/2
	if !skipped[c] {
		return c
	}
	for d := 1; c-d >= lo || c+d < hi; d++ {
		if c-d >= lo && !skipped[c-d] {
			return c - d
		}
		if c+d < hi && !skipped[c+d] {
			return c + d
		}
	}
	return -1
}

type compiledObj struct {
	RelPath, GoodObj, BadObj, SourceFile, WorkDir string
	IsCXX                                         bool
	Args                                          []string
	CompileRec                                    compileRec
	GoodNativeLTOObj, BadNativeLTOObj             string
	GoodImportBC, BadImportBC                     string
}

type reduceRelink struct {
	LinkDriver string   `json:"link_driver"`
	LinkDir    string   `json:"link_dir"`
	LinkArgs   []string `json:"link_args"`
	CandObj    string   `json:"cand_obj"`
	ArTool     string   `json:"ar_tool,omitempty"`
	RanlibTool string   `json:"ranlib_tool,omitempty"`
	ArOut      string   `json:"ar_out,omitempty"`
	ArMembers  []string `json:"ar_members,omitempty"`
}

type objectBisectOpts struct {
	Spec           platformSpec
	Profile        string
	GoodTC, BadTC  *toolchain
	GoodBuildDir   string
	BadBuildDir    string
	BadManifestDir string
	ScratchDir     string
	ForceNativeLTO bool
	Test           func(context.Context) (bool, string, error)
}

type objectBisectResult struct {
	Culprit       *compiledObj
	UsedNativeLTO bool
	IsLinkerBug   bool
	LinkerName    string
	LinkDiff      string
	TargetLink    *linkRec
	decomp        *linkDecomp
	relinkSingle  func(context.Context, string) (bool, string, error)
	relinkLinker  func(context.Context, string) (bool, string, error)
	buildRelink   func(string) (reduceRelink, error)
}

func bisectObjects(ctx context.Context, o objectBisectOpts) (*objectBisectResult, error) {
	if o.GoodTC == nil || o.BadTC == nil || o.Test == nil {
		return nil, errors.New("good toolchain, bad toolchain, and test func are required")
	}
	goodBuild := evalSymlinksExisting(o.GoodBuildDir)
	badBuild := evalSymlinksExisting(o.BadBuildDir)
	if err := os.MkdirAll(o.ScratchDir, 0o755); err != nil {
		return nil, err
	}
	badComp, err := readCompileRecs(o.BadManifestDir)
	if err != nil {
		return nil, fmt.Errorf("read bad compile manifest: %w", err)
	}
	badComp = slices.DeleteFunc(badComp, func(r compileRec) bool { return r.ExitCode != 0 })
	badLinks, err := readLinkRecs(o.BadManifestDir)
	if err != nil {
		return nil, fmt.Errorf("read bad link manifest: %w", err)
	}
	badLinks = slices.DeleteFunc(badLinks, func(r linkRec) bool { return r.ExitCode != 0 })

	var links []linkRec
	linkOrder := make(map[string]int)
	skippedMissing := 0
	for _, bl := range badLinks {
		rel, ok := relWithinDir(badBuild, bl.Output)
		if !ok {
			continue
		}
		if !fileExists(bl.Output) {
			skippedMissing++
			continue
		}
		if idx, seen := linkOrder[rel]; seen {
			links[idx] = bl
		} else {
			linkOrder[rel] = len(links)
			links = append(links, bl)
		}
	}
	if len(links) == 0 {
		if skippedMissing > 0 {
			return nil, fmt.Errorf("no link records found in wrapper manifests (%d manifest outputs missing on disk)", skippedMissing)
		}
		return nil, errors.New("no link records found in wrapper manifests")
	}

	backups := make([]string, len(links))
	for i, lr := range links {
		backups[i] = filepath.Join(o.ScratchDir, "orig_links", strconv.Itoa(i)+"_"+filepath.Base(lr.Output))
		_ = copyFile(lr.Output, backups[i], 0)
	}

	runTest := func() (bool, error) {
		pass, _, err := o.Test(ctx)
		return pass, err
	}

	targetIdx := 0
	if len(links) > 1 {
		goodBackups := make([]string, len(links))
		var relinkable []int
		var lastErr error
		for i := range links {
			if err := relinkMapped(ctx, o.GoodTC, goodBuild, badBuild, links[i], o.ScratchDir, strconv.Itoa(i)); err != nil {
				lastErr = err
				_ = copyFile(backups[i], links[i].Output, 0)
				continue
			}
			gb := filepath.Join(o.ScratchDir, "good_links", strconv.Itoa(i)+"_"+filepath.Base(links[i].Output))
			if err := copyFile(links[i].Output, gb, 0); err != nil {
				return nil, err
			}
			goodBackups[i] = gb
			relinkable = append(relinkable, i)
		}
		if len(relinkable) == 0 {
			return nil, fmt.Errorf("failed to relink any of %d link targets with good toolchain: %w", len(links), lastErr)
		}
		setLink := func(i int, useBad bool) error {
			if useBad {
				return copyFile(backups[i], links[i].Output, 0)
			}
			return copyFile(goodBackups[i], links[i].Output, 0)
		}
		allGood, err := runTest()
		if err != nil {
			return nil, err
		}
		if !allGood {
			for _, li := range relinkable {
				_ = setLink(li, true)
			}
			if skippedMissing > 0 {
				return nil, fmt.Errorf("relinking %d/%d binaries with good toolchain still failed test (%d manifest outputs missing on disk)", len(relinkable), len(links), skippedMissing)
			}
			return nil, fmt.Errorf("relinking %d/%d binaries with good toolchain still failed test", len(relinkable), len(links))
		}
		if len(relinkable) == 1 {
			targetIdx = relinkable[0]
		} else {
			pos, err := bisectFirstFail(len(relinkable)+1, func(k int) (bool, error) {
				if k == 0 {
					return false, nil
				}
				for j, li := range relinkable {
					if err := setLink(li, j < k); err != nil {
						return false, err
					}
				}
				pass, err := runTest()
				return !pass, err
			})
			if err != nil {
				return nil, err
			}
			targetIdx = relinkable[pos-1]
		}
		for _, li := range relinkable {
			if err := setLink(li, li == targetIdx); err != nil {
				return nil, err
			}
		}
	}

	targetLink := links[targetIdx]
	if synth, sb, ok, err := splitDirectCompileLink(ctx, o, goodBuild, badBuild, targetLink, badComp); err != nil {
		return nil, err
	} else if ok {
		targetLink, badComp = synth, append(badComp, sb...)
	}

	if o.Profile == profReleaseLTO && o.ForceNativeLTO {
		if res, ok := tryThinLTONativeBisect(ctx, o, goodBuild, badBuild, targetLink, badComp); ok {
			return res, nil
		}
	}

	// bisect input bitcode first to keep source-TU attribution; fall back to save-temps native .lto.o
	d, err := expandLinkUnits(o, goodBuild, badBuild, targetLink, badComp)
	if err != nil {
		return nil, err
	}
	if len(d.units) == 0 {
		return nil, fmt.Errorf("link target %s has zero bisectable object units", targetLink.Output)
	}
	finish := func(cIdx, pIdx int) *objectBisectResult {
		return &objectBisectResult{
			Culprit:      d.units[cIdx],
			relinkSingle: d.makeSingle(o.Test, cIdx, pIdx),
			buildRelink:  func(cand string) (reduceRelink, error) { return d.freezeRelink(ctx, cIdx, pIdx, cand) },
		}
	}

	testPick := func(pick func(int) string) (bool, error) {
		if err := d.relink(ctx, pick); err != nil {
			return false, err
		}
		return runTest()
	}
	pickGood := func(i int) string { return d.units[i].GoodObj }
	goodPass, err := testPick(pickGood)
	if err != nil {
		return nil, fmt.Errorf("relink %s with all good objects: %w", targetLink.Output, err)
	}
	if !goodPass {
		if res, ok, lErr := detectLinkerBug(ctx, o, d, targetLink, runTest, pickGood); lErr != nil {
			return nil, lErr
		} else if ok {
			return res, nil
		}
		if o.Profile == profReleaseLTO {
			if res, ok := tryThinLTONativeBisect(ctx, o, goodBuild, badBuild, targetLink, badComp); ok {
				return res, nil
			}
		}
		return nil, fmt.Errorf("relinking %s with all good objects still failed test", targetLink.Output)
	}
	if len(d.units) == 1 {
		return finish(0, -1), nil
	}

	pos, err := bisectFirstFail(len(d.units)+1, func(k int) (bool, error) {
		if k == 0 {
			return false, nil
		}
		pass, err := testPick(func(i int) string {
			if i < k {
				return d.units[i].BadObj
			}
			return d.units[i].GoodObj
		})
		return !pass, err
	})
	if err != nil {
		return nil, err
	}
	cIdx := pos - 1

	singlePass, err := testPick(func(i int) string {
		if i == cIdx {
			return d.units[i].BadObj
		}
		return d.units[i].GoodObj
	})
	if err != nil {
		return nil, err
	}
	pIdx := -1
	if singlePass && cIdx > 0 {
		pPos, err := bisectFirstFail(cIdx+1, func(k int) (bool, error) {
			if k == 0 {
				return false, nil
			}
			pass, err := testPick(func(i int) string {
				if i == cIdx || i < k {
					return d.units[i].BadObj
				}
				return d.units[i].GoodObj
			})
			return !pass, err
		})
		if err != nil {
			return nil, err
		}
		pIdx = pPos - 1
	}
	return finish(cIdx, pIdx), nil
}

func detectLinkerBug(ctx context.Context, o objectBisectOpts, d *linkDecomp, targetLink linkRec, runTest func() (bool, error), pickGood func(int) string) (*objectBisectResult, bool, error) {
	if o.GoodTC.Linker == "" || o.BadTC.Linker == "" {
		return nil, false, nil
	}
	linkOut := targetLink.Output
	if linkOut != "" && !filepath.IsAbs(linkOut) && targetLink.CWD != "" {
		linkOut = filepath.Join(targetLink.CWD, linkOut)
	}
	if err := d.relinkWith(ctx, o.GoodTC, o.GoodTC.Linker, pickGood); err != nil {
		return nil, false, nil
	}
	goodLDPass, err := runTest()
	if err != nil || !goodLDPass {
		return nil, false, err
	}
	goodSyms, goodOK := exportedSymbols(ctx, o.GoodTC, linkOut)
	if err := d.relinkWith(ctx, o.GoodTC, o.BadTC.Linker, pickGood); err != nil {
		return nil, false, nil
	}
	badLDPass, err := runTest()
	if err != nil || badLDPass {
		return nil, false, err
	}
	var linkDiff string
	if goodOK {
		if badSyms, badOK := exportedSymbols(ctx, o.BadTC, linkOut); badOK {
			linkDiff = diffExportedSymbols(ctx, linkOut, goodSyms, badSyms)
		}
	}
	linkerName := filepath.Base(o.BadTC.Linker)
	if o.Profile == profReleaseLTO {
		linkerName += " (ThinLTO)"
	}
	tlCopy := targetLink
	return &objectBisectResult{
		IsLinkerBug: true,
		LinkerName:  linkerName,
		LinkDiff:    linkDiff,
		TargetLink:  &tlCopy,
		decomp:      d,
		relinkLinker: func(rctx context.Context, lldBin string) (bool, string, error) {
			if err := d.relinkWith(rctx, o.GoodTC, lldBin, pickGood); err != nil {
				return false, "", err
			}
			return o.Test(rctx)
		},
	}, true, nil
}

func exportedSymbols(ctx context.Context, tc *toolchain, binPath string) ([]string, bool) {
	if binPath == "" {
		return nil, false
	}
	var nmBin string
	if tc != nil && tc.NM != "" {
		nmBin = tc.NM
	} else if p, err := exec.LookPath("llvm-nm"); err == nil {
		nmBin = p
	} else if p, err := exec.LookPath("nm"); err == nil {
		nmBin = p
	}
	if nmBin == "" {
		return nil, false
	}
	var args []string
	switch {
	case strings.Contains(filepath.Base(nmBin), "llvm-nm"):
		args = []string{"--extern-only", "--defined-only", "--just-symbol-name", binPath}
	case (tc != nil && tc.Spec.IsDarwin) || runtime.GOOS == "darwin":
		args = []string{"-gU", "-j", binPath}
	default:
		args = []string{"-g", "--defined-only", "-j", binPath}
	}
	out, err := exec.CommandContext(ctx, nmBin, args...).Output()
	if err != nil {
		return nil, false
	}
	var syms []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasSuffix(line, ":") {
			continue
		}
		syms = append(syms, line)
	}
	if len(syms) == 0 {
		return nil, false
	}
	slices.Sort(syms)
	return slices.Compact(syms), true
}

func diffExportedSymbols(ctx context.Context, target string, goodSyms, badSyms []string) string {
	if len(goodSyms) == 0 || len(badSyms) == 0 {
		return ""
	}
	base := filepath.Base(target)
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "binary"
	}
	return unifiedDiff(ctx, "good ("+base+")", strings.Join(goodSyms, "\n"), "bad ("+base+")", strings.Join(badSyms, "\n"))
}

func relinkMapped(ctx context.Context, tc *toolchain, goodBuild, badBuild string, rec linkRec, scratchDir, tag string) error {
	mapInput := func(canon string) (string, bool) {
		rel, ok := relWithinDir(badBuild, canon)
		if !ok {
			return "", false
		}
		cand := filepath.Join(goodBuild, rel)
		switch strings.ToLower(filepath.Ext(cand)) {
		case ".o", ".lo", ".obj", ".bc", ".a":
			if fileExists(cand) {
				return cand, true
			}
		}
		return "", false
	}
	args, err := rewriteLinkArgs(rec.FullArgs, linkRewriteOpts{
		cwd: rec.CWD, scratchDir: scratchDir, tag: "mapped_" + tag,
		newLinker: tc.Linker, mapObj: mapInput, mapAr: mapInput,
	})
	if err != nil {
		return fmt.Errorf("rewrite link args for %s: %w", rec.Output, err)
	}
	extraEnv, args := applySDKRoot(tc, args)
	if out, err := runToolInDirEnv(ctx, driverFor(tc, rec.IsCXX), args, rec.CWD, extraEnv); err != nil {
		return fmt.Errorf("relink %s: %w\n%s", rec.Output, err, out)
	}
	return nil
}

func applySDKRoot(tc *toolchain, args []string) ([]string, []string) {
	if tc == nil || tc.SDKRoot == "" {
		return nil, args
	}
	extraEnv := []string{"SDKROOT=" + tc.SDKRoot}
	if tc.Spec.IsDarwin && !hasSysrootFlag(args) {
		args = append(args, "-isysroot", tc.SDKRoot)
	}
	return extraEnv, args
}

func hasSysrootFlag(args []string) bool {
	return slices.ContainsFunc(args, func(a string) bool {
		return a == "-isysroot" || a == "--sysroot" || strings.HasPrefix(a, "-isysroot=") || strings.HasPrefix(a, "--sysroot=")
	})
}

func splitDirectCompileLink(ctx context.Context, o objectBisectOpts, goodBuild, badBuild string, rec linkRec, badComp []compileRec) (linkRec, []compileRec, bool, error) {
	wantOut := evalSymlinksExisting(rec.Output)
	var match *compileRec
	for i := len(badComp) - 1; i >= 0; i-- {
		if evalSymlinksExisting(badComp[i].Output) == wantOut && len(badComp[i].Sources) > 0 {
			match = &badComp[i]
			break
		}
	}
	if match == nil {
		return linkRec{}, nil, false, nil
	}
	gDir, bDir := filepath.Join(goodBuild, ".lmc_split_objs"), filepath.Join(badBuild, ".lmc_split_objs")
	if err := mkdirAll(gDir, bDir); err != nil {
		return linkRec{}, nil, false, err
	}

	base := stripLinkLibs(stripFlags(match.FullArgs, stripMode|stripOutput|stripDep|stripLink|stripSources, match.CWD, match.Sources...))
	gDrv, bDrv := driverFor(o.GoodTC, match.IsCXX), driverFor(o.BadTC, match.IsCXX)
	var badObjs []string
	var sBad []compileRec
	for i, src := range match.Sources {
		name := fmt.Sprintf("split_%03d_%s.o", i, filepath.Base(src))
		gObj, bObj := filepath.Join(gDir, name), filepath.Join(bDir, name)
		if out, err := runToolInDir(ctx, gDrv, append(slices.Clone(base), "-c", src, "-o", gObj), match.CWD); err != nil {
			return linkRec{}, nil, false, fmt.Errorf("split good compile %s: %w\n%s", src, err, out)
		}
		bArgs := append(slices.Clone(base), "-c", src, "-o", bObj)
		if out, err := runToolInDir(ctx, bDrv, bArgs, match.CWD); err != nil {
			return linkRec{}, nil, false, fmt.Errorf("split bad compile %s: %w\n%s", src, err, out)
		}
		badObjs = append(badObjs, bObj)
		sBad = append(sBad, compileRec{CWD: match.CWD, Compiler: bDrv, IsCXX: match.IsCXX, Source: src, Sources: []string{src}, Output: bObj, FullArgs: bArgs})
	}

	srcSet := make(map[string]bool, len(match.Sources))
	for _, s := range match.Sources {
		srcSet[evalSymlinksExisting(s)] = true
	}
	var linkArgs []string
	inserted := false
	for _, a := range expandResponseFiles(rec.CWD, rec.FullArgs) {
		if !strings.HasPrefix(a, "-") && srcSet[evalSymlinksExisting(resolvePath(rec.CWD, a))] {
			if !inserted {
				linkArgs, inserted = append(linkArgs, badObjs...), true
			}
			continue
		}
		linkArgs = append(linkArgs, a)
	}
	if !inserted {
		linkArgs = append(linkArgs, badObjs...)
	}
	rec.ObjectFiles = append(slices.Clone(rec.ObjectFiles), badObjs...)
	rec.FullArgs = linkArgs
	return rec, sBad, true, nil
}

type archiveGroup struct {
	badPath   string
	goodPath  string
	memberIdx []int
}

type linkDecomp struct {
	units                                []*compiledObj
	directIdx                            map[string]int
	archives                             []archiveGroup
	targetLink                           linkRec
	badTC                                *toolchain
	scratchDir, mixedDir, arTool, ranlib string
	counter                              int
}

func expandLinkUnits(o objectBisectOpts, goodBuild, badBuild string, rec linkRec, badComp []compileRec) (*linkDecomp, error) {
	byOut, byHash := make(map[string]compileRec, len(badComp)), make(map[string]compileRec, len(badComp))
	byBase := make(map[string][]compileRec)
	for _, cr := range badComp {
		out := evalSymlinksExisting(cr.Output)
		byOut[out] = cr
		if h, err := fileSHA256Hex(out); err == nil {
			byHash[h] = cr
		}
		byBase[filepath.Base(out)] = append(byBase[filepath.Base(out)], cr)
	}

	var units []*compiledObj
	directIdx := make(map[string]int)
	for _, obj := range rec.ObjectFiles {
		bad := evalSymlinksExisting(obj)
		rel, ok := relWithinDir(badBuild, bad)
		good := filepath.Join(goodBuild, rel)
		if !ok || !fileExists(good) || !fileExists(bad) {
			continue
		}
		if _, dup := directIdx[bad]; dup {
			continue
		}
		cr := byOut[bad]
		directIdx[bad] = len(units)
		units = append(units, &compiledObj{
			RelPath: rel, GoodObj: good, BadObj: bad, SourceFile: cr.Source,
			WorkDir: firstNonEmpty(cr.CWD, rec.CWD), IsCXX: cr.IsCXX, Args: slices.Clone(cr.FullArgs), CompileRec: cr,
		})
	}

	var archives []archiveGroup
	seenAr := make(map[string]bool)
	arRoot := filepath.Join(o.ScratchDir, "ar_members")
	for i, ar := range rec.ArchiveFiles {
		badAr := evalSymlinksExisting(ar)
		relAr, ok := relWithinDir(badBuild, badAr)
		goodAr := filepath.Join(goodBuild, relAr)
		if !ok || seenAr[badAr] || !fileExists(goodAr) || !fileExists(badAr) {
			continue
		}
		gMem, err := extractArMembers(goodAr, filepath.Join(arRoot, fmt.Sprintf("ar%d_good", i)))
		if err != nil || len(gMem) == 0 {
			continue
		}
		bMem, err := extractArMembers(badAr, filepath.Join(arRoot, fmt.Sprintf("ar%d_bad", i)))
		if err != nil || len(bMem) != len(gMem) {
			continue
		}
		pair := pairArchiveMembers(gMem, bMem)
		grp := archiveGroup{badPath: badAr, goodPath: goodAr, memberIdx: make([]int, len(bMem))}
		for m := range bMem {
			cr := byHash[bMem[m].sha256]
			if cr.Output == "" {
				if cands := byBase[bMem[m].name]; len(cands) == 1 {
					cr = cands[0]
				}
			}
			rel := fmt.Sprintf("%s(%s#%d)", relAr, bMem[m].name, m)
			if r, ok := relWithinDir(badBuild, cr.Output); cr.Output != "" && ok {
				rel = r
			}
			grp.memberIdx[m] = len(units)
			units = append(units, &compiledObj{
				RelPath: rel, GoodObj: gMem[pair[m]].path, BadObj: bMem[m].path, SourceFile: cr.Source,
				WorkDir: firstNonEmpty(cr.CWD, rec.CWD), IsCXX: cr.IsCXX, Args: slices.Clone(cr.FullArgs), CompileRec: cr,
			})
		}
		seenAr[badAr] = true
		archives = append(archives, grp)
	}

	mixedDir := filepath.Join(o.ScratchDir, "mixed_archives")
	if len(archives) > 0 {
		if err := os.MkdirAll(mixedDir, 0o755); err != nil {
			return nil, err
		}
	}
	return &linkDecomp{
		units: units, directIdx: directIdx, archives: archives, targetLink: rec,
		badTC: o.BadTC, scratchDir: o.ScratchDir, mixedDir: mixedDir,
		arTool: firstNonEmpty(o.BadTC.Ar, "ar"), ranlib: o.BadTC.Ranlib,
	}, nil
}

func pairArchiveMembers(gMem, bMem []arMember) []int {
	gByName := make(map[string][]int, len(gMem))
	for gi, m := range gMem {
		gByName[m.name] = append(gByName[m.name], gi)
	}
	pair := make([]int, len(bMem))
	used := make([]bool, len(gMem))
	for m, bm := range bMem {
		if q := gByName[bm.name]; len(q) > 0 {
			pair[m], gByName[bm.name] = q[0], q[1:]
			used[pair[m]] = true
		} else {
			pair[m] = -1
		}
	}
	nextUnused := 0
	for m, gi := range pair {
		if gi >= 0 {
			continue
		}
		if m < len(gMem) && !used[m] {
			pair[m], used[m] = m, true
			continue
		}
		for nextUnused < len(gMem) && used[nextUnused] {
			nextUnused++
		}
		if nextUnused < len(gMem) {
			pair[m], used[nextUnused] = nextUnused, true
		} else {
			pair[m] = m
		}
	}
	return pair
}

func (d *linkDecomp) pick(cIdx, pIdx int, cand string) func(int) string {
	return func(i int) string {
		if i == cIdx {
			return cand
		}
		if pIdx >= 0 && i == pIdx {
			return d.units[i].BadObj
		}
		return d.units[i].GoodObj
	}
}

func (d *linkDecomp) buildArgs(pick func(int) string, builtAr map[string]string, linkerPath, tag string) ([]string, error) {
	return rewriteLinkArgs(d.targetLink.FullArgs, linkRewriteOpts{
		cwd: d.targetLink.CWD, scratchDir: d.scratchDir, tag: tag, newLinker: linkerPath,
		mapObj: func(canon string) (string, bool) {
			if uIdx, ok := d.directIdx[canon]; ok {
				return pick(uIdx), true
			}
			return "", false
		},
		mapAr: func(canon string) (string, bool) {
			if mixed, ok := builtAr[canon]; ok {
				return mixed, true
			}
			return "", false
		},
	})
}

func (d *linkDecomp) relinkWith(ctx context.Context, driverTC *toolchain, linkerPath string, pick func(int) string) error {
	if driverTC == nil {
		driverTC = d.badTC
	}
	d.counter++
	arTool := firstNonEmpty(driverTC.Ar, d.arTool)
	ranlib := firstNonEmpty(driverTC.Ranlib, d.ranlib)
	builtAr := make(map[string]string, len(d.archives))
	for i, g := range d.archives {
		members := make([]string, len(g.memberIdx))
		for m, uIdx := range g.memberIdx {
			members[m] = pick(uIdx)
		}
		outAr := filepath.Join(d.mixedDir, fmt.Sprintf("mix_%d_%d_%s", d.counter, i, filepath.Base(g.badPath)))
		if err := createStaticArchive(ctx, arTool, ranlib, outAr, members); err != nil {
			return err
		}
		builtAr[g.badPath] = outAr
		defer os.Remove(outAr)
	}
	args, err := d.buildArgs(pick, builtAr, linkerPath, strconv.Itoa(d.counter))
	if err != nil {
		return err
	}
	extraEnv, args := applySDKRoot(driverTC, args)
	if out, err := runToolInDirEnv(ctx, driverFor(driverTC, d.targetLink.IsCXX), args, d.targetLink.CWD, extraEnv); err != nil {
		return fmt.Errorf("relink %s: %w\n%s", d.targetLink.Output, err, out)
	}
	return nil
}

func (d *linkDecomp) relink(ctx context.Context, pick func(int) string) error {
	return d.relinkWith(ctx, d.badTC, "", pick)
}

func (d *linkDecomp) makeSingle(testFn func(context.Context) (bool, string, error), cIdx, pIdx int) func(context.Context, string) (bool, string, error) {
	return func(ctx context.Context, cand string) (bool, string, error) {
		if err := d.relink(ctx, d.pick(cIdx, pIdx, cand)); err != nil {
			return false, "", err
		}
		return testFn(ctx)
	}
}

func (d *linkDecomp) freezeRelink(ctx context.Context, cIdx, pIdx int, candObj string) (reduceRelink, error) {
	pick := d.pick(cIdx, pIdx, candObj)
	rr := reduceRelink{LinkDriver: driverFor(d.badTC, d.targetLink.IsCXX), LinkDir: d.targetLink.CWD, CandObj: candObj}
	builtAr := make(map[string]string, len(d.archives))
	for i, g := range d.archives {
		members := make([]string, len(g.memberIdx))
		hasCulprit := false
		for m, uIdx := range g.memberIdx {
			members[m] = pick(uIdx)
			hasCulprit = hasCulprit || uIdx == cIdx
		}
		if hasCulprit {
			outAr := filepath.Join(d.mixedDir, fmt.Sprintf("reduce_culprit_%d_%s", i, filepath.Base(g.badPath)))
			builtAr[g.badPath] = outAr
			rr.ArTool, rr.RanlibTool, rr.ArOut, rr.ArMembers = d.arTool, d.ranlib, outAr, members
		} else {
			outAr := filepath.Join(d.mixedDir, fmt.Sprintf("reduce_fixed_%d_%s", i, filepath.Base(g.badPath)))
			if err := createStaticArchive(ctx, d.arTool, d.ranlib, outAr, members); err != nil {
				return reduceRelink{}, err
			}
			builtAr[g.badPath] = outAr
		}
	}
	var err error
	if rr.LinkArgs, err = d.buildArgs(pick, builtAr, "", "reduce"); err != nil {
		return reduceRelink{}, err
	}
	return rr, nil
}

type savedLTOMod struct {
	key, inputBC, memberName, nativeObj, importBC string
}

type savedLTOLink struct {
	task0 savedLTOMod
	mods  []savedLTOMod
}

func tryThinLTONativeBisect(ctx context.Context, o objectBisectOpts, goodBuild, badBuild string, rec linkRec, badComp []compileRec) (*objectBisectResult, bool) {
	if len(rec.ObjectFiles) == 0 && len(rec.ArchiveFiles) == 0 {
		return nil, false
	}
	gLink, err := runSaveTempsLink(ctx, o.Spec, o.GoodTC, goodBuild, badBuild, rec, false, filepath.Join(o.ScratchDir, "lto_save_good"))
	if err != nil || (len(gLink.mods) == 0 && gLink.task0.nativeObj == "") {
		return nil, false
	}
	bLink, err := runSaveTempsLink(ctx, o.Spec, o.BadTC, goodBuild, badBuild, rec, true, filepath.Join(o.ScratchDir, "lto_save_bad"))
	if err != nil || (len(bLink.mods) == 0 && bLink.task0.nativeObj == "") {
		return nil, false
	}

	gAligned, bAligned := alignSavedLTOMods(gLink, bLink)
	if len(bAligned) == 0 {
		return nil, false
	}

	byOut, byHash := make(map[string]compileRec, len(badComp)), make(map[string]compileRec, len(badComp))
	byBase := make(map[string][]compileRec)
	for _, cr := range badComp {
		out := evalSymlinksExisting(cr.Output)
		byOut[out] = cr
		if h, err := fileSHA256Hex(out); err == nil {
			byHash[h] = cr
		}
		byBase[filepath.Base(out)] = append(byBase[filepath.Base(out)], cr)
	}

	// build archive member sha256 index and native-only fallback archives for mixed bitcode+asm archives
	arTool := firstNonEmpty(o.BadTC.Ar, "ar")
	nativeArDir := filepath.Join(o.ScratchDir, "lto_native_ar")
	stripAr := make(map[string]string)
	arMemByName := make(map[string]map[string][]string)
	for i, ar := range rec.ArchiveFiles {
		badAr := evalSymlinksExisting(ar)
		if _, ok := relWithinDir(badBuild, badAr); !ok || !fileExists(badAr) {
			continue
		}
		if _, seen := stripAr[badAr]; seen {
			continue
		}
		mems, err := extractArMembers(badAr, filepath.Join(nativeArDir, fmt.Sprintf("ar%d", i)))
		if err != nil {
			stripAr[badAr] = ""
			continue
		}
		var nativeMems []string
		byName := make(map[string][]string, len(mems))
		for _, m := range mems {
			byName[m.name] = append(byName[m.name], m.sha256)
			if !isBitcodeFile(m.path) {
				nativeMems = append(nativeMems, m.path)
			}
		}
		arMemByName[badAr] = byName
		if len(nativeMems) > 0 {
			outAr := filepath.Join(nativeArDir, fmt.Sprintf("native_%d_%s", i, filepath.Base(badAr)))
			if createStaticArchive(ctx, arTool, o.BadTC.Ranlib, outAr, nativeMems) == nil {
				stripAr[badAr] = outAr
			} else {
				stripAr[badAr] = ""
			}
		} else {
			stripAr[badAr] = ""
		}
	}

	units := make([]*compiledObj, 0, len(bAligned))
	bitcodeObjs := make(map[string]bool, len(bAligned))
	anyNative := false
	for i := range bAligned {
		gm, bm := gAligned[i], bAligned[i]
		if gm.nativeObj != "" || bm.nativeObj != "" {
			anyNative = true
		}
		ref := bm
		if ref.inputBC == "" {
			ref = gm
		}
		var cr compileRec
		rel := ""
		if ref.memberName != "" {
			if cands := byBase[ref.memberName]; len(cands) == 1 {
				cr = cands[0]
			} else if hashes := arMemByName[evalSymlinksExisting(ref.inputBC)][ref.memberName]; len(hashes) > 0 {
				for _, h := range hashes {
					if c, ok := byHash[h]; ok {
						cr = c
						break
					}
				}
			}
			if r, ok := relWithinDir(badBuild, cr.Output); cr.Output != "" && ok {
				rel = r
			} else if rAr, ok := relWithinDir(badBuild, ref.inputBC); ok {
				rel = fmt.Sprintf("%s(%s)", rAr, ref.memberName)
			} else {
				rel = ref.memberName
			}
		} else if ref.inputBC != "" && ref.inputBC != "ld-temp.o" {
			canon := evalSymlinksExisting(ref.inputBC)
			bitcodeObjs[canon] = true
			cr = byOut[canon]
			rel, _ = relWithinDir(badBuild, canon)
		} else {
			rel = "ld-temp.o"
		}
		units = append(units, &compiledObj{
			RelPath: firstNonEmpty(rel, filepath.Base(ref.inputBC)), GoodObj: gm.inputBC, BadObj: bm.inputBC,
			SourceFile: cr.Source, WorkDir: firstNonEmpty(cr.CWD, rec.CWD), IsCXX: cr.IsCXX,
			Args: slices.Clone(cr.FullArgs), CompileRec: cr,
			GoodNativeLTOObj: gm.nativeObj, BadNativeLTOObj: bm.nativeObj,
			GoodImportBC: gm.importBC, BadImportBC: bm.importBC,
		})
	}
	if !anyNative {
		return nil, false
	}

	driver := driverFor(o.BadTC, rec.IsCXX)
	relinkSeq := 0
	relink := func(ctx context.Context, pick func(int) string) error {
		relinkSeq++
		args, err := buildNativeRelinkArgs(rec, bitcodeObjs, stripAr, len(units), pick, o.ScratchDir, fmt.Sprintf("nat_%d", relinkSeq))
		if err != nil {
			return err
		}
		_, err = runToolInDir(ctx, driver, args, rec.CWD)
		return err
	}
	testNative := func(pick func(int) string) (bool, error) {
		if err := relink(ctx, pick); err != nil {
			return false, err
		}
		pass, _, err := o.Test(ctx)
		return pass, err
	}
	if pass, err := testNative(func(i int) string { return units[i].GoodNativeLTOObj }); err != nil || !pass {
		return nil, false
	}
	if pass, err := testNative(func(i int) string { return units[i].BadNativeLTOObj }); err != nil || pass {
		return nil, false
	}
	cIdx := 0
	if len(units) > 1 {
		pos, err := bisectFirstFail(len(units)+1, func(k int) (bool, error) {
			if k == 0 {
				return false, nil
			}
			pass, err := testNative(func(i int) string {
				if i < k {
					return units[i].BadNativeLTOObj
				}
				return units[i].GoodNativeLTOObj
			})
			return !pass, err
		})
		if err != nil {
			return nil, false
		}
		cIdx = pos - 1
	}

	pIdx := -1
	if cIdx > 0 {
		singlePass, err := testNative(func(i int) string {
			if i == cIdx {
				return units[i].BadNativeLTOObj
			}
			return units[i].GoodNativeLTOObj
		})
		if err != nil {
			return nil, false
		}
		if singlePass {
			pPos, err := bisectFirstFail(cIdx+1, func(k int) (bool, error) {
				if k == 0 {
					return false, nil
				}
				pass, err := testNative(func(i int) string {
					if i == cIdx || i < k {
						return units[i].BadNativeLTOObj
					}
					return units[i].GoodNativeLTOObj
				})
				return !pass, err
			})
			if err != nil {
				return nil, false
			}
			pIdx = pPos - 1
		}
	}

	pickCand := func(cand string) func(int) string {
		return func(i int) string {
			if i == cIdx {
				return cand
			}
			if pIdx >= 0 && i == pIdx {
				return units[i].BadNativeLTOObj
			}
			return units[i].GoodNativeLTOObj
		}
	}
	return &objectBisectResult{
		Culprit:       units[cIdx],
		UsedNativeLTO: true,
		relinkSingle: func(ctx context.Context, cand string) (bool, string, error) {
			if err := relink(ctx, pickCand(cand)); err != nil {
				return false, "", err
			}
			return o.Test(ctx)
		},
		buildRelink: func(cand string) (reduceRelink, error) {
			args, err := buildNativeRelinkArgs(rec, bitcodeObjs, stripAr, len(units), pickCand(cand), o.ScratchDir, "nat_reduce")
			if err != nil {
				return reduceRelink{}, err
			}
			return reduceRelink{LinkDriver: driver, LinkDir: rec.CWD, CandObj: cand, LinkArgs: args}, nil
		},
	}, true
}

func alignSavedLTOMods(gLink, bLink savedLTOLink) ([]savedLTOMod, []savedLTOMod) {
	var gOut, bOut []savedLTOMod
	if gLink.task0.nativeObj != "" || bLink.task0.nativeObj != "" {
		gOut = append(gOut, gLink.task0)
		bOut = append(bOut, bLink.task0)
	}
	sameOrder := len(gLink.mods) == len(bLink.mods)
	if sameOrder {
		for i := range bLink.mods {
			if gLink.mods[i].key != bLink.mods[i].key {
				sameOrder = false
				break
			}
		}
	}
	if sameOrder {
		gOut = append(gOut, gLink.mods...)
		bOut = append(bOut, bLink.mods...)
		return gOut, bOut
	}
	gByKey := make(map[string][]savedLTOMod, len(gLink.mods))
	for _, gm := range gLink.mods {
		gByKey[gm.key] = append(gByKey[gm.key], gm)
	}
	for _, bm := range bLink.mods {
		if q := gByKey[bm.key]; len(q) > 0 {
			gOut = append(gOut, q[0])
			gByKey[bm.key] = q[1:]
		} else {
			gOut = append(gOut, savedLTOMod{key: bm.key, inputBC: bm.inputBC, memberName: bm.memberName})
		}
		bOut = append(bOut, bm)
	}
	for _, gm := range gLink.mods {
		if q := gByKey[gm.key]; len(q) > 0 {
			gOut = append(gOut, q[0])
			gByKey[gm.key] = q[1:]
			bOut = append(bOut, savedLTOMod{key: gm.key, inputBC: gm.inputBC, memberName: gm.memberName})
		}
	}
	return gOut, bOut
}

func runSaveTempsLink(ctx context.Context, spec platformSpec, tc *toolchain, goodBuild, badBuild string, rec linkRec, useBad bool, workDir string) (savedLTOLink, error) {
	objsDir, ltoDir := filepath.Join(workDir, "objs"), filepath.Join(workDir, "lto_native")
	if err := os.RemoveAll(workDir); err != nil {
		return savedLTOLink{}, err
	}
	if err := mkdirAll(objsDir, ltoDir); err != nil {
		return savedLTOLink{}, err
	}

	copyToOrig, origToCopy := make(map[string]string), make(map[string]string)
	copyInput := func(prefix string, idx int, rawPath string) error {
		bad := evalSymlinksExisting(rawPath)
		if _, seen := origToCopy[bad]; seen {
			return nil
		}
		rel, ok := relWithinDir(badBuild, bad)
		if !ok {
			return nil
		}
		src := bad
		if !useBad {
			src = filepath.Join(goodBuild, rel)
		}
		if !fileExists(src) {
			return nil
		}
		cp := filepath.Join(objsDir, fmt.Sprintf("%s%04d_%s", prefix, idx, filepath.Base(bad)))
		if err := copyFile(src, cp, 0); err != nil {
			return err
		}
		copyToOrig[evalSymlinksExisting(cp)], origToCopy[bad] = bad, cp
		return nil
	}
	for i, badObj := range rec.ObjectFiles {
		if err := copyInput("m", i, badObj); err != nil {
			return savedLTOLink{}, err
		}
	}
	for i, badAr := range rec.ArchiveFiles {
		if err := copyInput("a", i, badAr); err != nil {
			return savedLTOLink{}, err
		}
	}

	mapCopy := func(canon string) (string, bool) {
		if cp, ok := origToCopy[canon]; ok {
			return cp, true
		}
		return "", false
	}
	args, err := rewriteLinkArgs(rec.FullArgs, linkRewriteOpts{
		cwd: rec.CWD, scratchDir: workDir, tag: "savetemps",
		stripOut: true, mapObj: mapCopy, mapAr: mapCopy,
	})
	if err != nil {
		return savedLTOLink{}, err
	}

	outBin, objPrefix := filepath.Join(workDir, filepath.Base(rec.Output)), filepath.Join(ltoDir, "mod")
	args = append(args, linkerFlag(tc.Linker), "-o", outBin)
	if spec.IsDarwin {
		args = append(args, "-Wl,-save-temps", "-Wl,-object_path_lto,"+ltoDir)
	} else {
		args = append(args, "-Wl,--save-temps", "-Wl,--lto-obj-path="+objPrefix)
	}
	if out, err := runToolInDir(ctx, driverFor(tc, rec.IsCXX), args, rec.CWD); err != nil {
		return savedLTOLink{}, fmt.Errorf("save-temps link: %w\n%s", err, out)
	}

	resTxt, err := os.ReadFile(outBin + ".resolution.txt")
	if err != nil {
		return savedLTOLink{}, err
	}
	var ordered []string
	for _, line := range nonEmptyLines(string(resTxt)) {
		if !strings.HasPrefix(line, "-r=") {
			ordered = append(ordered, line)
		}
	}
	if len(ordered) == 0 {
		return savedLTOLink{}, errors.New("empty resolution.txt")
	}

	var res savedLTOLink
	// check task 0 (regular LTO / split-LTO-unit partition) if non-empty
	var task0Native string
	if spec.IsDarwin {
		if c := outBin + ".lto.o"; fileNonEmpty(c) {
			task0Native = c
		} else if ms, _ := filepath.Glob(filepath.Join(ltoDir, "0.*.lto.o")); len(ms) > 0 && fileNonEmpty(ms[0]) {
			task0Native = ms[0]
		}
	} else {
		if fileNonEmpty(objPrefix) {
			task0Native = objPrefix
		} else if c := outBin + ".lto.o"; fileNonEmpty(c) {
			task0Native = c
		}
	}
	if task0Native != "" {
		t0BC := ""
		for _, c := range []string{outBin + ".0.3.import.bc", outBin + ".0.0.preopt.bc"} {
			if fileNonEmpty(c) {
				t0BC = c
				break
			}
		}
		res.task0 = savedLTOMod{key: "task0", inputBC: "ld-temp.o", nativeObj: task0Native, importBC: t0BC}
	}

	res.mods = make([]savedLTOMod, 0, len(ordered))
	for i, rawLine := range ordered {
		modIdx := i + 1
		var native string
		if spec.IsDarwin {
			if c := fmt.Sprintf("%s%d.lto.o", outBin, modIdx); fileNonEmpty(c) {
				native = c
			} else if ms, _ := filepath.Glob(filepath.Join(ltoDir, fmt.Sprintf("%d.*.lto.o", modIdx))); len(ms) > 0 && fileNonEmpty(ms[0]) {
				native = ms[0]
			}
		} else {
			if c := fmt.Sprintf("%s%d", objPrefix, modIdx); fileNonEmpty(c) {
				native = c
			} else {
				cleanLine := filepath.Clean(rawLine)
				stem := strings.TrimSuffix(filepath.Base(cleanLine), filepath.Ext(cleanLine))
				if c := filepath.Join(filepath.Dir(cleanLine), fmt.Sprintf("%s.lto.%s.o", filepath.Base(outBin), stem)); fileNonEmpty(c) {
					native = c
				}
			}
		}
		importBC := ""
		for _, cand := range []string{rawLine + ".3.import.bc", filepath.Clean(rawLine) + ".3.import.bc"} {
			if fileNonEmpty(cand) {
				importBC = cand
				break
			}
		}
		arPath, memName := parseResolutionArchive(rawLine)
		var key, inputBC string
		if arPath != "" {
			origAr := firstNonEmpty(copyToOrig[evalSymlinksExisting(arPath)], arPath)
			key = origAr + "(" + memName + ")"
			inputBC = origAr
		} else {
			orig := firstNonEmpty(copyToOrig[evalSymlinksExisting(rawLine)], filepath.Clean(rawLine))
			key = orig
			inputBC = orig
		}
		res.mods = append(res.mods, savedLTOMod{key: key, inputBC: inputBC, memberName: memName, nativeObj: native, importBC: importBC})
	}
	return res, nil
}

func parseResolutionArchive(line string) (arPath, memberName string) {
	// ELF uses "ar.a(member.o at off)" while MachO uses "ar.a(member.o)off"
	trimmed := strings.TrimRight(line, "0123456789")
	if !strings.HasSuffix(trimmed, ")") {
		return "", ""
	}
	lp := strings.LastIndexByte(trimmed, '(')
	if lp <= 0 {
		return "", ""
	}
	ar := filepath.Clean(trimmed[:lp])
	if !strings.EqualFold(filepath.Ext(ar), ".a") {
		return "", ""
	}
	inside := trimmed[lp+1 : len(trimmed)-1]
	if before, _, ok := strings.Cut(inside, " at "); ok {
		inside = before
	}
	return ar, filepath.Base(strings.TrimSpace(inside))
}

func buildNativeRelinkArgs(rec linkRec, bitcodeObjs map[string]bool, stripAr map[string]string, numUnits int, pick func(int) string, scratchDir, tag string) ([]string, error) {
	insertObjs := make([]string, 0, numUnits)
	for i := range numUnits {
		if obj := pick(i); obj != "" {
			insertObjs = append(insertObjs, obj)
		}
	}
	return rewriteLinkArgs(rec.FullArgs, linkRewriteOpts{
		cwd: rec.CWD, scratchDir: scratchDir, tag: tag, stripLTO: true,
		mapObj: func(canon string) (string, bool) {
			if bitcodeObjs[canon] {
				return "", true
			}
			return "", false
		},
		mapAr: func(canon string) (string, bool) {
			if repl, ok := stripAr[canon]; ok {
				return repl, true
			}
			return "", false
		},
		insertObjs: insertObjs,
	})
}

type linkRewriteOpts struct {
	cwd        string
	scratchDir string
	tag        string
	stripLTO   bool
	stripOut   bool
	newLinker  string
	mapObj     func(string) (string, bool)
	mapAr      func(string) (string, bool)
	insertObjs []string
}

func rewriteLinkArgs(rawArgs []string, opts linkRewriteOpts) ([]string, error) {
	expanded := expandResponseFiles(opts.cwd, rawArgs)
	libDirs := collectLinkLibDirs(opts.cwd, expanded)
	out := make([]string, 0, len(expanded)+len(opts.insertObjs))
	flSeq := 0
	inserted := false
	staticOnly := false

	emitInsert := func() {
		if len(opts.insertObjs) > 0 && !inserted {
			out = append(out, opts.insertObjs...)
			inserted = true
		}
	}
	applyMap := func(p string) (string, bool) {
		canon := evalSymlinksExisting(p)
		if opts.mapObj != nil {
			if repl, ok := opts.mapObj(canon); ok {
				return repl, true
			}
		}
		if opts.mapAr != nil {
			if repl, ok := opts.mapAr(canon); ok {
				return repl, true
			}
		}
		return "", false
	}
	makeFilelist := func(orig string) (string, int, bool, error) {
		if opts.scratchDir != "" {
			if err := os.MkdirAll(opts.scratchDir, 0o755); err != nil {
				return "", 0, false, err
			}
		}
		dst := filepath.Join(opts.scratchDir, fmt.Sprintf("filelist_%s_%d.txt", opts.tag, flSeq))
		flSeq++
		kept, mapped, err := rewriteFilelistMapped(resolvePath(opts.cwd, orig), opts.cwd, dst, applyMap)
		return dst, kept, mapped, err
	}
	rewriteLinkerToks := func(toks []string) ([]string, error) {
		toks = expandLinkerTokens(opts.cwd, toks, 0)
		var kept []string
		for j := 0; j < len(toks); j++ {
			t := toks[j]
			switch {
			case isSaveTempsLinkerTok(t):
				continue
			case (t == "-object_path_lto" || t == "--lto-obj-path") && j+1 < len(toks):
				j++
				continue
			case opts.stripLTO && strings.HasPrefix(t, "--thinlto-jobs="):
				continue
			case t == "-Bstatic" || t == "-dn" || t == "-non_shared" || t == "-static":
				staticOnly = true
				kept = append(kept, t)
			case t == "-Bdynamic" || t == "-dy" || t == "-call_shared":
				staticOnly = false
				kept = append(kept, t)
			case t == "-filelist" && j+1 < len(toks):
				j++
				dst, nKept, mapped, err := makeFilelist(toks[j])
				if err != nil {
					return nil, err
				}
				if mapped {
					emitInsert()
				}
				if nKept > 0 || !mapped {
					kept = append(kept, "-filelist", dst)
				}
			case t == "-force_load" && j+1 < len(toks):
				j++
				if repl, ok := applyMap(resolvePath(opts.cwd, toks[j])); ok {
					emitInsert()
					if repl != "" {
						kept = append(kept, "-force_load", repl)
					}
				} else {
					kept = append(kept, "-force_load", toks[j])
				}
			case t == "-l" && j+1 < len(toks):
				j++
				if ar := resolveLibArchive(libDirs, toks[j], staticOnly); ar != "" {
					if repl, ok := applyMap(ar); ok {
						emitInsert()
						if repl != "" {
							kept = append(kept, repl)
						}
						continue
					}
				}
				kept = append(kept, "-l", toks[j])
			case strings.HasPrefix(t, "-l") && len(t) > 2:
				if ar := resolveLibArchive(libDirs, t[2:], staticOnly); ar != "" {
					if repl, ok := applyMap(ar); ok {
						emitInsert()
						if repl != "" {
							kept = append(kept, repl)
						}
						continue
					}
				}
				kept = append(kept, t)
			case !strings.HasPrefix(t, "-"):
				if repl, ok := applyMap(resolvePath(opts.cwd, t)); ok {
					emitInsert()
					if repl != "" {
						kept = append(kept, repl)
					}
				} else {
					kept = append(kept, t)
				}
			default:
				kept = append(kept, t)
			}
		}
		return kept, nil
	}

	for i := 0; i < len(expanded); i++ {
		a := expanded[i]
		if a == "-o" {
			if opts.stripOut {
				i++
				continue
			}
			out = append(out, a)
			if i+1 < len(expanded) {
				i++
				out = append(out, expanded[i])
			}
			continue
		}
		if opts.stripOut && isAttachedOutputFlag(a) {
			continue
		}
		if opts.stripOut || opts.newLinker != "" {
			if a == "--ld-path" {
				i++
				continue
			}
			if strings.HasPrefix(a, "--ld-path=") || strings.HasPrefix(a, "-fuse-ld=") {
				continue
			}
		}
		if isSaveTempsFlag(a) {
			continue
		}
		if opts.stripLTO && (a == "-flto" || strings.HasPrefix(a, "-flto=")) {
			continue
		}
		if a == "-static" {
			staticOnly = true
			out = append(out, a)
			continue
		}
		if a == "-filelist" && i+1 < len(expanded) {
			dst, nKept, mapped, err := makeFilelist(expanded[i+1])
			if err != nil {
				return nil, err
			}
			if mapped {
				emitInsert()
			}
			if nKept > 0 || !mapped {
				out = append(out, "-filelist", dst)
			}
			i++
			continue
		}
		if a == "-force_load" && i+1 < len(expanded) {
			if repl, ok := applyMap(resolvePath(opts.cwd, expanded[i+1])); ok {
				emitInsert()
				if repl != "" {
					out = append(out, "-force_load", repl)
				}
			} else {
				out = append(out, a, expanded[i+1])
			}
			i++
			continue
		}
		if a == "-l" && i+1 < len(expanded) {
			if ar := resolveLibArchive(libDirs, expanded[i+1], staticOnly); ar != "" {
				if repl, ok := applyMap(ar); ok {
					emitInsert()
					if repl != "" {
						out = append(out, repl)
					}
					i++
					continue
				}
			}
			out = append(out, a, expanded[i+1])
			i++
			continue
		}
		if strings.HasPrefix(a, "-l") && len(a) > 2 {
			if ar := resolveLibArchive(libDirs, a[2:], staticOnly); ar != "" {
				if repl, ok := applyMap(ar); ok {
					emitInsert()
					if repl != "" {
						out = append(out, repl)
					}
					continue
				}
			}
			out = append(out, a)
			continue
		}
		if strings.HasPrefix(a, "-Wl,") {
			kept, err := rewriteLinkerToks(strings.Split(a[4:], ","))
			if err != nil {
				return nil, err
			}
			if len(kept) > 0 {
				out = append(out, "-Wl,"+strings.Join(kept, ","))
			}
			continue
		}
		if a == "-Xlinker" && i+1 < len(expanded) {
			var xl []string
			for i+1 < len(expanded) && expanded[i] == "-Xlinker" {
				xl = append(xl, expanded[i+1])
				i += 2
			}
			i--
			kept, err := rewriteLinkerToks(xl)
			if err != nil {
				return nil, err
			}
			for _, k := range kept {
				out = append(out, "-Xlinker", k)
			}
			continue
		}
		if twoArgClangFlags[a] || a == "-x" {
			out = append(out, a)
			if i+1 < len(expanded) {
				i++
				out = append(out, expanded[i])
			}
			continue
		}
		if !strings.HasPrefix(a, "-") {
			if repl, ok := applyMap(resolvePath(opts.cwd, a)); ok {
				emitInsert()
				if repl != "" {
					out = append(out, repl)
				}
				continue
			}
		}
		out = append(out, a)
	}
	if len(opts.insertObjs) > 0 && !inserted {
		out = append(out, opts.insertObjs...)
	}
	if opts.newLinker != "" {
		out = append(out, linkerFlag(opts.newLinker))
	}
	return out, nil
}

func collectLinkLibDirs(cwd string, expanded []string) []string {
	var dirs []string
	addToks := func(toks []string) {
		toks = expandLinkerTokens(cwd, toks, 0)
		for j := 0; j < len(toks); j++ {
			t := toks[j]
			if t == "-L" && j+1 < len(toks) {
				j++
				dirs = append(dirs, resolvePath(cwd, toks[j]))
			} else if strings.HasPrefix(t, "-L") && len(t) > 2 {
				dirs = append(dirs, resolvePath(cwd, t[2:]))
			}
		}
	}
	for i := 0; i < len(expanded); i++ {
		a := expanded[i]
		switch {
		case a == "-L" && i+1 < len(expanded):
			i++
			dirs = append(dirs, resolvePath(cwd, expanded[i]))
		case strings.HasPrefix(a, "-L") && len(a) > 2:
			dirs = append(dirs, resolvePath(cwd, a[2:]))
		case strings.HasPrefix(a, "-Wl,"):
			addToks(strings.Split(a[4:], ","))
		case a == "-Xlinker" && i+1 < len(expanded):
			var xl []string
			for i+1 < len(expanded) && expanded[i] == "-Xlinker" {
				xl = append(xl, expanded[i+1])
				i += 2
			}
			i--
			addToks(xl)
		}
	}
	return dirs
}

func isSaveTempsFlag(a string) bool {
	return a == "-save-temps" || a == "--save-temps" ||
		strings.HasPrefix(a, "-save-temps=") || strings.HasPrefix(a, "--save-temps=")
}

func isSaveTempsLinkerTok(t string) bool {
	return t == "-save-temps" || t == "--save-temps" ||
		strings.HasPrefix(t, "-save-temps=") || strings.HasPrefix(t, "--save-temps=") ||
		strings.HasPrefix(t, "--lto-obj-path=") || strings.HasPrefix(t, "-object_path_lto=")
}

func isBitcodeFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [4]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return hdr == [4]byte{'B', 'C', 0xc0, 0xde} || hdr == [4]byte{0xde, 0xc0, 0x17, 0x0b}
}

func fileNonEmpty(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

type arMember struct{ name, path, sha256 string }

func extractArMembers(arPath, outDir string) ([]arMember, error) {
	data, err := os.ReadFile(arPath)
	if err != nil {
		return nil, err
	}
	const magic = "!<arch>\n"
	if len(data) < len(magic) || string(data[:len(magic)]) != magic {
		return nil, fmt.Errorf("%s: not an ar archive", arPath)
	}
	if err := os.RemoveAll(outDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}

	var gnuStrTab []byte
	var members []arMember
	for pos := len(magic); pos+60 <= len(data); {
		hdr := data[pos : pos+60]
		if hdr[58] != 0x60 || hdr[59] != '\n' {
			return nil, fmt.Errorf("%s: invalid ar header", arPath)
		}
		rawName := strings.TrimRight(string(hdr[:16]), " ")
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		pos += 60
		if err != nil || size < 0 || pos+int(size) > len(data) {
			return nil, fmt.Errorf("%s: invalid ar member size", arPath)
		}
		body := data[pos : pos+int(size)]
		pos += int(size) + int(size)%2

		if rawName == "//" {
			gnuStrTab = body
			continue
		}
		name := rawName
		switch {
		case strings.HasPrefix(rawName, "#1/"):
			// BSD ar stores extended names inline after #1/<len>
			n, err := strconv.Atoi(strings.TrimSpace(rawName[3:]))
			if err != nil || n < 0 || n > len(body) {
				return nil, fmt.Errorf("%s: invalid BSD #1 name", arPath)
			}
			name, body = strings.TrimRight(string(body[:n]), "\x00"), body[n:]
		case len(rawName) > 1 && rawName[0] == '/' && rawName[1] >= '0' && rawName[1] <= '9':
			if off, err := strconv.Atoi(strings.TrimSpace(rawName[1:])); err == nil && off >= 0 && off < len(gnuStrTab) {
				end := off
				for end < len(gnuStrTab) && gnuStrTab[end] != '\n' && gnuStrTab[end] != '/' && gnuStrTab[end] != 0 {
					end++
				}
				name = string(gnuStrTab[off:end])
			}
		default:
			name = strings.TrimSuffix(rawName, "/")
		}
		if name == "" || name == "/" || name == "//" || name == "/SYM64/" ||
			strings.HasPrefix(name, "__.SYMDEF") || strings.HasPrefix(name, "/.SYMDEF") {
			continue
		}
		base := filepath.Base(name)
		dst := filepath.Join(outDir, fmt.Sprintf("m%04d_%s", len(members), base))
		if err := os.WriteFile(dst, body, 0o644); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		members = append(members, arMember{name: base, path: dst, sha256: hex.EncodeToString(sum[:])})
	}
	return members, nil
}

func createStaticArchive(ctx context.Context, arTool, ranlibTool, outAr string, members []string) error {
	_ = os.Remove(outAr)
	// ar qc appends without replacing duplicate member basenames
	if out, err := runToolInDir(ctx, arTool, append([]string{"qc", outAr}, members...), ""); err != nil {
		return fmt.Errorf("%s qc %s: %w (%s)", arTool, outAr, err, out)
	}
	if ranlibTool != "" {
		if out, err := runToolInDir(ctx, ranlibTool, []string{outAr}, ""); err != nil {
			return fmt.Errorf("%s %s: %w (%s)", ranlibTool, outAr, err, out)
		}
	} else {
		_, _ = runToolInDir(ctx, arTool, []string{"s", outAr}, "")
	}
	return nil
}

func rewriteFilelistMapped(orig, cwd, dst string, mapFn func(string) (string, bool)) (int, bool, error) {
	raw, err := os.ReadFile(orig)
	if err != nil {
		return 0, false, err
	}
	var b bytes.Buffer
	kept := 0
	mapped := false
	for _, line := range nonEmptyLines(string(raw)) {
		if repl, ok := mapFn(resolvePath(cwd, line)); ok {
			mapped = true
			if repl != "" {
				b.WriteString(repl)
				b.WriteByte('\n')
				kept++
			}
		} else {
			b.WriteString(line)
			b.WriteByte('\n')
			kept++
		}
	}
	if err := os.WriteFile(dst, b.Bytes(), 0o644); err != nil {
		return 0, false, err
	}
	return kept, mapped, nil
}

type passEntry struct {
	Index                  int
	PassName, Target, Func string
}

func parseBisectOutput(stderr string) []passEntry {
	var entries []passEntry
	var lastFunc string
	sc := bufio.NewScanner(strings.NewReader(stderr))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		m := bisectLineRe.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}
		idx, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		target := strings.TrimSpace(m[3])
		fn := extractTargetFunction(target, lastFunc)
		if fn != "" {
			lastFunc = fn
		}
		entries = append(entries, passEntry{Index: idx, PassName: strings.TrimSpace(m[2]), Target: target, Func: fn})
	}
	return entries
}

func extractTargetFunction(raw, prevFunc string) string {
	t := strings.TrimSpace(raw)
	switch {
	case t == "", t == "[module]", strings.HasPrefix(t, "module ("), strings.HasPrefix(t, "module "):
		return ""
	case strings.HasPrefix(t, "function (") && strings.HasSuffix(t, ")"):
		return strings.TrimSpace(t[len("function (") : len(t)-1])
	case strings.Contains(t, " in function "):
		i := strings.LastIndex(t, " in function ")
		return strings.Trim(strings.TrimSpace(t[i+len(" in function "):]), "()")
	case t == "loop" || strings.HasPrefix(t, "loop "):
		return prevFunc
	case strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")"):
		head, _, _ := strings.Cut(strings.TrimSpace(t[1:len(t)-1]), ",")
		return strings.TrimSpace(head)
	}
	return t
}

type passBisectResult struct {
	CulpritPassIndex                            int
	CulpritPass, CulpritFunc                    string
	BeforeIRPath, AfterIRPath                   string
	BeforeFullIRPath, AfterFullIRPath, PassDiff string
	BeforeAsmPath, AfterAsmPath                 string
	IsCodeGenPass, IsInterprocedural            bool
}

func isInterproceduralPass(passName, target string) bool {
	t := strings.TrimSpace(target)
	if t == "[module]" || (strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")")) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(passName)) {
	case "inlinerpass", "alwaysinlinerpass", "moduleinlinerpass", "partialinlinerpass",
		"postorderfunctionattrspass", "reversepostorderfunctionattrspass", "inferfunctionattrspass",
		"argumentpromotionpass", "deadargumenteliminationpass", "ipsccppass",
		"globaloptpass", "globaldcepass", "attributorpass", "attributorcgsccpass",
		"functionspecializationpass", "mergefunctionspass",
		"inline", "always-inline", "function-attrs", "argpromotion", "deadargelim",
		"ipsccp", "globalopt", "globaldce", "attributor",
		"called-value-propagation", "constmerge", "openmp-opt", "rpo-function-attrs", "rel-lookup-table-converter":
		return true
	}
	return false
}

func hasLTOFlag(args []string) bool {
	return slices.ContainsFunc(args, func(a string) bool {
		return a == "-flto" || strings.HasPrefix(a, "-flto=")
	})
}

func tuCodegenFlags(args []string, cwd string) []string {
	var out []string
	for _, a := range expandResponseFiles(cwd, args) {
		switch a {
		case "-fPIC", "-fpic", "-fno-PIC", "-fno-pic", "-fPIE", "-fpie", "-fno-PIE", "-fno-pie":
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		default:
			if (strings.HasPrefix(a, "-mcmodel=") || strings.HasPrefix(a, "-ffp-contract=")) && !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	return out
}

func bisectPass(ctx context.Context, spec platformSpec, badTC *toolchain, culprit *compiledObj, scratchDir string, relinkAndTest func(context.Context, string) (bool, string, error)) (*passBisectResult, error) {
	return bisectPassMode(ctx, spec, badTC, culprit, scratchDir, relinkAndTest, false)
}

func bisectPassMode(ctx context.Context, spec platformSpec, badTC *toolchain, culprit *compiledObj, scratchDir string, relinkAndTest func(context.Context, string) (bool, string, error), keepLTO bool) (*passBisectResult, error) {
	if badTC == nil || culprit == nil || relinkAndTest == nil {
		return nil, errors.New("bad toolchain, culprit, and relinkAndTest are required")
	}
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		return nil, err
	}
	allObj := filepath.Join(scratchDir, "pass_limit_all.o")
	stderrAll, err := compileCulpritWithBisect(ctx, spec, badTC, culprit, -1, "obj", allObj, keepLTO)
	if err != nil {
		return nil, fmt.Errorf("enumerate passes (-opt-bisect-limit=-1): %w", err)
	}
	entries := parseBisectOutput(stderrAll)
	if len(entries) == 0 {
		return nil, errors.New("no BISECT pass lines emitted with -opt-bisect-limit=-1")
	}
	maxPass := entries[len(entries)-1].Index
	byIndex := make(map[int]passEntry, len(entries))
	for _, e := range entries {
		byIndex[e.Index] = e
	}
	if pass, _, err := relinkAndTest(ctx, allObj); err != nil {
		return nil, fmt.Errorf("test full pass pipeline: %w", err)
	} else if pass {
		if !keepLTO && culprit.BadImportBC == "" && hasLTOFlag(culprit.Args) {
			return bisectPassMode(ctx, spec, badTC, culprit, scratchDir, relinkAndTest, true)
		}
		return nil, errors.New("culprit TU passed at -opt-bisect-limit=-1")
	}

	testLimit := func(limit int) (bool, error) {
		cand := filepath.Join(scratchDir, fmt.Sprintf("cand_limit_%d.o", limit))
		if _, err := compileCulpritWithBisect(ctx, spec, badTC, culprit, limit, "obj", cand, keepLTO); err != nil {
			return false, fmt.Errorf("compile culprit at limit=%d: %w", limit, err)
		}
		pass, _, err := relinkAndTest(ctx, cand)
		return pass, err
	}

	// if post-import bitcode already fails at limit=0, retry pass bisect from source
	zeroPass, err := testLimit(0)
	if err != nil {
		return nil, err
	}
	if !zeroPass && culprit.BadImportBC != "" && len(culprit.Args) > 0 {
		srcCopy := *culprit
		srcCopy.BadImportBC = ""
		if srcRes, err := bisectPassMode(ctx, spec, badTC, &srcCopy, scratchDir, relinkAndTest, false); err == nil {
			return srcRes, nil
		}
	}

	culpritIdx := 0
	if zeroPass && maxPass > 0 {
		culpritIdx, err = bisectFirstFail(maxPass+1, func(limit int) (bool, error) {
			if limit == 0 {
				return false, nil
			}
			pass, err := testLimit(limit)
			return !pass, err
		})
		if err != nil {
			return nil, err
		}
	}

	entry, ok := byIndex[culpritIdx]
	if !ok && culpritIdx == 0 {
		entry = passEntry{PassName: "frontend-irgen"}
	}
	res := &passBisectResult{
		CulpritPassIndex:  culpritIdx,
		CulpritPass:       entry.PassName,
		CulpritFunc:       entry.Func,
		IsInterprocedural: isInterproceduralPass(entry.PassName, entry.Target),
	}
	if err := capturePassIRAndDiff(ctx, spec, badTC, culprit, scratchDir, res, keepLTO); err != nil {
		return nil, err
	}
	return res, nil
}

func compileCulpritWithBisect(ctx context.Context, spec platformSpec, tc *toolchain, culprit *compiledObj, limit int, mode, outPath string, keepLTO bool) (string, error) {
	compiler := driverFor(tc, culprit.IsCXX && culprit.BadImportBC == "")
	modeFlags := []string{"-c"}
	if mode == "ir" {
		modeFlags = []string{"-S", "-emit-llvm"}
	} else if mode == "asm" {
		modeFlags = []string{"-S"}
	}
	var args []string
	if culprit.BadImportBC != "" {
		args = append(args, crossTargetArgs(spec)...)
		args = append(args, "-O3", "-Wno-error")
		args = append(args, spec.BaselineFlags...)
		cgArgs := culprit.Args
		if len(cgArgs) == 0 {
			cgArgs = culprit.CompileRec.FullArgs
		}
		args = append(args, tuCodegenFlags(cgArgs, culprit.WorkDir)...)
		if spec.IsDarwin && tc.SDKRoot != "" {
			args = append(args, "-isysroot", tc.SDKRoot)
		}
		args = append(args, "-x", "ir")
		args = append(args, modeFlags...)
		args = append(args, culprit.BadImportBC)
	} else {
		args = append(bisectCompileArgs(culprit.Args, culprit.WorkDir, keepLTO && mode != "asm"), modeFlags...)
	}
	args = append(args, "-o", outPath, "-mllvm", fmt.Sprintf("-opt-bisect-limit=%d", limit))
	out, err := runToolInDir(ctx, compiler, args, culprit.WorkDir)
	if err != nil {
		return out, fmt.Errorf("%s failed: %w\n%s", filepath.Base(compiler), err, out)
	}
	return out, nil
}

func bisectCompileArgs(in []string, cwd string, keepLTO bool) []string {
	mask := stripMode | stripOutput | stripDep | stripLink | stripOptBisect
	if !keepLTO {
		mask |= stripLTO
	}
	var out []string
	for _, a := range stripFlags(in, mask, cwd) {
		if !isSaveTempsFlag(a) && !strings.HasPrefix(a, "-opt-bisect-limit") {
			out = append(out, a)
		}
	}
	return out
}

func capturePassIRAndDiff(ctx context.Context, spec platformSpec, tc *toolchain, culprit *compiledObj, scratchDir string, res *passBisectResult, keepLTO bool) error {
	bLim, aLim := max(0, res.CulpritPassIndex-1), res.CulpritPassIndex
	bFull, aFull := filepath.Join(scratchDir, "before_full.ll"), filepath.Join(scratchDir, "after_full.ll")
	if _, err := compileCulpritWithBisect(ctx, spec, tc, culprit, bLim, "ir", bFull, keepLTO); err != nil {
		return fmt.Errorf("dump before_full.ll: %w", err)
	}
	stderrAfter, err := compileCulpritWithBisect(ctx, spec, tc, culprit, aLim, "ir", aFull, keepLTO)
	if err != nil {
		return fmt.Errorf("dump after_full.ll: %w", err)
	}
	res.BeforeFullIRPath, res.AfterFullIRPath = bFull, aFull

	bFullRaw, err := os.ReadFile(bFull)
	if err != nil {
		return err
	}
	aFullRaw, err := os.ReadFile(aFull)
	if err != nil {
		return err
	}
	irEntries := parseBisectOutput(stderrAfter)
	maxIR := 0
	if len(irEntries) > 0 {
		maxIR = irEntries[len(irEntries)-1].Index
	}
	bIR, aIR := filepath.Join(scratchDir, "before.ll"), filepath.Join(scratchDir, "after.ll")
	if res.CulpritPassIndex > maxIR && cleanIR(string(bFullRaw)) == cleanIR(string(aFullRaw)) {
		res.IsCodeGenPass = true
		_ = os.Remove(bIR)
		_ = os.Remove(aIR)
		res.BeforeIRPath, res.AfterIRPath = "", ""
		bAsm, aAsm := filepath.Join(scratchDir, "before.s"), filepath.Join(scratchDir, "after.s")
		if _, e1 := compileCulpritWithBisect(ctx, spec, tc, culprit, bLim, "asm", bAsm, false); e1 == nil {
			if _, e2 := compileCulpritWithBisect(ctx, spec, tc, culprit, aLim, "asm", aAsm, false); e2 == nil {
				res.BeforeAsmPath, res.AfterAsmPath = bAsm, aAsm
				bS, _ := os.ReadFile(bAsm)
				aS, _ := os.ReadFile(aAsm)
				res.PassDiff = unifiedDiff(ctx, fmt.Sprintf("before.s (limit=%d)", bLim), string(bS),
					fmt.Sprintf("after.s (limit=%d, %s)", aLim, res.CulpritPass), string(aS))
				return nil
			}
		}
		return nil
	}

	if res.IsInterprocedural {
		// avoid single-function extraction and skip alive-tv IR drop for interprocedural passes
		_ = os.Remove(bIR)
		_ = os.Remove(aIR)
		res.BeforeIRPath, res.AfterIRPath = bFull, aFull
	} else {
		extracted := false
		if res.CulpritFunc != "" && tc.LLVMExtract != "" {
			tryExtract := func(in, out string) bool {
				if _, err := runToolInDir(ctx, tc.LLVMExtract, []string{"--func=" + res.CulpritFunc, "-S", in, "-o", out}, ""); err == nil {
					return fileNonEmpty(out)
				}
				return false
			}
			if tryExtract(bFull, bIR) && tryExtract(aFull, aIR) {
				extracted = true
			}
		}
		if !extracted {
			if err := copyFile(bFull, bIR, 0o644); err != nil {
				return err
			}
			if err := copyFile(aFull, aIR, 0o644); err != nil {
				return err
			}
		}
		res.BeforeIRPath, res.AfterIRPath = bIR, aIR
	}

	bRaw, err := os.ReadFile(res.BeforeIRPath)
	if err != nil {
		return err
	}
	aRaw, err := os.ReadFile(res.AfterIRPath)
	if err != nil {
		return err
	}
	bClean, aClean := cleanIR(string(bRaw)), cleanIR(string(aRaw))
	bDiff, aDiff := cleanIRForDiff(string(bRaw)), cleanIRForDiff(string(aRaw))
	if bDiff == aDiff {
		bDiff, aDiff = bClean, aClean
	}
	if bDiff == aDiff {
		bDiff, aDiff = string(bRaw), string(aRaw)
	}
	res.PassDiff = unifiedDiff(ctx, fmt.Sprintf("before.ll (limit=%d)", bLim), bDiff,
		fmt.Sprintf("after.ll (limit=%d, %s)", aLim, res.CulpritPass), aDiff)
	return nil
}

func unifiedDiff(ctx context.Context, oldLabel, oldText, newLabel, newText string) string {
	if oldText == newText {
		return ""
	}
	dir, err := os.MkdirTemp("", "lmc-diff-*")
	if err != nil {
		return ""
	}
	defer os.RemoveAll(dir)
	nl := func(s string) string {
		if s != "" && !strings.HasSuffix(s, "\n") {
			return s + "\n"
		}
		return s
	}
	p1, p2 := filepath.Join(dir, "before"), filepath.Join(dir, "after")
	if os.WriteFile(p1, []byte(nl(oldText)), 0o600) != nil || os.WriteFile(p2, []byte(nl(newText)), 0o600) != nil {
		return ""
	}
	out, err := exec.CommandContext(ctx, "diff", "-u", "--label", oldLabel, "--label", newLabel, p1, p2).CombinedOutput()
	var exitErr *exec.ExitError
	if err == nil || (errors.As(err, &exitErr) && exitErr.ExitCode() == 1) {
		return string(out)
	}
	return ""
}

type commitBisectOpts struct {
	LLVMSrcDir, GoodSHA, BadSHA, WorkDir, SDKRoot string
	Spec                                          platformSpec
	Jobs                                          int
	Culprit                                       *compiledObj
	RelinkAndTest                                 func(context.Context, string) (bool, string, error)
	buildClang                                    func(ctx context.Context, wtDir, buildDir, sha string) (string, error)
	testClang                                     func(ctx context.Context, clangBin, sha string) (bool, string, error)
}

func bisectCommit(ctx context.Context, o commitBisectOpts) (string, string, error) {
	if strings.TrimSpace(o.LLVMSrcDir) == "" || strings.TrimSpace(o.GoodSHA) == "" || strings.TrimSpace(o.BadSHA) == "" {
		return "", "", errors.New("llvm src dir, good SHA, and bad SHA are required")
	}
	if o.testClang == nil && (o.Culprit == nil || o.RelinkAndTest == nil) {
		return "", "", errors.New("culprit and relinkAndTest are required")
	}
	goodFull, err := gitOut(ctx, o.LLVMSrcDir, "rev-parse", "--verify", o.GoodSHA+"^{commit}")
	if err != nil {
		return "", "", fmt.Errorf("resolve good SHA %q: %w", o.GoodSHA, err)
	}
	badFull, err := gitOut(ctx, o.LLVMSrcDir, "rev-parse", "--verify", o.BadSHA+"^{commit}")
	if err != nil {
		return "", "", fmt.Errorf("resolve bad SHA %q: %w", o.BadSHA, err)
	}
	if goodFull == badFull {
		return "", "", fmt.Errorf("good and bad SHA are identical (%s)", goodFull)
	}
	if _, err := gitOut(ctx, o.LLVMSrcDir, "merge-base", "--is-ancestor", goodFull, badFull); err != nil {
		return "", "", fmt.Errorf("%s is not an ancestor of %s: %w", goodFull, badFull, err)
	}

	commits, err := gitListCommits(ctx, o.LLVMSrcDir, goodFull, badFull)
	if err != nil {
		return "", "", fmt.Errorf("list commits %s..%s: %w", goodFull, badFull, err)
	}
	if len(commits) == 0 {
		return "", "", fmt.Errorf("list commits %s..%s: no commits found", goodFull, badFull)
	}
	if len(commits) == 1 {
		subj, _ := gitOut(ctx, o.LLVMSrcDir, "show", "-s", "--format=%s", commits[0])
		return commits[0], subj, nil
	}

	workRoot := o.WorkDir
	if workRoot == "" {
		if workRoot, err = os.MkdirTemp("", "lmc-commit-bisect-*"); err != nil {
			return "", "", err
		}
		defer os.RemoveAll(workRoot)
	}
	workRoot = evalSymlinksExisting(workRoot)
	wtDir, buildDir, objDir := filepath.Join(workRoot, "llvm-project"), filepath.Join(workRoot, "llvm-build"), filepath.Join(workRoot, "tu-objs")
	if err := os.MkdirAll(objDir, 0o755); err != nil {
		return "", "", err
	}
	_, _ = gitOut(ctx, o.LLVMSrcDir, "worktree", "prune")
	_ = os.RemoveAll(wtDir)
	defer func() {
		_, _ = gitOut(context.Background(), o.LLVMSrcDir, "worktree", "remove", "--force", wtDir)
		_ = os.RemoveAll(wtDir)
		_, _ = gitOut(context.Background(), o.LLVMSrcDir, "worktree", "prune")
	}()
	if _, err := gitOut(ctx, o.LLVMSrcDir, "worktree", "add", "--detach", wtDir, badFull); err != nil {
		return "", "", err
	}

	buildFn, testFn := o.buildClang, o.testClang
	if buildFn == nil {
		buildFn = func(ctx context.Context, wt, bd, _ string) (string, error) {
			return buildClangInWorktree(ctx, wt, bd, o.Spec, o.Jobs)
		}
	}
	if testFn == nil {
		testFn = func(ctx context.Context, clangBin, sha string) (bool, string, error) {
			cand := filepath.Join(objDir, "tu_"+shortSHA(sha)+".o")
			if err := compileSingleTUWithClang(ctx, clangBin, o.Spec, o.SDKRoot, o.Culprit, cand); err != nil {
				return false, "", err
			}
			return o.RelinkAndTest(ctx, cand)
		}
	}

	// verify bad endpoint reproduces before bisecting so broken harnesses fail fast
	badBin, err := buildFn(ctx, wtDir, buildDir, badFull)
	if err != nil {
		if ctx.Err() != nil && !errors.Is(err, ctx.Err()) {
			return "", "", fmt.Errorf("build bad commit %s: %w", shortSHA(badFull), ctx.Err())
		}
		return "", "", fmt.Errorf("build bad commit %s: %w", shortSHA(badFull), err)
	}
	if ctx.Err() != nil {
		return "", "", fmt.Errorf("build bad commit %s: %w", shortSHA(badFull), ctx.Err())
	}
	badPass, _, err := testFn(ctx, badBin, badFull)
	if err != nil {
		if ctx.Err() != nil && !errors.Is(err, ctx.Err()) {
			return "", "", fmt.Errorf("test bad commit %s: %w", shortSHA(badFull), ctx.Err())
		}
		return "", "", fmt.Errorf("test bad commit %s: %w", shortSHA(badFull), err)
	}
	if ctx.Err() != nil {
		return "", "", fmt.Errorf("test bad commit %s: %w", shortSHA(badFull), ctx.Err())
	}
	if badPass {
		return "", "", fmt.Errorf("bad commit %s passed during commit bisect", shortSHA(badFull))
	}

	revs := append([]string{goodFull}, commits...)
	cIdx, err := bisectFirstFail(len(revs), func(mid int) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if mid == len(revs)-1 {
			return true, nil
		}
		sha := revs[mid]
		if _, err := gitOut(ctx, wtDir, "checkout", "--force", "--detach", sha); err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, fmt.Errorf("checkout %s: %w", sha, err)
		}
		clangBin, err := buildFn(ctx, wtDir, buildDir, sha)
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, errBisectSkip
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		pass, _, err := testFn(ctx, clangBin, sha)
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, errBisectSkip
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		return !pass, nil
	})
	if err != nil {
		return "", "", err
	}
	sha := revs[cIdx]
	subj, _ := gitOut(ctx, o.LLVMSrcDir, "show", "-s", "--format=%s", sha)
	return sha, subj, nil
}

func driverForClangBin(clangBin string, isCXX bool) string {
	if isCXX {
		if cxx := filepath.Join(filepath.Dir(clangBin), "clang++"); fileExists(cxx) {
			return cxx
		}
	}
	return clangBin
}

func compileSingleTUWithClang(ctx context.Context, clangBin string, spec platformSpec, sdkRoot string, culprit *compiledObj, outObj string) error {
	driver := clangBin
	if culprit.IsCXX && len(culprit.Args) > 0 {
		driver = driverForClangBin(clangBin, true)
	}
	var args []string
	if len(culprit.Args) > 0 {
		args = bisectCompileArgs(culprit.Args, culprit.WorkDir, false)
		if culprit.IsCXX && filepath.Base(driver) == "clang" {
			args = append([]string{"--driver-mode=g++"}, args...)
		}
		args = append(args, "-c", "-o", outObj)
	} else if bc := firstNonEmpty(culprit.GoodImportBC, culprit.BadImportBC); bc != "" {
		args = append(args, crossTargetArgs(spec)...)
		args = append(args, "-O3", "-Wno-error")
		args = append(args, spec.BaselineFlags...)
		args = append(args, tuCodegenFlags(culprit.CompileRec.FullArgs, culprit.WorkDir)...)
		if spec.IsDarwin && sdkRoot != "" {
			args = append(args, "-isysroot", sdkRoot)
		}
		args = append(args, "-x", "ir", "-c", bc, "-o", outObj)
	} else {
		return errors.New("culprit object has neither compile args nor bitcode input")
	}
	if out, err := runToolInDir(ctx, driver, args, culprit.WorkDir); err != nil {
		return fmt.Errorf("compile single TU with %s: %w\n%s", driver, err, out)
	}
	return nil
}

func buildFailCompileArgs(rec compileRec, spec platformSpec, sdkRoot, outPath string) ([]string, []string) {
	expanded := expandResponseFiles(rec.CWD, rec.FullArgs)
	var hasC, hasS, hasEmitLLVM bool
	for i := 0; i < len(expanded); i++ {
		a := expanded[i]
		if a == "--" {
			break
		}
		if twoArgClangFlags[a] || a == "-x" || a == "-o" {
			i++
			continue
		}
		switch a {
		case "-c":
			hasC = true
		case "-S":
			hasS = true
		case "-emit-llvm":
			hasEmitLLVM = true
		}
	}
	args := bisectCompileArgs(expanded, rec.CWD, true)
	if !hasC && !hasS && !hasEmitLLVM {
		args = stripLinkLibs(args)
	}
	modeFlags := []string{"-c"}
	if hasS && !hasC {
		modeFlags = []string{"-S"}
	}
	if hasEmitLLVM {
		modeFlags = append(modeFlags, "-emit-llvm")
	}
	args = appendBeforeDashDash(args, append(modeFlags, "-o", outPath))
	extraEnv, args := applySDKRoot(&toolchain{Spec: spec, SDKRoot: sdkRoot}, args)
	return extraEnv, args
}

func runBuildFailCompile(ctx context.Context, driver string, isCXX bool, spec platformSpec, sdkRoot string, rec compileRec, outPath string) (string, error) {
	extraEnv, args := buildFailCompileArgs(rec, spec, sdkRoot, outPath)
	if isCXX && filepath.Base(driver) == "clang" {
		args = append([]string{"--driver-mode=g++"}, args...)
	}
	return runToolInDirEnv(ctx, driver, args, rec.CWD, extraEnv)
}

func runBuildFailLink(ctx context.Context, driverTC *toolchain, driverOverride, linkerPath, goodBuild, badBuild string, mapToGood bool, rec linkRec, scratchDir, tag, outBin string) (string, error) {
	var mapInput func(string) (string, bool)
	if mapToGood && goodBuild != "" && badBuild != "" {
		mapInput = func(canon string) (string, bool) {
			rel, ok := relWithinDir(badBuild, canon)
			if !ok {
				return "", false
			}
			cand := filepath.Join(goodBuild, rel)
			switch strings.ToLower(filepath.Ext(cand)) {
			case ".o", ".lo", ".obj", ".bc", ".a":
				if fileExists(cand) {
					return cand, true
				}
			}
			return "", false
		}
	}
	args, err := rewriteLinkArgs(rec.FullArgs, linkRewriteOpts{
		cwd: rec.CWD, scratchDir: scratchDir, tag: tag,
		stripOut: true, newLinker: linkerPath, mapObj: mapInput, mapAr: mapInput,
	})
	if err != nil {
		return "", err
	}
	args = appendBeforeDashDash(args, []string{"-o", outBin})
	extraEnv, args := applySDKRoot(driverTC, args)
	driver := driverOverride
	if driver == "" {
		driver = driverFor(driverTC, rec.IsCXX)
	} else if rec.IsCXX && filepath.Base(driver) == "clang" {
		args = append([]string{"--driver-mode=g++"}, args...)
	}
	return runToolInDirEnv(ctx, driver, args, rec.CWD, extraEnv)
}

func bisectLLVMTargets(spec platformSpec, hostOS, hostArch string) string {
	if spec.ID == platLinuxRISCV64 && hostOS == "linux" && hostArch == "amd64" {
		return "X86;RISCV"
	}
	return firstNonEmpty(spec.LLVMTarget, "Native")
}

func buildClangInWorktree(ctx context.Context, wtDir, buildDir string, spec platformSpec, jobs int) (string, error) {
	return buildProjectToolInWorktree(ctx, wtDir, buildDir, spec, jobs, "clang", "clang", "clang")
}

func buildProjectToolInWorktree(ctx context.Context, wtDir, buildDir string, spec platformSpec, jobs int, project, target, binName string) (string, error) {
	return buildProjectTool(ctx, wtDir, buildDir, spec, jobs, project, target, binName, os.Environ(), exec.LookPath)
}

func buildProjectTool(ctx context.Context, wtDir, buildDir string, spec platformSpec, jobs int, project, target, binName string, env []string, lookPath func(string) (string, error)) (string, error) {
	if jobs <= 0 {
		jobs = runtime.NumCPU()
	}
	llvmDir := filepath.Join(wtDir, "llvm")
	var clangPath, clangXXPath string
	useClang := false
	if !spec.IsDarwin {
		if c, err1 := lookPath("clang"); err1 == nil {
			if cxx, err2 := lookPath("clang++"); err2 == nil {
				clangPath, clangXXPath, useClang = c, cxx, true
			}
		}
	}
	baseEnv := stripEnv(env, "CCACHE_DISABLE", "SCCACHE_DISABLE")
	if useClang {
		baseEnv = stripEnv(baseEnv, "CC", "CXX")
	}
	extraEnv := []string{"CCACHE_BASEDIR=" + evalSymlinksExisting(filepath.Dir(wtDir))}
	resolveBin := func(name string) string {
		if p, err := lookPath(name); err == nil {
			return p
		}
		return name
	}
	configure := func() error {
		if err := os.MkdirAll(buildDir, 0o755); err != nil {
			return err
		}
		args := []string{
			"-G", "Ninja", "-S", llvmDir, "-B", buildDir,
			"-DCMAKE_BUILD_TYPE=Release", "-DLLVM_ENABLE_ASSERTIONS=ON",
			"-DLLVM_TARGETS_TO_BUILD=" + bisectLLVMTargets(spec, runtime.GOOS, runtime.GOARCH), "-DLLVM_ENABLE_PROJECTS=" + project,
			"-DLLVM_APPEND_VC_REV=OFF", "-DLLVM_INCLUDE_TESTS=OFF", "-DLLVM_INCLUDE_BENCHMARKS=OFF",
			"-DLLVM_INCLUDE_EXAMPLES=OFF", "-DLLVM_INCLUDE_DOCS=OFF", "-DLLVM_ENABLE_BINDINGS=OFF", "-DLLVM_PARALLEL_LINK_JOBS=2",
		}
		if project == "clang" {
			args = append(args, "-DCLANG_ENABLE_CIR=OFF", "-DCLANG_ENABLE_STATIC_ANALYZER=OFF")
		}
		if _, err := lookPath("ccache"); err == nil {
			args = append(args,
				"-DLLVM_CCACHE_BUILD=ON",
				"-DLLVM_CCACHE_PARAMS=CCACHE_CPP2=yes CCACHE_NOHASHDIR=yes CCACHE_SLOPPINESS=pch_defines,time_macros",
			)
		}
		if !spec.IsDarwin {
			if useClang {
				args = append(args, "-DCMAKE_C_COMPILER=clang", "-DCMAKE_CXX_COMPILER=clang++")
			}
			if _, err := lookPath("ld.lld"); err == nil {
				args = append(args, "-DLLVM_USE_LINKER=lld")
			}
		}
		if out, err := runToolInDirBaseEnv(ctx, resolveBin("cmake"), args, "", baseEnv, extraEnv); err != nil {
			return fmt.Errorf("cmake configure %s: %w\n%s", project, err, tailText(out, 4096))
		}
		return nil
	}

	needCfg := !fileExists(filepath.Join(buildDir, "build.ninja"))
	if !needCfg {
		raw, err := os.ReadFile(filepath.Join(buildDir, "CMakeCache.txt"))
		cache := string(raw)
		if err != nil ||
			!strings.Contains(cache, llvmDir) ||
			!strings.Contains(cache, "LLVM_ENABLE_PROJECTS:STRING="+project) ||
			(useClang && (!cmakeCacheMatchesCompiler(cache, "CMAKE_C_COMPILER", "clang", clangPath) ||
				!cmakeCacheMatchesCompiler(cache, "CMAKE_CXX_COMPILER", "clang++", clangXXPath))) {
			needCfg = true
		}
	}
	if needCfg {
		_ = os.RemoveAll(buildDir)
		if err := configure(); err != nil {
			return "", err
		}
	}
	out, err := runToolInDirBaseEnv(ctx, resolveBin("ninja"), []string{"-C", buildDir, "-j", strconv.Itoa(jobs), target}, "", baseEnv, extraEnv)
	if err != nil && ctx.Err() == nil && !needCfg && isStaleNinjaError(out) {
		_ = os.RemoveAll(buildDir)
		if cfgErr := configure(); cfgErr != nil {
			return "", cfgErr
		}
		out, err = runToolInDirBaseEnv(ctx, resolveBin("ninja"), []string{"-C", buildDir, "-j", strconv.Itoa(jobs), target}, "", baseEnv, extraEnv)
	}
	if err != nil {
		return "", fmt.Errorf("ninja %s: %w\n%s", target, err, tailText(out, 4096))
	}
	toolBin := filepath.Join(buildDir, "bin", binName)
	if !fileExists(toolBin) {
		return "", fmt.Errorf("built %s missing at %s", binName, toolBin)
	}
	if binName == "clang" {
		if _, err := os.Lstat(filepath.Join(buildDir, "bin", "clang++")); err != nil {
			_ = os.Symlink("clang", filepath.Join(buildDir, "bin", "clang++"))
		}
	}
	return toolBin, nil
}

func cmakeCacheValue(raw, key string) string {
	prefix := key + ":"
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if _, val, ok := strings.Cut(line, "="); ok {
			return strings.TrimSpace(val)
		}
	}
	return ""
}

func cmakeCacheMatchesCompiler(raw, key, wantName, wantPath string) bool {
	got := cmakeCacheValue(raw, key)
	if got == "" {
		return false
	}
	if got == wantName || got == wantPath {
		return true
	}
	return wantPath != "" && evalSymlinksExisting(got) == evalSymlinksExisting(wantPath)
}

func isStaleNinjaError(out string) bool {
	return containsAny(out, []string{"ninja: error:", "build.ninja", "CMake Error", "re-run cmake", "multiple rules generate"})
}

func gitListCommits(ctx context.Context, repoDir, goodSHA, badSHA string) ([]string, error) {
	out, err := gitOut(ctx, repoDir, "rev-list", "--first-parent", "--ancestry-path", "--reverse", goodSHA+".."+badSHA)
	if err != nil {
		return nil, err
	}
	if list := nonEmptyLines(out); len(list) > 0 {
		return list, nil
	}
	out, err = gitOut(ctx, repoDir, "rev-list", "--ancestry-path", "--reverse", goodSHA+".."+badSHA)
	if err != nil {
		return nil, err
	}
	return nonEmptyLines(out), nil
}

func gitOut(ctx context.Context, repoDir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repoDir}, args...)...)
	setCmdProcessGroup(cmd)
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		if ctx.Err() != nil && !errors.Is(err, ctx.Err()) {
			return s, fmt.Errorf("%w: %v (%s)", ctx.Err(), err, s)
		}
		return s, fmt.Errorf("%w (%s)", err, s)
	}
	return s, nil
}

func runToolInDir(ctx context.Context, bin string, args []string, dir string) (string, error) {
	return runToolInDirEnv(ctx, bin, args, dir, nil)
}

func runToolInDirEnv(ctx context.Context, bin string, args []string, dir string, extraEnv []string) (string, error) {
	return runToolInDirBaseEnv(ctx, bin, args, dir, os.Environ(), extraEnv)
}

func runToolInDirBaseEnv(ctx context.Context, bin string, args []string, dir string, baseEnv, extraEnv []string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = mergeEnv(baseEnv, append([]string{"SOURCE_DATE_EPOCH=0"}, extraEnv...))
	setCmdProcessGroup(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil && ctx.Err() != nil && !errors.Is(err, ctx.Err()) {
		err = fmt.Errorf("%w: %v", ctx.Err(), err)
	}
	return strings.TrimSpace(string(out)), err
}

func driverFor(tc *toolchain, isCXX bool) string {
	if isCXX && tc.ClangXX != "" {
		return tc.ClangXX
	}
	return tc.Clang
}

func stripLinkLibs(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			out = append(out, args[i:]...)
			break
		}
		if a == "-l" || a == "-L" || a == "-force_load" || a == "-filelist" {
			i++
			continue
		}
		if strings.HasPrefix(a, "-l") || strings.HasPrefix(a, "-L") {
			continue
		}
		if twoArgClangFlags[a] || a == "-x" {
			out = append(out, a)
			if i+1 < len(args) {
				i++
				out = append(out, args[i])
			}
			continue
		}
		if !strings.HasPrefix(a, "-") {
			switch ext := strings.ToLower(filepath.Ext(a)); {
			case ext == ".o" || ext == ".lo" || ext == ".obj" || ext == ".bc" || ext == ".a" || ext == ".so" || ext == ".dylib" || strings.Contains(filepath.Base(a), ".so."):
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

func mkdirAll(dirs ...string) error {
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func relWithinDir(root, target string) (string, bool) {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return rel, true
	}
	rel, err = filepath.Rel(evalSymlinksExisting(root), evalSymlinksExisting(target))
	return rel, err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func fileSHA256Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
