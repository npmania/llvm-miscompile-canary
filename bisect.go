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

var (
	errBisectSkip = errors.New("skip")
	bisectLineRe  = regexp.MustCompile(`^BISECT:\s+running pass \((\d+)\)\s+(.+?)\s+on\s+(.+)$`)
)

func bisectFirstFail(n int, fails func(int) (bool, error)) (int, error) {
	if n <= 1 {
		return 0, nil
	}
	lo, hi := 0, n-1
	var skipped map[int]bool
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
			continue
		}
		if err != nil {
			return 0, err
		}
		if bad {
			hi = mid
		} else {
			lo = mid + 1
		}
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
	relinkSingle  func(context.Context, string) (bool, string, error)
	buildRelink   func(string) (reduceRelink, error)
}

func bisectObjects(ctx context.Context, o objectBisectOpts) (*objectBisectResult, error) {
	if o.GoodTC == nil || o.BadTC == nil || o.Test == nil {
		return nil, errors.New("good toolchain, bad toolchain, and test func are required")
	}
	goodBuild, err := filepath.Abs(o.GoodBuildDir)
	if err != nil {
		return nil, err
	}
	badBuild, err := filepath.Abs(o.BadBuildDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(o.ScratchDir, 0o755); err != nil {
		return nil, err
	}
	badComp, err := readCompileRecs(o.BadManifestDir)
	if err != nil {
		return nil, fmt.Errorf("read bad compile manifest: %w", err)
	}
	badLinks, err := readLinkRecs(o.BadManifestDir)
	if err != nil {
		return nil, fmt.Errorf("read bad link manifest: %w", err)
	}

	var links []linkRec
	linkOrder := make(map[string]int)
	for _, bl := range badLinks {
		rel, ok := relWithinDir(badBuild, bl.Output)
		if !ok || !fileExists(bl.Output) {
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
		setLink := func(i int, useBad bool) error {
			if useBad {
				return copyFile(backups[i], links[i].Output, 0)
			}
			return relinkMapped(ctx, o.BadTC, goodBuild, badBuild, links[i])
		}
		for i := range links {
			if err := setLink(i, false); err != nil {
				return nil, fmt.Errorf("relink %s with good inputs: %w", links[i].Output, err)
			}
		}
		allGood, err := runTest()
		if err != nil {
			return nil, err
		}
		if allGood {
			if targetIdx, err = bisectFirstFail(len(links), func(mid int) (bool, error) {
				for i := range links {
					if err := setLink(i, i <= mid); err != nil {
						return false, err
					}
				}
				pass, err := runTest()
				return !pass, err
			}); err != nil {
				return nil, err
			}
		}
		for i := range links {
			if err := setLink(i, i == targetIdx); err != nil {
				return nil, err
			}
		}
	}

	targetLink := links[targetIdx]
	if len(targetLink.ObjectFiles) == 0 && len(targetLink.ArchiveFiles) == 0 {
		if synth, sb, ok, err := splitDirectCompileLink(ctx, o, goodBuild, badBuild, targetLink, badComp); err != nil {
			return nil, err
		} else if ok {
			targetLink, badComp = synth, append(badComp, sb...)
		}
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
	if len(d.units) == 1 {
		return finish(0, -1), nil
	}

	testPick := func(pick func(int) string) (bool, error) {
		if err := d.relink(ctx, pick); err != nil {
			return false, err
		}
		return runTest()
	}
	goodPass, err := testPick(func(i int) string { return d.units[i].GoodObj })
	if err != nil {
		return nil, fmt.Errorf("relink %s with all good objects: %w", targetLink.Output, err)
	}
	if !goodPass {
		if o.Profile == profReleaseLTO {
			if res, ok := tryThinLTONativeBisect(ctx, o, goodBuild, badBuild, targetLink, badComp); ok {
				return res, nil
			}
		}
		return nil, fmt.Errorf("relinking %s with all good objects still failed test", targetLink.Output)
	}

	cIdx, err := bisectFirstFail(len(d.units), func(mid int) (bool, error) {
		pass, err := testPick(func(i int) string {
			if i <= mid {
				return d.units[i].BadObj
			}
			return d.units[i].GoodObj
		})
		return !pass, err
	})
	if err != nil {
		return nil, err
	}

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
		if pIdx, err = bisectFirstFail(cIdx, func(mid int) (bool, error) {
			pass, err := testPick(func(i int) string {
				if i == cIdx || i <= mid {
					return d.units[i].BadObj
				}
				return d.units[i].GoodObj
			})
			return !pass, err
		}); err != nil {
			return nil, err
		}
	}
	return finish(cIdx, pIdx), nil
}

func relinkMapped(ctx context.Context, tc *toolchain, goodBuild, badBuild string, rec linkRec) error {
	args := slices.Clone(rec.FullArgs)
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if rel, ok := relWithinDir(badBuild, resolvePath(rec.CWD, a)); ok {
			cand := filepath.Join(goodBuild, rel)
			switch strings.ToLower(filepath.Ext(cand)) {
			case ".o", ".lo", ".obj", ".bc", ".a":
				if fileExists(cand) {
					args[i] = cand
				}
			}
		}
	}
	if out, err := runToolInDir(ctx, driverFor(tc, rec.IsCXX), args, rec.CWD); err != nil {
		return fmt.Errorf("relink %s: %w\n%s", rec.Output, err, out)
	}
	return nil
}

func splitDirectCompileLink(ctx context.Context, o objectBisectOpts, goodBuild, badBuild string, rec linkRec, badComp []compileRec) (linkRec, []compileRec, bool, error) {
	var match *compileRec
	for i := len(badComp) - 1; i >= 0; i-- {
		if filepath.Clean(badComp[i].Output) == filepath.Clean(rec.Output) && len(badComp[i].Sources) > 0 {
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
		srcSet[filepath.Clean(s)] = true
	}
	var linkArgs []string
	inserted := false
	for _, a := range rec.FullArgs {
		if !strings.HasPrefix(a, "-") && srcSet[resolvePath(rec.CWD, a)] {
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
	rec.ObjectFiles, rec.FullArgs = badObjs, linkArgs
	return rec, sBad, true, nil
}

type archiveGroup struct {
	badPath   string
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
		out := filepath.Clean(cr.Output)
		byOut[out] = cr
		if h, err := fileSHA256Hex(out); err == nil {
			byHash[h] = cr
		}
		byBase[filepath.Base(out)] = append(byBase[filepath.Base(out)], cr)
	}

	var units []*compiledObj
	directIdx := make(map[string]int)
	for _, obj := range rec.ObjectFiles {
		bad := filepath.Clean(obj)
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
		badAr := filepath.Clean(ar)
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
		grp := archiveGroup{badPath: badAr, memberIdx: make([]int, len(bMem))}
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
				RelPath: rel, GoodObj: gMem[m].path, BadObj: bMem[m].path, SourceFile: cr.Source,
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

func (d *linkDecomp) buildArgs(pick func(int) string, builtAr map[string]string, tag string) ([]string, error) {
	args := make([]string, 0, len(d.targetLink.FullArgs))
	for i := 0; i < len(d.targetLink.FullArgs); i++ {
		a := d.targetLink.FullArgs[i]
		if a == "-filelist" && i+1 < len(d.targetLink.FullArgs) {
			dst := filepath.Join(d.scratchDir, "filelist_"+tag+".txt")
			if err := rewriteFilelist(resolvePath(d.targetLink.CWD, d.targetLink.FullArgs[i+1]), d.targetLink.CWD, dst, d.directIdx, pick); err != nil {
				return nil, err
			}
			args = append(args, "-filelist", dst)
			i++
			continue
		}
		if !strings.HasPrefix(a, "-") {
			res := resolvePath(d.targetLink.CWD, a)
			if uIdx, ok := d.directIdx[res]; ok {
				args = append(args, pick(uIdx))
				continue
			}
			if mixed, ok := builtAr[res]; ok {
				args = append(args, mixed)
				continue
			}
		}
		args = append(args, a)
	}
	return args, nil
}

func (d *linkDecomp) relink(ctx context.Context, pick func(int) string) error {
	d.counter++
	builtAr := make(map[string]string, len(d.archives))
	for i, g := range d.archives {
		members := make([]string, len(g.memberIdx))
		for m, uIdx := range g.memberIdx {
			members[m] = pick(uIdx)
		}
		outAr := filepath.Join(d.mixedDir, fmt.Sprintf("mix_%d_%d_%s", d.counter, i, filepath.Base(g.badPath)))
		if err := createStaticArchive(ctx, d.arTool, d.ranlib, outAr, members); err != nil {
			return err
		}
		builtAr[g.badPath] = outAr
		defer os.Remove(outAr)
	}
	args, err := d.buildArgs(pick, builtAr, strconv.Itoa(d.counter))
	if err != nil {
		return err
	}
	if out, err := runToolInDir(ctx, driverFor(d.badTC, d.targetLink.IsCXX), args, d.targetLink.CWD); err != nil {
		return fmt.Errorf("relink %s: %w\n%s", d.targetLink.Output, err, out)
	}
	return nil
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
	if rr.LinkArgs, err = d.buildArgs(pick, builtAr, "reduce"); err != nil {
		return reduceRelink{}, err
	}
	return rr, nil
}

func tryThinLTONativeBisect(ctx context.Context, o objectBisectOpts, goodBuild, badBuild string, rec linkRec, badComp []compileRec) (*objectBisectResult, bool) {
	if len(rec.ArchiveFiles) > 0 || len(rec.ObjectFiles) == 0 {
		return nil, false
	}
	gMods, err := runSaveTempsLink(ctx, o.Spec, o.GoodTC, goodBuild, badBuild, rec, false, filepath.Join(o.ScratchDir, "lto_save_good"))
	if err != nil || len(gMods) == 0 {
		return nil, false
	}
	bMods, err := runSaveTempsLink(ctx, o.Spec, o.BadTC, goodBuild, badBuild, rec, true, filepath.Join(o.ScratchDir, "lto_save_bad"))
	if err != nil || len(bMods) != len(gMods) {
		return nil, false
	}

	byOut := make(map[string]compileRec, len(badComp))
	for _, cr := range badComp {
		byOut[filepath.Clean(cr.Output)] = cr
	}
	units := make([]*compiledObj, 0, len(bMods))
	inputSet := make(map[string]int, len(bMods))
	for i := range bMods {
		gm, bm := gMods[i], bMods[i]
		if !fileExists(gm.nativeObj) || !fileExists(bm.nativeObj) {
			return nil, false
		}
		rel, _ := relWithinDir(badBuild, bm.inputBC)
		cr := byOut[filepath.Clean(bm.inputBC)]
		inputSet[filepath.Clean(bm.inputBC)] = len(units)
		units = append(units, &compiledObj{
			RelPath: firstNonEmpty(rel, filepath.Base(bm.inputBC)), GoodObj: gm.inputBC, BadObj: bm.inputBC,
			SourceFile: cr.Source, WorkDir: firstNonEmpty(cr.CWD, rec.CWD), IsCXX: cr.IsCXX,
			Args: slices.Clone(cr.FullArgs), CompileRec: cr,
			GoodNativeLTOObj: gm.nativeObj, BadNativeLTOObj: bm.nativeObj,
			GoodImportBC: gm.importBC, BadImportBC: bm.importBC,
		})
	}

	driver := driverFor(o.BadTC, rec.IsCXX)
	relink := func(ctx context.Context, pick func(int) string) error {
		_, err := runToolInDir(ctx, driver, buildNativeRelinkArgs(rec, inputSet, pick), rec.CWD)
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
	cIdx, err := bisectFirstFail(len(units), func(mid int) (bool, error) {
		pass, err := testNative(func(i int) string {
			if i <= mid {
				return units[i].BadNativeLTOObj
			}
			return units[i].GoodNativeLTOObj
		})
		return !pass, err
	})
	if err != nil {
		return nil, false
	}

	pickCand := func(cand string) func(int) string {
		return func(i int) string {
			if i == cIdx {
				return cand
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
			return reduceRelink{LinkDriver: driver, LinkDir: rec.CWD, CandObj: cand, LinkArgs: buildNativeRelinkArgs(rec, inputSet, pickCand(cand))}, nil
		},
	}, true
}

type savedLTOMod struct{ inputBC, nativeObj, importBC string }

func runSaveTempsLink(ctx context.Context, spec platformSpec, tc *toolchain, goodBuild, badBuild string, rec linkRec, useBad bool, workDir string) ([]savedLTOMod, error) {
	objsDir, ltoDir := filepath.Join(workDir, "objs"), filepath.Join(workDir, "lto_native")
	if err := os.RemoveAll(workDir); err != nil {
		return nil, err
	}
	if err := mkdirAll(objsDir, ltoDir); err != nil {
		return nil, err
	}

	copyToOrig, origToCopy := make(map[string]string), make(map[string]string)
	for i, badObj := range rec.ObjectFiles {
		bad, src := filepath.Clean(badObj), filepath.Clean(badObj)
		if !useBad {
			rel, ok := relWithinDir(badBuild, bad)
			if !ok {
				return nil, fmt.Errorf("object %s outside badBuild", bad)
			}
			src = filepath.Join(goodBuild, rel)
		}
		cp := filepath.Join(objsDir, fmt.Sprintf("m%04d_%s", i, filepath.Base(bad)))
		if err := copyFile(src, cp, 0); err != nil {
			return nil, err
		}
		copyToOrig[cp], origToCopy[bad] = bad, cp
	}

	var args []string
	for i := 0; i < len(rec.FullArgs); i++ {
		a := rec.FullArgs[i]
		if a == "-o" || a == "--ld-path" {
			i++
			continue
		}
		if isAttachedOutputFlag(a) || strings.HasPrefix(a, "-fuse-ld=") || strings.HasPrefix(a, "--ld-path=") ||
			strings.Contains(a, "save-temps") || strings.Contains(a, "object_path_lto") || strings.Contains(a, "lto-obj-path") {
			continue
		}
		if !strings.HasPrefix(a, "-") {
			if cp, ok := origToCopy[resolvePath(rec.CWD, a)]; ok {
				args = append(args, cp)
				continue
			}
		}
		args = append(args, a)
	}

	outBin, objPrefix := filepath.Join(workDir, filepath.Base(rec.Output)), filepath.Join(ltoDir, "mod")
	args = append(args, linkerFlag(tc.Linker), "-o", outBin)
	if spec.IsDarwin {
		args = append(args, "-Wl,-save-temps", "-Wl,-object_path_lto,"+ltoDir)
	} else {
		args = append(args, "-Wl,--save-temps", "-Wl,--lto-obj-path="+objPrefix)
	}
	if out, err := runToolInDir(ctx, driverFor(tc, rec.IsCXX), args, rec.CWD); err != nil {
		return nil, fmt.Errorf("save-temps link: %w\n%s", err, out)
	}

	resTxt, err := os.ReadFile(outBin + ".resolution.txt")
	if err != nil {
		return nil, err
	}
	var ordered []string
	for _, line := range nonEmptyLines(string(resTxt)) {
		if !strings.HasPrefix(line, "-r=") {
			ordered = append(ordered, filepath.Clean(line))
		}
	}
	if len(ordered) == 0 {
		return nil, errors.New("empty resolution.txt")
	}

	mods := make([]savedLTOMod, 0, len(ordered))
	for i, cp := range ordered {
		// ThinLTO module tasks start at 1; 0 is the regular LTO partition
		modIdx := i + 1
		var native string
		if spec.IsDarwin {
			if c := fmt.Sprintf("%s%d.lto.o", outBin, modIdx); fileExists(c) {
				native = c
			} else if ms, _ := filepath.Glob(filepath.Join(ltoDir, fmt.Sprintf("%d.*.lto.o", modIdx))); len(ms) > 0 {
				native = ms[0]
			}
		} else {
			stem := strings.TrimSuffix(filepath.Base(cp), filepath.Ext(cp))
			if c := fmt.Sprintf("%s%d", objPrefix, modIdx); fileExists(c) {
				native = c
			} else if c := filepath.Join(filepath.Dir(cp), fmt.Sprintf("%s.lto.%s.o", filepath.Base(outBin), stem)); fileExists(c) {
				native = c
			}
		}
		if native == "" {
			return nil, fmt.Errorf("missing native LTO object for module %d", modIdx)
		}
		importBC := ""
		if c := cp + ".3.import.bc"; fileExists(c) {
			importBC = c
		}
		mods = append(mods, savedLTOMod{inputBC: firstNonEmpty(copyToOrig[cp], cp), nativeObj: native, importBC: importBC})
	}
	return mods, nil
}

func buildNativeRelinkArgs(rec linkRec, inputSet map[string]int, pick func(int) string) []string {
	var out []string
	replaced := false
	for _, a := range rec.FullArgs {
		if strings.HasPrefix(a, "-flto") || strings.Contains(a, "thinlto-jobs") ||
			strings.Contains(a, "save-temps") || strings.Contains(a, "object_path_lto") || strings.Contains(a, "lto-obj-path") {
			continue
		}
		if !strings.HasPrefix(a, "-") {
			if idx, ok := inputSet[resolvePath(rec.CWD, a)]; ok {
				out, replaced = append(out, pick(idx)), true
				continue
			}
		}
		out = append(out, a)
	}
	if !replaced {
		for i := range len(inputSet) {
			out = append(out, pick(i))
		}
	}
	return out
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

func rewriteFilelist(orig, cwd, dst string, directIdx map[string]int, pick func(int) string) error {
	raw, err := os.ReadFile(orig)
	if err != nil {
		return err
	}
	var b bytes.Buffer
	for _, line := range nonEmptyLines(string(raw)) {
		if idx, ok := directIdx[resolvePath(cwd, line)]; ok {
			b.WriteString(pick(idx))
		} else {
			b.WriteString(line)
		}
		b.WriteByte('\n')
	}
	return os.WriteFile(dst, b.Bytes(), 0o644)
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
	IsCodeGenPass                               bool
}

func bisectPass(ctx context.Context, spec platformSpec, badTC *toolchain, culprit *compiledObj, scratchDir string, relinkAndTest func(context.Context, string) (bool, string, error)) (*passBisectResult, error) {
	if badTC == nil || culprit == nil || relinkAndTest == nil {
		return nil, errors.New("bad toolchain, culprit, and relinkAndTest are required")
	}
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		return nil, err
	}
	allObj := filepath.Join(scratchDir, "pass_limit_all.o")
	stderrAll, err := compileCulpritWithBisect(ctx, spec, badTC, culprit, -1, "obj", allObj)
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
		return nil, errors.New("culprit TU passed at -opt-bisect-limit=-1")
	}

	testLimit := func(limit int) (bool, error) {
		cand := filepath.Join(scratchDir, fmt.Sprintf("cand_limit_%d.o", limit))
		if _, err := compileCulpritWithBisect(ctx, spec, badTC, culprit, limit, "obj", cand); err != nil {
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
		if srcRes, err := bisectPass(ctx, spec, badTC, &srcCopy, scratchDir, relinkAndTest); err == nil {
			return srcRes, nil
		}
	}

	culpritIdx := 0
	if zeroPass && maxPass > 0 {
		idx, err := bisectFirstFail(maxPass, func(i int) (bool, error) {
			pass, err := testLimit(i + 1)
			return !pass, err
		})
		if err != nil {
			return nil, err
		}
		culpritIdx = idx + 1
	}

	entry, ok := byIndex[culpritIdx]
	if !ok && culpritIdx == 0 {
		entry = passEntry{PassName: "frontend-irgen"}
	}
	res := &passBisectResult{CulpritPassIndex: culpritIdx, CulpritPass: entry.PassName, CulpritFunc: entry.Func}
	if err := capturePassIRAndDiff(ctx, spec, badTC, culprit, scratchDir, res); err != nil {
		return nil, err
	}
	return res, nil
}

func compileCulpritWithBisect(ctx context.Context, spec platformSpec, tc *toolchain, culprit *compiledObj, limit int, mode, outPath string) (string, error) {
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
		if spec.IsDarwin && tc.SDKRoot != "" {
			args = append(args, "-isysroot", tc.SDKRoot)
		}
		args = append(args, "-x", "ir")
		args = append(args, modeFlags...)
		args = append(args, culprit.BadImportBC)
	} else {
		args = append(bisectCompileArgs(culprit.Args), modeFlags...)
	}
	args = append(args, "-o", outPath, "-mllvm", fmt.Sprintf("-opt-bisect-limit=%d", limit))
	out, err := runToolInDir(ctx, compiler, args, culprit.WorkDir)
	if err != nil {
		return out, fmt.Errorf("%s failed: %w\n%s", filepath.Base(compiler), err, out)
	}
	return out, nil
}

func bisectCompileArgs(in []string) []string {
	var out []string
	for _, a := range stripFlags(in, stripMode|stripOutput|stripDep|stripLink|stripLTO|stripOptBisect, "") {
		if !strings.HasPrefix(a, "-save-temps") && !strings.HasPrefix(a, "--save-temps") && !strings.HasPrefix(a, "-opt-bisect-limit") {
			out = append(out, a)
		}
	}
	return out
}

func capturePassIRAndDiff(ctx context.Context, spec platformSpec, tc *toolchain, culprit *compiledObj, scratchDir string, res *passBisectResult) error {
	bLim, aLim := max(0, res.CulpritPassIndex-1), res.CulpritPassIndex
	bFull, aFull := filepath.Join(scratchDir, "before_full.ll"), filepath.Join(scratchDir, "after_full.ll")
	if _, err := compileCulpritWithBisect(ctx, spec, tc, culprit, bLim, "ir", bFull); err != nil {
		return fmt.Errorf("dump before_full.ll: %w", err)
	}
	stderrAfter, err := compileCulpritWithBisect(ctx, spec, tc, culprit, aLim, "ir", aFull)
	if err != nil {
		return fmt.Errorf("dump after_full.ll: %w", err)
	}
	res.BeforeFullIRPath, res.AfterFullIRPath = bFull, aFull

	bIR, aIR := filepath.Join(scratchDir, "before.ll"), filepath.Join(scratchDir, "after.ll")
	extractOrCopy := func(in, out string) error {
		if res.CulpritFunc != "" && tc.LLVMExtract != "" {
			if _, err := runToolInDir(ctx, tc.LLVMExtract, []string{"--func=" + res.CulpritFunc, "-S", in, "-o", out}, ""); err == nil {
				if info, err := os.Stat(out); err == nil && info.Size() > 0 {
					return nil
				}
			}
		}
		return copyFile(in, out, 0o644)
	}
	if err := extractOrCopy(bFull, bIR); err != nil {
		return err
	}
	if err := extractOrCopy(aFull, aIR); err != nil {
		return err
	}
	res.BeforeIRPath, res.AfterIRPath = bIR, aIR

	bRaw, err := os.ReadFile(bIR)
	if err != nil {
		return err
	}
	aRaw, err := os.ReadFile(aIR)
	if err != nil {
		return err
	}
	irEntries := parseBisectOutput(stderrAfter)
	maxIR := 0
	if len(irEntries) > 0 {
		maxIR = irEntries[len(irEntries)-1].Index
	}
	bClean, aClean := cleanIR(string(bRaw)), cleanIR(string(aRaw))
	if res.CulpritPassIndex > maxIR && bClean == aClean {
		res.IsCodeGenPass = true
		bAsm, aAsm := filepath.Join(scratchDir, "before.s"), filepath.Join(scratchDir, "after.s")
		if _, e1 := compileCulpritWithBisect(ctx, spec, tc, culprit, bLim, "asm", bAsm); e1 == nil {
			if _, e2 := compileCulpritWithBisect(ctx, spec, tc, culprit, aLim, "asm", aAsm); e2 == nil {
				bS, _ := os.ReadFile(bAsm)
				aS, _ := os.ReadFile(aAsm)
				res.PassDiff = unifiedDiff(ctx, fmt.Sprintf("before.s (limit=%d)", bLim), string(bS),
					fmt.Sprintf("after.s (limit=%d, %s)", aLim, res.CulpritPass), string(aS))
				return nil
			}
		}
	}

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
	if err != nil || len(commits) == 0 {
		return "", "", fmt.Errorf("list commits %s..%s: %v", goodFull, badFull, err)
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
	wtDir, buildDir, objDir := filepath.Join(workRoot, "llvm-wt"), filepath.Join(workRoot, "llvm-build"), filepath.Join(workRoot, "tu-objs")
	if err := os.MkdirAll(objDir, 0o755); err != nil {
		return "", "", err
	}
	_ = os.RemoveAll(wtDir)
	if _, err := gitOut(ctx, o.LLVMSrcDir, "worktree", "add", "--detach", wtDir, commits[len(commits)/2]); err != nil {
		return "", "", err
	}
	defer func() {
		_, _ = gitOut(context.Background(), o.LLVMSrcDir, "worktree", "remove", "--force", wtDir)
		_ = os.RemoveAll(wtDir)
		_, _ = gitOut(context.Background(), o.LLVMSrcDir, "worktree", "prune")
	}()

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

	cIdx, err := bisectFirstFail(len(commits), func(mid int) (bool, error) {
		sha := commits[mid]
		if _, err := gitOut(ctx, wtDir, "checkout", "--force", "--detach", sha); err != nil {
			return false, fmt.Errorf("checkout %s: %w", sha, err)
		}
		clangBin, err := buildFn(ctx, wtDir, buildDir, sha)
		if err != nil {
			return false, errBisectSkip
		}
		pass, _, err := testFn(ctx, clangBin, sha)
		if err != nil {
			return false, errBisectSkip
		}
		return !pass, nil
	})
	if err != nil {
		return "", "", err
	}
	sha := commits[cIdx]
	subj, _ := gitOut(ctx, o.LLVMSrcDir, "show", "-s", "--format=%s", sha)
	return sha, subj, nil
}

func compileSingleTUWithClang(ctx context.Context, clangBin string, spec platformSpec, sdkRoot string, culprit *compiledObj, outObj string) error {
	driver := clangBin
	if culprit.IsCXX && culprit.BadImportBC == "" {
		if cxx := filepath.Join(filepath.Dir(clangBin), "clang++"); fileExists(cxx) {
			driver = cxx
		}
	}
	var args []string
	if len(culprit.Args) > 0 {
		args = bisectCompileArgs(culprit.Args)
		if culprit.IsCXX && filepath.Base(driver) == "clang" {
			args = append([]string{"--driver-mode=g++"}, args...)
		}
		args = append(args, "-c", "-o", outObj)
	} else if bc := firstNonEmpty(culprit.GoodImportBC, culprit.BadImportBC); bc != "" {
		args = append(args, crossTargetArgs(spec)...)
		args = append(args, "-O3", "-Wno-error")
		args = append(args, spec.BaselineFlags...)
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

func buildClangInWorktree(ctx context.Context, wtDir, buildDir string, spec platformSpec, jobs int) (string, error) {
	if jobs <= 0 {
		jobs = runtime.NumCPU()
	}
	if !fileExists(filepath.Join(buildDir, "build.ninja")) {
		if err := os.MkdirAll(buildDir, 0o755); err != nil {
			return "", err
		}
		args := []string{
			"-G", "Ninja", "-S", filepath.Join(wtDir, "llvm"), "-B", buildDir,
			"-DCMAKE_BUILD_TYPE=Release", "-DLLVM_ENABLE_ASSERTIONS=OFF",
			"-DLLVM_TARGETS_TO_BUILD=" + firstNonEmpty(spec.LLVMTarget, "Native"), "-DLLVM_ENABLE_PROJECTS=clang",
			"-DLLVM_APPEND_VC_REV=OFF", "-DCLANG_ENABLE_CIR=OFF", "-DCLANG_ENABLE_STATIC_ANALYZER=OFF",
			"-DLLVM_INCLUDE_TESTS=OFF", "-DLLVM_INCLUDE_BENCHMARKS=OFF", "-DLLVM_INCLUDE_EXAMPLES=OFF",
			"-DLLVM_INCLUDE_DOCS=OFF", "-DLLVM_ENABLE_BINDINGS=OFF", "-DLLVM_PARALLEL_LINK_JOBS=2",
		}
		if _, err := exec.LookPath("ccache"); err == nil {
			args = append(args, "-DLLVM_CCACHE_BUILD=ON")
		}
		if !spec.IsDarwin {
			if _, err := exec.LookPath("ld.lld"); err == nil {
				args = append(args, "-DLLVM_USE_LINKER=lld")
			}
		}
		if out, err := runToolInDir(ctx, "cmake", args, ""); err != nil {
			return "", fmt.Errorf("cmake configure clang: %w\n%s", err, tailText(out, 4096))
		}
	}
	if out, err := runToolInDir(ctx, "ninja", []string{"-C", buildDir, "-j", strconv.Itoa(jobs), "clang"}, ""); err != nil {
		return "", fmt.Errorf("ninja clang: %w\n%s", err, tailText(out, 4096))
	}
	clangBin := filepath.Join(buildDir, "bin", "clang")
	if !fileExists(clangBin) {
		return "", fmt.Errorf("built clang missing at %s", clangBin)
	}
	if _, err := os.Lstat(filepath.Join(buildDir, "bin", "clang++")); err != nil {
		_ = os.Symlink("clang", filepath.Join(buildDir, "bin", "clang++"))
	}
	return clangBin, nil
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
	out, err := exec.CommandContext(ctx, "git", append([]string{"-C", repoDir}, args...)...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		return s, fmt.Errorf("%w (%s)", err, s)
	}
	return s, nil
}

func runToolInDir(ctx context.Context, bin string, args []string, dir string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir, cmd.Env = dir, append(os.Environ(), "SOURCE_DATE_EPOCH=0")
	out, err := cmd.CombinedOutput()
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
		if args[i] == "-l" || args[i] == "-L" {
			i++
			continue
		}
		if !strings.HasPrefix(args[i], "-l") && !strings.HasPrefix(args[i], "-L") {
			out = append(out, args[i])
		}
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
	rel, err := filepath.Rel(root, filepath.Clean(target))
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
