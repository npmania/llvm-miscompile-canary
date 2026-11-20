package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) > 0 {
		if _, ok := isWrapperArgv0(os.Args[0]); ok {
			os.Exit(runWrapperMain(os.Args))
		}
	}
	log.SetPrefix("lmc: ")
	log.SetFlags(0)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(runCLI(ctx, os.Args, os.Stdout, os.Stderr))
}

func runCLI(ctx context.Context, argv []string, stdout, stderr io.Writer) int {
	if len(argv) > 0 {
		if _, ok := isWrapperArgv0(argv[0]); ok {
			return runWrapperMain(argv)
		}
	}
	if len(argv) < 2 {
		printUsage(stderr)
		return 2
	}

	sub, args := argv[1], argv[2:]
	var err error
	switch sub {
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	case "validate-corpus":
		err = cmdValidateCorpus(args, stdout, stderr)
	case "corpus-matrix":
		err = cmdCorpusMatrix(args, stdout, stderr)
	case "build":
		err = cmdBuild(ctx, args, stdout, stderr)
	case "test":
		err = cmdTest(ctx, args, stdout, stderr)
	case "sweep":
		err = cmdSweep(ctx, args, stdout, stderr)
	case "aggregate":
		err = cmdAggregate(args, stdout, stderr)
	case "triage":
		err = cmdTriage(ctx, args, stdout, stderr)
	case "merge-incident":
		err = cmdMergeIncident(args, stdout, stderr)
	case "alive-check":
		err = cmdAliveCheck(ctx, args, stdout, stderr)
	case "reduce-check":
		err = cmdReduceCheck(ctx, args, stderr)
	case "site":
		err = cmdSite(args, stdout, stderr)
	case "sync-issues":
		err = cmdSyncIssues(ctx, args, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "lmc: unknown subcommand %q\n\n", sub)
		printUsage(stderr)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		if errors.Is(err, errNotInteresting) {
			return 1
		}
		fmt.Fprintf(stderr, "lmc: %v\n", err)
		return 1
	}
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `usage: lmc <subcommand> [flags]

subcommands:
  validate-corpus  validate corpus recipes and scripts
  corpus-matrix    print JSON array of corpus package names
  build            build a corpus package under the compiler wrapper
  test             run tests in a built package workspace
  sweep            build and test corpus packages across profiles
  aggregate        merge sweep fragments, update state, and render site
  triage           bisect and reduce a failing package test
  merge-incident   merge an incident JSON file into the store
  alive-check      run alive-tv on before/after IR and update an incident
  reduce-check     internal llvm-reduce interestingness check
  site             render static HTML pages from store data
  sync-issues      create, update, and close GitHub issues from store incidents
`)
}

func cmdValidateCorpus(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("validate-corpus", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpusDir := fs.String("corpus", "corpus", "corpus directory")
	require := fs.Int("require", 0, "required package count")
	if err := fs.Parse(args); err != nil {
		return err
	}
	recipes, err := validateCorpus(*corpusDir, *require)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "validated %d corpus recipes in %s\n", len(recipes), *corpusDir)
	return nil
}

func cmdCorpusMatrix(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("corpus-matrix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpusDir := fs.String("corpus", "corpus", "corpus directory")
	include := fs.Bool("include", false, "emit GitHub Actions include matrix filtered by recipe platforms")
	shards := fs.Int("shards", 0, "pack each platform into at most N shards (requires -include)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *shards < 0 {
		return errors.New("-shards must be >= 0")
	}
	if *shards > 0 && !*include {
		return errors.New("-shards requires -include")
	}
	recipes, err := loadCorpus(*corpusDir)
	if err != nil {
		return err
	}
	var payload any
	if *include {
		targets := []struct{ plat, runner, tc string }{
			{platLinuxX86, "ubuntu-24.04", platLinuxX86},
			{platLinuxARM64, "ubuntu-24.04-arm", platLinuxARM64},
			{platLinuxRISCV64, "ubuntu-24.04", platLinuxX86},
			{platDarwinARM, "macos-latest", platDarwinARM},
		}
		if *shards > 0 {
			type shardEntry struct {
				Shard      string `json:"shard"`
				Label      string `json:"label"`
				Packages   string `json:"packages"`
				SrcHash    string `json:"src_hash"`
				Platform   string `json:"platform"`
				Runner     string `json:"runner"`
				TCPlatform string `json:"tc_platform"`
			}
			binsByTarget := make([][][]*recipe, len(targets))
			maxShards, total := 0, 0
			for ti, t := range targets {
				var supported []*recipe
				for _, r := range recipes {
					if r.supportsPlatform(t.plat) {
						supported = append(supported, r)
					}
				}
				bins := shardRecipes(supported, *shards)
				binsByTarget[ti] = bins
				maxShards = max(maxShards, len(bins))
				total += len(bins)
			}
			rows := make([]shardEntry, 0, total)
			for si := range maxShards {
				id := fmt.Sprintf("%02d", si+1)
				for ti, t := range targets {
					if si >= len(binsByTarget[ti]) {
						continue
					}
					bin := binsByTarget[ti][si]
					names := make([]string, len(bin))
					for i, r := range bin {
						names[i] = r.Name
					}
					label := "shard-" + id
					if len(bin) == 1 {
						label = bin[0].Name
					}
					rows = append(rows, shardEntry{
						Shard:      id,
						Label:      label,
						Packages:   strings.Join(names, ","),
						SrcHash:    shardSrcHash(bin),
						Platform:   t.plat,
						Runner:     t.runner,
						TCPlatform: t.tc,
					})
				}
			}
			payload = struct {
				Include []shardEntry `json:"include"`
			}{Include: rows}
		} else {
			type entry struct {
				Package    string `json:"package"`
				Platform   string `json:"platform"`
				Runner     string `json:"runner"`
				TCPlatform string `json:"tc_platform"`
			}
			rows := make([]entry, 0, len(recipes)*len(targets))
			for _, r := range recipes {
				for _, t := range targets {
					if r.supportsPlatform(t.plat) {
						rows = append(rows, entry{Package: r.Name, Platform: t.plat, Runner: t.runner, TCPlatform: t.tc})
					}
				}
			}
			payload = struct {
				Include []entry `json:"include"`
			}{Include: rows}
		}
	} else {
		names := make([]string, len(recipes))
		for i, r := range recipes {
			names[i] = r.Name
		}
		payload = names
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s\n", raw)
	return nil
}

func cmdBuild(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpusDir := fs.String("corpus", "corpus", "corpus directory")
	pkg := fs.String("pkg", "", "package name")
	plat := fs.String("plat", "", "target platform")
	prof := fs.String("prof", profDistroO2, "optimization profile")
	tcBin := fs.String("tc", "", "LLVM toolchain bin dir")
	aux := fs.String("aux", "", "comma-separated extra LLVM tool dirs")
	dir := fs.String("dir", "", "build workspace dir")
	cache := fs.String("cache", ".cache", "tarball cache dir")
	saveLTO := fs.Bool("save-lto", false, "preserve ThinLTO temps")
	jobs := fs.Int("jobs", 0, "parallel build jobs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*pkg) == "" {
		return errors.New("-pkg is required")
	}
	if !validProfile(*prof) {
		return fmt.Errorf("invalid -prof %q", *prof)
	}
	tc, err := resolveToolchain(*plat, *tcBin, *aux, "", "", "")
	if err != nil {
		return err
	}
	rec, err := loadRecipe(filepath.Join(*corpusDir, *pkg))
	if err != nil {
		return err
	}
	wd := *dir
	if wd == "" {
		wd = filepath.Join("work", fmt.Sprintf("%s-%s-%s", rec.Name, tc.Spec.ID, *prof))
	}
	r := &runner{CacheDir: *cache, Jobs: *jobs}
	ws, out, err := r.build(ctx, runConfig{
		Recipe: rec, Spec: tc.Spec, Profile: *prof, TC: tc, WorkDir: wd, SaveLTOTemps: *saveLTO,
	})
	if err != nil {
		return err
	}
	if !out.Passed {
		ice := ""
		if detectICE(out.Output) {
			ice = " (compiler ICE)"
		}
		return fmt.Errorf("build failed%s (exit %d):\n%s", ice, out.ExitCode, tailText(out.Output, 3000))
	}
	fmt.Fprintf(stdout, "built %s (%s / %s) in %.2fs -> %s\n", rec.Name, tc.Spec.ID, *prof, out.Duration.Seconds(), ws.BuildDir)
	return nil
}

func cmdTest(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpusDir := fs.String("corpus", "corpus", "corpus directory")
	pkg := fs.String("pkg", "", "package name")
	plat := fs.String("plat", "", "target platform")
	prof := fs.String("prof", profDistroO2, "optimization profile")
	tcBin := fs.String("tc", "", "LLVM toolchain bin dir")
	aux := fs.String("aux", "", "comma-separated extra LLVM tool dirs")
	dir := fs.String("dir", "", "workspace dir from build")
	testID := fs.String("test", "", "single test ID")
	smoke := fs.Bool("smoke", false, "run smoke_test only")
	jobs := fs.Int("jobs", 0, "parallel test jobs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*pkg) == "" {
		return errors.New("-pkg is required")
	}
	if !validProfile(*prof) {
		return fmt.Errorf("invalid -prof %q", *prof)
	}
	tc, err := resolveToolchain(*plat, *tcBin, *aux, "", "", "")
	if err != nil {
		return err
	}
	rec, err := loadRecipe(filepath.Join(*corpusDir, *pkg))
	if err != nil {
		return err
	}
	wd := *dir
	if wd == "" {
		wd = filepath.Join("work", fmt.Sprintf("%s-%s-%s", rec.Name, tc.Spec.ID, *prof))
	}
	r := &runner{Jobs: *jobs}
	ws, err := r.attachWorkspace(wd, tc.Spec, *prof, tc)
	if err != nil {
		return err
	}
	target := strings.TrimSpace(*testID)
	if target == "" && *smoke {
		target = rec.SmokeTest
	}
	if target != "" {
		out := r.testOne(ctx, rec, ws, target, nil, crossTimeout(tc.Spec, rec.timeout()))
		if !out.Passed {
			return fmt.Errorf("test %s failed (exit %d):\n%s", target, out.ExitCode, tailText(out.Output, 3000))
		}
		fmt.Fprintf(stdout, "PASS %s %s (%.2fs)\n", rec.Name, target, out.Duration.Seconds())
		return nil
	}
	out, failIDs := r.testAll(ctx, rec, ws, nil, crossTimeout(tc.Spec, rec.timeout()))
	if !out.Passed {
		return fmt.Errorf("test_all failed (failed=%v, exit=%d):\n%s", failIDs, out.ExitCode, tailText(out.Output, 3000))
	}
	fmt.Fprintf(stdout, "PASS %s test_all (%.2fs)\n", rec.Name, out.Duration.Seconds())
	return nil
}

func cmdSweep(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sweep", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpusDir := fs.String("corpus", "corpus", "corpus directory")
	pkg := fs.String("pkg", "all", "package name, CSV, or all")
	plat := fs.String("plat", "", "target platform")
	profCSV := fs.String("prof", profDistroO2+","+profReleaseLTO, "comma-separated profiles")
	tcBin := fs.String("tc", "", "LLVM toolchain bin dir")
	aux := fs.String("aux", "", "comma-separated extra LLVM tool dirs")
	sha := fs.String("sha", "", "LLVM commit SHA")
	dir := fs.String("dir", filepath.Join("work", "sweep"), "sweep work dir")
	cache := fs.String("cache", ".cache", "tarball cache dir")
	frag := fs.String("frag", "", "output JSON fragment path")
	storeDir := fs.String("store", "", "optional store dir")
	keep := fs.Bool("keep", false, "keep work dirs")
	failOnReg := fs.Bool("fail", false, "exit non-zero on failure")
	jobs := fs.Int("jobs", 0, "parallel jobs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	profiles, err := parseProfilesCSV(*profCSV)
	if err != nil {
		return err
	}
	tc, err := resolveToolchain(*plat, *tcBin, *aux, "", "", "")
	if err != nil {
		return err
	}
	recipes, err := selectRecipes(*corpusDir, *pkg)
	if err != nil {
		return err
	}

	r := &runner{CacheDir: *cache, Jobs: *jobs}
	started := time.Now().UTC()
	results := make([]pkgResult, 0, len(recipes)*len(profiles))
	anyFail := false
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, rec := range recipes {
		for _, prof := range profiles {
			if err := ctx.Err(); err != nil {
				return err
			}
			wd := filepath.Join(*dir, fmt.Sprintf("%s-%s-%s", rec.Name, tc.Spec.ID, prof))
			pr := r.sweepPackage(ctx, runConfig{Recipe: rec, Spec: tc.Spec, Profile: prof, TC: tc, WorkDir: wd})
			if !*keep {
				_ = os.RemoveAll(wd)
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			results = append(results, pr)
			if *frag != "" {
				if err := writeResultFragment(*frag, results); err != nil {
					return err
				}
			}
			if pr.Status == statusTestFail || pr.Status == statusBuildFail {
				anyFail = true
			}
			fmt.Fprintf(stdout, "[sweep] %-16s %-14s %-12s -> %s (%.2fs)\n", pr.Package, pr.Platform, pr.Profile, pr.Status, pr.DurationSec)
		}
	}
	completed := time.Now().UTC()

	if *frag != "" && len(results) == 0 {
		if err := writeResultFragment(*frag, results); err != nil {
			return err
		}
	}
	if *storeDir != "" {
		st, err := loadState(*storeDir)
		if err != nil {
			return err
		}
		incs, err := loadAllIncidents(*storeDir)
		if err != nil {
			return err
		}
		rec := sweep{LLVMCommit: *sha, PreviousSHA: st.LastSweepSHA, StartedAt: started, CompletedAt: completed, Results: results}
		if _, err := saveSweep(*storeDir, &rec); err != nil {
			return err
		}
		recordSweep(st, rec, incs)
		if err := saveState(*storeDir, st); err != nil {
			return err
		}
	}
	if *failOnReg && anyFail {
		return errors.New("one or more packages failed")
	}
	return nil
}

type regressionTarget struct {
	Package     string   `json:"package"`
	Platform    string   `json:"platform"`
	Profile     string   `json:"profile"`
	GoodSHA     string   `json:"good_sha"`
	BadSHA      string   `json:"bad_sha"`
	FailedTests []string `json:"failed_tests,omitempty"`
}

func cmpDuration(a, b float64) int {
	aPos, bPos := a > 0, b > 0
	if aPos != bPos {
		if aPos {
			return -1
		}
		return 1
	}
	if !aPos {
		return 0
	}
	return cmp.Compare(a, b)
}

func regPlatRank(plat string) int {
	switch plat {
	case platLinuxX86:
		return 0
	case platLinuxARM64:
		return 1
	case platDarwinARM:
		return 2
	case platLinuxRISCV64:
		return 3
	default:
		return 4
	}
}

func regProfRank(prof string) int {
	switch prof {
	case profDistroO2:
		return 0
	case profReleaseLTO:
		return 1
	default:
		return 2
	}
}

type regCandidate struct {
	res     pkgResult
	goodSHA string
}

func cmpRegCandidate(a, b regCandidate) int {
	return cmp.Or(
		cmpDuration(a.res.DurationSec, b.res.DurationSec),
		cmp.Compare(regPlatRank(a.res.Platform), regPlatRank(b.res.Platform)),
		cmp.Compare(regProfRank(a.res.Profile), regProfRank(b.res.Profile)),
		cmp.Compare(a.res.Package, b.res.Package),
		cmp.Compare(a.res.Platform, b.res.Platform),
		cmp.Compare(a.res.Profile, b.res.Profile),
	)
}

func capRegressions(regs []regressionTarget, maxCount, maxBytes int) []regressionTarget {
	if maxCount > 0 && len(regs) > maxCount {
		regs = regs[:maxCount]
	}
	if maxBytes <= 0 {
		return regs
	}
	for len(regs) > 0 {
		raw, err := json.Marshal(regs)
		if err == nil && len(raw) <= maxBytes {
			break
		}
		regs = regs[:len(regs)-1]
	}
	return regs
}

func cmdAggregate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("aggregate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	frags := fs.String("frags", "", "fragments dir")
	storeDir := fs.String("store", "", "store dir")
	sha := fs.String("sha", "", "LLVM commit SHA")
	subj := fs.String("subj", "", "LLVM commit subject")
	prev := fs.String("prev", "", "previous sweep SHA override")
	outDir := fs.String("out", "", "optional site output dir")
	corpusDir := fs.String("corpus", "corpus", "corpus dir for site")
	regOut := fs.String("reg-out", "", "optional regressions JSON output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*frags) == "" || strings.TrimSpace(*storeDir) == "" || strings.TrimSpace(*sha) == "" {
		return errors.New("-frags, -store, and -sha are required")
	}
	results, err := readResultFragments(*frags)
	if err != nil {
		return err
	}
	st, err := loadState(*storeDir)
	if err != nil {
		return err
	}
	incs, err := loadAllIncidents(*storeDir)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	statusByKey := make(map[string]string, len(results))
	for _, r := range results {
		statusByKey[targetKey(r.Package, r.Platform, r.Profile)] = r.Status
	}

	resolved := 0
	for _, inc := range incs {
		if inc == nil || inc.Status != incidentOpen || len(inc.Affected) == 0 {
			continue
		}
		allPass := !slices.ContainsFunc(inc.Affected, func(a affected) bool {
			return statusByKey[targetKey(a.Package, a.Platform, a.Profile)] != statusPass
		})
		if allPass {
			inc.Status = incidentResolved
			if inc.FixedSHA == "" {
				inc.FixedSHA = *sha
			}
			ts := now
			inc.ResolvedAt, inc.UpdatedAt = &ts, now
			if _, err := saveIncident(*storeDir, inc); err != nil {
				return err
			}
			resolved++
		}
	}

	const (
		maxRegressionTargets = 8
		maxRegressionsBytes  = 60000
	)
	openCovered := make(map[string]bool)
	closedGoods := make(map[string]map[string]bool)
	openBuildByPkg := make(map[string]*incident)
	usedIDs := make(map[string]bool, len(incs))
	for _, inc := range incs {
		if inc == nil {
			continue
		}
		if inc.ID != "" {
			usedIDs[inc.ID] = true
		}
		switch inc.Status {
		case incidentOpen:
			for _, a := range inc.Affected {
				openCovered[targetKey(a.Package, a.Platform, a.Profile)] = true
			}
			if inc.isBuildFail() {
				for _, p := range uniquePkgs([]*incident{inc}) {
					if openBuildByPkg[p] == nil {
						openBuildByPkg[p] = inc
					}
				}
			}
		case incidentClosed:
			for _, a := range inc.Affected {
				k := targetKey(a.Package, a.Platform, a.Profile)
				if closedGoods[k] == nil {
					closedGoods[k] = make(map[string]bool)
				}
				closedGoods[k][cmp.Or(a.GoodSHA, inc.GoodSHA)] = true
			}
		}
	}
	isCovered := func(pkg, plat, prof, curGood string) bool {
		k := targetKey(pkg, plat, prof)
		return openCovered[k] || closedGoods[k][curGood]
	}

	bestRegByPkg := make(map[string]regCandidate)
	buildFailsByPkg := make(map[string][]pkgResult)
	var buildFailPkgs []string
	for _, r := range results {
		switch r.Status {
		case statusTestFail:
			goodSHA := st.targetGoodSHA(r.Package, r.Platform, r.Profile)
			if goodSHA == "" || isCovered(r.Package, r.Platform, r.Profile, goodSHA) {
				continue
			}
			cand := regCandidate{res: r, goodSHA: goodSHA}
			if prev, ok := bestRegByPkg[r.Package]; !ok || cmpRegCandidate(cand, prev) < 0 {
				bestRegByPkg[r.Package] = cand
			}
		case statusBuildFail:
			goodSHA := st.targetGoodSHA(r.Package, r.Platform, r.Profile)
			if goodSHA == "" || isCovered(r.Package, r.Platform, r.Profile, goodSHA) {
				continue
			}
			if _, ok := buildFailsByPkg[r.Package]; !ok {
				buildFailPkgs = append(buildFailPkgs, r.Package)
			}
			buildFailsByPkg[r.Package] = append(buildFailsByPkg[r.Package], r)
		}
	}
	regCands := make([]regCandidate, 0, len(bestRegByPkg))
	for _, c := range bestRegByPkg {
		regCands = append(regCands, c)
	}
	slices.SortFunc(regCands, cmpRegCandidate)
	regs := make([]regressionTarget, 0, len(regCands))
	for _, c := range regCands {
		var failed []string
		if len(c.res.FailedTests) > 0 {
			failed = c.res.FailedTests[:1]
		}
		regs = append(regs, regressionTarget{
			Package: c.res.Package, Platform: c.res.Platform, Profile: c.res.Profile,
			GoodSHA: c.goodSHA, BadSHA: *sha, FailedTests: failed,
		})
	}
	regs = capRegressions(regs, maxRegressionTargets, maxRegressionsBytes)

	slices.Sort(buildFailPkgs)
	buildFails := 0
	for _, pkg := range buildFailPkgs {
		list := buildFailsByPkg[pkg]
		targets := make([]affected, 0, len(list))
		var bestExcerpt string
		for _, r := range list {
			targets = append(targets, affected{
				Package:  r.Package,
				Version:  r.Version,
				Platform: r.Platform,
				Profile:  r.Profile,
				GoodSHA:  st.targetGoodSHA(r.Package, r.Platform, r.Profile),
			})
			if ex := strings.ReplaceAll(strings.TrimSpace(r.ErrorExcerpt), "\r\n", "\n"); ex != "" {
				if bestExcerpt == "" || (!isICEExcerpt(bestExcerpt) && isICEExcerpt(ex)) {
					bestExcerpt = ex
				}
			}
		}
		excerpt := clipCode(sanitizeCode(bestExcerpt), 8000)

		if ex := openBuildByPkg[pkg]; ex != nil {
			changed := ex.mergeAffected(targets...)
			if excerpt != "" && (ex.ErrorExcerpt == "" || (!isICEExcerpt(ex.ErrorExcerpt) && isICEExcerpt(excerpt))) {
				ex.ErrorExcerpt = excerpt
				if isICEExcerpt(excerpt) {
					ex.Title = sanitizeText(pkg + ": compiler ICE")
				}
				changed = true
			}
			if changed {
				ex.UpdatedAt = now
				if _, err := saveIncident(*storeDir, ex); err != nil {
					return err
				}
				buildFails++
			}
			continue
		}

		pkgSlug := cmp.Or(sanitizeSlug(pkg), "pkg")
		bad12 := cmp.Or(sanitizeSlug(shortSHA(*sha)), "unknown")
		id := fmt.Sprintf("%s-%s-build-%s", now.Format("20060102"), pkgSlug, bad12)
		if usedIDs[id] {
			id = uniqueIncidentID(id, usedIDs)
		}
		usedIDs[id] = true

		inc := &incident{
			ID:           id,
			Kind:         incidentKindBuildFail,
			Title:        sanitizeText(pkg + ": " + pick(isICEExcerpt(excerpt), "compiler ICE", "build failure")),
			Status:       incidentOpen,
			Confidence:   confNeedsReview,
			GoodSHA:      targets[0].GoodSHA,
			BadSHA:       *sha,
			ErrorExcerpt: excerpt,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		inc.mergeAffected(targets...)
		if _, err := saveIncident(*storeDir, inc); err != nil {
			return err
		}
		incs = append(incs, inc)
		openBuildByPkg[pkg] = inc
		buildFails++
	}

	prevSHA := *prev
	if prevSHA == "" {
		prevSHA = st.LastSweepSHA
	}
	rec := sweep{
		LLVMCommit: *sha, LLVMSubject: sanitizeText(*subj), PreviousSHA: prevSHA,
		StartedAt: now, CompletedAt: now, Results: results,
	}
	sweepPath, err := saveSweep(*storeDir, &rec)
	if err != nil {
		return err
	}
	recordSweep(st, rec, incs)
	if err := saveState(*storeDir, st); err != nil {
		return err
	}
	if *regOut != "" {
		if err := writeJSONAtomic(*regOut, regs); err != nil {
			return err
		}
	}
	if *outDir != "" {
		cDir := ""
		if info, err := os.Stat(*corpusDir); err == nil && info.IsDir() {
			cDir = *corpusDir
		}
		if err := generateSite(*storeDir, *outDir, cDir); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "aggregated %d results -> %s (regressions=%d, build_fails=%d, resolved=%d)\n", len(results), sweepPath, len(regs), buildFails, resolved)
	return nil
}

func cmdTriage(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpusDir := fs.String("corpus", "corpus", "corpus dir")
	pkg := fs.String("pkg", "", "package name")
	plat := fs.String("plat", "", "target platform")
	prof := fs.String("prof", profDistroO2, "optimization profile")
	testID := fs.String("test", "", "specific failing test ID")
	goodTCBin := fs.String("good-tc", "", "last-known-good LLVM bin dir")
	badTCBin := fs.String("bad-tc", "", "failing LLVM bin dir")
	aux := fs.String("aux", "", "comma-separated extra LLVM tool dirs")
	aliveTV := fs.String("alive-tv", "", "explicit alive-tv binary")
	goodSHA := fs.String("good", "good", "good LLVM SHA")
	badSHA := fs.String("bad", "bad", "bad LLVM SHA")
	llvmSrc := fs.String("llvm", "", "llvm-project checkout dir")
	dir := fs.String("dir", filepath.Join("work", "triage"), "triage work dir")
	cache := fs.String("cache", ".cache", "tarball cache dir")
	bundle := fs.String("bundle", "dist", "bundle output dir")
	bundleURL := fs.String("bundle-url", "", "optional bundle URL")
	storeDir := fs.String("store", "", "optional store dir")
	outPath := fs.String("out", "", "optional incident JSON output path")
	timeout := fs.Duration("timeout", 0, "overall triage timeout (0 = unlimited)")
	commitTimeout := fs.Duration("commit-timeout", defaultCommitTimeout, "commit bisection timeout")
	jobs := fs.Int("jobs", 0, "parallel jobs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*pkg) == "" || strings.TrimSpace(*goodTCBin) == "" || strings.TrimSpace(*badTCBin) == "" {
		return errors.New("-pkg, -good-tc, and -bad-tc are required")
	}
	if !validProfile(*prof) {
		return fmt.Errorf("invalid -prof %q", *prof)
	}
	goodTC, err := resolveToolchain(*plat, *goodTCBin, *aux, "", "", "")
	if err != nil {
		return fmt.Errorf("good toolchain: %w", err)
	}
	badTC, err := resolveToolchain(*plat, *badTCBin, *aux, "", *aliveTV, "")
	if err != nil {
		return fmt.Errorf("bad toolchain: %w", err)
	}
	rec, err := loadRecipe(filepath.Join(*corpusDir, *pkg))
	if err != nil {
		return err
	}
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	res, err := triage(ctx, triageOpts{
		Runner: &runner{CacheDir: *cache, Jobs: *jobs}, Recipe: rec, Spec: badTC.Spec, Profile: *prof,
		GoodTC: goodTC, BadTC: badTC, GoodSHA: *goodSHA, BadSHA: *badSHA, TestID: *testID,
		WorkDir: *dir, BundleDir: *bundle, BundleBaseURL: *bundleURL, LLVMSrcDir: *llvmSrc,
		CommitTimeout: *commitTimeout, Jobs: *jobs,
	})
	if err != nil {
		return err
	}
	if res.Dropped {
		if res.BuildFailed {
			fmt.Fprintf(stdout, "[triage] dropped %s (%s/%s): build_fail (ice=%v)\n", rec.Name, badTC.Spec.ID, *prof, res.IsICE)
		} else {
			fmt.Fprintf(stdout, "[triage] dropped %s (%s/%s): %s\n", rec.Name, badTC.Spec.ID, *prof, res.DropReason)
		}
		return nil
	}
	if res.CommitBisectErr != "" {
		fmt.Fprintf(stderr, "[triage] commit bisect skipped/failed (continuing with pass bisect): %s\n", res.CommitBisectErr)
	}

	inc := res.Incident
	if *storeDir != "" {
		if inc, err = mergeIncident(*storeDir, inc); err != nil {
			return err
		}
	}
	if *outPath != "" {
		if err := writeJSONAtomic(*outPath, inc); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "[triage] incident=%s confidence=%s tu=%s pass=%s func=%s culprit_sha=%s bundle=%s\n",
		inc.ID, inc.Confidence, inc.CulpritTU, inc.CulpritPass, inc.CulpritFunc, inc.CulpritSHA, res.BundlePath)
	return nil
}

func cmdMergeIncident(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("merge-incident", flag.ContinueOnError)
	fs.SetOutput(stderr)
	storeDir := fs.String("store", "", "store dir")
	incPath := fs.String("inc", "", "incident JSON path")
	bundleURL := fs.String("bundle-url", "", "optional bundle URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*storeDir) == "" || strings.TrimSpace(*incPath) == "" {
		return errors.New("-store and -inc are required")
	}
	var inc incident
	if err := readJSON(*incPath, &inc); err != nil {
		return err
	}
	if u := strings.TrimSpace(*bundleURL); u != "" {
		inc.BundleURL = u
	}
	merged, err := mergeIncident(*storeDir, &inc)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "merged incident %s (%d affected)\n", merged.ID, len(merged.Affected))
	return nil
}

func cmdAliveCheck(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("alive-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bin := fs.String("alive-tv", "", "alive-tv binary path")
	before := fs.String("before", "", "before-pass .ll path")
	after := fs.String("after", "", "after-pass .ll path")
	incPath := fs.String("inc", "", "optional incident JSON to update")
	storeDir := fs.String("store", "", "optional store dir to sync incident")
	timeout := fs.Duration("timeout", 60*time.Second, "alive-tv timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*before) == "" || strings.TrimSpace(*after) == "" {
		return errors.New("-before and -after are required")
	}
	tvBin := strings.TrimSpace(*bin)
	if tvBin == "" {
		if p, err := exec.LookPath("alive-tv"); err == nil {
			tvBin = p
		}
	}

	if strings.TrimSpace(*incPath) != "" {
		var inc incident
		if err := readJSON(*incPath, &inc); err != nil {
			return err
		}
		if !isOmittedFormalStatus(inc.AliveTVStatus) {
			fmt.Fprintf(stdout, "alive-tv: %s (kept)\n", inc.AliveTVStatus)
			return nil
		}
		res := runAliveTV(ctx, tvBin, *before, *after, *timeout)
		inc.AliveTVStatus = res.Status
		inc.AliveTVOutput = sanitizeCode(res.Output)
		if res.ProvesBug {
			inc.Confidence = confConfirmed
		} else if res.Status == aliveVerified && inc.Confidence == confLikely {
			inc.Confidence = confNeedsReview
		}
		inc.UpdatedAt = time.Now().UTC()
		if err := writeJSONAtomic(*incPath, &inc); err != nil {
			return err
		}
		if *storeDir != "" && fileExists(filepath.Join(*storeDir, "incidents", inc.ID+".json")) {
			if _, err := saveIncident(*storeDir, &inc); err != nil {
				return err
			}
		}
		fmt.Fprintf(stdout, "alive-tv: %s\n", res.Status)
		return nil
	}

	res := runAliveTV(ctx, tvBin, *before, *after, *timeout)
	raw, err := json.Marshal(res)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s\n", raw)
	return nil
}

func cmdSite(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("site", flag.ContinueOnError)
	fs.SetOutput(stderr)
	storeDir := fs.String("store", "", "store dir")
	outDir := fs.String("out", "", "output dir")
	corpusDir := fs.String("corpus", "corpus", "corpus dir")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*storeDir) == "" || strings.TrimSpace(*outDir) == "" {
		return errors.New("-store and -out are required")
	}
	cDir := ""
	if info, err := os.Stat(*corpusDir); err == nil && info.IsDir() {
		cDir = *corpusDir
	}
	if err := generateSite(*storeDir, *outDir, cDir); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "rendered static site -> %s\n", *outDir)
	return nil
}

func cmdSyncIssues(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sync-issues", flag.ContinueOnError)
	fs.SetOutput(stderr)
	storeDir := fs.String("store", "", "store dir")
	repo := fs.String("repo", defaultRepo, "GitHub owner/repo")
	url := fs.String("url", defaultSiteURL, "dashboard base URL")
	sha := fs.String("sha", "", "head SHA for closing resolved issues")
	dryRun := fs.Bool("dry-run", false, "print planned actions without calling GitHub")
	quiet := fs.Bool("quiet", false, "suppress dry-run output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*storeDir) == "" {
		return errors.New("-store is required")
	}
	incs, err := loadAllIncidents(*storeDir)
	if err != nil {
		return err
	}
	_, err = syncIssues(ctx, issueSyncCfg{
		Repo: *repo, SiteURL: *url, HeadSHA: *sha, StoreDir: *storeDir,
		DryRun: *dryRun, Quiet: *quiet, Out: stdout,
	}, incs)
	return err
}

func parseProfilesCSV(csv string) ([]string, error) {
	parts := splitCSV(csv)
	if len(parts) == 0 {
		return standardProfiles(), nil
	}
	var out []string
	for _, p := range parts {
		if !validProfile(p) {
			return nil, fmt.Errorf("invalid -prof %q", p)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

func selectRecipes(corpusDir, filter string) ([]*recipe, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" || filter == "all" {
		return loadCorpus(corpusDir)
	}
	var out []*recipe
	for _, name := range splitCSV(filter) {
		r, err := loadRecipe(filepath.Join(corpusDir, name))
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
