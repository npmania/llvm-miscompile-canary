package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	sha256HexRe = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	cmdSepRe    = regexp.MustCompile(`[;&|()]+`)
)

type cmakeSpec struct {
	Subdir   string   `yaml:"subdir,omitempty" json:"subdir,omitempty"`
	Flags    []string `yaml:"flags,omitempty" json:"flags,omitempty"`
	Targets  []string `yaml:"targets,omitempty" json:"targets,omitempty"`
	CFlags   string   `yaml:"cflags,omitempty" json:"cflags,omitempty"`
	CXXFlags string   `yaml:"cxxflags,omitempty" json:"cxxflags,omitempty"`
}

type ctestSpec struct {
	Regex   string            `yaml:"regex,omitempty" json:"regex,omitempty"`
	Exclude string            `yaml:"exclude,omitempty" json:"exclude,omitempty"`
	Env     map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
}

type recipe struct {
	Name            string     `yaml:"name" json:"name"`
	Category        string     `yaml:"category,omitempty" json:"category,omitempty"`
	Repo            string     `yaml:"repo" json:"repo"`
	Version         string     `yaml:"version" json:"version"`
	URL             string     `yaml:"url" json:"url"`
	SHA256          string     `yaml:"sha256" json:"sha256"`
	StripComponents int        `yaml:"strip_components" json:"strip_components"`
	Lang            string     `yaml:"lang" json:"lang"`
	TimeoutMin      int        `yaml:"timeout_min" json:"timeout_min"`
	SmokeTest       string     `yaml:"smoke_test" json:"smoke_test"`
	Platforms       []string   `yaml:"platforms" json:"platforms"`
	Description     string     `yaml:"description" json:"description"`
	CMake           *cmakeSpec `yaml:"cmake,omitempty" json:"cmake,omitempty"`
	CTest           *ctestSpec `yaml:"ctest,omitempty" json:"ctest,omitempty"`

	Dir string `yaml:"-" json:"-"`
}

func loadRecipe(pkgDir string) (*recipe, error) {
	absDir, err := filepath.Abs(pkgDir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(absDir, "recipe.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := recipe{StripComponents: 1, Dir: absDir}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	r.SHA256 = strings.ToLower(strings.TrimSpace(r.SHA256))
	if err := r.validateFields(); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", path, err)
	}
	return &r, nil
}

func (r *recipe) validateFields() error {
	if strings.TrimSpace(r.Name) == "" || strings.ContainsAny(r.Name, `/\ `) {
		return fmt.Errorf("invalid name %q", r.Name)
	}
	if owner, name, ok := strings.Cut(r.Repo, "/"); !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return fmt.Errorf("repo %q must be owner/repo", r.Repo)
	}
	if strings.TrimSpace(r.Version) == "" || strings.TrimSpace(r.SmokeTest) == "" || strings.TrimSpace(r.Description) == "" {
		return errors.New("version, smoke_test, and description are required")
	}
	if !strings.HasPrefix(r.URL, "https://") && !strings.HasPrefix(r.URL, "http://") && !strings.HasPrefix(r.URL, "file://") {
		return fmt.Errorf("invalid url %q", r.URL)
	}
	if !sha256HexRe.MatchString(r.SHA256) {
		return fmt.Errorf("invalid sha256 %q", r.SHA256)
	}
	if r.StripComponents < 0 || r.TimeoutMin <= 0 || (r.Lang != "c" && r.Lang != "cxx") || len(r.Platforms) == 0 {
		return errors.New("invalid strip_components, timeout_min, lang, or platforms")
	}
	seen := make(map[string]bool, len(r.Platforms))
	for _, p := range r.Platforms {
		if _, err := lookupPlatform(p); err != nil {
			return err
		}
		if seen[p] {
			return fmt.Errorf("duplicate platform %q", p)
		}
		seen[p] = true
	}
	return nil
}

func (r *recipe) supportsPlatform(id string) bool { return slices.Contains(r.Platforms, id) }

func (r *recipe) timeout() time.Duration {
	if r.TimeoutMin <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(r.TimeoutMin) * time.Minute
}

func (r *recipe) archiveFilename() string {
	return fmt.Sprintf("%s-%s.tar.gz", r.Name, strings.ReplaceAll(r.Version, "/", "_"))
}

func loadCorpus(dir string) ([]*recipe, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	out := make([]*recipe, 0, len(names))
	for _, name := range names {
		r, err := loadRecipe(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func validateCorpus(dir string, require int) ([]*recipe, error) {
	recipes, err := loadCorpus(dir)
	if err != nil {
		return nil, err
	}
	if len(recipes) == 0 {
		return nil, fmt.Errorf("no corpus recipes in %s", dir)
	}
	if require > 0 && len(recipes) != require {
		return nil, fmt.Errorf("expected %d recipes in %s, got %d", require, dir, len(recipes))
	}
	for _, r := range recipes {
		if base := filepath.Base(r.Dir); r.Name != base {
			return nil, fmt.Errorf("recipe name %q != dir %q", r.Name, base)
		}
		if strings.TrimSpace(r.Category) == "" {
			return nil, fmt.Errorf("%s: category is empty", r.Name)
		}
		hasBuild, err := validateOptionalScript(filepath.Join(r.Dir, "build.sh"))
		if err != nil {
			return nil, err
		}
		if !hasBuild && r.CMake == nil {
			return nil, fmt.Errorf("%s: requires cmake config or executable build.sh", r.Name)
		}
		if r.CMake != nil {
			text := strings.Join(append(slices.Clone(r.CMake.Flags), r.CMake.CFlags, r.CMake.CXXFlags), "\n")
			if err := checkNoAssembler(filepath.Join(r.Dir, "recipe.yaml"), text); err != nil {
				return nil, err
			}
		}
		hasAll, err := validateOptionalScript(filepath.Join(r.Dir, "test_all.sh"))
		if err != nil {
			return nil, err
		}
		hasOne, err := validateOptionalScript(filepath.Join(r.Dir, "test_one.sh"))
		if err != nil {
			return nil, err
		}
		if (!hasAll || !hasOne) && r.CTest == nil {
			return nil, fmt.Errorf("%s: requires ctest config or executable test_all.sh and test_one.sh", r.Name)
		}
	}
	return recipes, nil
}

func validateOptionalScript(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return false, fmt.Errorf("%s must be a regular executable file", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return false, fmt.Errorf("%s is empty", path)
	}
	return true, checkNoAssembler(path, string(raw))
}

func checkNoAssembler(path, text string) error {
	for i, line := range strings.Split(text, "\n") {
		if cut := strings.IndexByte(line, '#'); cut >= 0 {
			line = line[:cut]
		}
		for _, seg := range cmdSepRe.Split(line, -1) {
			for _, tok := range strings.Fields(seg) {
				val := tok
				if _, rhs, ok := strings.Cut(tok, "="); ok {
					val = rhs
				}
				if base := filepath.Base(strings.Trim(val, `"'`)); base == "nasm" || base == "yasm" {
					return fmt.Errorf("%s:%d references external assembler %q", path, i+1, tok)
				}
			}
		}
	}
	return nil
}

func fetchSource(ctx context.Context, r *recipe, cacheDir, mirror string, client *http.Client) (string, error) {
	if cacheDir == "" {
		return "", errors.New("cacheDir is empty")
	}
	dst := filepath.Join(cacheDir, "sources", r.archiveFilename())
	if ok, _ := verifyFileSHA256(dst, r.SHA256); ok {
		return dst, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	if mirror == "" {
		mirror = strings.TrimSpace(os.Getenv("LMC_SOURCE_MIRROR"))
	}
	var urls []string
	if m := strings.TrimRight(strings.TrimSpace(mirror), "/"); m != "" {
		urls = append(urls, m+"/"+r.archiveFilename())
	}
	urls = append(urls, r.URL)

	var errs []error
	for _, u := range urls {
		if err := downloadVerified(ctx, client, u, dst, r.SHA256); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u, err))
			continue
		}
		return dst, nil
	}
	return "", fmt.Errorf("fetch %s: %w", r.Name, errors.Join(errs...))
}

func downloadVerified(ctx context.Context, client *http.Client, srcURL, dst, wantSHA string) error {
	var rb [6]byte
	_, _ = rand.Read(rb[:])
	tmp := fmt.Sprintf("%s.tmp.%d.%s", dst, os.Getpid(), hex.EncodeToString(rb[:]))
	defer func() { _ = os.Remove(tmp) }()

	var body io.ReadCloser
	if strings.HasPrefix(srcURL, "http://") || strings.HasPrefix(srcURL, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srcURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "llvm-miscompile-canary/1.0")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		body = resp.Body
	} else {
		f, err := os.Open(strings.TrimPrefix(srcURL, "file://"))
		if err != nil {
			return err
		}
		body = f
	}
	defer body.Close()

	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(out, h), body)
	if closeErr := out.Close(); copyErr != nil {
		return copyErr
	} else if closeErr != nil {
		return closeErr
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, wantSHA) {
		return fmt.Errorf("sha256 mismatch: got %s, want %s", got, wantSHA)
	}
	return os.Rename(tmp, dst)
}

func verifyFileSHA256(path, wantHex string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), wantHex), nil
}

func unpackSource(ctx context.Context, archive, dst string, strip int) error {
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	args := []string{"-xf", archive, "-C", dst}
	if strip > 0 {
		args = append(args, fmt.Sprintf("--strip-components=%d", strip))
	}
	if out, err := exec.CommandContext(ctx, "tar", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("tar %s: %w: %s", archive, err, strings.TrimSpace(string(out)))
	}
	return nil
}

type runner struct {
	CacheDir   string
	MirrorBase string
	LMCBin     string
	Jobs       int
}

type runConfig struct {
	Recipe        *recipe
	Spec          platformSpec
	Profile       string
	TC            *toolchain
	WorkDir       string
	SrcDir        string
	Tarball       string
	ExtraCFlags   []string
	ExtraLDFlags  []string
	SaveLTOTemps  bool
	CaptureTU     string
	CaptureOutDir string
	ExtraEnv      []string
	Timeout       time.Duration
}

type workspace struct {
	WorkDir, SrcDir, BuildDir, ManifestDir, WrapperDir, TmpDir string
	Env                                                        []string
}

type runOut struct {
	Passed   bool
	ExitCode int
	Output   string
	Duration time.Duration
	Err      error
}

func (r *runner) jobs() int {
	if r.Jobs > 0 {
		return r.Jobs
	}
	return runtime.NumCPU()
}

func (r *runner) prepareWorkspace(ctx context.Context, cfg runConfig) (*workspace, error) {
	if cfg.Recipe == nil || cfg.TC == nil || strings.TrimSpace(cfg.WorkDir) == "" {
		return nil, errors.New("recipe, toolchain, and workDir are required")
	}
	absWork, err := filepath.Abs(cfg.WorkDir)
	if err != nil {
		return nil, err
	}
	srcDir := cfg.SrcDir
	if srcDir == "" {
		srcDir = filepath.Join(absWork, "src")
		tb := cfg.Tarball
		if tb == "" {
			if tb, err = fetchSource(ctx, cfg.Recipe, r.CacheDir, r.MirrorBase, nil); err != nil {
				return nil, err
			}
		}
		if err := unpackSource(ctx, tb, srcDir, cfg.Recipe.StripComponents); err != nil {
			return nil, err
		}
	} else if srcDir, err = filepath.Abs(srcDir); err != nil {
		return nil, err
	}
	for _, sub := range []string{"build", "manifest", "tmp"} {
		d := filepath.Join(absWork, sub)
		if err := os.RemoveAll(d); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	return r.wireWorkspace(absWork, srcDir, cfg)
}

func (r *runner) attachWorkspace(workDir string, spec platformSpec, prof string, tc *toolchain) (*workspace, error) {
	absWork, err := filepath.Abs(workDir)
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(filepath.Join(absWork, "build")); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("build dir %s not found", filepath.Join(absWork, "build"))
	}
	_ = os.MkdirAll(filepath.Join(absWork, "tmp"), 0o755)
	return r.wireWorkspace(absWork, filepath.Join(absWork, "src"), runConfig{Spec: spec, Profile: prof, TC: tc})
}

func (r *runner) wireWorkspace(absWork, srcDir string, cfg runConfig) (*workspace, error) {
	bin := r.LMCBin
	if bin == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		bin = exe
	}
	wrapperDir := filepath.Join(absWork, "wrapper")
	if err := setupWrapperDir(wrapperDir, bin); err != nil {
		return nil, err
	}
	buildDir := filepath.Join(absWork, "build")
	manifestDir := filepath.Join(absWork, "manifest")
	tmpDir := filepath.Join(absWork, "tmp")

	pathEntries := []string{wrapperDir}
	if cfg.TC.BinDir != "" {
		pathEntries = append(pathEntries, cfg.TC.BinDir)
	}
	if orig := os.Getenv("PATH"); orig != "" {
		pathEntries = append(pathEntries, orig)
	}
	overrides := []string{
		"PATH=" + strings.Join(pathEntries, string(os.PathListSeparator)),
		"CC=" + filepath.Join(wrapperDir, "clang"),
		"CXX=" + filepath.Join(wrapperDir, "clang++"),
		"JOBS=" + strconv.Itoa(r.jobs()),
		"SRC_DIR=" + srcDir,
		"BUILD_DIR=" + buildDir,
		"TMPDIR=" + tmpDir,
		"SOURCE_DATE_EPOCH=0",
	}
	if cfg.TC.Ar != "" {
		overrides = append(overrides, "AR="+cfg.TC.Ar)
	}
	if cfg.TC.Ranlib != "" {
		overrides = append(overrides, "RANLIB="+cfg.TC.Ranlib)
	}
	if cfg.TC.NM != "" {
		overrides = append(overrides, "NM="+cfg.TC.NM)
	}
	overrides = append(overrides, wrapEnv(wrapConfig{
		RealCC: cfg.TC.Clang, RealCXX: cfg.TC.ClangXX, Linker: cfg.TC.Linker,
		Platform: cfg.Spec.ID, Profile: cfg.Profile, SDKRoot: cfg.TC.SDKRoot,
		ManifestDir: manifestDir, ExtraCFlags: cfg.ExtraCFlags, ExtraLDFlags: cfg.ExtraLDFlags,
		SaveLTOTemps: cfg.SaveLTOTemps, CaptureTU: cfg.CaptureTU, CaptureOutDir: cfg.CaptureOutDir,
	})...)
	overrides = append(overrides, cfg.ExtraEnv...)

	return &workspace{
		WorkDir: absWork, SrcDir: srcDir, BuildDir: buildDir,
		ManifestDir: manifestDir, WrapperDir: wrapperDir, TmpDir: tmpDir,
		Env: mergeEnv(os.Environ(), overrides),
	}, nil
}

func (r *runner) build(ctx context.Context, cfg runConfig) (*workspace, runOut, error) {
	ws, err := r.prepareWorkspace(ctx, cfg)
	if err != nil {
		return nil, runOut{}, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = cfg.Recipe.timeout()
	}
	start := time.Now()
	script := filepath.Join(cfg.Recipe.Dir, "build.sh")
	var out runOut
	switch {
	case fileExists(script):
		out = runCmd(ctx, []string{script}, ws.BuildDir, ws.Env, timeout)
	case cfg.Recipe.CMake != nil:
		out = r.runCMakeBuild(ctx, cfg.Recipe.CMake, cfg.TC, ws, timeout)
	default:
		return ws, runOut{}, fmt.Errorf("%s: missing build.sh and cmake config", cfg.Recipe.Name)
	}
	out.Duration = time.Since(start)
	return ws, out, nil
}

func (r *runner) runCMakeBuild(ctx context.Context, cm *cmakeSpec, tc *toolchain, ws *workspace, timeout time.Duration) runOut {
	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	srcDir := ws.SrcDir
	if cm.Subdir != "" {
		srcDir = filepath.Join(ws.SrcDir, cm.Subdir)
	}
	cfgArgs := []string{
		"cmake", "-S", srcDir, "-B", ws.BuildDir,
		"-DCMAKE_BUILD_TYPE=Release",
		"-DCMAKE_C_COMPILER=" + filepath.Join(ws.WrapperDir, "clang"),
		"-DCMAKE_CXX_COMPILER=" + filepath.Join(ws.WrapperDir, "clang++"),
		"-DFETCHCONTENT_FULLY_DISCONNECTED=ON",
	}
	if _, err := exec.LookPath("ninja"); err == nil {
		cfgArgs = append(cfgArgs, "-G", "Ninja")
	}
	if tc != nil && tc.Ar != "" {
		cfgArgs = append(cfgArgs, "-DCMAKE_AR="+tc.Ar)
	}
	if tc != nil && tc.Ranlib != "" {
		cfgArgs = append(cfgArgs, "-DCMAKE_RANLIB="+tc.Ranlib)
	}
	if cm.CFlags != "" {
		cfgArgs = append(cfgArgs, "-DCMAKE_C_FLAGS="+cm.CFlags)
	}
	if cm.CXXFlags != "" {
		cfgArgs = append(cfgArgs, "-DCMAKE_CXX_FLAGS="+cm.CXXFlags)
	}
	cfgArgs = append(cfgArgs, cm.Flags...)

	cfgOut := runCmd(runCtx, cfgArgs, ws.BuildDir, ws.Env, 0)
	if !cfgOut.Passed {
		return cfgOut
	}

	buildArgs := []string{"cmake", "--build", ws.BuildDir, "-j", strconv.Itoa(r.jobs())}
	if len(cm.Targets) > 0 {
		buildArgs = append(buildArgs, "--target")
		buildArgs = append(buildArgs, cm.Targets...)
	}
	bOut := runCmd(runCtx, buildArgs, ws.BuildDir, ws.Env, 0)
	bOut.Output = cfgOut.Output + bOut.Output
	return bOut
}

func (r *runner) testAll(ctx context.Context, rec *recipe, ws *workspace, extraEnv []string, timeout time.Duration) (runOut, []string) {
	if timeout <= 0 {
		timeout = rec.timeout()
	}
	start := time.Now()
	script := filepath.Join(rec.Dir, "test_all.sh")
	var out runOut
	var failIDs []string

	switch {
	case fileExists(script):
		out = runCmd(ctx, []string{script}, ws.BuildDir, mergeEnv(ws.Env, extraEnv), timeout)
		if !out.Passed {
			failIDs = parseFailIDs(out.Output)
		}
	case rec.CTest != nil:
		args := []string{"ctest", "--test-dir", ws.BuildDir, "--output-on-failure", "--no-tests=error", "-j", strconv.Itoa(r.jobs())}
		if rec.CTest.Regex != "" {
			args = append(args, "-R", rec.CTest.Regex)
		}
		if rec.CTest.Exclude != "" {
			args = append(args, "-E", rec.CTest.Exclude)
		}
		out = runCmd(ctx, args, ws.BuildDir, mergeEnv(ws.Env, append(mapEnv(rec.CTest.Env), extraEnv...)), timeout)
		if !out.Passed {
			failIDs = readCTestFailures(ws.BuildDir)
		}
	default:
		out = runOut{ExitCode: 1, Err: fmt.Errorf("%s: missing test_all.sh and ctest config", rec.Name)}
	}
	out.Duration = time.Since(start)

	if !out.Passed && len(failIDs) == 0 && rec.SmokeTest != "" {
		if one := r.testOne(ctx, rec, ws, rec.SmokeTest, extraEnv, 2*time.Minute); !one.Passed {
			failIDs = []string{rec.SmokeTest}
		}
	}
	return out, failIDs
}

func (r *runner) testOneCmd(rec *recipe, ws *workspace, testID string, extraEnv []string) (argv []string, dir string, env []string) {
	if script := filepath.Join(rec.Dir, "test_one.sh"); fileExists(script) {
		return []string{script, testID}, ws.BuildDir, mergeEnv(ws.Env, extraEnv)
	}
	if rec.CTest != nil {
		args := []string{"ctest", "--test-dir", ws.BuildDir, "--output-on-failure", "--no-tests=error", "-R", "^" + regexp.QuoteMeta(testID) + "$"}
		return args, ws.BuildDir, mergeEnv(ws.Env, append(mapEnv(rec.CTest.Env), extraEnv...))
	}
	return nil, ws.BuildDir, mergeEnv(ws.Env, extraEnv)
}

func (r *runner) testOne(ctx context.Context, rec *recipe, ws *workspace, testID string, extraEnv []string, timeout time.Duration) runOut {
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	argv, dir, env := r.testOneCmd(rec, ws, testID, extraEnv)
	if len(argv) == 0 {
		return runOut{ExitCode: 1, Err: fmt.Errorf("%s: missing test_one.sh and ctest config", rec.Name)}
	}
	start := time.Now()
	out := runCmd(ctx, argv, dir, env, timeout)
	out.Duration = time.Since(start)
	return out
}

func (r *runner) sweepPackage(ctx context.Context, cfg runConfig) pkgResult {
	res := pkgResult{Package: cfg.Recipe.Name, Version: cfg.Recipe.Version, Platform: cfg.Spec.ID, Profile: cfg.Profile}
	if !cfg.Recipe.supportsPlatform(cfg.Spec.ID) {
		res.Status = statusSkipped
		return res
	}
	start := time.Now()
	ws, bOut, err := r.build(ctx, cfg)
	if err != nil {
		res.Status, res.DurationSec, res.ErrorExcerpt = statusBuildFail, time.Since(start).Seconds(), tailText(err.Error(), 1500)
		return res
	}
	if !bOut.Passed {
		prefix := ""
		if detectICE(bOut.Output) {
			prefix = "[compiler ICE] "
		}
		res.Status, res.DurationSec, res.ErrorExcerpt = statusBuildFail, time.Since(start).Seconds(), prefix+tailText(bOut.Output, 1500)
		return res
	}
	tOut, failIDs := r.testAll(ctx, cfg.Recipe, ws, cfg.ExtraEnv, cfg.Timeout)
	res.DurationSec = time.Since(start).Seconds()
	if tOut.Passed {
		res.Status = statusPass
		return res
	}
	res.Status, res.FailedTests, res.ErrorExcerpt = statusTestFail, failIDs, tailText(tOut.Output, 1500)
	return res
}

func runCmd(ctx context.Context, argv []string, dir string, env []string, timeout time.Duration) runOut {
	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	cmd.Dir, cmd.Env = dir, env
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	out := buf.String()
	if err == nil {
		return runOut{Passed: true, Output: out}
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return runOut{ExitCode: 124, Output: out, Err: fmt.Errorf("%s timed out after %s", filepath.Base(argv[0]), timeout)}
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return runOut{ExitCode: exitErr.ExitCode(), Output: out, Err: err}
	}
	return runOut{ExitCode: 1, Output: out, Err: err}
}

func mapEnv(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}

func readCTestFailures(buildDir string) []string {
	data, err := os.ReadFile(filepath.Join(buildDir, "Testing", "Temporary", "LastTestsFailed.log"))
	if err != nil {
		return nil
	}
	var ids []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		if _, name, ok := strings.Cut(strings.TrimSpace(line), ":"); ok {
			if name = strings.TrimSpace(name); name != "" && !seen[name] {
				seen[name] = true
				ids = append(ids, name)
			}
		}
	}
	return ids
}

func parseFailIDs(output string) []string {
	var ids []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(strings.NewReader(output))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if idx := strings.Index(line, "FAIL_ID:"); idx >= 0 {
			if id := strings.TrimSpace(line[idx+len("FAIL_ID:"):]); id != "" && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids
}

func detectICE(output string) bool {
	for _, sig := range []string{
		"PLEASE submit a bug report",
		"unable to execute command: Aborted",
		"unable to execute command: Segmentation fault",
		"unable to execute command: Bus error",
		"clang frontend command failed with exit code",
		"LLVM ERROR:",
		"fatal error: error in backend:",
	} {
		if strings.Contains(output, sig) {
			return true
		}
	}
	return false
}
