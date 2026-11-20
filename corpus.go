package main

import (
	"bufio"
	"bytes"
	"cmp"
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
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	maxCmdOutput     = 8 << 20
	soloShardTimeout = 25 * time.Minute
)

var (
	sha256HexRe  = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	cmdSepRe     = regexp.MustCompile(`[;&|()]+`)
	ctestStartRe = regexp.MustCompile(`^\s*Start\s+(\d+):\s+(.+?)\s*$`)
	ctestDoneRe  = regexp.MustCompile(`^\s*\d+/\d+\s+Test\s+#(\d+):\s+(.+?)\s+\.{2,}(.+)$`)
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

// isolate heavy recipes before lpt packing so slow qemu targets never share a shard
func shardRecipes(recipes []*recipe, shards int) [][]*recipe {
	if len(recipes) == 0 || shards <= 0 {
		return nil
	}
	k := min(shards, len(recipes))
	ordered := slices.Clone(recipes)
	slices.SortFunc(ordered, func(a, b *recipe) int {
		return cmp.Or(cmp.Compare(b.timeout(), a.timeout()), cmp.Compare(a.Name, b.Name))
	})

	var heavy, rest []*recipe
	for _, r := range ordered {
		if r.timeout() >= soloShardTimeout {
			heavy = append(heavy, r)
		} else {
			rest = append(rest, r)
		}
	}

	bins := make([][]*recipe, 0, k)
	pack := ordered
	packBins := k
	if len(heavy) > 0 && len(rest) > 0 && len(heavy) < k {
		for _, r := range heavy {
			bins = append(bins, []*recipe{r})
		}
		pack = rest
		packBins = k - len(heavy)
	}

	lptBins := make([][]*recipe, packBins)
	loads := make([]time.Duration, packBins)
	for _, r := range pack {
		best := 0
		for i := 1; i < packBins; i++ {
			if loads[i] < loads[best] {
				best = i
			}
		}
		lptBins[best] = append(lptBins[best], r)
		loads[best] += r.timeout()
	}
	bins = append(bins, lptBins...)
	for _, b := range bins {
		slices.SortFunc(b, func(a, b *recipe) int {
			return cmp.Compare(a.Name, b.Name)
		})
	}
	return bins
}

func shardSrcHash(recs []*recipe) string {
	ordered := slices.Clone(recs)
	slices.SortFunc(ordered, func(a, b *recipe) int {
		return cmp.Compare(a.Name, b.Name)
	})
	h := sha256.New()
	for _, r := range ordered {
		h.Write([]byte(r.Name))
		h.Write([]byte{0})
		h.Write([]byte(r.Version))
		h.Write([]byte{0})
		h.Write([]byte(r.URL))
		h.Write([]byte{0})
		h.Write([]byte(r.SHA256))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
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
	if !strings.HasPrefix(srcURL, "http://") && !strings.HasPrefix(srcURL, "https://") {
		_, err := downloadVerifiedOnce(ctx, client, srcURL, dst, wantSHA)
		return err
	}
	backoffs := []time.Duration{2 * time.Second, 5 * time.Second}
	var err error
	for attempt := 0; attempt <= len(backoffs); attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(backoffs[attempt-1])
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		var retry bool
		retry, err = downloadVerifiedOnce(ctx, client, srcURL, dst, wantSHA)
		if err == nil || !retry || ctx.Err() != nil {
			return err
		}
	}
	return err
}

func downloadVerifiedOnce(ctx context.Context, client *http.Client, srcURL, dst, wantSHA string) (bool, error) {
	var rb [6]byte
	_, _ = rand.Read(rb[:])
	tmp := fmt.Sprintf("%s.tmp.%d.%s", dst, os.Getpid(), hex.EncodeToString(rb[:]))
	defer func() { _ = os.Remove(tmp) }()

	isHTTP := strings.HasPrefix(srcURL, "http://") || strings.HasPrefix(srcURL, "https://")
	var body io.ReadCloser
	if isHTTP {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srcURL, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("User-Agent", "llvm-miscompile-canary/1.0")
		resp, err := client.Do(req)
		if err != nil {
			return true, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
			return retry, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		body = resp.Body
	} else {
		f, err := os.Open(strings.TrimPrefix(srcURL, "file://"))
		if err != nil {
			return false, err
		}
		body = f
	}
	defer body.Close()

	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return false, err
	}
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(out, h), body)
	if closeErr := out.Close(); copyErr != nil {
		return isHTTP, copyErr
	} else if closeErr != nil {
		return false, closeErr
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, wantSHA) {
		return false, fmt.Errorf("sha256 mismatch: got %s, want %s", got, wantSHA)
	}
	return false, os.Rename(tmp, dst)
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
	Spec                                                       platformSpec
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
	var err error
	if overrides, err = setupCrossWorkspace(absWork, cfg.Spec, overrides); err != nil {
		return nil, err
	}
	overrides = append(overrides, cfg.ExtraEnv...)

	drop := []string{"CFLAGS", "CXXFLAGS", "LDFLAGS", "CPPFLAGS"}
	if !isCross(cfg.Spec) {
		drop = append(drop, "CMAKE_TOOLCHAIN_FILE")
	}

	return &workspace{
		Spec: cfg.Spec, WorkDir: absWork, SrcDir: srcDir, BuildDir: buildDir,
		ManifestDir: manifestDir, WrapperDir: wrapperDir, TmpDir: tmpDir,
		Env: mergeEnv(stripEnv(os.Environ(), drop...), overrides),
	}, nil
}

func (r *runner) build(ctx context.Context, cfg runConfig) (*workspace, runOut, error) {
	ws, err := r.prepareWorkspace(ctx, cfg)
	if err != nil {
		return nil, runOut{}, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = crossTimeout(cfg.Spec, cfg.Recipe.timeout())
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
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
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

	cfgOut := runCmd(ctx, cfgArgs, ws.BuildDir, ws.Env, timeout)
	if !cfgOut.Passed {
		return cfgOut
	}

	var rem time.Duration
	if !deadline.IsZero() {
		rem = time.Until(deadline)
		if rem <= 0 {
			return runOut{ExitCode: 124, Output: cfgOut.Output, Err: fmt.Errorf("cmake timed out after %s", timeout)}
		}
	}

	buildArgs := []string{"cmake", "--build", ws.BuildDir, "-j", strconv.Itoa(r.jobs())}
	if len(cm.Targets) > 0 {
		buildArgs = append(buildArgs, "--target")
		buildArgs = append(buildArgs, cm.Targets...)
	}
	bOut := runCmd(ctx, buildArgs, ws.BuildDir, ws.Env, rem)
	bOut.Output = cfgOut.Output + bOut.Output
	return bOut
}

func (r *runner) testAll(ctx context.Context, rec *recipe, ws *workspace, extraEnv []string, timeout time.Duration) (runOut, []string) {
	if timeout <= 0 {
		timeout = crossTimeout(ws.Spec, rec.timeout())
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
		_ = os.Remove(filepath.Join(ws.BuildDir, "Testing", "Temporary", "LastTestsFailed.log"))
		perTest := crossTimeout(ws.Spec, 3*time.Minute)
		if headroom := timeout - 30*time.Second; headroom > 0 {
			perTest = min(perTest, headroom)
		} else {
			perTest = max(timeout/2, time.Second)
		}
		perTestSec := max(int(perTest/time.Second), 1)
		args := []string{
			"ctest", "--test-dir", ws.BuildDir, "--output-on-failure", "--no-tests=error",
			"--timeout", strconv.Itoa(perTestSec), "-j", strconv.Itoa(r.jobs()),
		}
		if rec.CTest.Regex != "" {
			args = append(args, "-R", rec.CTest.Regex)
		}
		if rec.CTest.Exclude != "" {
			args = append(args, "-E", rec.CTest.Exclude)
		}
		out = runCmd(ctx, args, ws.BuildDir, mergeEnv(ws.Env, append(mapEnv(rec.CTest.Env), extraEnv...)), timeout)
		if !out.Passed {
			failIDs = readCTestFailures(ws.BuildDir, out.Output)
		}
	default:
		out = runOut{ExitCode: 1, Err: fmt.Errorf("%s: missing test_all.sh and ctest config", rec.Name)}
	}
	out.Duration = time.Since(start)

	if !out.Passed && len(failIDs) == 0 && rec.SmokeTest != "" {
		if one := r.testOne(ctx, rec, ws, rec.SmokeTest, extraEnv, crossTimeout(ws.Spec, 2*time.Minute)); !one.Passed {
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
		timeout = crossTimeout(ws.Spec, 3*time.Minute)
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

func setCmdProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 5 * time.Second
}

type boundedBuf struct {
	head    []byte
	tail    []byte
	headCap int
	tailCap int
	tailPos int
	tailLen int
	dropped int64
}

func newBoundedBuf(limit int) *boundedBuf {
	h := limit / 2
	return &boundedBuf{headCap: h, tailCap: limit - h}
}

func (b *boundedBuf) Write(p []byte) (int, error) {
	n := len(p)
	if rem := b.headCap - len(b.head); rem > 0 {
		take := min(rem, len(p))
		b.head = append(b.head, p[:take]...)
		p = p[take:]
	}
	if len(p) == 0 {
		return n, nil
	}
	if b.tailCap <= 0 {
		b.dropped += int64(len(p))
		return n, nil
	}
	if len(b.tail) == 0 {
		b.tail = make([]byte, b.tailCap)
	}
	if len(p) >= b.tailCap {
		b.dropped += int64(b.tailLen) + int64(len(p)-b.tailCap)
		copy(b.tail, p[len(p)-b.tailCap:])
		b.tailPos = 0
		b.tailLen = b.tailCap
		return n, nil
	}
	if over := b.tailLen + len(p) - b.tailCap; over > 0 {
		b.dropped += int64(over)
	}
	first := min(len(p), b.tailCap-b.tailPos)
	copy(b.tail[b.tailPos:], p[:first])
	if first < len(p) {
		copy(b.tail, p[first:])
	}
	b.tailPos = (b.tailPos + len(p)) % b.tailCap
	b.tailLen = min(b.tailCap, b.tailLen+len(p))
	return n, nil
}

func (b *boundedBuf) String() string {
	if b.tailLen == 0 {
		return string(b.head)
	}
	var marker string
	if b.dropped > 0 {
		marker = fmt.Sprintf("\n... [truncated %d bytes] ...\n", b.dropped)
	}
	var sb strings.Builder
	sb.Grow(len(b.head) + len(marker) + b.tailLen)
	sb.Write(b.head)
	if marker != "" {
		sb.WriteString(marker)
	}
	if b.tailLen < b.tailCap {
		sb.Write(b.tail[:b.tailLen])
	} else {
		sb.Write(b.tail[b.tailPos:])
		sb.Write(b.tail[:b.tailPos])
	}
	return sb.String()
}

func runCmd(ctx context.Context, argv []string, dir string, env []string, timeout time.Duration) runOut {
	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	start := time.Now()
	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	cmd.Dir, cmd.Env = dir, env
	setCmdProcessGroup(cmd)
	buf := newBoundedBuf(maxCmdOutput)
	cmd.Stdout, cmd.Stderr = buf, buf
	err := cmd.Run()
	out := buf.String()
	if err == nil {
		return runOut{Passed: true, Output: out}
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		d := timeout
		if d <= 0 {
			d = time.Since(start).Round(time.Millisecond)
		}
		return runOut{ExitCode: 124, Output: out, Err: fmt.Errorf("%s timed out after %s", filepath.Base(argv[0]), d)}
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return runOut{ExitCode: exitErr.ExitCode(), Output: out, Err: err}
	}
	return runOut{ExitCode: 1, Output: out, Err: err}
}

func stripEnv(env []string, drop ...string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok && slices.Contains(drop, k) {
			continue
		}
		out = append(out, kv)
	}
	return out
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

func readCTestFailures(buildDir, output string) []string {
	var ids []string
	seen := make(map[string]bool)
	add := func(name string) {
		if name = strings.TrimSpace(name); name != "" && !seen[name] {
			seen[name] = true
			ids = append(ids, name)
		}
	}
	if data, err := os.ReadFile(filepath.Join(buildDir, "Testing", "Temporary", "LastTestsFailed.log")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if _, name, ok := strings.Cut(strings.TrimSpace(line), ":"); ok {
				add(name)
			}
		}
	}
	if len(ids) > 0 {
		return ids
	}

	var startedOrder []string
	startedName := make(map[string]string)
	done := make(map[string]bool)
	for _, line := range strings.Split(output, "\n") {
		if m := ctestStartRe.FindStringSubmatch(line); m != nil {
			if !done[m[1]] && startedName[m[1]] == "" {
				startedOrder = append(startedOrder, m[1])
				startedName[m[1]] = m[2]
			}
			continue
		}
		if m := ctestDoneRe.FindStringSubmatch(line); m != nil {
			status := strings.TrimSpace(m[3])
			isPass := strings.HasPrefix(status, "Passed") ||
				strings.HasPrefix(status, "***Skipped") ||
				strings.HasPrefix(status, "***Disabled") ||
				strings.HasPrefix(status, "***Not Run (Disabled)")
			isFail := !isPass && strings.Contains(status, "***")
			if isPass || isFail {
				done[m[1]] = true
				if isFail {
					name := startedName[m[1]]
					if name == "" {
						name = m[2]
					}
					add(name)
				}
			}
		}
	}
	for _, num := range startedOrder {
		if !done[num] {
			add(startedName[num])
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
