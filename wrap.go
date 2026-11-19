package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

const (
	compileManifestFile = "compile_commands.jsonl"
	linkManifestFile    = "link_commands.jsonl"

	stripMode uint = 1 << iota
	stripOutput
	stripDep
	stripLink
	stripLTO
	stripInclude
	stripHost
	stripOptBisect
	stripSources
)

type wrapConfig struct {
	RealCC        string
	RealCXX       string
	Linker        string
	Platform      string
	Profile       string
	SDKRoot       string
	ManifestDir   string
	ExtraCFlags   []string
	ExtraLDFlags  []string
	SaveLTOTemps  bool
	CaptureTU     string
	CaptureOutDir string
}

type compileRec struct {
	ID               string    `json:"id,omitempty"`
	CWD              string    `json:"cwd"`
	Compiler         string    `json:"compiler"`
	IsCXX            bool      `json:"is_cxx"`
	Source           string    `json:"source"`
	Sources          []string  `json:"sources,omitempty"`
	Output           string    `json:"output"`
	RawArgs          []string  `json:"raw_args"`
	FullArgs         []string  `json:"full_args"`
	RandomSeed       string    `json:"random_seed,omitempty"`
	PreprocessedPath string    `json:"preprocessed_path,omitempty"`
	BitcodePath      string    `json:"bitcode_path,omitempty"`
	Timestamp        time.Time `json:"timestamp"`
}

type linkRec struct {
	CWD          string    `json:"cwd"`
	Compiler     string    `json:"compiler"`
	IsCXX        bool      `json:"is_cxx"`
	Output       string    `json:"output"`
	ObjectFiles  []string  `json:"object_files"`
	ArchiveFiles []string  `json:"archive_files,omitempty"`
	RawArgs      []string  `json:"raw_args"`
	FullArgs     []string  `json:"full_args"`
	IsShared     bool      `json:"is_shared,omitempty"`
	LTOTempsDir  string    `json:"lto_temps_dir,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

func isWrapperArgv0(argv0 string) (isCXX, ok bool) {
	switch filepath.Base(argv0) {
	case "clang", "cc", "lmc-cc":
		return false, true
	case "clang++", "c++", "lmc-c++":
		return true, true
	default:
		return false, false
	}
}

func setupWrapperDir(dir, lmcBin string) error {
	absBin, err := filepath.Abs(lmcBin)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"clang", "clang++", "cc", "c++"} {
		dst := filepath.Join(dir, name)
		_ = os.Remove(dst)
		if err := os.Symlink(absBin, dst); err != nil {
			return err
		}
	}
	return nil
}

func wrapEnv(c wrapConfig) []string {
	save := "0"
	if c.SaveLTOTemps {
		save = "1"
	}
	return []string{
		"LMC_REAL_CC=" + c.RealCC,
		"LMC_REAL_CXX=" + c.RealCXX,
		"LMC_LINKER=" + c.Linker,
		"LMC_PLATFORM=" + c.Platform,
		"LMC_PROFILE=" + c.Profile,
		"LMC_SDKROOT=" + c.SDKRoot,
		"LMC_MANIFEST_DIR=" + c.ManifestDir,
		"LMC_EXTRA_CFLAGS=" + joinFlags(c.ExtraCFlags),
		"LMC_EXTRA_LDFLAGS=" + joinFlags(c.ExtraLDFlags),
		"LMC_SAVE_LTO_TEMPS=" + save,
		"LMC_CAPTURE_TU=" + c.CaptureTU,
		"LMC_CAPTURE_OUT_DIR=" + c.CaptureOutDir,
	}
}

func loadWrapConfig(getenv func(string) string) wrapConfig {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	save := get("LMC_SAVE_LTO_TEMPS")
	return wrapConfig{
		RealCC:        get("LMC_REAL_CC"),
		RealCXX:       get("LMC_REAL_CXX"),
		Linker:        get("LMC_LINKER"),
		Platform:      get("LMC_PLATFORM"),
		Profile:       get("LMC_PROFILE"),
		SDKRoot:       get("LMC_SDKROOT"),
		ManifestDir:   get("LMC_MANIFEST_DIR"),
		ExtraCFlags:   splitFlags(getenv("LMC_EXTRA_CFLAGS")),
		ExtraLDFlags:  splitFlags(getenv("LMC_EXTRA_LDFLAGS")),
		SaveLTOTemps:  save == "1" || strings.EqualFold(save, "true"),
		CaptureTU:     get("LMC_CAPTURE_TU"),
		CaptureOutDir: get("LMC_CAPTURE_OUT_DIR"),
	}
}

func runWrapperMain(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "lmc: empty argv")
		return 1
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "lmc: %v\n", err)
		return 1
	}
	code, err := runWrapper(context.Background(), argv[0], argv[1:], cwd, os.Environ(), loadWrapConfig(os.Getenv), os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lmc: %v\n", err)
		if code == 0 {
			return 1
		}
	}
	return code
}

type wrapPlan struct {
	mode          string
	compiler      string
	isCXX         bool
	cwd           string
	rawArgs       []string
	fullArgs      []string
	extraEnv      []string
	sources       []string
	objectFiles   []string
	archiveFiles  []string
	output        string
	randomSeed    string
	isShared      bool
	ltoTempsDir   string
	captureMatch  bool
	captureSrcOut string
	captureBCOut  string
}

func runWrapper(ctx context.Context, argv0 string, args []string, cwd string, env []string, cfg wrapConfig, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	isCXX, ok := isWrapperArgv0(argv0)
	if !ok {
		return 1, fmt.Errorf("argv0 %q is not a wrapper invocation", argv0)
	}
	if cwd == "" {
		var err error
		if cwd, err = os.Getwd(); err != nil {
			return 1, err
		}
	}

	plan, err := planWrap(cfg, isCXX, cwd, args)
	if err != nil {
		return 1, err
	}
	if strings.HasSuffix(plan.ltoTempsDir, ".lto.d") {
		if err := os.MkdirAll(plan.ltoTempsDir, 0o755); err != nil {
			return 1, err
		}
	}

	childEnv := mergeEnv(env, plan.extraEnv)
	code, runErr := execCompiler(ctx, plan.compiler, plan.fullArgs, cwd, childEnv, stdin, stdout, stderr)
	if runErr != nil || code != 0 || plan.mode == "probe" {
		return code, runErr
	}

	var preprocPath, bcPath string
	if plan.captureMatch && len(plan.sources) > 0 {
		preprocPath, bcPath, err = runTUCapture(ctx, plan, childEnv)
		if err != nil {
			return 1, fmt.Errorf("capture TU %q: %w", plan.sources[0], err)
		}
	}

	if cfg.ManifestDir != "" {
		now := time.Now().UTC()
		if plan.mode == "compile" || plan.mode == "compile_link" {
			primary := ""
			if len(plan.sources) > 0 {
				primary = plan.sources[0]
			}
			if err := appendManifest(cfg.ManifestDir, compileManifestFile, compileRec{
				ID: plan.randomSeed, CWD: cwd, Compiler: plan.compiler, IsCXX: isCXX,
				Source: primary, Sources: slices.Clone(plan.sources), Output: plan.output,
				RawArgs: slices.Clone(plan.rawArgs), FullArgs: slices.Clone(plan.fullArgs),
				RandomSeed: plan.randomSeed, PreprocessedPath: preprocPath, BitcodePath: bcPath, Timestamp: now,
			}); err != nil {
				return 1, err
			}
		}
		if plan.mode == "link" || plan.mode == "compile_link" {
			if err := appendManifest(cfg.ManifestDir, linkManifestFile, linkRec{
				CWD: cwd, Compiler: plan.compiler, IsCXX: isCXX, Output: plan.output,
				ObjectFiles: slices.Clone(plan.objectFiles), ArchiveFiles: slices.Clone(plan.archiveFiles),
				RawArgs: slices.Clone(plan.rawArgs), FullArgs: slices.Clone(plan.fullArgs),
				IsShared: plan.isShared, LTOTempsDir: plan.ltoTempsDir, Timestamp: now,
			}); err != nil {
				return 1, err
			}
		}
	}
	return 0, nil
}

func planWrap(cfg wrapConfig, isCXX bool, cwd string, args []string) (*wrapPlan, error) {
	compiler := cfg.RealCC
	if isCXX && cfg.RealCXX != "" {
		compiler = cfg.RealCXX
	} else if compiler == "" {
		compiler = cfg.RealCXX
	}
	if compiler == "" {
		return nil, errors.New("missing real compiler (LMC_REAL_CC / LMC_REAL_CXX)")
	}

	parsed := parseClangArgs(cwd, args)
	captureMatch := matchesCaptureTU(cfg.CaptureTU, parsed.sources, parsed.output)

	var baseEnv []string
	if cfg.SDKRoot != "" && os.Getenv("SDKROOT") == "" {
		baseEnv = append(baseEnv, "SDKROOT="+cfg.SDKRoot)
	}

	spec, err := resolvePlatform(cfg.Platform)
	if err != nil {
		return nil, err
	}

	// bypass configure/cmake probes so feature tests keep original exit status
	if isProbe(cwd, args, parsed, captureMatch) {
		return &wrapPlan{
			mode: "probe", compiler: compiler, isCXX: isCXX, cwd: cwd,
			rawArgs: slices.Clone(args), fullArgs: crossProbeArgs(spec, cfg.Linker, args, parsed), extraEnv: baseEnv,
		}, nil
	}

	prof := cfg.Profile
	if prof == "" {
		prof = profDistroO2
	}
	cFlags, err := profileCompilerFlags(prof, spec)
	if err != nil {
		return nil, err
	}

	mode := "link"
	switch {
	case parsed.compileOnly || parsed.preprocessOnly:
		mode = "compile"
	case len(parsed.sources) > 0:
		mode = "compile_link"
	}

	out := parsed.output
	if out == "" {
		if mode == "compile" && !parsed.preprocessOnly && len(parsed.sources) > 0 {
			base := filepath.Base(parsed.sources[0])
			out = resolvePath(cwd, strings.TrimSuffix(base, filepath.Ext(base))+".o")
		} else if mode != "compile" {
			out = resolvePath(cwd, "a.out")
		}
	}

	seedIn := out
	if seedIn == "" && len(parsed.sources) > 0 {
		seedIn = parsed.sources[0]
	}
	sum := sha256.Sum256([]byte(seedIn))
	seed := hex.EncodeToString(sum[:8])

	var injected []string
	if !parsed.hasTarget {
		injected = append(injected, crossTargetArgs(spec)...)
	}
	if spec.IsDarwin && cfg.SDKRoot != "" && !parsed.hasSysroot {
		injected = append(injected, "-isysroot", cfg.SDKRoot)
	}
	if mode == "compile" || mode == "compile_link" {
		injected = append(injected, cFlags...)
		if !parsed.hasRandomSeed && !parsed.isAssemblyOnly {
			injected = append(injected, "-frandom-seed="+seed)
		}
		injected = append(injected, cfg.ExtraCFlags...)
	}

	var ltoTempsDir string
	if mode == "link" || mode == "compile_link" {
		if cfg.Linker != "" {
			injected = append(injected, linkerFlag(cfg.Linker))
		}
		injected = append(injected, profileLinkerFlags(prof, spec)...)
		if cfg.SaveLTOTemps && prof == profReleaseLTO {
			if spec.IsDarwin {
				// ld64.lld takes single-dash -save-temps rather than --save-temps
				ltoTempsDir = out + ".lto.d"
				injected = append(injected, "-Wl,-save-temps", "-Wl,-object_path_lto,"+ltoTempsDir)
			} else {
				ltoTempsDir = filepath.Dir(out)
				injected = append(injected, "-Wl,--save-temps")
			}
		}
		injected = append(injected, cfg.ExtraLDFlags...)
	}
	injected = append(injected, "-Wno-error")

	var capSrc, capBC string
	if captureMatch && len(parsed.sources) > 0 && mode != "link" && !parsed.isAssemblyOnly {
		outDir := cwd
		if cfg.CaptureOutDir != "" {
			outDir = resolvePath(cwd, cfg.CaptureOutDir)
		} else if out != "" {
			outDir = filepath.Dir(out)
		}
		ext := ".c"
		if isCXX || isCXXExt(filepath.Ext(parsed.sources[0])) {
			ext = ".cpp"
		}
		stem := sanitizeStem(filepath.Base(out))
		if stem == "" {
			stem = sanitizeStem(filepath.Base(parsed.sources[0]))
		}
		capSrc = filepath.Join(outDir, stem+".standalone"+ext)
		capBC = filepath.Join(outDir, stem+".preopt.bc")
	} else {
		captureMatch = false
	}

	return &wrapPlan{
		mode: mode, compiler: compiler, isCXX: isCXX, cwd: cwd,
		rawArgs: slices.Clone(args), fullArgs: appendBeforeDashDash(args, injected),
		extraEnv: append(baseEnv, "SOURCE_DATE_EPOCH=0"),
		sources:  parsed.sources, objectFiles: parsed.objectFiles, archiveFiles: parsed.archiveFiles,
		output: out, randomSeed: seed, isShared: parsed.isShared, ltoTempsDir: ltoTempsDir,
		captureMatch: captureMatch, captureSrcOut: capSrc, captureBCOut: capBC,
	}, nil
}

func isProbe(cwd string, args []string, parsed parsedClangArgs, captureMatch bool) bool {
	if len(args) == 0 || hasProbeMarker(cwd) {
		return true
	}
	for _, a := range args {
		if hasProbeMarker(a) || strings.HasPrefix(a, "-print-") || strings.HasPrefix(a, "--print-") {
			return true
		}
		switch a {
		case "-v", "--version", "-V", "-dumpmachine", "-dumpversion", "--help", "-help", "-###", "-M", "-MM", "-fsyntax-only":
			return true
		case "-E":
			if !captureMatch {
				return true
			}
		}
	}
	return len(parsed.sources) == 0 && len(parsed.objectFiles) == 0 && len(parsed.archiveFiles) == 0 &&
		len(parsed.sharedLibs) == 0 && !parsed.hasStdin && !parsed.hasFilelist
}

func hasProbeMarker(s string) bool {
	for _, m := range []string{"conftest", "CMakeScratch", "CMakeTmp", "CompilerIdC", "CompilerIdCXX", "meson-private", "ffconf."} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func linkerFlag(linker string) string {
	if strings.ContainsRune(linker, filepath.Separator) {
		return "--ld-path=" + linker
	}
	return "-fuse-ld=" + linker
}

func runTUCapture(ctx context.Context, plan *wrapPlan, childEnv []string) (string, string, error) {
	if err := os.MkdirAll(filepath.Dir(plan.captureSrcOut), 0o755); err != nil {
		return "", "", err
	}
	base := stripFlags(plan.fullArgs, stripMode|stripOutput|stripDep|stripLink, "")

	preArgs := append(slices.Clone(base), "-E", "-frewrite-includes", "-o", plan.captureSrcOut)
	var buf bytes.Buffer
	if code, err := execCompiler(ctx, plan.compiler, preArgs, plan.cwd, childEnv, nil, io.Discard, &buf); err != nil || code != 0 {
		return "", "", fmt.Errorf("-frewrite-includes exit %d (%v): %s", code, err, strings.TrimSpace(buf.String()))
	}

	buf.Reset()
	bcArgs := append(stripFlags(base, stripLTO, ""), "-Xclang", "-disable-llvm-passes", "-emit-llvm", "-c", "-o", plan.captureBCOut)
	if code, err := execCompiler(ctx, plan.compiler, bcArgs, plan.cwd, childEnv, nil, io.Discard, &buf); err != nil || code != 0 {
		return "", "", fmt.Errorf("-emit-llvm exit %d (%v): %s", code, err, strings.TrimSpace(buf.String()))
	}
	return plan.captureSrcOut, plan.captureBCOut, nil
}

func standaloneCompileArgs(rec compileRec, src, outObj string, portable bool) []string {
	mask := stripMode | stripOutput | stripDep | stripLink | stripInclude | stripSources
	if portable {
		mask |= stripHost
	}
	drop := append([]string{rec.Source}, rec.Sources...)
	return append(stripFlags(rec.FullArgs, mask, rec.CWD, drop...), "-c", src, "-o", outObj)
}

func stripFlags(args []string, mask uint, cwd string, dropSources ...string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if mask&stripSources == 0 {
				out = append(out, args[i:]...)
			}
			break
		}
		if mask&stripMode != 0 && (a == "-c" || a == "-S" || a == "-E" || a == "-emit-llvm") {
			continue
		}
		if mask&stripOutput != 0 {
			if a == "-o" {
				i++
				continue
			}
			if isAttachedOutputFlag(a) {
				continue
			}
		}
		if mask&stripDep != 0 {
			if a == "-MD" || a == "-MMD" || a == "-MP" || a == "-MG" ||
				strings.HasPrefix(a, "-MF") || strings.HasPrefix(a, "-MT") || strings.HasPrefix(a, "-MQ") {
				if a == "-MF" || a == "-MT" || a == "-MQ" {
					i++
				}
				continue
			}
			if a == "-MJ" {
				i++
				continue
			}
		}
		if mask&stripInclude != 0 {
			if a == "-I" || a == "-isystem" || a == "-iquote" || a == "-idirafter" || a == "-include" || a == "-imacros" {
				i++
				continue
			}
			if strings.HasPrefix(a, "-I") || strings.HasPrefix(a, "-isystem") ||
				strings.HasPrefix(a, "-iquote") || strings.HasPrefix(a, "-idirafter") {
				continue
			}
		}
		if mask&stripHost != 0 {
			if a == "-isysroot" {
				i++
				continue
			}
			if strings.HasPrefix(a, "-frandom-seed=") || strings.HasPrefix(a, "-isysroot=") {
				continue
			}
		}
		if mask&stripOptBisect != 0 && a == "-mllvm" && i+1 < len(args) && strings.HasPrefix(args[i+1], "-opt-bisect-limit") {
			i++
			continue
		}
		if mask&stripLink != 0 {
			if a == "--ld-path" {
				i++
				continue
			}
			if strings.HasPrefix(a, "-fuse-ld=") || strings.HasPrefix(a, "--ld-path=") || strings.HasPrefix(a, "-Wl,") {
				continue
			}
		}
		if mask&stripLTO != 0 && (a == "-flto" || strings.HasPrefix(a, "-flto=")) {
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
		if mask&stripSources != 0 {
			if (!strings.HasPrefix(a, "-") && isSourceExt(filepath.Ext(a))) ||
				(len(dropSources) > 0 && slices.Contains(dropSources, resolvePath(cwd, a))) {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

func isAttachedOutputFlag(a string) bool {
	return strings.HasPrefix(a, "-o") && len(a) > 2 && !strings.HasPrefix(a, "-object-file-name=") && a != "-objc"
}

type parsedClangArgs struct {
	compileOnly, preprocessOnly, isShared, hasSysroot, hasTarget, hasLinkerFlag, hasRandomSeed, hasStdin, hasFilelist, isAssemblyOnly bool
	output                                                                                                                            string
	sources, objectFiles, archiveFiles, sharedLibs                                                                                    []string
}

var twoArgClangFlags = map[string]bool{
	"-I": true, "-isystem": true, "-iquote": true, "-idirafter": true,
	"-include": true, "-imacros": true, "-isysroot": true, "-D": true, "-U": true,
	"-MF": true, "-MT": true, "-MQ": true, "-MJ": true,
	"-L": true, "-l": true, "-F": true, "-framework": true, "-weak_framework": true,
	"-mllvm": true, "-Xclang": true, "-Xlinker": true, "-Xpreprocessor": true,
	"-target": true, "--target": true, "--ld-path": true, "-arch": true, "-rpath": true,
	"-install_name": true, "-current_version": true, "-compatibility_version": true,
	"-exported_symbols_list": true, "-unexported_symbols_list": true,
	"-bundle_loader": true, "-order_file": true, "-serialize-diagnostics": true,
}

func parseClangArgs(cwd string, args []string) parsedClangArgs {
	var p parsedClangArgs
	explicitLang := ""
	afterDash := false
	expanded := expandResponseFiles(cwd, args)

	for i := 0; i < len(expanded); i++ {
		a := expanded[i]
		if !afterDash && a == "--" {
			afterDash = true
			continue
		}
		if !afterDash {
			switch a {
			case "-c", "-S", "-emit-llvm":
				p.compileOnly = true
				continue
			case "-E":
				p.preprocessOnly = true
				continue
			case "-shared", "-dynamiclib", "-bundle":
				p.isShared = true
				continue
			case "-":
				p.hasStdin = true
				continue
			case "-o":
				if i+1 < len(expanded) {
					i++
					p.output = resolvePath(cwd, expanded[i])
				}
				continue
			case "-x":
				if i+1 < len(expanded) {
					i++
					explicitLang = expanded[i]
				}
				continue
			case "-filelist":
				p.hasFilelist = true
				if i+1 < len(expanded) {
					i++
					p.objectFiles = append(p.objectFiles, readFilelistObjects(cwd, expanded[i])...)
				}
				continue
			}
			if a == "-isysroot" || strings.HasPrefix(a, "--sysroot=") || strings.HasPrefix(a, "-isysroot=") {
				p.hasSysroot = true
			}
			if a == "-target" || a == "--target" || strings.HasPrefix(a, "--target=") || strings.HasPrefix(a, "-target=") {
				p.hasTarget = true
			}
			if a == "--ld-path" || strings.HasPrefix(a, "--ld-path=") || strings.HasPrefix(a, "-fuse-ld=") {
				p.hasLinkerFlag = true
			}
			if twoArgClangFlags[a] {
				i++
				continue
			}
			if isAttachedOutputFlag(a) {
				p.output = resolvePath(cwd, a[2:])
				continue
			}
			if strings.HasPrefix(a, "-frandom-seed=") {
				p.hasRandomSeed = true
			}
			if strings.HasPrefix(a, "-Wl,") {
				parts := strings.Split(a[4:], ",")
				for j := 0; j+1 < len(parts); j++ {
					if parts[j] == "-filelist" {
						p.hasFilelist = true
						p.objectFiles = append(p.objectFiles, readFilelistObjects(cwd, parts[j+1])...)
						j++
					}
				}
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
		}

		res := resolvePath(cwd, a)
		if explicitLang != "" && explicitLang != "none" {
			if strings.Contains(explicitLang, "header") {
				p.compileOnly = true
			}
			p.sources = append(p.sources, res)
			continue
		}
		switch ext := strings.ToLower(filepath.Ext(a)); {
		case isSourceExt(ext):
			p.sources = append(p.sources, res)
		case ext == ".o" || ext == ".lo" || ext == ".obj" || ext == ".bc":
			p.objectFiles = append(p.objectFiles, res)
		case ext == ".a":
			p.archiveFiles = append(p.archiveFiles, res)
		case ext == ".so" || ext == ".dylib" || strings.Contains(filepath.Base(a), ".so."):
			p.sharedLibs = append(p.sharedLibs, res)
		}
	}

	if len(p.sources) > 0 {
		p.isAssemblyOnly = explicitLang == "assembler" || explicitLang == "assembler-with-cpp" ||
			!slices.ContainsFunc(p.sources, func(s string) bool {
				ext := strings.ToLower(filepath.Ext(s))
				return ext != ".s" && ext != ".asm"
			})
	}
	return p
}

func expandResponseFiles(cwd string, args []string) []string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "@") && len(a) > 1 {
			if data, err := os.ReadFile(resolvePath(cwd, a[1:])); err == nil {
				out = append(out, splitFlags(string(data))...)
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

func readFilelistObjects(cwd, listPath string) []string {
	data, err := os.ReadFile(resolvePath(cwd, listPath))
	if err != nil {
		return nil
	}
	var objs []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			objs = append(objs, resolvePath(cwd, line))
		}
	}
	return objs
}

func isSourceExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm", ".i", ".ii", ".s", ".asm":
		return true
	}
	return false
}

func isCXXExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".cc", ".cpp", ".cxx", ".c++", ".mm", ".ii":
		return true
	}
	return false
}

func matchesCaptureTU(pattern string, sources []string, output string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == "*" || pattern == "1" {
		return true
	}
	norm := filepath.Clean(pattern)
	match := func(cand string) bool {
		if cand == "" {
			return false
		}
		c := filepath.Clean(cand)
		return c == norm || filepath.Base(c) == norm || strings.HasSuffix(c, string(filepath.Separator)+norm)
	}
	return match(output) || slices.ContainsFunc(sources, match)
}

func sanitizeStem(name string) string {
	name = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(name), ".o"), ".obj")
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func appendBeforeDashDash(args, extra []string) []string {
	if idx := slices.Index(args, "--"); idx >= 0 {
		out := make([]string, 0, len(args)+len(extra))
		return append(append(append(out, args[:idx]...), extra...), args[idx:]...)
	}
	return append(slices.Clone(args), extra...)
}

func execCompiler(ctx context.Context, bin string, args []string, cwd string, env []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir, cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = cwd, env, stdin, stdout, stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return 1, fmt.Errorf("exec %q: %w", bin, err)
}

func appendManifest(dir, name string, val any) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	line, err := json.Marshal(val)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	// serialize concurrent ninja/make wrapper processes appending jsonl
	lockF, err := os.OpenFile(filepath.Join(dir, "manifest.lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer lockF.Close()
	if err := syscall.Flock(int(lockF.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(lockF.Fd()), syscall.LOCK_UN) }()

	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	_, wErr := f.Write(line)
	if cErr := f.Close(); wErr == nil {
		return cErr
	}
	return wErr
}

func readCompileRecs(manifestDir string) ([]compileRec, error) {
	return readJSONLines[compileRec](filepath.Join(manifestDir, compileManifestFile))
}

func readLinkRecs(manifestDir string) ([]linkRec, error) {
	return readJSONLines[linkRec](filepath.Join(manifestDir, linkManifestFile))
}

func readJSONLines[T any](path string) ([]T, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []T
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for lineNo := 1; sc.Scan(); lineNo++ {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var item T
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, fmt.Errorf("parse %s:%d: %w", path, lineNo, err)
		}
		out = append(out, item)
	}
	return out, sc.Err()
}

func splitFlags(s string) []string {
	var args []string
	var cur strings.Builder
	var quote rune
	inTok, esc := false, false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			inTok, esc = true, false
		case r == '\\' && quote != '\'':
			inTok, esc = true, true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			inTok = true
		case r == '\'' || r == '"':
			quote, inTok = r, true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if inTok {
				args = append(args, cur.String())
				cur.Reset()
				inTok = false
			}
		default:
			cur.WriteRune(r)
			inTok = true
		}
	}
	if inTok {
		args = append(args, cur.String())
	}
	return args
}

func joinFlags(flags []string) string {
	parts := make([]string, 0, len(flags))
	for _, f := range flags {
		switch {
		case f == "":
			parts = append(parts, "''")
		case strings.ContainsAny(f, " \t\n\"'\\"):
			e := strings.ReplaceAll(strings.ReplaceAll(f, `\`, `\\`), `"`, `\"`)
			parts = append(parts, `"`+e+`"`)
		default:
			parts = append(parts, f)
		}
	}
	return strings.Join(parts, " ")
}
