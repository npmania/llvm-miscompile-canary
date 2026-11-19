package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

const (
	platLinuxX86     = "linux-x86_64"
	platLinuxARM64   = "linux-aarch64"
	platLinuxRISCV64 = "linux-riscv64"
	platDarwinARM    = "darwin-arm64"

	profDistroO2   = "distro-O2"
	profReleaseLTO = "release-lto"
	profDiagO0     = "diag-O0"
	profDiagSan    = "diag-asan-ubsan"
)

type platformSpec struct {
	ID            string
	OS            string
	Arch          string
	LLVMTarget    string
	TargetTriple  string
	BaselineFlags []string
	IsDarwin      bool
}

var platformSpecs = map[string]platformSpec{
	platLinuxX86:     {ID: platLinuxX86, OS: "linux", Arch: "amd64", LLVMTarget: "X86", BaselineFlags: []string{"-march=x86-64-v3"}},
	platLinuxARM64:   {ID: platLinuxARM64, OS: "linux", Arch: "arm64", LLVMTarget: "AArch64", BaselineFlags: []string{"-mcpu=neoverse-v1"}},
	platLinuxRISCV64: {ID: platLinuxRISCV64, OS: "linux", Arch: "riscv64", LLVMTarget: "RISCV", TargetTriple: "riscv64-linux-gnu", BaselineFlags: []string{"-march=rva23u64"}},
	platDarwinARM:    {ID: platDarwinARM, OS: "darwin", Arch: "arm64", LLVMTarget: "AArch64", BaselineFlags: []string{"-mcpu=apple-m1"}, IsDarwin: true},
}

func lookupPlatform(id string) (platformSpec, error) {
	spec, ok := platformSpecs[id]
	if !ok {
		return platformSpec{}, fmt.Errorf("unsupported platform %q", id)
	}
	spec.BaselineFlags = slices.Clone(spec.BaselineFlags)
	return spec, nil
}

func lookupOSArch(goos, goarch string) (platformSpec, error) {
	switch goos + "/" + goarch {
	case "linux/amd64":
		return lookupPlatform(platLinuxX86)
	case "linux/arm64":
		return lookupPlatform(platLinuxARM64)
	case "linux/riscv64":
		return lookupPlatform(platLinuxRISCV64)
	case "darwin/arm64":
		return lookupPlatform(platDarwinARM)
	default:
		return platformSpec{}, fmt.Errorf("unsupported host %s/%s", goos, goarch)
	}
}

func resolvePlatform(id string) (platformSpec, error) {
	if id = strings.TrimSpace(id); id == "" {
		return lookupOSArch(runtime.GOOS, runtime.GOARCH)
	}
	return lookupPlatform(id)
}

func validProfile(p string) bool {
	return p == profDistroO2 || p == profReleaseLTO || p == profDiagO0 || p == profDiagSan
}

func standardProfiles() []string { return []string{profDistroO2, profReleaseLTO} }

func profileCompilerFlags(prof string, spec platformSpec) ([]string, error) {
	switch prof {
	case profDistroO2:
		return []string{"-O2"}, nil
	case profReleaseLTO:
		return append([]string{"-O3", "-flto=thin"}, spec.BaselineFlags...), nil
	case profDiagO0:
		return []string{"-O0"}, nil
	case profDiagSan:
		if c, _, ok := crossDiagSanFlags(spec); ok {
			return c, nil
		}
		return []string{"-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=address,undefined"}, nil
	default:
		return nil, fmt.Errorf("unsupported profile %q", prof)
	}
}

func profileLinkerFlags(prof string, spec platformSpec) []string {
	switch prof {
	case profReleaseLTO:
		// both ld.lld and ld64.lld accept --thinlto-jobs=4
		return append([]string{"-O3", "-flto=thin", "-Wl,--thinlto-jobs=4"}, spec.BaselineFlags...)
	case profDiagSan:
		if _, ld, ok := crossDiagSanFlags(spec); ok {
			return ld
		}
		return []string{"-fsanitize=address,undefined", "-fno-sanitize-recover=address,undefined"}
	default:
		return nil
	}
}

func conservativeFlags() []string {
	return []string{"-fno-strict-aliasing", "-fwrapv", "-ftrivial-auto-var-init=zero"}
}

func sanitizerEnv() []string {
	return []string{
		"ASAN_OPTIONS=detect_leaks=0:abort_on_error=1",
		"UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1",
	}
}

type toolchain struct {
	Spec        platformSpec
	BinDir      string
	Clang       string
	ClangXX     string
	Linker      string
	Ar          string
	Ranlib      string
	NM          string
	Opt         string
	LLC         string
	LLUBI       string
	LLVMExtract string
	LLVMReduce  string
	LLVMLink    string
	LLVMDis     string
	AliveTV     string
	SDKRoot     string
}

var (
	darwinLLVMFallbackDirs = []string{"/opt/homebrew/opt/llvm@22/bin", "/opt/homebrew/opt/llvm/bin"}
	darwinLLDFallbackPaths = []string{"/opt/homebrew/opt/lld@22/bin/ld64.lld", "/opt/homebrew/opt/lld/bin/ld64.lld", "/opt/homebrew/bin/ld64.lld"}
)

func resolveToolchain(plat, binDir, auxDirs, linker, aliveTV, sdkRoot string) (*toolchain, error) {
	spec, err := resolvePlatform(plat)
	if err != nil {
		return nil, err
	}

	var dirs []string
	if binDir != "" {
		abs, err := filepath.Abs(binDir)
		if err != nil {
			return nil, fmt.Errorf("resolve toolchain dir %q: %w", binDir, err)
		}
		dirs = append(dirs, abs)
	}
	for _, aux := range splitCSV(auxDirs) {
		abs, err := filepath.Abs(aux)
		if err != nil {
			return nil, fmt.Errorf("resolve aux dir %q: %w", aux, err)
		}
		dirs = append(dirs, abs)
	}
	allowPath := binDir == ""
	if allowPath && spec.IsDarwin {
		for _, d := range darwinLLVMFallbackDirs {
			if info, err := os.Stat(d); err == nil && info.IsDir() {
				dirs = append(dirs, d)
			}
		}
	}

	clang, err := findTool([]string{"clang"}, "", dirs, nil, allowPath, true)
	if err != nil {
		return nil, err
	}
	clangDir := filepath.Dir(clang)
	withClang := prependUnique(dirs, clangDir)

	clangXX, err := findTool([]string{"clang++"}, "", withClang, nil, allowPath, true)
	if err != nil {
		return nil, err
	}

	linkerName := "ld.lld"
	var linkerFallbacks []string
	if spec.IsDarwin {
		linkerName = "ld64.lld"
		linkerFallbacks = darwinLLDFallbackPaths
	}
	resolvedLinker, err := findTool([]string{linkerName}, linker, withClang, linkerFallbacks, true, true)
	if err != nil {
		return nil, err
	}

	tc := &toolchain{
		Spec:    spec,
		BinDir:  clangDir,
		Clang:   clang,
		ClangXX: clangXX,
		Linker:  resolvedLinker,
	}
	if binDir != "" {
		if abs, err := filepath.Abs(binDir); err == nil {
			tc.BinDir = abs
		} else {
			tc.BinDir = binDir
		}
	}

	optTools := []struct {
		dst       *string
		names     []string
		explicit  string
		allowPath bool
	}{
		{&tc.Ar, []string{"llvm-ar", "ar"}, "", true},
		{&tc.Ranlib, []string{"llvm-ranlib", "ranlib"}, "", true},
		{&tc.NM, []string{"llvm-nm", "nm"}, "", true},
		{&tc.Opt, []string{"opt"}, "", allowPath},
		{&tc.LLC, []string{"llc"}, "", allowPath},
		{&tc.LLUBI, []string{"llubi"}, "", allowPath},
		{&tc.LLVMExtract, []string{"llvm-extract"}, "", allowPath},
		{&tc.LLVMReduce, []string{"llvm-reduce"}, "", allowPath},
		{&tc.LLVMLink, []string{"llvm-link"}, "", allowPath},
		{&tc.LLVMDis, []string{"llvm-dis"}, "", allowPath},
		{&tc.AliveTV, []string{"alive-tv"}, aliveTV, true},
	}
	for _, t := range optTools {
		p, err := findTool(t.names, t.explicit, withClang, nil, t.allowPath, false)
		if err != nil {
			return nil, err
		}
		*t.dst = p
	}

	tc.SDKRoot, err = resolveSDKRoot(spec, sdkRoot)
	if err != nil {
		return nil, err
	}
	return tc, nil
}

func findTool(names []string, explicit string, searchDirs, fallbackFiles []string, allowPath, required bool) (string, error) {
	if explicit != "" {
		p := explicit
		if !strings.ContainsRune(p, filepath.Separator) {
			found, err := exec.LookPath(p)
			if err != nil {
				return "", fmt.Errorf("resolve explicit %s %q: %w", names[0], explicit, err)
			}
			p = found
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", fmt.Errorf("resolve explicit %s %q: %w", names[0], explicit, err)
		}
		if !isExecFile(abs) {
			return "", fmt.Errorf("explicit %s %q is not executable", names[0], abs)
		}
		return abs, nil
	}
	for _, dir := range searchDirs {
		for _, name := range names {
			if cand := filepath.Join(dir, name); isExecFile(cand) {
				return cand, nil
			}
		}
	}
	for _, cand := range fallbackFiles {
		if isExecFile(cand) {
			return cand, nil
		}
	}
	if allowPath {
		for _, name := range names {
			if p, err := exec.LookPath(name); err == nil {
				if abs, err := filepath.Abs(p); err == nil {
					return abs, nil
				}
				return p, nil
			}
		}
	}
	if required {
		return "", fmt.Errorf("required tool %q not found in %v", names[0], searchDirs)
	}
	return "", nil
}

func isExecFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func prependUnique(dirs []string, first string) []string {
	out := make([]string, 0, len(dirs)+1)
	out = append(out, first)
	for _, d := range dirs {
		if d != first {
			out = append(out, d)
		}
	}
	return out
}

func resolveSDKRoot(spec platformSpec, explicit string) (string, error) {
	if explicit != "" {
		abs, err := filepath.Abs(explicit)
		if err != nil {
			return "", err
		}
		if info, err := os.Stat(abs); err != nil || !info.IsDir() {
			return "", fmt.Errorf("sdkroot %q is not a directory", abs)
		}
		return abs, nil
	}
	if !spec.IsDarwin {
		return "", nil
	}
	if envSDK := strings.TrimSpace(os.Getenv("SDKROOT")); envSDK != "" {
		if info, err := os.Stat(envSDK); err == nil && info.IsDir() {
			return envSDK, nil
		}
	}
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("xcrun", "--show-sdk-path").Output(); err == nil {
			sdk := strings.TrimSpace(string(out))
			if info, statErr := os.Stat(sdk); sdk != "" && statErr == nil && info.IsDir() {
				return sdk, nil
			}
		}
		const cltSDK = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"
		if info, err := os.Stat(cltSDK); err == nil && info.IsDir() {
			return cltSDK, nil
		}
		return "", errors.New("darwin SDK root not found")
	}
	return "", nil
}

func shortSHA(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func tailText(s string, maxBytes int) string {
	s = strings.TrimSpace(s)
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	return "...\n" + strings.TrimSpace(s[len(s)-maxBytes:])
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func mergeEnv(base, overrides []string) []string {
	if len(base) == 0 {
		base = os.Environ()
	}
	out := slices.Clone(base)
	for _, kv := range overrides {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		prefix := k + "="
		idx := slices.IndexFunc(out, func(cur string) bool { return strings.HasPrefix(cur, prefix) })
		if idx >= 0 {
			out[idx] = kv
		} else {
			out = append(out, kv)
		}
	}
	return out
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if mode == 0 {
		if info, err := in.Stat(); err == nil {
			mode = info.Mode().Perm()
		} else {
			mode = 0o644
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	if closeErr := out.Close(); copyErr == nil {
		return closeErr
	}
	return copyErr
}

func resolvePath(cwd, p string) string {
	if p == "" || p == "-" || p == "/dev/null" {
		return p
	}
	if filepath.IsAbs(p) || cwd == "" {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(cwd, p))
}

func isWithinDir(root, cand string) bool {
	rel, err := filepath.Rel(root, cand)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}
