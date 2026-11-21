package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

func isCross(spec platformSpec) bool {
	return spec.OS != runtime.GOOS || spec.Arch != runtime.GOARCH
}

func crossTargetArgs(spec platformSpec) []string {
	if isCross(spec) && spec.TargetTriple != "" {
		return []string{"--target=" + spec.TargetTriple}
	}
	return nil
}

func crossSysrootArgs(spec platformSpec) []string {
	return crossSysrootArgsForRoot(spec, "/")
}

func crossSysrootArgsForRoot(spec platformSpec, rootfs string) []string {
	if spec.ID != platLinuxRISCV64 {
		return nil
	}
	usrDir := filepath.Join(rootfs, "usr")
	sysroot := filepath.Join(usrDir, "riscv64-linux-gnu")
	raw, err := os.ReadFile(filepath.Join(sysroot, "lib", "libc.so"))
	if err != nil {
		return nil
	}
	txt := string(raw)
	if strings.Contains(txt, "/usr/riscv64-linux-gnu") || (!strings.Contains(txt, "/lib/ld-linux-riscv64") && !strings.Contains(txt, "/usr/lib64/")) {
		return nil
	}
	var gccDir string
	for _, libDir := range []string{"lib", "lib64"} {
		matches, _ := filepath.Glob(filepath.Join(usrDir, libDir, "gcc", "riscv64-linux-gnu", "*"))
		slices.SortFunc(matches, func(a, b string) int {
			return cmpDotVersion(filepath.Base(b), filepath.Base(a))
		})
		for _, m := range matches {
			if fileExists(filepath.Join(m, "crtbeginS.o")) {
				gccDir = m
				break
			}
		}
		if gccDir != "" {
			break
		}
	}
	args := []string{"--sysroot=" + sysroot, "--gcc-toolchain=" + usrDir}
	if gccDir != "" {
		args = append(args, "-B"+gccDir, "-L"+gccDir)
	}
	return args
}

func appendCrossSysrootArgs(dst []string, spec platformSpec, hasSysroot, linking bool) []string {
	return filterCrossSysrootArgs(dst, crossSysrootArgs(spec), hasSysroot, linking)
}

func filterCrossSysrootArgs(dst, sysArgs []string, hasSysroot, linking bool) []string {
	for _, a := range sysArgs {
		if hasSysroot && strings.HasPrefix(a, "--sysroot=") {
			continue
		}
		if !linking && strings.HasPrefix(a, "-L") {
			continue
		}
		dst = append(dst, a)
	}
	return dst
}

func cmpDotVersion(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var sa, sb string
		if i < len(pa) {
			sa = pa[i]
		}
		if i < len(pb) {
			sb = pb[i]
		}
		na, ea := strconv.Atoi(sa)
		nb, eb := strconv.Atoi(sb)
		if ea == nil && eb == nil {
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
			continue
		}
		if sa != sb {
			return strings.Compare(sa, sb)
		}
	}
	return 0
}

func crossTargetFlag(targets []affected) string {
	for _, a := range targets {
		if spec, err := lookupPlatform(a.Platform); err == nil && spec.TargetTriple != "" {
			return " --target=" + spec.TargetTriple
		}
	}
	return ""
}

func crossDiagSanFlags(spec platformSpec) (compile, link []string, ok bool) {
	if spec.ID == platLinuxRISCV64 {
		// qemu-riscv64 user-mode collides with asan shadow mmap
		return []string{"-O1", "-g", "-fsanitize=undefined", "-fno-sanitize-recover=undefined"},
			[]string{"-fsanitize=undefined", "-fno-sanitize-recover=undefined"}, true
	}
	return nil, nil, false
}

func crossTimeout(spec platformSpec, d time.Duration) time.Duration {
	if isCross(spec) {
		return d * 3
	}
	return d
}

func crossProbeArgs(spec platformSpec, linker string, args []string, parsed parsedClangArgs) []string {
	targetArgs := crossTargetArgs(spec)
	if len(targetArgs) == 0 || len(args) == 0 || slices.ContainsFunc(args, func(a string) bool { return a == "-help" || a == "--help" }) {
		return slices.Clone(args)
	}
	var extra []string
	if !parsed.hasTarget {
		extra = append(extra, targetArgs...)
	}
	linking := isLinkingProbe(args, parsed)
	extra = appendCrossSysrootArgs(extra, spec, parsed.hasSysroot, linking)
	if linker != "" && !parsed.hasLinkerFlag && linking {
		extra = append(extra, linkerFlag(linker))
	}
	if len(extra) == 0 {
		return slices.Clone(args)
	}
	return appendBeforeDashDash(args, extra)
}

func isLinkingProbe(args []string, parsed parsedClangArgs) bool {
	if parsed.compileOnly || parsed.preprocessOnly {
		return false
	}
	hasInput := len(parsed.sources) > 0 || len(parsed.objectFiles) > 0 || len(parsed.archiveFiles) > 0 ||
		len(parsed.sharedLibs) > 0 || parsed.hasStdin || parsed.hasFilelist || parsed.hasResponseFile
	hasLinkerFlag := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-Xlinker" {
			hasLinkerFlag = true
			i++
			continue
		}
		if strings.HasPrefix(a, "-Wl,") {
			hasLinkerFlag = true
			continue
		}
		switch a {
		case "-M", "-MM", "-fsyntax-only", "-###", "--version", "-dumpmachine", "-dumpversion":
			return false
		}
		if strings.HasPrefix(a, "-print-") || strings.HasPrefix(a, "--print-") {
			return false
		}
	}
	return hasInput || hasLinkerFlag
}

func setupCrossWorkspace(workDir string, spec platformSpec, env []string) ([]string, error) {
	if !isCross(spec) || spec.TargetTriple == "" {
		return env, nil
	}
	tcFile := filepath.Join(workDir, "cross.cmake")
	sysName := "Linux"
	if spec.IsDarwin {
		sysName = "Darwin"
	}
	// preserve QEMU_LD_PREFIX across brotli roundtrip test cmake script
	tcContent := fmt.Sprintf("set(CMAKE_SYSTEM_NAME %s)\nset(CMAKE_SYSTEM_PROCESSOR %s)\nset(CMAKE_C_COMPILER_TARGET %s)\nset(CMAKE_CXX_COMPILER_TARGET %s)\nset(CMAKE_ASM_COMPILER_TARGET %s)\nset(BROTLI_WRAPPER_LD_PREFIX \"$ENV{QEMU_LD_PREFIX}\")\n",
		sysName, spec.Arch, spec.TargetTriple, spec.TargetTriple, spec.TargetTriple)
	for _, a := range crossSysrootArgs(spec) {
		if sr, ok := strings.CutPrefix(a, "--sysroot="); ok {
			tcContent += fmt.Sprintf("set(CMAKE_SYSROOT %s)\n", sr)
			break
		}
	}
	if err := os.WriteFile(tcFile, []byte(tcContent), 0o644); err != nil {
		return nil, err
	}
	env = append(env, "CMAKE_TOOLCHAIN_FILE="+tcFile)
	if spec.ID == platLinuxRISCV64 {
		env = append(env, "PKG_CONFIG_LIBDIR=/usr/riscv64-linux-gnu/lib/pkgconfig", "PKG_CONFIG_PATH=")
		if os.Getenv("QEMU_LD_PREFIX") == "" {
			if info, err := os.Stat("/usr/riscv64-linux-gnu"); err == nil && info.IsDir() {
				env = append(env, "QEMU_LD_PREFIX=/usr/riscv64-linux-gnu")
			}
		}
		if os.Getenv("QEMU_CPU") == "" {
			env = append(env, "QEMU_CPU=rva23u64")
		}
	}
	return env, nil
}
