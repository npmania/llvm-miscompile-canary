package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
	if linker != "" && !parsed.hasLinkerFlag && isLinkingProbe(args, parsed) {
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
	if err := os.WriteFile(tcFile, []byte(tcContent), 0o644); err != nil {
		return nil, err
	}
	env = append(env, "CMAKE_TOOLCHAIN_FILE="+tcFile)
	if spec.ID == platLinuxRISCV64 {
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
