package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestSanitize(t *testing.T) {
	sha64 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	bundleURL := "https://github.com/npmania/llvm-miscompile-canary/releases/download/reproducers/reproducer-inc-1.tar.zst"
	cases := []struct {
		name, in     string
		want, forbid []string
	}{
		{"commitAndRefs", `Revert "Foo (#241234)" by @nikic, fixes llvm/llvm-project#240000 https://github.com/llvm/llvm-project/commit/abcdef1234567890abcdef1234567890abcdef12`, []string{`Revert "Foo" by nikic`, "`abcdef123456`"}, []string{`@nikic`, `llvm/llvm-project`, `#\d+`, `github\.com/llvm`, `abcdef1234567890`}},
		{"nestedRefs", "see llvm/llvm-llvm/llvm-project#111project#222 and @@nikic and @llvm/pr-subscribers-x86", []string{"nikic", "llvm/pr-subscribers-x86"}, []string{`llvm/llvm-project`, `@[A-Za-z0-9_-]+`, `#\d+`}},
		{"entitiesAndGH", "Reviewed by &#64;fhahn and &#x40;arsenm; closes GH-123456 and &#35;987654", []string{"fhahn", "arsenm"}, []string{`@[A-Za-z0-9_-]+`, `(?i)GH-\d+`, `#\d+`, `&#`}},
		{"unclosedFence", "Revert \"```\" by @nikic on llvm/llvm-project@0212d77fa269abcdef0123456789abcdef012345", []string{"by nikic", "`0212d77fa269`"}, []string{`@nikic`, `llvm/llvm-project`}},
		{"linksAndHex", "Commit [view](https://github.com/llvm/llvm-project/commit/0212d77fa269abcdef) raw 11223344556677889900aabbccddeeff00112233 " + sha64 + " " + bundleURL, []string{"`0212d77fa269`", "`112233445566`", sha64, bundleURL}, []string{`github\.com/llvm`, `11223344556677889900aabbccddeeff00112233`}},
		{"codeAndEmail", "Author `@LebedevRI` <author@example.org> fixed [PR](https://github.com/llvm/llvm-project/pull/99999)", []string{"`LebedevRI`", "author[at]example.org"}, []string{`@[A-Za-z0-9_-]+`, `github\.com/llvm`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeText(tc.in)
			if err := checkNoCrossRefs(got); err != nil {
				t.Fatalf("checkNoCrossRefs(%q): %v", got, err)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("got %q, want %q", got, w)
				}
			}
			for _, p := range tc.forbid {
				if m := regexp.MustCompile(p).FindString(got); m != "" {
					t.Errorf("got %q matched forbidden %q (%q)", got, p, m)
				}
			}
		})
	}
	ir := sanitizeCode("; https://github.com/llvm/llvm-project/issues/123 llvm/llvm-project#456\ndefine i32 @foo(i32 %x) {\n  ret i32 %x\n}")
	doc := "Header\n```llvm\n" + ir + "\n```\nFooter"
	if err := checkNoCrossRefs(doc); err != nil || !strings.Contains(doc, "define i32 @foo(i32 %x)") {
		t.Errorf("fenced IR failed: err=%v doc=%q", err, doc)
	}
	for _, bad := range []string{"https://github.com/llvm/llvm-project/issues/1", "llvm/llvm-project#123", "llvm/llvm-project@0123456789ab", "GH-1234", "Fix (#1234)", "ping @nikic", "```llvm\n@unclosed"} {
		if err := checkNoCrossRefs(bad); err == nil {
			t.Errorf("checkNoCrossRefs(%q) = nil, want error", bad)
		}
	}
}

func TestCleanIR(t *testing.T) {
	noisy := "; ModuleID = '/tmp/work/before.ll'\nsource_filename = \"/tmp/work/foo.c\"\ntarget datalayout = \"e-m:e-i64:64\"\ntarget triple = \"x86_64-unknown-linux-gnu\"\n\ndeclare void @dead() #0\n; Function Attrs: noinline\ndefine i32 @foo(i32 %a) #1 {\n  %s = private constant [8 x i8] c\"tag #1\\00\"\n  %r = add i32 %a, 1, !dbg !10\n  ret i32 %r\n}\n\nattributes #0 = { nounwind }\n!llvm.ident = !{!0}\n!0 = !{!\"clang\"}\n!10 = !DILocation(line: 1)\n"
	ir := cleanIR(noisy)
	for _, w := range []string{"target triple =", "define i32 @foo(i32 %a) #1 {", "%r = add i32 %a, 1", "attributes #0 ="} {
		if !strings.Contains(ir, w) {
			t.Errorf("cleanIR missing %q", w)
		}
	}
	for _, b := range []string{"ModuleID", "source_filename", "!llvm.", "!0 =", "!dbg"} {
		if strings.Contains(ir, b) {
			t.Errorf("cleanIR kept %q", b)
		}
	}
	diffIR := cleanIRForDiff(noisy)
	for _, w := range []string{"define i32 @foo(i32 %a) {", `c"tag #1\00"`, "%r = add i32 %a, 1"} {
		if !strings.Contains(diffIR, w) {
			t.Errorf("cleanIRForDiff missing %q", w)
		}
	}
	for _, b := range []string{"target triple", "declare ", "Function Attrs", "attributes #", ") #1 {"} {
		if strings.Contains(diffIR, b) {
			t.Errorf("cleanIRForDiff kept %q", b)
		}
	}
}

func TestIssueTitleAndBody(t *testing.T) {
	cases := []struct {
		incs []*incident
		want string
	}{
		{nil, "unknown miscompile"},
		{[]*incident{{}}, "unknown miscompile"},
		{[]*incident{{CulpritPass: "constraint-elimination", CulpritSHA: "07a94e61110e600d82ddabf1680de6f9728296c3", Affected: []affected{{Package: "checked-arith"}}}}, "[constraint-elimination] checked-arith miscompiled at 07a94e61110e"},
		{[]*incident{{CulpritPass: "loop-vectorize", CulpritSHA: "07a94e61110e600d", Affected: []affected{{Package: "zstd"}, {Package: "ffmpeg"}, {Package: "brotli"}, {Package: "dav1d"}}}}, "[loop-vectorize] brotli, dav1d, ffmpeg (+1 more) miscompiled at 07a94e61110e"},
		{[]*incident{{CulpritPass: "GVNPass", BadSHA: "aaaaaaaaaaaa0000", Affected: []affected{{Package: "lua"}}}}, "[GVNPass] lua miscompiled on aaaaaaaaaaaa"},
		{[]*incident{{CulpritPass: "`instcombine` (#241234) by @nikic", CulpritSHA: "07a94e61110e600d", Affected: []affected{{Package: "`zstd`\nGH-99"}}}}, "[instcombine by nikic] zstd miscompiled at 07a94e61110e"},
		{[]*incident{{ID: "inc-1"}}, "inc-1 miscompiled"},
	}
	for _, tc := range cases {
		got := formatGroupTitle(tc.incs)
		if got != tc.want || checkNoCrossRefs(got) != nil || strings.ContainsRune(got, '`') || strings.Contains(got, "[miscompile]") {
			t.Errorf("formatGroupTitle = %q, want %q", got, tc.want)
		}
	}
	long := formatGroupTitle([]*incident{{CulpritPass: strings.Repeat("loop-vectorize-", 20), CulpritSHA: "07a94e61110e600d", Affected: []affected{{Package: "zstd"}}}})
	if len([]rune(long)) != 240 || !strings.HasSuffix(long, "...") {
		t.Errorf("truncated title len=%d: %q", len([]rune(long)), long)
	}
}

func TestIssueSync(t *testing.T) {
	ctx := context.Background()
	if _, err := syncIssues(ctx, issueSyncCfg{Repo: "llvm/llvm-project", DryRun: true, Quiet: true}, nil); err == nil {
		t.Fatal("expected error targeting llvm/llvm-project")
	}

	var mu sync.Mutex
	nextNum, reqs := 1, 0
	issues := map[int]*ghIssue{}
	comments := map[int][]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		reqs++
		const prefix = "/repos/npmania/llvm-miscompile-canary/issues"
		if r.URL.Path == prefix && r.Method == http.MethodGet {
			out := []ghIssue{{Number: 999, State: "open", PullRequest: &struct{}{}}}
			for _, iss := range issues {
				if iss.State == "open" {
					out = append(out, *iss)
				}
			}
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		if r.URL.Path == prefix && r.Method == http.MethodPost {
			var p struct {
				Title, Body string
				Labels      []string
			}
			_ = json.NewDecoder(r.Body).Decode(&p)
			if err := checkNoCrossRefs(p.Title + "\n" + p.Body); err != nil {
				t.Errorf("unsanitized POST: %v", err)
			}
			n := nextNum
			nextNum++
			iss := &ghIssue{Number: n, HTMLURL: fmt.Sprintf("https://github.com/npmania/llvm-miscompile-canary/issues/%d", n), State: "open", Title: p.Title, Body: p.Body}
			for _, l := range p.Labels {
				iss.Labels = append(iss.Labels, struct{ Name string }{l})
			}
			issues[n] = iss
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(iss)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix+"/"), "/")
		n, err := strconv.Atoi(parts[0])
		iss := issues[n]
		if err != nil || iss == nil {
			http.NotFound(w, r)
			return
		}
		if len(parts) == 2 && parts[1] == "comments" {
			var p struct{ Body string }
			_ = json.NewDecoder(r.Body).Decode(&p)
			comments[n] = append(comments[n], p.Body)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":1}`))
			return
		}
		var p struct {
			Title, Body, State *string
			Labels             []string
		}
		_ = json.NewDecoder(r.Body).Decode(&p)
		if p.Title != nil {
			iss.Title = *p.Title
		}
		if p.Body != nil {
			iss.Body = *p.Body
		}
		if p.State != nil {
			iss.State = *p.State
		}
		if p.Labels != nil {
			iss.Labels = nil
			for _, l := range p.Labels {
				iss.Labels = append(iss.Labels, struct{ Name string }{l})
			}
		}
		_ = json.NewEncoder(w).Encode(iss)
	}))
	defer srv.Close()

	storeDir := t.TempDir()
	now := time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)
	inc1 := &incident{
		ID: "inc-zstd", Status: incidentOpen, Confidence: confConfirmed,
		GoodSHA: "1111111111111111111111111111111111111111", BadSHA: "0212d77fa269abcdef0123456789abcdef012345",
		CulpritSHA: "0212d77fa269abcdef0123456789abcdef012345", CulpritSubject: "[InstCombine] Fold (#241234) by @nikic",
		CulpritPass: "InstCombinePass", CulpritPassIndex: 42, CulpritFunc: "ZSTD_compress", CulpritTU: "zstd.c",
		ASanUBSanClean: true, ConservativeFlagIndependent: true, AliveTVStatus: "unavailable",
		LLUBIStatus: "mismatch", LLUBIOutput: "before_exit=11 after_exit=2",
		ReducedIR: "define i32 @ZSTD_compress(i32 %x) {\n  ret i32 %x\n}",
		PassDiff:  "--- before.ll\n+++ after.ll\n@@ -1 +1 @@\n-  ret i32 %x\n+  ret i32 0",
		BundleURL: "https://github.com/npmania/llvm-miscompile-canary/releases/download/reproducers/reproducer-inc-zstd.tar.zst",
		Affected:  []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, TestID: "fuzzer"}},
		CreatedAt: now, UpdatedAt: now,
	}
	inc2 := &incident{
		ID: "inc-sqlite", Status: incidentOpen, Confidence: confNeedsReview,
		GoodSHA: inc1.GoodSHA, BadSHA: inc1.BadSHA, CulpritSHA: inc1.CulpritSHA, CulpritPass: "InstCombinePass",
		ASanUBSanClean: true, Affected: []affected{{Package: "sqlite", Platform: platDarwinARM, Profile: profReleaseLTO, TestID: "smoke"}},
		CreatedAt: now.Add(time.Minute), UpdatedAt: now.Add(time.Minute),
	}
	for _, inc := range []*incident{inc1, inc2} {
		if _, err := saveIncident(storeDir, inc); err != nil {
			t.Fatal(err)
		}
	}

	var dry bytes.Buffer
	if _, err := syncIssues(ctx, issueSyncCfg{DryRun: true, Out: &dry}, []*incident{inc1}); err != nil || !strings.Contains(dry.String(), "Title: [InstCombinePass] zstd miscompiled at 0212d77fa269\n") || strings.Count(dry.String(), "/incidents/inc-zstd/") != 1 {
		t.Fatalf("dry-run err=%v out=%s", err, dry.String())
	}

	cfg := issueSyncCfg{Repo: defaultRepo, Token: "tok", APIBase: srv.URL, StoreDir: storeDir}
	acts, err := syncIssues(ctx, cfg, []*incident{inc1, inc2})
	if err != nil || len(acts) != 1 || acts[0].Kind != "create" || inc1.IssueNumber == 0 || inc1.IssueNumber != inc2.IssueNumber {
		t.Fatalf("create sync acts=%+v err=%v", acts, err)
	}
	iss := issues[inc1.IssueNumber]
	if iss.Title != "[InstCombinePass] sqlite, zstd miscompiled at 0212d77fa269" {
		t.Errorf("title = %q", iss.Title)
	}
	for _, want := range []string{"| | |\n| --- | --- |\n", "`11` (before) -> `2` (after)", "`opt -passes=InstCombinePass -S`:", "<!-- lmc-dedup-key: culprit:0212d77fa269 -->"} {
		if !strings.Contains(iss.Body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if strings.Count(iss.Body, "/incidents/inc-zstd/") != 1 || strings.Count(iss.Body, "/incidents/inc-sqlite/") != 1 {
		t.Errorf("duplicate or missing incident artifact links:\n%s", iss.Body)
	}
	if strings.Contains(iss.Body, "alive-tv") {
		t.Errorf("unavailable alive-tv should be omitted")
	}

	before := reqs
	if a, err := syncIssues(ctx, cfg, []*incident{inc1, inc2}); err != nil || len(a) != 1 || a[0].Kind != "noop" || reqs-before != 1 {
		t.Fatalf("noop sync a=%+v reqs=%d err=%v", a, reqs-before, err)
	}
	inc2.mergeAffected(affected{Package: "sqlite", Platform: platLinuxARM64, Profile: profReleaseLTO, TestID: "smoke"})
	if a, err := syncIssues(ctx, cfg, []*incident{inc1, inc2}); err != nil || len(a) != 1 || a[0].Kind != "update" {
		t.Fatalf("update sync a=%+v err=%v", a, err)
	}
	fixed := "fedcba9876543210fedcba9876543210fedcba98"
	inc1.Status, inc1.FixedSHA, inc2.Status, inc2.FixedSHA = incidentResolved, fixed, incidentResolved, fixed
	if a, err := syncIssues(ctx, cfg, []*incident{inc1, inc2}); err != nil || len(a) != 1 || a[0].Kind != "close" {
		t.Fatalf("close sync a=%+v err=%v", a, err)
	}
	if iss.State != "closed" || !slices.Equal(comments[inc1.IssueNumber], []string{"Fixed at `fedcba987654`."}) {
		t.Errorf("closed state=%q comments=%v", iss.State, comments[inc1.IssueNumber])
	}
}

func TestSiteGenerate(t *testing.T) {
	storeDir, outDir, corpusDir := t.TempDir(), t.TempDir(), t.TempDir()
	for _, r := range [][6]string{
		{"zstd", "Databases, Compression & Solvers", "facebook/zstd", "v1.5.6", "c", "fuzzer"},
		{"opus", "Codecs & DSP", "xiph/opus", "v1.5.2", "c", "test_opus_encode"},
	} {
		dir := filepath.Join(corpusDir, r[0])
		_ = os.MkdirAll(dir, 0o755)
		doc := fmt.Sprintf("name: %s\ncategory: %s\nrepo: %s\nversion: %s\nurl: https://example.com/%s.tar.gz\nsha256: %s\nlang: %s\ntimeout_min: 10\nsmoke_test: %s\nplatforms: [linux-x86_64]\ndescription: test\n",
			r[0], r[1], r[2], r[3], r[0], strings.Repeat("a", 64), r[4], r[5])
		if err := os.WriteFile(filepath.Join(dir, "recipe.yaml"), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t1 := time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)
	sw := &sweep{
		ID: formatSweepID(t1, "0212d77fa269abcdef"), LLVMCommit: "0212d77fa269abcdef0123456789abcdef012345",
		StartedAt: t1.Add(-10 * time.Minute), CompletedAt: t1,
		Results: []pkgResult{
			{Package: "zstd", Version: "v1.5.6", Platform: platLinuxX86, Profile: profDistroO2, Status: statusTestFail, IncidentID: "inc-open-1", DurationSec: 12},
			{Package: "zstd", Version: "v1.5.6", Platform: platLinuxX86, Profile: profReleaseLTO, Status: statusPass, DurationSec: 18.1},
			{Package: "opus", Version: "v1.5.2", Platform: platDarwinARM, Profile: profDistroO2, Status: statusBuildFail},
		},
	}
	openInc := &incident{
		ID: "inc-open-1", Status: incidentOpen, Confidence: confConfirmed,
		GoodSHA: "111111111111abcdef", BadSHA: sw.LLVMCommit, CulpritSHA: sw.LLVMCommit,
		CulpritSubject: "[InstCombine] Bug (#241234) by @author", CulpritTU: "zstd_lazy.c",
		CulpritPass: "InstCombinePass", CulpritPassIndex: 77, CulpritFunc: "ZSTD_compressBlock",
		ASanUBSanClean: true, ConservativeFlagIndependent: true,
		AliveTVStatus: "miscompile", LLUBIStatus: "mismatch", LLUBIOutput: "before_exit=11 after_exit=2",
		ReducedIR:   "; ModuleID = 'x'\ndefine i32 @ZSTD_compressBlock(i32 %a) {\n  ret i32 0\n}\n!0 = !{}",
		PassDiff:    "--- before.ll\n+++ after.ll\n@@ -1 +1 @@\n-  ret i32 %a\n+  ret i32 0",
		IssueNumber: 12, IssueURL: "https://github.com/npmania/llvm-miscompile-canary/issues/12",
		Affected:  []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, TestID: "fuzzer"}},
		CreatedAt: t1, UpdatedAt: t1,
	}
	resInc := &incident{
		ID: "opus-cccc1111", Status: incidentResolved, Confidence: confNeedsReview,
		GoodSHA: "aaaa11112222", BadSHA: "bbbb11112222", CulpritSHA: "bbbb11112222", FixedSHA: "cccc11112222",
		CulpritPass: "LoopVectorizePass", ASanUBSanClean: true,
		Affected:  []affected{{Package: "opus", Platform: platLinuxARM64, Profile: profReleaseLTO, TestID: "test_opus_encode"}},
		CreatedAt: t1.Add(-time.Hour), UpdatedAt: t1,
	}
	if _, err := saveSweep(storeDir, sw); err != nil {
		t.Fatal(err)
	}
	for _, inc := range []*incident{openInc, resInc} {
		if _, err := saveIncident(storeDir, inc); err != nil {
			t.Fatal(err)
		}
	}
	st := &state{}
	recordSweep(st, *sw, []*incident{openInc, resInc})
	if err := saveState(storeDir, st); err != nil {
		t.Fatal(err)
	}

	if err := generateSite(storeDir, outDir, corpusDir); err != nil {
		t.Fatalf("generateSite: %v", err)
	}
	read := func(rel string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(outDir, rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if read("CNAME") != siteDomain+"\n" || !fileExists(filepath.Join(outDir, ".nojekyll")) || !fileExists(filepath.Join(outDir, "style.css")) {
		t.Errorf("missing CNAME, .nojekyll, or style.css")
	}
	idx := read("index.html")
	for _, w := range []string{"trunk <code>0212d77fa269</code>", "<h2>Open</h2>", "<h2>Corpus</h2>", "<h2>Resolved</h2>", `<a class="fail" href="incidents/inc-open-1/index.html">fail</a>`, "18s", "err"} {
		if !strings.Contains(idx, w) {
			t.Errorf("index.html missing %q", w)
		}
	}
	if err := checkNoCrossRefs(idx); err != nil {
		t.Errorf("index.html cross-ref: %v", err)
	}
	incPage := html.UnescapeString(read(filepath.Join("incidents", "inc-open-1", "index.html")))
	for _, w := range []string{"<h1>zstd: InstCombinePass in ZSTD_compressBlock</h1>", "-opt-bisect-limit=77", "<code>11</code> (before) -> <code>2</code> (after)", "opt -passes=InstCombinePass -S", "define i32 @ZSTD_compressBlock(i32 %a) {"} {
		if !strings.Contains(incPage, w) {
			t.Errorf("incident page missing %q", w)
		}
	}
	if strings.Contains(incPage, "ModuleID") || !strings.Contains(read(filepath.Join("incidents", "opus-cccc1111", "index.html")), "resolved at <code>cccc11112222</code>") {
		t.Errorf("incident page check failed")
	}
	corp := html.UnescapeString(read(filepath.Join("corpus", "index.html")))
	for _, w := range []string{"<th>Package</th>", "<th>Version</th>", "<th>Lang</th>", "<th>Domain</th>", "<th>Smoke</th>", "<th>Upstream</th>", "Databases, Compression & Solvers", "Codecs & DSP", "facebook/zstd"} {
		if !strings.Contains(corp, w) {
			t.Errorf("corpus page missing %q", w)
		}
	}
	if strings.Contains(strings.ToLower(corp), "focus") {
		t.Errorf("corpus page has Focus column")
	}

	reHref := regexp.MustCompile(`href="([^"]+)"`)
	for _, rel := range []string{"index.html", filepath.Join("corpus", "index.html"), filepath.Join("incidents", "inc-open-1", "index.html")} {
		p := filepath.Join(outDir, rel)
		for _, m := range reHref.FindAllStringSubmatch(read(rel), -1) {
			if strings.HasPrefix(m[1], "http://") || strings.HasPrefix(m[1], "https://") || strings.HasPrefix(m[1], "#") {
				continue
			}
			if tgt := filepath.Clean(filepath.Join(filepath.Dir(p), m[1])); !isWithinDir(outDir, tgt) || !fileExists(tgt) {
				t.Errorf("%s broken link %q", rel, m[1])
			}
		}
	}

	emptyOut := t.TempDir()
	if err := generateSite(t.TempDir(), emptyOut, "corpus"); err != nil {
		t.Fatalf("empty store with real corpus: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(emptyOut, "index.html")); strings.Contains(string(b), "<h2>Open</h2>") || strings.Contains(string(b), "<h2>Resolved</h2>") {
		t.Errorf("empty store should omit Open and Resolved")
	}
	if b, _ := os.ReadFile(filepath.Join(emptyOut, "corpus", "index.html")); strings.Count(string(b), "<tr>") != 35 || checkNoCrossRefs(string(b)) != nil {
		t.Errorf("real corpus page row count = %d (want 35)", strings.Count(string(b), "<tr>"))
	}
}

func TestWorkflowsAndInitScript(t *testing.T) {
	checks := map[string][]string{
		"ci.yml":        {"go build -o lmc .", "validate-corpus -corpus corpus -require 34"},
		"toolchain.yml": {"'53 3,9,15,21 * * *'", "fail-fast: false", "--target master", "| zstd ", "GH_REPO: ${{ github.repository }}"},
		"sweep.yml":     {"corpus-matrix -corpus corpus", "fail-fast: false", "zstd -dc", "| tar -xf -", "GH_REPO: ${{ github.repository }}"},
		"triage.yml":    {"./lmc alive-check", "--target master", "LLVM_DIR=", "GH_REPO: ${{ github.repository }}"},
	}
	for name, wants := range checks {
		raw, err := os.ReadFile(filepath.Join(".github", "workflows", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(raw, &doc); err != nil || doc["jobs"] == nil {
			t.Fatalf("invalid YAML in %s: %v", name, err)
		}
		s := string(raw)
		if strings.Contains(s, "./cmd/lmc") || strings.Contains(s, "miscompile proven by alive-tv") {
			t.Errorf("%s contains stale command or status", name)
		}
		for _, w := range wants {
			if !strings.Contains(s, w) {
				t.Errorf("%s missing %q", name, w)
			}
		}
	}

	repoDir := t.TempDir()
	runGit := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", repoDir}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	runGit("init", "-b", "master")
	runGit("config", "user.name", "Test")
	runGit("config", "user.email", "test@example.com")
	scriptDst := filepath.Join(repoDir, "scripts", "init-branches.sh")
	if err := copyFile(filepath.Join("scripts", "init-branches.sh"), scriptDst, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(scriptDst).CombinedOutput(); err != nil {
		t.Fatalf("init-branches.sh: %v\n%s", err, out)
	}
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "state.json"), []byte(runGit("show", "data:state.json")), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(dataDir); err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if err := generateSite(dataDir, t.TempDir(), t.TempDir()); err != nil {
		t.Fatalf("generateSite: %v", err)
	}
}
