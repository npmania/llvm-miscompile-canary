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
	"unicode/utf8"

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
		{"mixedCaseGH", "See https://GitHub.com/LLVM/llvm-project/Commit/0212d77fa269abcdef and https://GitHub.com/llvm/circt/pull/1 and https://GitHub.com/other/repo/Issues/1 and [link](https://GITHUB.COM/other/repo/Pull/9)", []string{"`0212d77fa269`", "link"}, []string{`(?i)github\.com/llvm`, `(?i)github\.com/other`}},
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
	ir := sanitizeCode("; https://GitHub.com/LLVM/llvm-project/issues/123 https://GitHub.com/other/repo/issues/9 llvm/llvm-project#456\ndefine i32 @foo(i32 %x) {\n  ret i32 %x\n}")
	doc := "Header\n```llvm\n" + ir + "\n```\nFooter"
	if err := checkNoCrossRefs(doc); err != nil || !strings.Contains(doc, "define i32 @foo(i32 %x)") || strings.Contains(strings.ToLower(ir), "github.com/") {
		t.Errorf("fenced IR failed: err=%v doc=%q", err, doc)
	}
	for _, bad := range []string{"https://github.com/llvm/llvm-project/issues/1", "llvm/llvm-project#123", "llvm/llvm-project@0123456789ab", "GH-1234", "Fix (#1234)", "ping @nikic", "```llvm\n@unclosed"} {
		if err := checkNoCrossRefs(bad); err == nil {
			t.Errorf("checkNoCrossRefs(%q) = nil, want error", bad)
		}
	}

	angleInc := &incident{
		ID: "inc-angle", Status: incidentOpen, BadSHA: "0212d77fa269abcdef0123456789abcdef012345",
		CulpritPass: "InvalidateAnalysisPass<llvm::AAManager>",
		Affected:    []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, TestID: "suite@case (#12) GH-99"}},
	}
	dk := dedupKey(angleInc)
	if strings.ContainsAny(dk, "<>@ \t\n") || keyToken(dk) != dk {
		t.Fatalf("unsafe or non-idempotent dedupKey %q", dk)
	}
	angleBody := formatGroupBody([]*incident{angleInc}, dk, defaultSiteURL)
	if err := checkNoCrossRefs(angleBody); err != nil {
		t.Fatalf("angleBody cross-ref: %v", err)
	}
	if m := reDedupMarker.FindStringSubmatch(angleBody); len(m) < 2 || m[1] != dk {
		t.Fatalf("dedup marker mismatch: got %v want %q", m, dk)
	}

	var bigAffected []affected
	for i := range 320 {
		bigAffected = append(bigAffected, affected{
			Package: fmt.Sprintf("pkg-%03d", i), Platform: platLinuxX86, Profile: profDistroO2,
			TestID: fmt.Sprintf("long_test_name_for_truncation_%03d_%s", i, strings.Repeat("x", 40)),
		})
	}
	bigInc := &incident{
		ID: "inc-big", Status: incidentOpen, BadSHA: "0212d77fa269abcdef0123456789abcdef012345",
		CulpritSHA: "0212d77fa269abcdef0123456789abcdef012345", CulpritPass: "InstCombinePass",
		ReducedIR: strings.Repeat("define i32 @sym_ir(i32 %x) {\n  ret i32 %x\n}\n", 300),
		PassDiff:  strings.Repeat("+  call void @sym_diff()\n-  call void @sym_old()\n", 350),
		Affected:  bigAffected,
	}
	bigBody := formatGroupBody([]*incident{bigInc}, "", defaultSiteURL)
	if !strings.Contains(bigBody, "...(truncated)") || !utf8.ValidString(bigBody) {
		t.Fatalf("expected valid truncated body, len=%d", len(bigBody))
	}
	if err := checkNoCrossRefs(bigBody); err != nil {
		t.Fatalf("truncated body failed checkNoCrossRefs: %v", err)
	}
	if m := reDedupMarker.FindStringSubmatch(bigBody); len(m) < 2 || m[1] != dedupKey(bigInc) {
		t.Fatalf("truncated body missing dedup marker: %v", m)
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
			stateFilter := r.URL.Query().Get("state")
			if stateFilter != "all" {
				t.Errorf("expected state=all, got %q", stateFilter)
			}
			out := []ghIssue{{Number: 999, State: "open", PullRequest: &struct{}{}}}
			for _, iss := range issues {
				if stateFilter == "all" || iss.State == stateFilter {
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
	for _, want := range []string{"| | |\n| --- | --- |\n", "`11` (before) -> `2` (after)", "`opt -O2 -S`:", "<!-- lmc-dedup-key: culprit:0212d77fa269 -->"} {
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
	iss.Labels = append(iss.Labels, struct{ Name string }{"reported-upstream"})
	before = reqs
	if a, err := syncIssues(ctx, cfg, []*incident{inc1, inc2}); err != nil || len(a) != 1 || a[0].Kind != "noop" || reqs-before != 1 {
		t.Fatalf("manual label noop a=%+v reqs=%d err=%v", a, reqs-before, err)
	}
	inc2.mergeAffected(affected{Package: "sqlite", Platform: platLinuxARM64, Profile: profReleaseLTO, TestID: "smoke"})
	if a, err := syncIssues(ctx, cfg, []*incident{inc1, inc2}); err != nil || len(a) != 1 || a[0].Kind != "update" {
		t.Fatalf("update sync a=%+v err=%v", a, err)
	}
	if !slices.ContainsFunc(iss.Labels, func(l struct{ Name string }) bool { return l.Name == "reported-upstream" }) {
		t.Errorf("manual label wiped on update: %+v", iss.Labels)
	}
	fixed := "fedcba9876543210fedcba9876543210fedcba98"
	inc1.Status, inc1.FixedSHA, inc2.Status, inc2.FixedSHA = incidentResolved, fixed, incidentResolved, fixed
	if a, err := syncIssues(ctx, cfg, []*incident{inc1, inc2}); err != nil || len(a) != 1 || a[0].Kind != "close" {
		t.Fatalf("close sync a=%+v err=%v", a, err)
	}
	if iss.State != "closed" || !slices.Equal(comments[inc1.IssueNumber], []string{"Fixed at `fedcba987654`."}) {
		t.Errorf("closed state=%q comments=%v", iss.State, comments[inc1.IssueNumber])
	}

	inc3 := &incident{
		ID: "inc-manual-close", Status: incidentOpen, Confidence: confNeedsReview,
		GoodSHA: inc1.GoodSHA, BadSHA: inc1.BadSHA,
		CulpritSHA: "3333333333333333333333333333333333333333", CulpritPass: "GVNPass",
		Affected:  []affected{{Package: "lua", Platform: platLinuxX86, Profile: profDistroO2, TestID: "smoke"}},
		CreatedAt: now, UpdatedAt: now,
	}
	if a, err := syncIssues(ctx, cfg, []*incident{inc3}); err != nil || len(a) != 1 || a[0].Kind != "create" {
		t.Fatalf("create inc3 a=%+v err=%v", a, err)
	}
	iss3 := issues[inc3.IssueNumber]
	iss3.Labels = append(iss3.Labels, struct{ Name string }{"wontfix"})
	inc3.Confidence = confConfirmed
	if a, err := syncIssues(ctx, cfg, []*incident{inc3}); err != nil || len(a) != 1 || a[0].Kind != "update" {
		t.Fatalf("upgrade inc3 a=%+v err=%v", a, err)
	}
	var gotLabels []string
	for _, l := range iss3.Labels {
		gotLabels = append(gotLabels, l.Name)
	}
	if !slices.Contains(gotLabels, "wontfix") || !slices.Contains(gotLabels, confConfirmed) || slices.Contains(gotLabels, confNeedsReview) {
		t.Errorf("unexpected labels after confidence upgrade: %v", gotLabels)
	}
	iss3.State = "closed"
	countBefore := len(issues)
	if a, err := syncIssues(ctx, cfg, []*incident{inc3}); err != nil || len(a) != 1 || a[0].Kind != "noop" || len(issues) != countBefore {
		t.Fatalf("manual close reopened/duplicated: a=%+v count=%d->%d err=%v", a, countBefore, len(issues), err)
	}

	inc4 := &incident{
		ID: "inc-open-wins", Status: incidentOpen, Confidence: confConfirmed,
		GoodSHA: inc1.GoodSHA, BadSHA: inc1.BadSHA,
		CulpritSHA: "4444444444444444444444444444444444444444", CulpritPass: "LICMPass",
		Affected:  []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
		CreatedAt: now, UpdatedAt: now,
	}
	dk4 := dedupKey(inc4)
	body4 := formatGroupBody([]*incident{inc4}, dk4, defaultSiteURL)
	issues[90] = &ghIssue{Number: 90, HTMLURL: "https://github.com/npmania/llvm-miscompile-canary/issues/90", State: "closed", Title: "old", Body: body4}
	issues[91] = &ghIssue{Number: 91, HTMLURL: "https://github.com/npmania/llvm-miscompile-canary/issues/91", State: "open", Title: formatGroupTitle([]*incident{inc4}), Body: body4, Labels: []struct{ Name string }{{confConfirmed}, {platLinuxX86}}}
	if a, err := syncIssues(ctx, cfg, []*incident{inc4}); err != nil || len(a) != 1 || a[0].Kind != "noop" || a[0].IssueNumber != 91 {
		t.Fatalf("expected open issue #91 to win over closed #90: a=%+v err=%v", a, err)
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
	for _, w := range []string{"trunk <code>0212d77fa269</code>", "<h2>Open</h2>", "<h2>Corpus</h2>", "<h2>Resolved</h2>", `<a class="fail" href="/incidents/inc-open-1/">fail</a>`, `<a href="/">status</a>`, `<a href="/corpus/">corpus</a>`, `<link rel="stylesheet" href="/style.css">`, "18s", "err"} {
		if !strings.Contains(idx, w) {
			t.Errorf("index.html missing %q", w)
		}
	}
	if err := checkNoCrossRefs(idx); err != nil {
		t.Errorf("index.html cross-ref: %v", err)
	}
	incPage := html.UnescapeString(read(filepath.Join("incidents", "inc-open-1", "index.html")))
	for _, w := range []string{"<h1>zstd: InstCombinePass in ZSTD_compressBlock</h1>", "-opt-bisect-limit=77", "<code>11</code> (before) -> <code>2</code> (after)", "opt -O2 -S", "define i32 @ZSTD_compressBlock(i32 %a) {"} {
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
		body := read(rel)
		for _, m := range reHref.FindAllStringSubmatch(body, -1) {
			if strings.HasPrefix(m[1], "http://") || strings.HasPrefix(m[1], "https://") || strings.HasPrefix(m[1], "#") {
				continue
			}
			if strings.Contains(m[1], "index.html") {
				t.Errorf("%s contains non-canonical index.html link %q", rel, m[1])
			}
			hrefPath, _, _ := strings.Cut(m[1], "#")
			var tgt string
			if strings.HasPrefix(hrefPath, "/") {
				tgt = filepath.Clean(filepath.Join(outDir, strings.TrimPrefix(hrefPath, "/")))
			} else {
				tgt = filepath.Clean(filepath.Join(filepath.Dir(p), hrefPath))
			}
			if strings.HasSuffix(hrefPath, "/") {
				tgt = filepath.Join(tgt, "index.html")
			}
			if !isWithinDir(outDir, tgt) || !fileExists(tgt) {
				t.Errorf("%s broken link %q -> %s", rel, m[1], tgt)
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
	if b, _ := os.ReadFile(filepath.Join(emptyOut, "corpus", "index.html")); strings.Count(string(b), "<tr>") != 43 || checkNoCrossRefs(string(b)) != nil {
		t.Errorf("real corpus page row count = %d (want 43)", strings.Count(string(b), "<tr>"))
	}

	escStore, escOut := t.TempDir(), t.TempDir()
	escInc := &incident{
		ID: "inc-esc", Status: incidentOpen, Confidence: confConfirmed,
		GoodSHA: "111111111111", BadSHA: "222222222222", CulpritSHA: "222222222222",
		CulpritPass: "InvalidateAnalysisPass<llvm::AAManager>",
		CulpritFunc: "ns::fn<int>(const T&)",
		CulpritTU:   "a&b.cc",
		BundleURL:   "javascript:alert(1)",
		IssueNumber: 9, IssueURL: "javascript:alert(2)",
		Affected:  []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
		CreatedAt: t1, UpdatedAt: t1,
	}
	if _, err := saveIncident(escStore, escInc); err != nil {
		t.Fatal(err)
	}
	if err := generateSite(escStore, escOut, corpusDir); err != nil {
		t.Fatalf("generateSite esc: %v", err)
	}
	rawEsc, err := os.ReadFile(filepath.Join(escOut, "incidents", "inc-esc", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	rawEscStr := string(rawEsc)
	for _, want := range []string{
		"<code>InvalidateAnalysisPass&lt;llvm::AAManager&gt;</code>",
		"<code>ns::fn&lt;int&gt;(const T&amp;)</code>",
		"<code>a&amp;b.cc</code>",
	} {
		if !strings.Contains(rawEscStr, want) {
			t.Errorf("incident page missing single-escaped %q", want)
		}
	}
	if strings.Contains(rawEscStr, "&amp;lt;") || strings.Contains(rawEscStr, "&amp;amp;") || strings.Contains(strings.ToLower(rawEscStr), `href="javascript:`) {
		t.Errorf("incident page double-escaped or allowed javascript href:\n%s", rawEscStr)
	}
	rawIdx, err := os.ReadFile(filepath.Join(escOut, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(rawIdx)), "javascript:") {
		t.Errorf("index page allowed javascript URL:\n%s", string(rawIdx))
	}
}

func TestAggregateAndStoreFixes(t *testing.T) {
	st := &state{LastGoodSHA: "good111111111111111111111111111111111111"}
	openInc := &incident{
		ID: "open-1", Status: incidentOpen,
		GoodSHA: "aaaa111111111111111111111111111111111111", BadSHA: "bbbb111111111111111111111111111111111111",
		Affected: []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	resolvedInc := &incident{
		ID: "res-1", Status: incidentResolved,
		GoodSHA: "cccc111111111111111111111111111111111111", BadSHA: "dddd111111111111111111111111111111111111",
		FixedSHA: "eeee111111111111111111111111111111111111", IssueNumber: 7,
		Affected: []affected{{Package: "opus", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	recordSweep(st, sweep{
		LLVMCommit: "ice0000000000000000000000000000000000000",
		Results: []pkgResult{
			{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, Status: statusBuildFail},
		},
	}, []*incident{openInc, resolvedInc})
	if st.LastGoodSHA != "good111111111111111111111111111111111111" {
		t.Fatalf("build_fail overwrote LastGoodSHA: %q", st.LastGoodSHA)
	}
	if !slices.Equal(st.RetainedToolchains, []string{openInc.GoodSHA, openInc.BadSHA}) {
		t.Fatalf("RetainedToolchains = %v, want only open incident SHAs", st.RetainedToolchains)
	}

	storeDir := t.TempDir()
	t0 := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	resOrig := &incident{
		ID: "zstd-12345678", Status: incidentResolved, FixedSHA: "ffff111111111111111111111111111111111111",
		IssueNumber: 42, ResolvedAt: &t0,
		GoodSHA: openInc.GoodSHA, BadSHA: openInc.BadSHA, CulpritSHA: "1234567890ab1234567890ab1234567890ab1234",
		Affected: []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	if _, err := saveIncident(storeDir, resOrig); err != nil {
		t.Fatal(err)
	}
	reopen := &incident{
		ID: "zstd-12345678", Status: incidentOpen,
		GoodSHA: openInc.GoodSHA, BadSHA: openInc.BadSHA, CulpritSHA: "1234567890ab1234567890ab1234567890ab1234",
		Affected: []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	saved, err := mergeIncident(storeDir, reopen)
	if err != nil || saved.ID != "zstd-12345678-2" {
		t.Fatalf("resolved collision: saved=%+v err=%v", saved, err)
	}
	var checkOrig incident
	if err := readJSON(filepath.Join(storeDir, "incidents", "zstd-12345678.json"), &checkOrig); err != nil {
		t.Fatal(err)
	}
	if checkOrig.Status != incidentResolved || checkOrig.FixedSHA != resOrig.FixedSHA || checkOrig.IssueNumber != 42 {
		t.Fatalf("resolved incident overwritten: %+v", checkOrig)
	}

	passA := &incident{
		ID: "lua-aaaa1111", Status: incidentOpen, BadSHA: openInc.BadSHA, CulpritPass: "InstCombinePass",
		Affected: []affected{{Package: "lua", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	passB := &incident{
		ID: "lua-aaaa1111", Status: incidentOpen, BadSHA: openInc.BadSHA, CulpritPass: "GVNPass",
		Affected: []affected{{Package: "lua", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	if _, err := mergeIncident(storeDir, passA); err != nil {
		t.Fatal(err)
	}
	savedB, err := mergeIncident(storeDir, passB)
	if err != nil || savedB.ID != "lua-aaaa1111-2" {
		t.Fatalf("distinct passes merged: savedB=%+v err=%v", savedB, err)
	}

	aggStore := t.TempDir()
	if _, err := saveIncident(aggStore, openInc); err != nil {
		t.Fatal(err)
	}
	fragsDir := t.TempDir()
	results := []pkgResult{
		{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, Status: statusTestFail, FailedTests: []string{"t1", "t2"}},
	}
	for i := range 80 {
		results = append(results, pkgResult{
			Package: fmt.Sprintf("pkg-%02d", i), Platform: platLinuxX86, Profile: profDistroO2,
			Status: statusTestFail, FailedTests: []string{"first", "second", "third"},
		})
	}
	if err := writeResultFragment(filepath.Join(fragsDir, "all.json"), results); err != nil {
		t.Fatal(err)
	}
	regOut := filepath.Join(t.TempDir(), "regressions.json")
	var out, errBuf bytes.Buffer
	if code := runCLI(context.Background(), []string{
		"lmc", "aggregate", "-frags", fragsDir, "-store", aggStore,
		"-sha", "9999999999999999999999999999999999999999", "-reg-out", regOut,
	}, &out, &errBuf); code != 0 {
		t.Fatalf("aggregate failed (%d): %s", code, errBuf.String())
	}
	var regs []regressionTarget
	if err := readJSON(regOut, &regs); err != nil {
		t.Fatal(err)
	}
	if len(regs) != 8 {
		t.Fatalf("len(regs) = %d, want 8", len(regs))
	}
	for _, r := range regs {
		if r.Package == "zstd" {
			t.Errorf("open incident target should have been skipped: %+v", r)
		}
		if len(r.FailedTests) != 1 || r.FailedTests[0] != "first" {
			t.Errorf("FailedTests not trimmed to 1: %+v", r)
		}
	}

	var hugeRegs []regressionTarget
	for i := range 64 {
		hugeRegs = append(hugeRegs, regressionTarget{
			Package: fmt.Sprintf("p%02d", i), Platform: platLinuxX86, Profile: profDistroO2,
			GoodSHA: strings.Repeat("a", 40), BadSHA: strings.Repeat("b", 40),
			FailedTests: []string{strings.Repeat("x", 2000)},
		})
	}
	capped := capRegressions(hugeRegs, 64, 60000)
	raw, err := json.Marshal(capped)
	if err != nil || len(raw) > 60000 || len(capped) == 0 || len(capped) >= 64 {
		t.Fatalf("capRegressions len=%d bytes=%d err=%v", len(capped), len(raw), err)
	}

	rvOnly := &incident{
		ID: "rv-1", Status: incidentOpen, BadSHA: openInc.BadSHA, CulpritSHA: "5555555555555555555555555555555555555555",
		ASanUBSanClean: false,
		Affected:       []affected{{Package: "zstd", Platform: platLinuxRISCV64, Profile: profDistroO2, TestID: "t1"}},
	}
	x86Clean := &incident{
		ID: "x86-1", Status: incidentOpen, BadSHA: openInc.BadSHA, CulpritSHA: rvOnly.CulpritSHA,
		ASanUBSanClean: true,
		Affected:       []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	x86Fail := &incident{
		ID: "x86-2", Status: incidentOpen, BadSHA: openInc.BadSHA, CulpritSHA: rvOnly.CulpritSHA,
		ASanUBSanClean: false,
		Affected:       []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	sanRow := func(incs []*incident, htmlMode bool) string {
		for _, r := range incidentMetaRows(incs, htmlMode, defaultSiteURL) {
			if r[0] == "Sanitizers" {
				return r[1]
			}
		}
		return ""
	}
	if got := sanRow([]*incident{rvOnly}, false); got != "`ubsan` clean (asan disabled)" {
		t.Errorf("riscv64 md Sanitizers = %q", got)
	}
	if got := sanRow([]*incident{rvOnly}, true); got != "<code>ubsan</code> clean (asan disabled)" {
		t.Errorf("riscv64 html Sanitizers = %q", got)
	}
	if got := sanRow([]*incident{rvOnly, x86Clean}, false); got != "`asan,ubsan` clean" {
		t.Errorf("mixed riscv64+x86 clean Sanitizers = %q", got)
	}
	if got := sanRow([]*incident{rvOnly, x86Fail}, false); got != "`asan,ubsan` failed" {
		t.Errorf("mixed riscv64+x86 fail Sanitizers = %q", got)
	}

	sanStore := t.TempDir()
	if _, err := mergeIncident(sanStore, rvOnly); err != nil {
		t.Fatal(err)
	}
	mergedSan, err := mergeIncident(sanStore, x86Clean)
	if err != nil || !mergedSan.ASanUBSanClean || len(mergedSan.Affected) != 2 {
		t.Fatalf("merge riscv64 then x86 did not upgrade ASanUBSanClean: %+v err=%v", mergedSan, err)
	}
}

func TestWorkflowsAndInitScript(t *testing.T) {
	checks := map[string][]string{
		"ci.yml":        {"go build -o lmc .", "validate-corpus -corpus corpus -require 42"},
		"toolchain.yml": {"workflow_dispatch:", "fail-fast: false", "--target master", "| zstd ", "GH_REPO: ${{ github.repository }}", "git ls-remote --exit-code --heads", `select(.status == "open")`, "grep -Fxq", "--limit 500", "CCACHE_BASEDIR: ${{ github.workspace }}"},
		"sweep.yml":     {"corpus-matrix -corpus corpus -include -shards 12", "fail-fast: false", "zstd -dc", "| tar -xf -", "GH_REPO: ${{ github.repository }}", "if: always() && !cancelled()", "LLVM_SUBJ: ${{ steps.meta.outputs.subject }}", "./lmc site -store _data -out _site -corpus corpus", `case ",${PKGS}," in`, "contains(format(',{0},', matrix.packages), ',dav1d,')", "corpus-src-v2-${{ matrix.src_hash }}", "fragments/shard-${PLAT}-${SHARD}.json", "fragment-shard-${{ matrix.platform }}-${{ matrix.shard }}"},
		"triage.yml":    {"./lmc alive-check", "--target master", "BUILD_ALIVE2_LLVM=1", "GH_REPO: ${{ github.repository }}", "TEST_ID: ${{ matrix.test_id }}", "-print -quit", "Free runner disk space", "Fallback download raw triage artifacts", "group: miscompile-triage", "max-parallel: 4", "bad_sha12:", "ccache-toolchain-${{ matrix.tc_platform }}-${{ matrix.bad_sha12 }}", "reduced_before.ll", ".alive_tv_status"},
	}
	for name, wants := range checks {
		raw, err := os.ReadFile(filepath.Join(".github", "workflows", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var doc struct {
			Jobs map[string]struct {
				Steps []struct {
					Name string `yaml:"name"`
					Run  string `yaml:"run"`
				} `yaml:"steps"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil || len(doc.Jobs) == 0 {
			t.Fatalf("invalid YAML in %s: %v", name, err)
		}
		if name != "ci.yml" {
			for jn, j := range doc.Jobs {
				for _, st := range j.Steps {
					if strings.Contains(st.Run, "${{") {
						t.Errorf("%s job %s step %q interpolates ${{ in run", name, jn, st.Name)
					}
				}
			}
		}
		s := string(raw)
		if strings.Contains(s, "./cmd/lmc") || strings.Contains(s, "miscompile proven by alive-tv") {
			t.Errorf("%s contains stale command or status", name)
		}
		if name == "toolchain.yml" && strings.Contains(s, "schedule:") {
			t.Errorf("%s should not use GitHub schedule trigger", name)
		}
		if name == "sweep.yml" && regexp.MustCompile(`\bmatrix\.package\b`).MatchString(s) {
			t.Errorf("%s contains stale matrix.package reference", name)
		}
		if name == "triage.yml" {
			_, after, ok := strings.Cut(s, "key: ccache-bisect-")
			if !ok {
				t.Errorf("%s missing key: ccache-bisect-", name)
			} else {
				tcIdx := strings.Index(after, "ccache-toolchain-${{ matrix.tc_platform }}-${{ matrix.bad_sha12 }}")
				biIdx := strings.Index(after, "ccache-bisect-${{ matrix.platform }}-")
				if tcIdx < 0 || biIdx < 0 || tcIdx >= biIdx {
					t.Errorf("%s restore-keys order: tcIdx=%d biIdx=%d", name, tcIdx, biIdx)
				}
			}
		}
		for _, w := range wants {
			if !strings.Contains(s, w) {
				t.Errorf("%s missing %q", name, w)
			}
		}
	}

	cmakeRaw, err := os.ReadFile(filepath.Join("scripts", "toolchain.cmake"))
	if err != nil {
		t.Fatalf("read scripts/toolchain.cmake: %v", err)
	}
	cmakeStr := string(cmakeRaw)
	for _, w := range []string{
		`set(LLVM_ENABLE_ASSERTIONS ON CACHE BOOL "" FORCE)`,
		`set(LLVM_CCACHE_PARAMS "CCACHE_CPP2=yes CCACHE_NOHASHDIR=yes CCACHE_SLOPPINESS=pch_defines,time_macros" CACHE STRING "" FORCE)`,
	} {
		if !strings.Contains(cmakeStr, w) {
			t.Errorf("scripts/toolchain.cmake missing %q", w)
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

func newFakeGitHub(t *testing.T) (*httptest.Server, *sync.Mutex, map[int]*ghIssue, map[int][]string) {
	t.Helper()
	var mu sync.Mutex
	nextNum := 1
	issues := map[int]*ghIssue{}
	comments := map[int][]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		const prefix = "/repos/npmania/llvm-miscompile-canary/issues"
		if r.URL.Path == prefix && r.Method == http.MethodGet {
			var out []ghIssue
			for _, iss := range issues {
				out = append(out, *iss)
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
			iss := &ghIssue{
				Number:  n,
				HTMLURL: fmt.Sprintf("https://github.com/npmania/llvm-miscompile-canary/issues/%d", n),
				State:   "open",
				Title:   p.Title,
				Body:    p.Body,
			}
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
			if err := checkNoCrossRefs(p.Body); err != nil {
				t.Errorf("unsanitized comment: %v", err)
			}
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
	t.Cleanup(srv.Close)
	return srv, &mu, issues, comments
}

func TestBuildFailLifecycle(t *testing.T) {
	ctx := context.Background()
	srv, mu, issues, comments := newFakeGitHub(t)

	goodSHA1 := "1111111111111111111111111111111111111111"
	goodSHA2 := "2222222222222222222222222222222222222222"
	badSHA := "abcdef0123456789abcdef0123456789abcdef01"
	fixSHA := "fedcba9876543210fedcba9876543210fedcba98"

	storeDir := t.TempDir()
	st := &state{
		LastGoodSHA: goodSHA1,
		LastGoodByTarget: map[string]string{
			targetKey("zstd", platLinuxX86, profDistroO2):    goodSHA1,
			targetKey("zstd", platDarwinARM, profReleaseLTO): goodSHA2,
			targetKey("lua", platLinuxX86, profDistroO2):     goodSHA1,
		},
	}
	if err := saveState(storeDir, st); err != nil {
		t.Fatal(err)
	}

	advICE := "clang++: error: foo.cc:12:3: crash\n" +
		"PLEASE submit a bug report to https://github.com/llvm/llvm-project/issues/ and include backtrace\n" +
		"see llvm/llvm-project#12345 and llvm/llvm-project@0123456789abcdef0123456789abcdef01234567 and GH-999\n" +
		"cc @nikic fix (#555)\n" +
		"```\n@evil (#777)\n```"
	plainBuildErr := "lua.c:42:9: error: use of undeclared identifier 'x'\nsee https://github.com/llvm/llvm-project/pull/888"

	frags1 := t.TempDir()
	if err := writeResultFragment(filepath.Join(frags1, "sweep.json"), []pkgResult{
		{Package: "zstd", Version: "1.5.6", Platform: platLinuxX86, Profile: profDistroO2, Status: statusBuildFail, ErrorExcerpt: "zstd.c:1: error: syntax error"},
		{Package: "zstd", Version: "1.5.6", Platform: platDarwinARM, Profile: profReleaseLTO, Status: statusBuildFail, ErrorExcerpt: advICE},
		{Package: "lua", Version: "5.4.7", Platform: platLinuxX86, Profile: profDistroO2, Status: statusBuildFail, ErrorExcerpt: plainBuildErr},
		{Package: "never-passed", Version: "1.0", Platform: platLinuxX86, Profile: profDistroO2, Status: statusBuildFail, ErrorExcerpt: "LLVM ERROR: never passed before"},
	}); err != nil {
		t.Fatal(err)
	}

	regOut1 := filepath.Join(t.TempDir(), "regressions.json")
	var out, errBuf bytes.Buffer
	if code := runCLI(ctx, []string{
		"lmc", "aggregate", "-frags", frags1, "-store", storeDir, "-sha", badSHA, "-reg-out", regOut1,
	}, &out, &errBuf); code != 0 {
		t.Fatalf("aggregate failed (%d): %s", code, errBuf.String())
	}

	var regs []regressionTarget
	if err := readJSON(regOut1, &regs); err != nil {
		t.Fatal(err)
	}
	if len(regs) != 0 {
		t.Fatalf("build_fail leaked into regressions.json: %+v", regs)
	}

	incs, err := loadAllIncidents(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) != 2 {
		t.Fatalf("got %d incidents, want 2 (zstd and lua, not never-passed): %+v", len(incs), incs)
	}
	byPkg := map[string]*incident{}
	for _, inc := range incs {
		if !inc.isBuildFail() || inc.Status != incidentOpen {
			t.Fatalf("unexpected incident: %+v", inc)
		}
		pkgs := uniquePkgs([]*incident{inc})
		if len(pkgs) != 1 {
			t.Fatalf("expected 1 pkg per build_fail incident, got %v", pkgs)
		}
		byPkg[pkgs[0]] = inc
	}
	zstdInc, luaInc := byPkg["zstd"], byPkg["lua"]
	if zstdInc == nil || luaInc == nil {
		t.Fatalf("missing zstd or lua incident: %+v", byPkg)
	}
	if len(zstdInc.Affected) != 2 {
		t.Fatalf("zstd Affected = %+v, want 2 grouped targets", zstdInc.Affected)
	}
	if !isICEExcerpt(zstdInc.ErrorExcerpt) || isICEExcerpt(luaInc.ErrorExcerpt) {
		t.Fatalf("unexpected ICE classification: zstd=%q lua=%q", zstdInc.ErrorExcerpt, luaInc.ErrorExcerpt)
	}
	if strings.Contains(strings.ToLower(zstdInc.ErrorExcerpt), "github.com/llvm/") || strings.Contains(zstdInc.ErrorExcerpt, "GH-999") || strings.Contains(zstdInc.ErrorExcerpt, "llvm/llvm-project#12345") {
		t.Fatalf("unsanitized ErrorExcerpt stored: %q", zstdInc.ErrorExcerpt)
	}

	stAfter, err := loadState(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(stAfter.ActiveIncidentIDs) != 2 {
		t.Fatalf("ActiveIncidentIDs = %v, want 2", stAfter.ActiveIncidentIDs)
	}
	if !slices.Contains(stAfter.RetainedToolchains, badSHA) {
		t.Fatalf("RetainedToolchains missing badSHA: %v", stAfter.RetainedToolchains)
	}

	cfg := issueSyncCfg{Repo: defaultRepo, Token: "tok", APIBase: srv.URL, StoreDir: storeDir}
	acts, err := syncIssues(ctx, cfg, incs)
	if err != nil || len(acts) != 2 {
		t.Fatalf("syncIssues acts=%+v err=%v", acts, err)
	}
	mu.Lock()
	zstdIss := issues[zstdInc.IssueNumber]
	luaIss := issues[luaInc.IssueNumber]
	mu.Unlock()
	if zstdIss == nil || luaIss == nil {
		t.Fatalf("issues not created: zstd=%d lua=%d", zstdInc.IssueNumber, luaInc.IssueNumber)
	}
	if zstdIss.Title != "[ice] zstd compiler crash on abcdef012345" {
		t.Errorf("zstd title = %q", zstdIss.Title)
	}
	if luaIss.Title != "[build] lua failed to build on abcdef012345" {
		t.Errorf("lua title = %q", luaIss.Title)
	}
	labelNames := func(iss *ghIssue) []string {
		var ns []string
		for _, l := range iss.Labels {
			ns = append(ns, l.Name)
		}
		slices.Sort(ns)
		return ns
	}
	if got := labelNames(zstdIss); !slices.Equal(got, []string{labelBuildFail, labelCompilerICE, platDarwinARM, platLinuxX86}) {
		t.Errorf("zstd labels = %v", got)
	}
	if got := labelNames(luaIss); !slices.Equal(got, []string{labelBuildFail, platLinuxX86}) {
		t.Errorf("lua labels = %v", got)
	}
	for _, iss := range []*ghIssue{zstdIss, luaIss} {
		if err := checkNoCrossRefs(iss.Title + "\n" + iss.Body); err != nil {
			t.Errorf("issue #%d failed checkNoCrossRefs: %v\n%s", iss.Number, err, iss.Body)
		}
		for _, forbid := range []string{"| Sanitizers |", "| Conservative |", "alive-tv", "llubi"} {
			if strings.Contains(iss.Body, forbid) {
				t.Errorf("build_fail issue #%d contains miscompile row %q", iss.Number, forbid)
			}
		}
	}
	if !strings.Contains(zstdIss.Body, "| Kind | compiler ICE |") || !strings.Contains(luaIss.Body, "| Kind | build failure |") {
		t.Errorf("missing Kind row in bodies:\nzstd=%s\nlua=%s", zstdIss.Body, luaIss.Body)
	}
	if !strings.Contains(zstdIss.Body, "````\n") {
		t.Errorf("expected 4-backtick fence for excerpt containing triple backticks:\n%s", zstdIss.Body)
	}

	siteOut := t.TempDir()
	if err := generateSite(storeDir, siteOut, t.TempDir()); err != nil {
		t.Fatalf("generateSite: %v", err)
	}
	idxRaw, err := os.ReadFile(filepath.Join(siteOut, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	idx := string(idxRaw)
	if err := checkNoCrossRefs(idx); err != nil {
		t.Errorf("index.html failed checkNoCrossRefs: %v", err)
	}
	for _, want := range []string{
		fmt.Sprintf(`<a class="err" href="/incidents/%s/">err</a>`, zstdInc.ID),
		fmt.Sprintf(`<a class="err" href="/incidents/%s/">err</a>`, luaInc.ID),
		`<a class="err" href="/logs/#log-never-passed-linux-x86_64-distro-o2">err</a>`,
		">build (ice)<",
		">build<",
		">abcdef012345<",
	} {
		if !strings.Contains(idx, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
	zstdPageRaw, err := os.ReadFile(filepath.Join(siteOut, "incidents", zstdInc.ID, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	zstdPage := string(zstdPageRaw)
	for _, want := range []string{"<h2>Build Error</h2>", "compiler ICE", "PLEASE submit a bug report"} {
		if !strings.Contains(zstdPage, want) {
			t.Errorf("zstd incident page missing %q", want)
		}
	}
	for _, forbid := range []string{"Sanitizers", "Conservative", "github.com/llvm/"} {
		if strings.Contains(zstdPage, forbid) {
			t.Errorf("zstd incident page contains %q", forbid)
		}
	}

	prefixInc := &incident{
		ID: "prefixed-ice", Kind: incidentKindBuildFail, Status: incidentOpen,
		GoodSHA: goodSHA1, BadSHA: badSHA,
		ErrorExcerpt: "[compiler ICE] stack dump without signature",
		Affected:     []affected{{Package: "opus", Platform: platLinuxX86, Profile: profDistroO2}},
	}
	if got := formatGroupTitle([]*incident{prefixInc}); got != "[ice] opus compiler crash on abcdef012345" {
		t.Errorf("prefixed ICE title = %q", got)
	}
	if got := groupLabels([]*incident{prefixInc}); !slices.Equal(got, []string{labelBuildFail, labelCompilerICE, platLinuxX86}) {
		t.Errorf("prefixed ICE labels = %v", got)
	}

	stMid, err := loadState(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	stMid.LastGoodByTarget[targetKey("lua", platDarwinARM, profDistroO2)] = goodSHA2
	if err := saveState(storeDir, stMid); err != nil {
		t.Fatal(err)
	}
	frags2 := t.TempDir()
	if err := writeResultFragment(filepath.Join(frags2, "sweep.json"), []pkgResult{
		{Package: "lua", Version: "5.4.7", Platform: platLinuxX86, Profile: profDistroO2, Status: statusBuildFail, ErrorExcerpt: plainBuildErr},
		{Package: "lua", Version: "5.4.7", Platform: platDarwinARM, Profile: profDistroO2, Status: statusBuildFail, ErrorExcerpt: "LLVM ERROR: darwin crash"},
	}); err != nil {
		t.Fatal(err)
	}
	if code := runCLI(ctx, []string{"lmc", "aggregate", "-frags", frags2, "-store", storeDir, "-sha", badSHA}, &out, &errBuf); code != 0 {
		t.Fatalf("second aggregate failed (%d): %s", code, errBuf.String())
	}
	incs2, err := loadAllIncidents(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(incs2) != 2 {
		t.Fatalf("expected new lua target to merge into existing open build_fail, got %d incidents", len(incs2))
	}
	var luaMerged *incident
	for _, inc := range incs2 {
		if inc.ID == luaInc.ID {
			luaMerged = inc
		}
	}
	if luaMerged == nil || len(luaMerged.Affected) != 2 || !isICEExcerpt(luaMerged.ErrorExcerpt) {
		t.Fatalf("lua merge did not add target or upgrade ICE excerpt: %+v", luaMerged)
	}

	frags3 := t.TempDir()
	if err := writeResultFragment(filepath.Join(frags3, "pass.json"), []pkgResult{
		{Package: "zstd", Version: "1.5.6", Platform: platLinuxX86, Profile: profDistroO2, Status: statusPass},
		{Package: "zstd", Version: "1.5.6", Platform: platDarwinARM, Profile: profReleaseLTO, Status: statusPass},
		{Package: "lua", Version: "5.4.7", Platform: platLinuxX86, Profile: profDistroO2, Status: statusPass},
		{Package: "lua", Version: "5.4.7", Platform: platDarwinARM, Profile: profDistroO2, Status: statusPass},
	}); err != nil {
		t.Fatal(err)
	}
	if code := runCLI(ctx, []string{"lmc", "aggregate", "-frags", frags3, "-store", storeDir, "-sha", fixSHA}, &out, &errBuf); code != 0 {
		t.Fatalf("pass aggregate failed (%d): %s", code, errBuf.String())
	}
	incs3, err := loadAllIncidents(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, inc := range incs3 {
		if inc.Status != incidentResolved || inc.FixedSHA != fixSHA {
			t.Fatalf("build_fail incident not auto-resolved: %+v", inc)
		}
	}
	closeCfg := cfg
	closeCfg.HeadSHA = fixSHA
	closeActs, err := syncIssues(ctx, closeCfg, incs3)
	if err != nil || len(closeActs) != 2 {
		t.Fatalf("close sync acts=%+v err=%v", closeActs, err)
	}
	for _, a := range closeActs {
		if a.Kind != "close" {
			t.Errorf("expected close action, got %+v", a)
		}
	}
	mu.Lock()
	if issues[zstdInc.IssueNumber].State != "closed" || issues[luaInc.IssueNumber].State != "closed" {
		t.Errorf("expected both issues closed")
	}
	if !slices.Equal(comments[zstdInc.IssueNumber], []string{"Fixed at `fedcba987654`."}) {
		t.Errorf("unexpected close comment: %v", comments[zstdInc.IssueNumber])
	}
	mu.Unlock()
}

func TestHumanIssueCloseReopenAndSuppression(t *testing.T) {
	ctx := context.Background()
	srv, mu, issues, _ := newFakeGitHub(t)

	goodA := "1111111111111111111111111111111111111111"
	goodB := "2222222222222222222222222222222222222222"
	bad1 := "3333333333333333333333333333333333333333"
	passSHA := "4444444444444444444444444444444444444444"
	bad2 := "5555555555555555555555555555555555555555"

	storeDir := t.TempDir()
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

	st := &state{
		LastGoodSHA: goodA,
		LastGoodByTarget: map[string]string{
			targetKey("zstd", platLinuxX86, profDistroO2):    goodA,
			targetKey("zstd", platDarwinARM, profReleaseLTO): goodB,
			targetKey("opus", platLinuxX86, profDistroO2):    goodA,
			targetKey("sqlite", platLinuxX86, profDistroO2):  goodA,
		},
	}
	if err := saveState(storeDir, st); err != nil {
		t.Fatal(err)
	}

	buildInc := &incident{
		ID: "20261120-zstd-build-333333333333", Kind: incidentKindBuildFail,
		Title: "zstd: build failure", Status: incidentOpen, Confidence: confNeedsReview,
		GoodSHA: goodA, BadSHA: bad1, ErrorExcerpt: "zstd.c:1: error: broken",
		Affected: []affected{
			{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, GoodSHA: goodA},
			{Package: "zstd", Platform: platDarwinARM, Profile: profReleaseLTO, GoodSHA: goodB},
		},
		CreatedAt: now, UpdatedAt: now,
	}
	plainBuildInc := &incident{
		ID: "20261120-opus-build-333333333333", Kind: incidentKindBuildFail,
		Title: "opus: build failure", Status: incidentOpen, Confidence: confNeedsReview,
		GoodSHA: goodA, BadSHA: bad1, ErrorExcerpt: "opus.c:1: error: broken",
		Affected:  []affected{{Package: "opus", Platform: platLinuxX86, Profile: profDistroO2, GoodSHA: goodA}},
		CreatedAt: now.Add(time.Minute), UpdatedAt: now.Add(time.Minute),
	}
	misInc := &incident{
		ID:    "sqlite-linux-x86-64-distro-o2-33333333",
		Title: "sqlite: GVNPass", Status: incidentOpen, Confidence: confConfirmed,
		GoodSHA: goodA, BadSHA: bad1, CulpritSHA: bad1, CulpritPass: "GVNPass",
		ASanUBSanClean: true,
		Affected:       []affected{{Package: "sqlite", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
		CreatedAt:      now.Add(2 * time.Minute), UpdatedAt: now.Add(2 * time.Minute),
	}
	for _, inc := range []*incident{buildInc, plainBuildInc, misInc} {
		if _, err := saveIncident(storeDir, inc); err != nil {
			t.Fatal(err)
		}
	}
	refreshStateIncidents(st, []*incident{buildInc, plainBuildInc, misInc}, false)
	if err := saveState(storeDir, st); err != nil {
		t.Fatal(err)
	}

	cfg := issueSyncCfg{Repo: defaultRepo, Token: "tok", APIBase: srv.URL, StoreDir: storeDir}
	if acts, err := syncIssues(ctx, cfg, []*incident{buildInc, plainBuildInc, misInc}); err != nil || len(acts) != 3 {
		t.Fatalf("initial syncIssues acts=%+v err=%v", acts, err)
	}

	mu.Lock()
	issues[buildInc.IssueNumber].Labels = append(issues[buildInc.IssueNumber].Labels, struct{ Name string }{"upstream"}, struct{ Name string }{"package-bug"})
	issues[buildInc.IssueNumber].State = "closed"
	issues[plainBuildInc.IssueNumber].State = "closed"
	issues[misInc.IssueNumber].Labels = append(issues[misInc.IssueNumber].Labels, struct{ Name string }{"upstream"})
	issues[misInc.IssueNumber].State = "closed"
	mu.Unlock()

	incs, err := loadAllIncidents(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	acts, err := syncIssues(ctx, cfg, incs)
	if err != nil || len(acts) != 3 {
		t.Fatalf("close-sync acts=%+v err=%v", acts, err)
	}
	for _, a := range acts {
		if a.Kind != "noop" {
			t.Errorf("expected noop on human-closed issue, got %+v", a)
		}
	}

	reloaded, err := loadAllIncidents(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*incident{}
	for _, inc := range reloaded {
		byID[inc.ID] = inc
	}
	if byID[buildInc.ID].Status != incidentClosed || !slices.Equal(byID[buildInc.ID].Labels, []string{"package-bug", "upstream"}) || byID[buildInc.ID].ResolvedAt == nil {
		t.Fatalf("zstd closed sync mismatch: %+v", byID[buildInc.ID])
	}
	if byID[plainBuildInc.ID].Status != incidentClosed || len(byID[plainBuildInc.ID].Labels) != 0 || byID[plainBuildInc.ID].ResolvedAt == nil {
		t.Fatalf("opus plain closed sync mismatch: %+v", byID[plainBuildInc.ID])
	}
	if byID[misInc.ID].Status != incidentClosed || !slices.Equal(byID[misInc.ID].Labels, []string{"upstream"}) {
		t.Fatalf("sqlite closed sync mismatch: %+v", byID[misInc.ID])
	}

	stClosed, err := loadState(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(stClosed.ActiveIncidentIDs) != 0 || len(stClosed.RetainedToolchains) != 0 {
		t.Fatalf("expected empty active/retained after all closed: active=%v retained=%v", stClosed.ActiveIncidentIDs, stClosed.RetainedToolchains)
	}

	fragsStillFail := t.TempDir()
	if err := writeResultFragment(filepath.Join(fragsStillFail, "f.json"), []pkgResult{
		{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, Status: statusBuildFail, ErrorExcerpt: "still broken x86"},
		{Package: "zstd", Platform: platDarwinARM, Profile: profReleaseLTO, Status: statusBuildFail, ErrorExcerpt: "still broken darwin"},
		{Package: "opus", Platform: platLinuxX86, Profile: profDistroO2, Status: statusBuildFail, ErrorExcerpt: "still broken opus"},
		{Package: "sqlite", Platform: platLinuxX86, Profile: profDistroO2, Status: statusTestFail, FailedTests: []string{"t1"}},
	}); err != nil {
		t.Fatal(err)
	}
	regOutSuppressed := filepath.Join(t.TempDir(), "regs-suppressed.json")
	var out, errBuf bytes.Buffer
	if code := runCLI(ctx, []string{
		"lmc", "aggregate", "-frags", fragsStillFail, "-store", storeDir, "-sha", bad1, "-reg-out", regOutSuppressed,
	}, &out, &errBuf); code != 0 {
		t.Fatalf("suppressed aggregate failed (%d): %s", code, errBuf.String())
	}
	var supRegs []regressionTarget
	if err := readJSON(regOutSuppressed, &supRegs); err != nil {
		t.Fatal(err)
	}
	if len(supRegs) != 0 {
		t.Fatalf("human-closed test_fail re-triggered: %+v", supRegs)
	}
	afterSup, err := loadAllIncidents(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterSup) != 3 {
		t.Fatalf("human-closed build_fail created duplicate incident: count=%d", len(afterSup))
	}

	siteClosed := t.TempDir()
	if err := generateSite(storeDir, siteClosed, t.TempDir()); err != nil {
		t.Fatalf("generateSite closed: %v", err)
	}
	idxClosedRaw, err := os.ReadFile(filepath.Join(siteClosed, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	idxClosed := string(idxClosedRaw)
	if strings.Contains(idxClosed, "<h2>Open</h2>") {
		t.Errorf("closed incidents should not appear under Open:\n%s", idxClosed)
	}
	for _, want := range []string{
		"<h2>Resolved</h2>",
		">package-bug, upstream<",
		">closed<",
		fmt.Sprintf(`<a class="err" href="/incidents/%s/">err</a>`, buildInc.ID),
		fmt.Sprintf(`<a class="err" href="/incidents/%s/">err</a>`, plainBuildInc.ID),
		fmt.Sprintf(`<a class="fail" href="/incidents/%s/">fail</a>`, misInc.ID),
	} {
		if !strings.Contains(idxClosed, want) {
			t.Errorf("closed index.html missing %q", want)
		}
	}
	if fileExists(filepath.Join(siteClosed, "logs", "index.html")) {
		t.Errorf("closed incidents with matching targets should not generate unlinked logs page")
	}
	zstdClosedPageRaw, err := os.ReadFile(filepath.Join(siteClosed, "incidents", buildInc.ID, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(zstdClosedPageRaw), "closed (package-bug, upstream)") {
		t.Errorf("zstd closed page missing status with labels:\n%s", string(zstdClosedPageRaw))
	}
	opusClosedPageRaw, err := os.ReadFile(filepath.Join(siteClosed, "incidents", plainBuildInc.ID, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(opusClosedPageRaw), "<td>closed</td>") {
		t.Errorf("opus closed page missing plain closed status:\n%s", string(opusClosedPageRaw))
	}

	orphanClosed := &incident{
		ID: "20261120-orphan-build-333333333333", Kind: incidentKindBuildFail, Status: incidentClosed,
		GoodSHA: goodA, BadSHA: bad1,
		Affected: []affected{{Package: "orphan", Platform: platLinuxX86, Profile: profDistroO2, GoodSHA: goodA}},
	}
	mu.Lock()
	countBeforeOrphan := len(issues)
	mu.Unlock()
	if oActs, err := syncIssues(ctx, cfg, []*incident{orphanClosed}); err != nil || len(oActs) != 0 {
		t.Fatalf("closed incident without GH issue should be skipped: acts=%+v err=%v", oActs, err)
	}
	mu.Lock()
	if len(issues) != countBeforeOrphan {
		t.Fatalf("closed incident without GH issue created a new issue")
	}
	mu.Unlock()

	fragsPass := t.TempDir()
	if err := writeResultFragment(filepath.Join(fragsPass, "pass.json"), []pkgResult{
		{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, Status: statusPass},
		{Package: "zstd", Platform: platDarwinARM, Profile: profReleaseLTO, Status: statusPass},
		{Package: "sqlite", Platform: platLinuxX86, Profile: profDistroO2, Status: statusPass},
	}); err != nil {
		t.Fatal(err)
	}
	if code := runCLI(ctx, []string{"lmc", "aggregate", "-frags", fragsPass, "-store", storeDir, "-sha", passSHA}, &out, &errBuf); code != 0 {
		t.Fatalf("pass aggregate failed (%d): %s", code, errBuf.String())
	}
	afterPass, err := loadAllIncidents(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, inc := range afterPass {
		if inc.Status != incidentClosed {
			t.Fatalf("pass sweep overwrote incidentClosed to %q: %+v", inc.Status, inc)
		}
	}

	fragsRegress := t.TempDir()
	if err := writeResultFragment(filepath.Join(fragsRegress, "reg.json"), []pkgResult{
		{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, Status: statusBuildFail, ErrorExcerpt: "LLVM ERROR: new crash"},
		{Package: "opus", Platform: platLinuxX86, Profile: profDistroO2, Status: statusBuildFail, ErrorExcerpt: "still never passed"},
		{Package: "sqlite", Platform: platLinuxX86, Profile: profDistroO2, Status: statusTestFail, FailedTests: []string{"t2"}},
	}); err != nil {
		t.Fatal(err)
	}
	regOutFresh := filepath.Join(t.TempDir(), "regs-fresh.json")
	if code := runCLI(ctx, []string{
		"lmc", "aggregate", "-frags", fragsRegress, "-store", storeDir, "-sha", bad2, "-reg-out", regOutFresh,
	}, &out, &errBuf); code != 0 {
		t.Fatalf("regress aggregate failed (%d): %s", code, errBuf.String())
	}
	var freshRegs []regressionTarget
	if err := readJSON(regOutFresh, &freshRegs); err != nil {
		t.Fatal(err)
	}
	if len(freshRegs) != 1 || freshRegs[0].Package != "sqlite" || freshRegs[0].GoodSHA != passSHA {
		t.Fatalf("expected fresh sqlite regression after pass, got %+v", freshRegs)
	}
	afterFresh, err := loadAllIncidents(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterFresh) != 4 {
		t.Fatalf("expected 4 incidents (fresh zstd build_fail, opus still suppressed), got %d", len(afterFresh))
	}
	var freshZstd *incident
	for _, inc := range afterFresh {
		if inc.Status == incidentOpen && inc.isBuildFail() {
			freshZstd = inc
		}
	}
	if freshZstd == nil || freshZstd.GoodSHA != passSHA || dedupKey(freshZstd) == dedupKey(buildInc) {
		t.Fatalf("expected fresh zstd build_fail with new dedupKey: fresh=%+v oldKey=%q", freshZstd, dedupKey(buildInc))
	}
	mu.Lock()
	countBeforeFreshSync := len(issues)
	mu.Unlock()
	if _, err := syncIssues(ctx, cfg, afterFresh); err != nil {
		t.Fatalf("fresh syncIssues: %v", err)
	}
	mu.Lock()
	if len(issues) != countBeforeFreshSync+1 {
		t.Fatalf("expected 1 new GH issue for fresh build_fail, count %d -> %d", countBeforeFreshSync, len(issues))
	}
	mu.Unlock()

	mu.Lock()
	issues[plainBuildInc.IssueNumber].State = "open"
	issues[plainBuildInc.IssueNumber].Labels = append(issues[plainBuildInc.IssueNumber].Labels, struct{ Name string }{"needs-bisect"})
	mu.Unlock()

	allBeforeReopen, err := loadAllIncidents(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncIssues(ctx, cfg, allBeforeReopen); err != nil {
		t.Fatalf("reopen syncIssues: %v", err)
	}
	allAfterReopen, err := loadAllIncidents(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	var reopenedOpus *incident
	for _, inc := range allAfterReopen {
		if inc.ID == plainBuildInc.ID {
			reopenedOpus = inc
		}
	}
	if reopenedOpus == nil || reopenedOpus.Status != incidentOpen || reopenedOpus.ResolvedAt != nil || !slices.Equal(reopenedOpus.Labels, []string{"needs-bisect"}) {
		t.Fatalf("human reopen did not restore incidentOpen/labels: %+v", reopenedOpus)
	}
	stReopen, err := loadState(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(stReopen.ActiveIncidentIDs, plainBuildInc.ID) || !slices.Contains(stReopen.RetainedToolchains, goodA) {
		t.Fatalf("state.json not refreshed after human reopen: active=%v retained=%v", stReopen.ActiveIncidentIDs, stReopen.RetainedToolchains)
	}

	siteReopen := t.TempDir()
	if err := generateSite(storeDir, siteReopen, t.TempDir()); err != nil {
		t.Fatalf("generateSite reopen: %v", err)
	}
	opusOpenPageRaw, err := os.ReadFile(filepath.Join(siteReopen, "incidents", plainBuildInc.ID, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(opusOpenPageRaw), "open (needs-bisect)") {
		t.Errorf("reopened opus page missing open status with human label:\n%s", string(opusOpenPageRaw))
	}
}

func TestBuildFailDedupAndLabelSync(t *testing.T) {
	if got := dedupKey(&incident{
		ID: "b1", Kind: incidentKindBuildFail, GoodSHA: "111111111111abcdef",
		Affected: []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2}},
	}); got != "build:zstd|111111111111" {
		t.Errorf("dedupKey full = %q", got)
	}
	if got := dedupKey(&incident{
		ID: "b2", Kind: incidentKindBuildFail,
		Affected: []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2}},
	}); got != "build:zstd" {
		t.Errorf("dedupKey no-good = %q", got)
	}
	if got := dedupKey(&incident{ID: "b3", Kind: incidentKindBuildFail}); got != "incident:b3" {
		t.Errorf("dedupKey no-pkg = %q", got)
	}

	iss := &ghIssue{
		Labels: []struct{ Name string }{
			{confConfirmed}, {confLikely}, {confNeedsReview}, {labelBuildFail}, {labelCompilerICE},
			{platLinuxX86}, {platLinuxARM64}, {platLinuxRISCV64}, {platDarwinARM},
			{"Linux-x86_64"}, {"upstream"}, {"package-bug"}, {"@nikic (#99)"},
		},
	}
	if got := humanLabels(iss, []string{"custom-bot"}); !slices.Equal(got, []string{"nikic", "package-bug", "upstream"}) {
		t.Errorf("humanLabels = %v", got)
	}

	storeDir := t.TempDir()
	inc1 := &incident{
		ID: "m1", Kind: incidentKindBuildFail, Title: "zstd: build failure", Status: incidentOpen,
		GoodSHA: "1111111111111111111111111111111111111111", BadSHA: "2222222222222222222222222222222222222222",
		ErrorExcerpt: "a.c:1: error: bad",
		Affected:     []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, GoodSHA: "1111111111111111111111111111111111111111"}},
	}
	if _, err := mergeIncident(storeDir, inc1); err != nil {
		t.Fatal(err)
	}
	inc2 := &incident{
		ID: "m2", Kind: incidentKindBuildFail, Status: incidentOpen,
		GoodSHA: "1111111111111111111111111111111111111111", BadSHA: "2222222222222222222222222222222222222222",
		ErrorExcerpt: "LLVM ERROR: ice",
		Affected: []affected{
			{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2},
			{Package: "zstd", Platform: platDarwinARM, Profile: profReleaseLTO, GoodSHA: "3333333333333333333333333333333333333333"},
		},
	}
	merged, err := mergeIncident(storeDir, inc2)
	if err != nil {
		t.Fatal(err)
	}
	if merged.ID != "m1" || merged.Title != "zstd: compiler ICE" || !isICEExcerpt(merged.ErrorExcerpt) || len(merged.Affected) != 2 ||
		merged.Affected[0].GoodSHA != "1111111111111111111111111111111111111111" ||
		merged.Affected[1].GoodSHA != "3333333333333333333333333333333333333333" {
		t.Fatalf("unexpected merged build_fail incident: %+v", merged)
	}
	stMerged, err := loadState(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, wantSHA := range []string{
		"1111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222",
		"3333333333333333333333333333333333333333",
	} {
		if !slices.Contains(stMerged.RetainedToolchains, wantSHA) {
			t.Fatalf("RetainedToolchains missing multi-target SHA %s: %v", wantSHA, stMerged.RetainedToolchains)
		}
	}

	otherOpen := &incident{
		ID: "m-other", Kind: incidentKindBuildFail, Title: "lua: build failure", Status: incidentOpen,
		GoodSHA: "4444444444444444444444444444444444444444", BadSHA: "5555555555555555555555555555555555555555",
		ErrorExcerpt: "lua.c:1: error: boom",
		Affected:     []affected{{Package: "lua", Platform: platLinuxX86, Profile: profDistroO2, GoodSHA: "6666666666666666666666666666666666666666"}},
	}
	if _, err := saveIncident(storeDir, otherOpen); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	srv, mu, issues, _ := newFakeGitHub(t)
	cfg := issueSyncCfg{Repo: defaultRepo, Token: "tok", APIBase: srv.URL, StoreDir: storeDir}
	if _, err := syncIssues(ctx, cfg, []*incident{merged}); err != nil {
		t.Fatal(err)
	}
	stSubset, err := loadState(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(stSubset.ActiveIncidentIDs, "m1") || !slices.Contains(stSubset.ActiveIncidentIDs, "m-other") {
		t.Fatalf("subset syncIssues dropped other open incident from ActiveIncidentIDs: %v", stSubset.ActiveIncidentIDs)
	}
	for _, wantSHA := range []string{
		"1111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222",
		"3333333333333333333333333333333333333333",
		"4444444444444444444444444444444444444444",
		"5555555555555555555555555555555555555555",
		"6666666666666666666666666666666666666666",
	} {
		if !slices.Contains(stSubset.RetainedToolchains, wantSHA) {
			t.Fatalf("subset syncIssues dropped SHA %s from RetainedToolchains: %v", wantSHA, stSubset.RetainedToolchains)
		}
	}

	mu.Lock()
	issues[merged.IssueNumber].Labels = append(issues[merged.IssueNumber].Labels, struct{ Name string }{"triaged"})
	mu.Unlock()
	if acts, err := syncIssues(ctx, cfg, []*incident{merged}); err != nil || len(acts) != 1 || acts[0].Kind != "noop" {
		t.Fatalf("open human label sync acts=%+v err=%v", acts, err)
	}
	var onDisk incident
	if err := readJSON(filepath.Join(storeDir, "incidents", "m1.json"), &onDisk); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(onDisk.Labels, []string{"triaged"}) {
		t.Fatalf("open issue human label not persisted: %+v", onDisk.Labels)
	}

	mu.Lock()
	issues[merged.IssueNumber].State = "closed"
	mu.Unlock()
	if _, err := syncIssues(ctx, cfg, []*incident{merged}); err != nil {
		t.Fatal(err)
	}
	stAfterClose, err := loadState(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(stAfterClose.ActiveIncidentIDs, "m1") || !slices.Contains(stAfterClose.ActiveIncidentIDs, "m-other") {
		t.Fatalf("subset close corrupted ActiveIncidentIDs: %v", stAfterClose.ActiveIncidentIDs)
	}
	if slices.Contains(stAfterClose.RetainedToolchains, "3333333333333333333333333333333333333333") ||
		!slices.Contains(stAfterClose.RetainedToolchains, "6666666666666666666666666666666666666666") {
		t.Fatalf("subset close corrupted RetainedToolchains: %v", stAfterClose.RetainedToolchains)
	}

	xssStore, xssOut := t.TempDir(), t.TempDir()
	xssInc := &incident{
		ID: "xss-build", Kind: incidentKindBuildFail, Title: "zstd: build failure", Status: incidentClosed,
		GoodSHA: "1111111111111111111111111111111111111111", BadSHA: "2222222222222222222222222222222222222222",
		ErrorExcerpt: "foo.cc:1: error: <script>alert(1)</script> & bad",
		Labels:       []string{"<script>alert(2)</script>", "a&b"},
		Affected:     []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2}},
	}
	if _, err := saveIncident(xssStore, xssInc); err != nil {
		t.Fatal(err)
	}
	if err := generateSite(xssStore, xssOut, t.TempDir()); err != nil {
		t.Fatalf("generateSite xss: %v", err)
	}
	xssPageRaw, err := os.ReadFile(filepath.Join(xssOut, "incidents", "xss-build", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	xssPage := string(xssPageRaw)
	if strings.Contains(xssPage, "<script>") || strings.Contains(xssPage, "&amp;lt;") {
		t.Fatalf("incident page allowed raw script or double-escaped:\n%s", xssPage)
	}
	for _, want := range []string{"&lt;script&gt;alert(1)&lt;/script&gt; &amp; bad", "closed (&lt;script&gt;alert(2)&lt;/script&gt;, a&amp;b)"} {
		if !strings.Contains(xssPage, want) {
			t.Errorf("incident page missing escaped %q:\n%s", want, xssPage)
		}
	}
	xssIdxRaw, err := os.ReadFile(filepath.Join(xssOut, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	xssIdx := string(xssIdxRaw)
	if strings.Contains(xssIdx, "<script>") || !strings.Contains(xssIdx, "&lt;script&gt;alert(2)&lt;/script&gt;, a&amp;b") {
		t.Fatalf("index page script escaping failed:\n%s", xssIdx)
	}
}

func TestSiteFailureLogsPage(t *testing.T) {
	storeDir, outDir := t.TempDir(), t.TempDir()
	t1 := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	goodOld := "1111111111111111111111111111111111111111"
	goodNew := "2222222222222222222222222222222222222222"
	badSHA := "3333333333333333333333333333333333333333"

	staleClosed := &incident{
		ID: "inc-stale-closed", Kind: incidentKindBuildFail, Status: incidentClosed,
		GoodSHA: goodOld, BadSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Affected: []affected{{Package: "lua", Platform: platLinuxX86, Profile: profDistroO2, GoodSHA: goodOld}},
	}
	if _, err := saveIncident(storeDir, staleClosed); err != nil {
		t.Fatal(err)
	}
	st := &state{
		LastGoodByTarget: map[string]string{
			targetKey("lua", platLinuxX86, profDistroO2): goodNew,
		},
	}
	sw := &sweep{
		ID: formatSweepID(t1, badSHA), LLVMCommit: badSHA, StartedAt: t1, CompletedAt: t1,
		Results: []pkgResult{
			{Package: "cpython", Platform: platLinuxRISCV64, Profile: profDistroO2, Status: statusBuildFail, ErrorExcerpt: "Modules/_ctypes/_ctypes.c:119: fatal error: 'ffi.h' <script>x</script> https://github.com/llvm/llvm-project/issues/1"},
			{Package: "lua", Platform: platLinuxX86, Profile: profDistroO2, Status: statusBuildFail, ErrorExcerpt: "PLEASE submit a bug report to https://github.com/llvm/llvm-project/issues/"},
			{Package: "zstd", Platform: platLinuxX86, Profile: profReleaseLTO, Status: statusTestFail, FailedTests: []string{"fuzzer_test"}, ErrorExcerpt: "assertion failed"},
			{Package: "opus", Platform: platDarwinARM, Profile: profDistroO2, Status: statusBuildFail},
			{Package: "foo-bar", Platform: platLinuxX86, Profile: profDistroO2, Status: statusBuildFail, IncidentID: "missing-inc", ErrorExcerpt: "foo-bar err"},
			{Package: "foo.bar", Platform: platLinuxX86, Profile: profDistroO2, Status: statusBuildFail, IncidentID: ".", ErrorExcerpt: "foo.bar err"},
		},
	}
	if _, err := saveSweep(storeDir, sw); err != nil {
		t.Fatal(err)
	}
	recordSweep(st, *sw, []*incident{staleClosed})
	if err := saveState(storeDir, st); err != nil {
		t.Fatal(err)
	}

	if err := generateSite(storeDir, outDir, t.TempDir()); err != nil {
		t.Fatalf("generateSite: %v", err)
	}
	idxRaw, err := os.ReadFile(filepath.Join(outDir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	idx := string(idxRaw)
	if err := checkNoCrossRefs(idx); err != nil {
		t.Fatalf("index.html cross-ref: %v", err)
	}
	for _, want := range []string{
		`<a class="err" href="/logs/#log-cpython-linux-riscv64-distro-o2">err</a>`,
		`<a class="err" href="/logs/#log-lua-linux-x86_64-distro-o2">err</a>`,
		`<a class="fail" href="/logs/#log-zstd-linux-x86_64-release-lto">fail</a>`,
		`<a class="err" href="/logs/#log-foo-bar-linux-x86_64-distro-o2">err</a>`,
		`<a class="err" href="/logs/#log-foo-bar-linux-x86_64-distro-o2-2">err</a>`,
		`<span class="err">err</span>`,
	} {
		if !strings.Contains(idx, want) {
			t.Errorf("index.html missing %q:\n%s", want, idx)
		}
	}
	for _, forbid := range []string{`href="/incidents/inc-stale-closed/">err</a>`, `href="/incidents/missing-inc/"`, `href="/incidents/./"`, `index.html`} {
		if strings.Contains(idx, forbid) {
			t.Errorf("index.html should not contain %q:\n%s", forbid, idx)
		}
	}

	logsRaw, err := os.ReadFile(filepath.Join(outDir, "logs", "index.html"))
	if err != nil {
		t.Fatalf("expected logs/index.html: %v", err)
	}
	logsPage := string(logsRaw)
	if strings.Contains(logsPage, "<script>") || strings.Contains(strings.ToLower(logsPage), "github.com/llvm/") || strings.Contains(logsPage, "index.html") {
		t.Fatalf("logs/index.html unsanitized or has index.html link:\n%s", logsPage)
	}
	for _, want := range []string{
		`<link rel="stylesheet" href="/style.css">`,
		`<a href="/">status</a>`,
		`<a href="/corpus/">corpus</a>`,
		`id="log-cpython-linux-riscv64-distro-o2"`,
		`cpython (linux-riscv64 / -O2)`,
		`build failure`,
		`&lt;script&gt;x&lt;/script&gt;`,
		`id="log-lua-linux-x86_64-distro-o2"`,
		`compiler ICE`,
		`id="log-zstd-linux-x86_64-release-lto"`,
		`test failure`,
		`<code>fuzzer_test</code>`,
		`assertion failed`,
		`id="log-foo-bar-linux-x86_64-distro-o2"`,
		`id="log-foo-bar-linux-x86_64-distro-o2-2"`,
	} {
		if !strings.Contains(logsPage, want) {
			t.Errorf("logs/index.html missing %q:\n%s", want, logsPage)
		}
	}

	t2 := t1.Add(time.Hour)
	swGreen := &sweep{
		ID: formatSweepID(t2, "4444444444444444444444444444444444444444"), LLVMCommit: "4444444444444444444444444444444444444444",
		StartedAt: t2, CompletedAt: t2,
		Results: []pkgResult{
			{Package: "cpython", Platform: platLinuxRISCV64, Profile: profDistroO2, Status: statusPass, DurationSec: 10},
		},
	}
	if _, err := saveSweep(storeDir, swGreen); err != nil {
		t.Fatal(err)
	}
	recordSweep(st, *swGreen, []*incident{staleClosed})
	if err := saveState(storeDir, st); err != nil {
		t.Fatal(err)
	}
	if err := generateSite(storeDir, outDir, t.TempDir()); err != nil {
		t.Fatalf("generateSite green: %v", err)
	}
	if fileExists(filepath.Join(outDir, "logs", "index.html")) {
		t.Errorf("stale logs/index.html was not removed after sweep recovered")
	}
}

func TestIssueReproCommandAndPassName(t *testing.T) {
	passCases := []struct {
		pass string
		want bool
	}{
		{"instcombine", true},
		{"loop-vectorize", true},
		{"  gvn  ", true},
		{"sroa", true},
		{"", false},
		{"a", false},
		{"InstCombinePass", false},
		{"InvalidateAnalysisPass<llvm::AAManager>", false},
		{"frontend-irgen", false},
		{"inliner-ml-advisor-release", false},
		{"X86 Atom pad short functions", false},
		{"loop_vectorize", false},
	}
	for _, tc := range passCases {
		if got := isValidOptPassName(tc.pass); got != tc.want {
			t.Errorf("isValidOptPassName(%q) = %v, want %v", tc.pass, got, tc.want)
		}
	}

	reproCases := []struct {
		name string
		inc  *incident
		want string
	}{
		{"nil", nil, "opt -O2 -S"},
		{"codegenO2", &incident{CulpritPass: "x86-isel", IsCodeGenPass: true, Affected: []affected{{Profile: profDistroO2}}}, "llc -O2"},
		{"codegenLTO", &incident{CulpritPass: "codegenprepare", IsCodeGenPass: true, Affected: []affected{{Profile: profReleaseLTO}}}, "llc -O3"},
		{"codegenNoAffected", &incident{CulpritPass: "x86-isel", IsCodeGenPass: true}, "llc -O2"},
		{"validNPM", &incident{CulpritPass: "instcombine", Affected: []affected{{Profile: profDistroO2}}}, "opt -passes=instcombine -S"},
		{"validNPMLTO", &incident{CulpritPass: "loop-vectorize", Affected: []affected{{Profile: profReleaseLTO}}}, "opt -passes=loop-vectorize -S"},
		{"legacyClassO2", &incident{CulpritPass: "InstCombinePass", Affected: []affected{{Profile: profDistroO2}}}, "opt -O2 -S"},
		{"legacyClassLTO", &incident{CulpritPass: "InstCombinePass", Affected: []affected{{Profile: profReleaseLTO}}}, "opt -O3 -S"},
		{"invalidateO2", &incident{CulpritPass: "InvalidateAnalysisPass<llvm::AAManager>", Affected: []affected{{Profile: profDistroO2}}}, "opt -O2 -S"},
		{"frontendIrgen", &incident{CulpritPass: "frontend-irgen", Affected: []affected{{Profile: profReleaseLTO}}}, "opt -O3 -S"},
		{"mlAdvisor", &incident{CulpritPass: "inliner-ml-advisor-release", Affected: []affected{{Profile: profDistroO2}}}, "opt -O2 -S"},
	}
	for _, tc := range reproCases {
		if got := reproCommand(tc.inc); got != tc.want {
			t.Errorf("reproCommand(%s) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestStoreConfidenceDiagO0AndLLUBI(t *testing.T) {
	if confRank("") != 0 || confRank(confNeedsReview) != 0 || confRank(confLikely) != 1 || confRank(confConfirmed) != 2 {
		t.Fatalf("unexpected confRank values")
	}

	storeDir := t.TempDir()
	sha := "1234567890abcdef1234567890abcdef12345678"
	base := &incident{
		ID: "inc-merge-1", Status: incidentOpen, Confidence: confNeedsReview,
		GoodSHA: "1111111111111111111111111111111111111111", BadSHA: sha, CulpritSHA: sha,
		ReducedIR: "define i32 @f() {\n...[truncated]",
		Affected:  []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	if _, err := mergeIncident(storeDir, base); err != nil {
		t.Fatal(err)
	}
	stepLikely := &incident{
		ID: "inc-merge-2", Status: incidentOpen, Confidence: confLikely,
		GoodSHA: base.GoodSHA, BadSHA: sha, CulpritSHA: sha,
		DiagO0Status: "test_fail", CulpritPass: "x86-isel", CulpritPassIndex: 17,
		ReducedIR: "define i32 @f(i32 %x) {\n  ret i32 %x\n}",
		Affected:  []affected{{Package: "zstd", Platform: platLinuxARM64, Profile: profDistroO2, TestID: "t1"}},
	}
	m1, err := mergeIncident(storeDir, stepLikely)
	if err != nil {
		t.Fatal(err)
	}
	if m1.Confidence != confLikely || m1.DiagO0Status != "test_fail" || m1.CulpritPass != "x86-isel" || m1.CulpritPassIndex != 17 || m1.IsCodeGenPass || !strings.Contains(m1.ReducedIR, "ret i32 %x") {
		t.Fatalf("merge likely mismatch: %+v", m1)
	}

	stepConfirm := &incident{
		ID: "inc-merge-3", Status: incidentOpen, Confidence: confConfirmed,
		GoodSHA: base.GoodSHA, BadSHA: sha, CulpritSHA: sha,
		DiagO0Status: "pass", CulpritPass: "x86-isel", IsCodeGenPass: true,
		ReducedIR: "define i32 @other(i32 %x) {\n  ret i32 0\n}",
		Affected:  []affected{{Package: "zstd", Platform: platDarwinARM, Profile: profReleaseLTO, TestID: "t1"}},
	}
	m2, err := mergeIncident(storeDir, stepConfirm)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Confidence != confConfirmed || m2.DiagO0Status != "pass" || !m2.IsCodeGenPass || !strings.Contains(m2.ReducedIR, "ret i32 %x") {
		t.Fatalf("merge confirmed mismatch: %+v", m2)
	}

	stepDowngrade := &incident{
		ID: "inc-merge-4", Status: incidentOpen, Confidence: confLikely,
		GoodSHA: base.GoodSHA, BadSHA: sha, CulpritSHA: sha,
		DiagO0Status: "build_fail", CulpritPass: "instcombine", IsCodeGenPass: false,
		Affected: []affected{{Package: "zstd", Platform: platLinuxRISCV64, Profile: profDistroO2, TestID: "t1"}},
	}
	m3, err := mergeIncident(storeDir, stepDowngrade)
	if err != nil {
		t.Fatal(err)
	}
	if m3.Confidence != confConfirmed || m3.DiagO0Status != "pass" || m3.CulpritPass != "x86-isel" || !m3.IsCodeGenPass {
		t.Fatalf("merge downgraded fields: %+v", m3)
	}

	otherStore := t.TempDir()
	otherBase := &incident{
		ID: "inc-diff-pass-1", Status: incidentOpen, Confidence: confNeedsReview,
		GoodSHA: base.GoodSHA, BadSHA: sha, CulpritSHA: sha,
		CulpritPass: "instcombine", CulpritPassIndex: 5, IsCodeGenPass: false,
		Affected: []affected{{Package: "lua", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	if _, err := mergeIncident(otherStore, otherBase); err != nil {
		t.Fatal(err)
	}
	otherCG := &incident{
		ID: "inc-diff-pass-2", Status: incidentOpen, Confidence: confNeedsReview,
		GoodSHA: base.GoodSHA, BadSHA: sha, CulpritSHA: sha,
		CulpritPass: "x86-isel", CulpritPassIndex: 99, IsCodeGenPass: true,
		Affected: []affected{{Package: "lua", Platform: platLinuxARM64, Profile: profDistroO2, TestID: "t1"}},
	}
	mOther, err := mergeIncident(otherStore, otherCG)
	if err != nil {
		t.Fatal(err)
	}
	if mOther.CulpritPass != "instcombine" || mOther.IsCodeGenPass {
		t.Fatalf("mismatched CulpritPass wrongly set IsCodeGenPass: %+v", mOther)
	}

	if got := groupLabels([]*incident{
		{Confidence: confNeedsReview, Affected: []affected{{Platform: platLinuxX86}}},
		{Confidence: confLikely, Affected: []affected{{Platform: platLinuxARM64}}},
	}); !slices.Equal(got, []string{confLikely, platLinuxARM64, platLinuxX86}) {
		t.Errorf("groupLabels likely = %v", got)
	}
	if got := groupLabels([]*incident{
		{Confidence: confLikely, Affected: []affected{{Platform: platLinuxX86}}},
		{Confidence: confConfirmed, Affected: []affected{{Platform: platLinuxX86}}},
	}); !slices.Equal(got, []string{confConfirmed, platLinuxX86}) {
		t.Errorf("groupLabels confirmed = %v", got)
	}

	iss := &ghIssue{
		Labels: []struct{ Name string }{
			{confLikely}, {platLinuxX86}, {"reported-upstream"}, {"Needs-Review"},
		},
	}
	if got := mergeLabels(iss, []string{confConfirmed, platLinuxX86}); !slices.Equal(got, []string{confConfirmed, platLinuxX86, "reported-upstream"}) {
		t.Errorf("mergeLabels likely->confirmed = %v", got)
	}
	if got := mergeLabels(&ghIssue{Labels: []struct{ Name string }{{confNeedsReview}, {"triaged"}}}, []string{confLikely, platDarwinARM}); !slices.Equal(got, []string{platDarwinARM, confLikely, "triaged"}) {
		t.Errorf("mergeLabels needs-review->likely = %v", got)
	}

	validIR := "define i32 @f(i32 %x) {\n  ret i32 %x\n}"
	oversizedIR := strings.Repeat("define i32 @big(i32 %x) {\n  ret i32 %x\n}\n", 400)
	if got := pickPrimary([]*incident{
		{ID: "low-rich", Confidence: confNeedsReview, ReducedIR: validIR, PassDiff: "diff", ErrorExcerpt: "LLVM ERROR: boom"},
		{ID: "likely-bare", Confidence: confLikely},
		{ID: "conf-bare", Confidence: confConfirmed},
	}); got.ID != "conf-bare" {
		t.Errorf("pickPrimary confRank = %q, want conf-bare", got.ID)
	}
	if got := pickPrimary([]*incident{
		{ID: "oversized", Confidence: confLikely, ReducedIR: oversizedIR, PassDiff: "diff"},
		{ID: "truncated", Confidence: confLikely, ReducedIR: validIR + "\n...[truncated]", PassDiff: "diff"},
		{ID: "inline", Confidence: confLikely, ReducedIR: validIR},
	}); got.ID != "inline" {
		t.Errorf("pickPrimary inlineIR = %q, want inline", got.ID)
	}
	if got := pickPrimary([]*incident{
		{ID: "plain-err", Confidence: confNeedsReview, ErrorExcerpt: "a.c:1: error: bad"},
		{ID: "ice", Confidence: confNeedsReview, ErrorExcerpt: "LLVM ERROR: crash"},
	}); got.ID != "ice" {
		t.Errorf("pickPrimary ICE = %q, want ice", got.ID)
	}

	rowVal := func(rows [][2]string, key string) (string, bool) {
		for _, r := range rows {
			if r[0] == key {
				return r[1], true
			}
		}
		return "", false
	}
	noO0 := &incident{
		ID: "no-o0", Status: incidentOpen, Confidence: confLikely,
		BadSHA: sha, LLUBIStatus: formalUnsupported,
		LLUBIOutput: "before_exit=0 after_exit=0\nwarning: passing null values for all arguments.",
		Affected:    []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2}},
	}
	mdRows := incidentMetaRows([]*incident{noO0}, false, defaultSiteURL)
	if _, ok := rowVal(mdRows, "`-O0`"); ok {
		t.Errorf("expected -O0 row omitted when empty: %v", mdRows)
	}
	if got, ok := rowVal(mdRows, "`llubi`"); !ok || got != "unsupported" {
		t.Errorf("md llubi unsupported = (%q, %v), want unsupported", got, ok)
	}
	htmlRows := incidentMetaRows([]*incident{noO0}, true, "")
	if _, ok := rowVal(htmlRows, "<code>-O0</code>"); ok {
		t.Errorf("expected HTML -O0 row omitted when empty: %v", htmlRows)
	}
	if got, ok := rowVal(htmlRows, "<code>llubi</code>"); !ok || got != "unsupported" {
		t.Errorf("html llubi unsupported = (%q, %v), want unsupported", got, ok)
	}

	o0Fail := &incident{ID: "o0-fail", Status: incidentOpen, BadSHA: sha, DiagO0Status: "test_fail", Affected: []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2}}}
	o0Pass := &incident{ID: "o0-pass", Status: incidentOpen, BadSHA: sha, DiagO0Status: "pass", Affected: []affected{{Package: "zstd", Platform: platLinuxARM64, Profile: profDistroO2}}}
	if got, ok := rowVal(incidentMetaRows([]*incident{o0Fail, o0Pass}, false, defaultSiteURL), "`-O0`"); !ok || got != "pass" {
		t.Errorf("md -O0 prefer pass = (%q, %v)", got, ok)
	}
	if got, ok := rowVal(incidentMetaRows([]*incident{o0Fail}, true, ""), "<code>-O0</code>"); !ok || got != "test_fail" {
		t.Errorf("html -O0 test_fail = (%q, %v)", got, ok)
	}
}

func TestSiteAndIssueInlineReducedIR(t *testing.T) {
	smallIR := "define i32 @f(i32 %x) {\n  ret i32 %x\n}"
	noisyButClean := smallIR + "\n" + strings.Repeat("!1 = !DILocation(line: 1, column: 1, scope: !2)\n", 400)
	if got := inlineReducedIR(noisyButClean); got != smallIR {
		t.Errorf("inlineReducedIR noisy = %q, want %q", got, smallIR)
	}
	hugeIR := strings.Repeat("define i32 @big(i32 %x) {\n  ret i32 %x\n}\n", 400)
	if got := inlineReducedIR(hugeIR); got != "" {
		t.Errorf("inlineReducedIR >14KB = len %d, want empty", len(got))
	}
	if got := inlineReducedIR(smallIR + "\n...[truncated]"); got != "" {
		t.Errorf("inlineReducedIR legacy truncated = %q, want empty", got)
	}
	if got := inlineReducedIR(smallIR + "\n; ... [truncated]"); got != "" {
		t.Errorf("inlineReducedIR clipCode truncated = %q, want empty", got)
	}

	bundleURL := "https://github.com/npmania/llvm-miscompile-canary/releases/download/reproducers/reproducer-big.tar.zst"
	sha := "abcdef0123456789abcdef0123456789abcdef01"
	bigWithBundle := &incident{
		ID: "inc-big-bundle", Status: incidentOpen, Confidence: confLikely,
		GoodSHA: "1111111111111111111111111111111111111111", BadSHA: sha, CulpritSHA: sha,
		CulpritPass: "instcombine", ReducedIR: hugeIR, BundleURL: bundleURL,
		Affected: []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	body := formatGroupBody([]*incident{bigWithBundle}, "", defaultSiteURL)
	if err := checkNoCrossRefs(body); err != nil {
		t.Fatalf("bigWithBundle cross-ref: %v", err)
	}
	wantNote := fmt.Sprintf("Reduced IR exceeds inline limit; see `reduced.ll` in [reproducer.tar.zst](%s).", bundleURL)
	if !strings.Contains(body, wantNote) || strings.Contains(body, "```llvm") || strings.Contains(body, "[truncated]") {
		t.Errorf("bigWithBundle unexpected body:\n%s", body)
	}

	truncNoBundle := &incident{
		ID: "inc-trunc-none", Status: incidentOpen, Confidence: confLikely,
		GoodSHA: bigWithBundle.GoodSHA, BadSHA: sha, CulpritSHA: sha,
		CulpritPass: "instcombine", ReducedIR: smallIR + "\n...[truncated]",
		Affected: []affected{{Package: "lua", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	bodyNoBundle := formatGroupBody([]*incident{truncNoBundle}, "", defaultSiteURL)
	if strings.Contains(bodyNoBundle, "```llvm") || strings.Contains(bodyNoBundle, "Reduced IR exceeds inline limit") || strings.Contains(bodyNoBundle, "[truncated]") {
		t.Errorf("truncNoBundle should omit IR and bundle note:\n%s", bodyNoBundle)
	}

	unsafeBundle := &incident{
		ID: "inc-unsafe-bundle", Status: incidentOpen, Confidence: confLikely,
		GoodSHA: bigWithBundle.GoodSHA, BadSHA: sha, CulpritSHA: sha,
		CulpritPass: "instcombine", ReducedIR: hugeIR, BundleURL: "javascript:alert(1)",
		Affected: []affected{{Package: "opus", Platform: platLinuxX86, Profile: profDistroO2, TestID: "t1"}},
	}
	bodyUnsafe := formatGroupBody([]*incident{unsafeBundle}, "", defaultSiteURL)
	if strings.Contains(bodyUnsafe, "Reduced IR exceeds inline limit") || strings.Contains(strings.ToLower(bodyUnsafe), "javascript:") {
		t.Errorf("unsafeBundle leaked note or javascript URL:\n%s", bodyUnsafe)
	}

	cgInc := &incident{
		ID: "inc-cg", Status: incidentOpen, Confidence: confConfirmed,
		GoodSHA: bigWithBundle.GoodSHA, BadSHA: sha, CulpritSHA: sha,
		CulpritPass: "x86-isel", IsCodeGenPass: true, ReducedIR: smallIR,
		Affected: []affected{{Package: "sqlite", Platform: platLinuxX86, Profile: profReleaseLTO, TestID: "t1"}},
	}
	bodyCG := formatGroupBody([]*incident{cgInc}, "", defaultSiteURL)
	if !strings.Contains(bodyCG, "`llc -O3`:") {
		t.Errorf("cgInc missing llc -O3:\n%s", bodyCG)
	}

	buildWithBundle := &incident{
		ID: "inc-build-bundle", Kind: incidentKindBuildFail, Status: incidentOpen,
		GoodSHA: bigWithBundle.GoodSHA, BadSHA: sha, BundleURL: bundleURL,
		ErrorExcerpt: "foo.c:1: error: bad",
		Affected:     []affected{{Package: "zstd", Platform: platLinuxX86, Profile: profDistroO2}},
	}

	storeDir, outDir := t.TempDir(), t.TempDir()
	for _, inc := range []*incident{bigWithBundle, truncNoBundle, unsafeBundle, cgInc, buildWithBundle} {
		if _, err := saveIncident(storeDir, inc); err != nil {
			t.Fatal(err)
		}
	}
	if err := generateSite(storeDir, outDir, t.TempDir()); err != nil {
		t.Fatalf("generateSite: %v", err)
	}
	readPage := func(id string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(outDir, "incidents", id, "index.html"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	bigPage := readPage(bigWithBundle.ID)
	wantHTMLNote := fmt.Sprintf(`<h2>Reduced IR</h2>`+"\n    "+`<p>Reduced IR exceeds inline limit; see <code>reduced.ll</code> in <a href="%s">reproducer.tar.zst</a>.</p>`, bundleURL)
	if !strings.Contains(bigPage, wantHTMLNote) || strings.Contains(bigPage, "@big") || strings.Contains(bigPage, "[truncated]") {
		t.Errorf("bigPage unexpected HTML:\n%s", bigPage)
	}
	truncPage := readPage(truncNoBundle.ID)
	if strings.Contains(truncPage, "<h2>Reduced IR</h2>") || strings.Contains(truncPage, "Reduced IR exceeds inline limit") {
		t.Errorf("truncPage should omit Reduced IR section:\n%s", truncPage)
	}
	unsafePage := readPage(unsafeBundle.ID)
	if strings.Contains(unsafePage, "<h2>Reduced IR</h2>") || strings.Contains(strings.ToLower(unsafePage), "javascript:") {
		t.Errorf("unsafePage should omit Reduced IR section:\n%s", unsafePage)
	}
	cgPage := readPage(cgInc.ID)
	if !strings.Contains(cgPage, `<p class="cmd"><code>llc -O3</code></p>`) {
		t.Errorf("cgPage missing llc -O3:\n%s", cgPage)
	}
	buildPage := readPage(buildWithBundle.ID)
	if strings.Contains(buildPage, "<h2>Reduced IR</h2>") || strings.Contains(buildPage, "Reduced IR exceeds inline limit") {
		t.Errorf("buildPage should not show Reduced IR section:\n%s", buildPage)
	}
}

func TestAggregateRegressionSelection(t *testing.T) {
	storeDir := t.TempDir()
	fragsDir := t.TempDir()
	goodSHA := "1111111111111111111111111111111111111111"
	badSHA := "2222222222222222222222222222222222222222"
	if err := saveState(storeDir, &state{LastGoodSHA: goodSHA}); err != nil {
		t.Fatal(err)
	}

	results := []pkgResult{
		{Package: "p-fast", Platform: platLinuxRISCV64, Profile: profReleaseLTO, Status: statusTestFail, DurationSec: 25, FailedTests: []string{"t-rv"}},
		{Package: "p-fast", Platform: platDarwinARM, Profile: profDistroO2, Status: statusTestFail, DurationSec: 12, FailedTests: []string{"t-mac"}},
		{Package: "p-fast", Platform: platLinuxX86, Profile: profDistroO2, Status: statusTestFail, DurationSec: 5, FailedTests: []string{"t-x86"}},

		{Package: "p-pos", Platform: platLinuxX86, Profile: profDistroO2, Status: statusTestFail, DurationSec: 0, FailedTests: []string{"t-zero"}},
		{Package: "p-pos", Platform: platLinuxRISCV64, Profile: profReleaseLTO, Status: statusTestFail, DurationSec: 30, FailedTests: []string{"t-pos"}},

		{Package: "p-plat", Platform: platLinuxRISCV64, Profile: profDistroO2, Status: statusTestFail, DurationSec: 10, FailedTests: []string{"t-rv"}},
		{Package: "p-plat", Platform: platDarwinARM, Profile: profDistroO2, Status: statusTestFail, DurationSec: 10, FailedTests: []string{"t-mac"}},
		{Package: "p-plat", Platform: platLinuxARM64, Profile: profDistroO2, Status: statusTestFail, DurationSec: 10, FailedTests: []string{"t-arm"}},
		{Package: "p-plat", Platform: platLinuxX86, Profile: profDistroO2, Status: statusTestFail, DurationSec: 10, FailedTests: []string{"t-x86"}},

		{Package: "p-prof", Platform: platLinuxARM64, Profile: profReleaseLTO, Status: statusTestFail, DurationSec: 10, FailedTests: []string{"t-lto"}},
		{Package: "p-prof", Platform: platLinuxARM64, Profile: profDistroO2, Status: statusTestFail, DurationSec: 10, FailedTests: []string{"t-o2"}},

		{Package: "p-rv-slow", Platform: platLinuxRISCV64, Profile: profDistroO2, Status: statusTestFail, DurationSec: 10, FailedTests: []string{"t1"}},
		{Package: "p-mac-tie", Platform: platDarwinARM, Profile: profDistroO2, Status: statusTestFail, DurationSec: 10, FailedTests: []string{"t1"}},
		{Package: "p-arm-lto", Platform: platLinuxARM64, Profile: profReleaseLTO, Status: statusTestFail, DurationSec: 10, FailedTests: []string{"t1"}},
		{Package: "p-lex-a", Platform: platLinuxX86, Profile: profDistroO2, Status: statusTestFail, DurationSec: 20, FailedTests: []string{"t1"}},
		{Package: "p-lex-b", Platform: platLinuxX86, Profile: profDistroO2, Status: statusTestFail, DurationSec: 20, FailedTests: []string{"t1"}},
		{Package: "p-zero-mac", Platform: platDarwinARM, Profile: profDistroO2, Status: statusTestFail, DurationSec: 0, FailedTests: []string{"t1"}},
		{Package: "p-zero-rv", Platform: platLinuxRISCV64, Profile: profDistroO2, Status: statusTestFail, DurationSec: -1, FailedTests: []string{"t1"}},
	}
	if err := writeResultFragment(filepath.Join(fragsDir, "all.json"), results); err != nil {
		t.Fatal(err)
	}
	regOut := filepath.Join(t.TempDir(), "regs.json")
	var out, errBuf bytes.Buffer
	if code := runCLI(context.Background(), []string{
		"lmc", "aggregate", "-frags", fragsDir, "-store", storeDir, "-sha", badSHA, "-reg-out", regOut,
	}, &out, &errBuf); code != 0 {
		t.Fatalf("aggregate failed (%d): %s", code, errBuf.String())
	}
	var regs []regressionTarget
	if err := readJSON(regOut, &regs); err != nil {
		t.Fatal(err)
	}
	type wantReg struct{ pkg, plat, prof, test string }
	want := []wantReg{
		{"p-fast", platLinuxX86, profDistroO2, "t-x86"},
		{"p-plat", platLinuxX86, profDistroO2, "t-x86"},
		{"p-prof", platLinuxARM64, profDistroO2, "t-o2"},
		{"p-arm-lto", platLinuxARM64, profReleaseLTO, "t1"},
		{"p-mac-tie", platDarwinARM, profDistroO2, "t1"},
		{"p-rv-slow", platLinuxRISCV64, profDistroO2, "t1"},
		{"p-lex-a", platLinuxX86, profDistroO2, "t1"},
		{"p-lex-b", platLinuxX86, profDistroO2, "t1"},
	}
	if len(regs) != len(want) {
		t.Fatalf("len(regs) = %d, want %d: %+v", len(regs), len(want), regs)
	}
	seenPkg := map[string]bool{}
	for i, w := range want {
		r := regs[i]
		if seenPkg[r.Package] {
			t.Errorf("duplicate package in regs: %q", r.Package)
		}
		seenPkg[r.Package] = true
		gotTest := ""
		if len(r.FailedTests) > 0 {
			gotTest = r.FailedTests[0]
		}
		if r.Package != w.pkg || r.Platform != w.plat || r.Profile != w.prof || gotTest != w.test || r.GoodSHA != goodSHA || r.BadSHA != badSHA {
			t.Errorf("regs[%d] = (%s, %s, %s, %s), want (%s, %s, %s, %s)", i, r.Package, r.Platform, r.Profile, gotTest, w.pkg, w.plat, w.prof, w.test)
		}
	}

	frags2 := t.TempDir()
	store2 := t.TempDir()
	if err := saveState(store2, &state{LastGoodSHA: goodSHA}); err != nil {
		t.Fatal(err)
	}
	if err := writeResultFragment(filepath.Join(frags2, "zero.json"), []pkgResult{
		{Package: "p-pos", Platform: platLinuxX86, Profile: profDistroO2, Status: statusTestFail, DurationSec: 0, FailedTests: []string{"t-zero"}},
		{Package: "p-pos", Platform: platLinuxRISCV64, Profile: profReleaseLTO, Status: statusTestFail, DurationSec: 30, FailedTests: []string{"t-pos"}},
		{Package: "p-zero-tie", Platform: platLinuxRISCV64, Profile: profDistroO2, Status: statusTestFail, DurationSec: 0, FailedTests: []string{"t-rv"}},
		{Package: "p-zero-tie", Platform: platLinuxX86, Profile: profDistroO2, Status: statusTestFail, DurationSec: -1, FailedTests: []string{"t-x86"}},
		{Package: "p-zero-rv", Platform: platLinuxRISCV64, Profile: profDistroO2, Status: statusTestFail, DurationSec: -1, FailedTests: []string{"t1"}},
		{Package: "p-zero-mac", Platform: platDarwinARM, Profile: profDistroO2, Status: statusTestFail, DurationSec: 0, FailedTests: []string{"t1"}},
	}); err != nil {
		t.Fatal(err)
	}
	regOut2 := filepath.Join(t.TempDir(), "regs2.json")
	if code := runCLI(context.Background(), []string{
		"lmc", "aggregate", "-frags", frags2, "-store", store2, "-sha", badSHA, "-reg-out", regOut2,
	}, &out, &errBuf); code != 0 {
		t.Fatalf("aggregate2 failed (%d): %s", code, errBuf.String())
	}
	var regs2 []regressionTarget
	if err := readJSON(regOut2, &regs2); err != nil {
		t.Fatal(err)
	}
	want2 := []wantReg{
		{"p-pos", platLinuxRISCV64, profReleaseLTO, "t-pos"},
		{"p-zero-tie", platLinuxX86, profDistroO2, "t-x86"},
		{"p-zero-mac", platDarwinARM, profDistroO2, "t1"},
		{"p-zero-rv", platLinuxRISCV64, profDistroO2, "t1"},
	}
	if len(regs2) != len(want2) {
		t.Fatalf("len(regs2) = %d, want %d: %+v", len(regs2), len(want2), regs2)
	}
	for i, w := range want2 {
		r := regs2[i]
		gotTest := ""
		if len(r.FailedTests) > 0 {
			gotTest = r.FailedTests[0]
		}
		if r.Package != w.pkg || r.Platform != w.plat || r.Profile != w.prof || gotTest != w.test {
			t.Errorf("regs2[%d] = (%s, %s, %s, %s), want (%s, %s, %s, %s)", i, r.Package, r.Platform, r.Profile, gotTest, w.pkg, w.plat, w.prof, w.test)
		}
	}

	frags3 := t.TempDir()
	store3 := t.TempDir()
	if err := saveState(store3, &state{
		LastGoodByTarget: map[string]string{
			targetKey("p-shadow", platLinuxARM64, profDistroO2):     goodSHA,
			targetKey("p-real-1", platLinuxRISCV64, profReleaseLTO): goodSHA,
			targetKey("p-real-2", platDarwinARM, profDistroO2):      goodSHA,
		},
	}); err != nil {
		t.Fatal(err)
	}
	mixed := []pkgResult{
		{Package: "p-shadow", Platform: platLinuxX86, Profile: profDistroO2, Status: statusTestFail, DurationSec: 1, FailedTests: []string{"t-no-good"}},
		{Package: "p-shadow", Platform: platLinuxARM64, Profile: profDistroO2, Status: statusTestFail, DurationSec: 50, FailedTests: []string{"t-has-good"}},
		{Package: "p-real-1", Platform: platLinuxRISCV64, Profile: profReleaseLTO, Status: statusTestFail, DurationSec: 100, FailedTests: []string{"t-r1"}},
		{Package: "p-real-2", Platform: platDarwinARM, Profile: profDistroO2, Status: statusTestFail, DurationSec: 60, FailedTests: []string{"t-r2"}},
	}
	for i := range 8 {
		mixed = append(mixed, pkgResult{
			Package: fmt.Sprintf("p-never-%d", i), Platform: platLinuxX86, Profile: profDistroO2,
			Status: statusTestFail, DurationSec: float64(i + 1), FailedTests: []string{"t-never"},
		})
	}
	if err := writeResultFragment(filepath.Join(frags3, "mixed.json"), mixed); err != nil {
		t.Fatal(err)
	}
	regOut3 := filepath.Join(t.TempDir(), "regs3.json")
	if code := runCLI(context.Background(), []string{
		"lmc", "aggregate", "-frags", frags3, "-store", store3, "-sha", badSHA, "-reg-out", regOut3,
	}, &out, &errBuf); code != 0 {
		t.Fatalf("aggregate3 failed (%d): %s", code, errBuf.String())
	}
	var regs3 []regressionTarget
	if err := readJSON(regOut3, &regs3); err != nil {
		t.Fatal(err)
	}
	type wantMixed struct{ pkg, plat, prof, test, good string }
	want3 := []wantMixed{
		{"p-shadow", platLinuxARM64, profDistroO2, "t-has-good", goodSHA},
		{"p-real-2", platDarwinARM, profDistroO2, "t-r2", goodSHA},
		{"p-real-1", platLinuxRISCV64, profReleaseLTO, "t-r1", goodSHA},
		{"p-never-0", platLinuxX86, profDistroO2, "t-never", ""},
		{"p-never-1", platLinuxX86, profDistroO2, "t-never", ""},
		{"p-never-2", platLinuxX86, profDistroO2, "t-never", ""},
		{"p-never-3", platLinuxX86, profDistroO2, "t-never", ""},
		{"p-never-4", platLinuxX86, profDistroO2, "t-never", ""},
	}
	if len(regs3) != len(want3) {
		t.Fatalf("len(regs3) = %d, want %d: %+v", len(regs3), len(want3), regs3)
	}
	for i, w := range want3 {
		r := regs3[i]
		gotTest := ""
		if len(r.FailedTests) > 0 {
			gotTest = r.FailedTests[0]
		}
		if r.Package != w.pkg || r.Platform != w.plat || r.Profile != w.prof || gotTest != w.test || r.GoodSHA != w.good {
			t.Errorf("regs3[%d] = (%s, %s, %s, %s, %q), want (%s, %s, %s, %s, %q)", i, r.Package, r.Platform, r.Profile, gotTest, r.GoodSHA, w.pkg, w.plat, w.prof, w.test, w.good)
		}
	}
}
