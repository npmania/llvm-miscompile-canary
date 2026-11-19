package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	defaultRepo       = "npmania/llvm-miscompile-canary"
	defaultAPIBase    = "https://api.github.com"
	defaultSiteURL    = "https://llvm-miscompile-canary.glendalab.com"
	siteDomain        = "llvm-miscompile-canary.glendalab.com"
	maxIssueBodyBytes = 60000
)

type rxRepl struct {
	re   *regexp.Regexp
	repl string
}

var (
	reMDGHLink     = regexp.MustCompile(`(?i)\[([^\]\n]*)\]\(\s*(?:https?://)?(?:www\.)?github\.com/(?:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:issues|pull|discussions|commits?)/([^\s)]*)|llvm/[^\s)]*)\s*\)`)
	reGHCommitURL  = regexp.MustCompile(`(?i)(?:https?://)?(?:www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/commits?/([0-9a-fA-F]{7,40})[^\s)>\]]*`)
	reGHBlockURL   = regexp.MustCompile(`(?i)(?:https?://)?(?:www\.)?github\.com/(?:llvm/[^\s)>\]]*|[A-Za-z0-9_.-]*/?llvm-project[^\s)>\]]*|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:issues|pull|discussions)/[^\s)>\]]*)`)
	reRepoSHA      = regexp.MustCompile(`[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@([0-9a-fA-F]{7,40})`)
	reRepoNum      = regexp.MustCompile(`[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#\d+`)
	rePRParen      = regexp.MustCompile(`[ \t]*\(\s*#\d+\s*\)`)
	reGHNum        = regexp.MustCompile(`(?i)\bGH-\d+`)
	reHandleAt     = regexp.MustCompile(`@+([A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)?)`)
	reHex40        = regexp.MustCompile("(?i)(^|[^0-9a-zA-Z/_-])([0-9a-f]{40})($|[^0-9a-zA-Z/_-])")
	reHexSHA       = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)
	reDedupMarker  = regexp.MustCompile(`<!--\s*lmc-dedup-key:\s*([^\s>]+)\s*-->`)
	reMetaDefLine  = regexp.MustCompile(`^!\d+\s*=`)
	reInlineMeta   = regexp.MustCompile(`,\s*![A-Za-z0-9_.]+\s+!\d+|\s+!(?:dbg|DIAssignID|prof|callees|heapallocsite|srcloc|tbaa(?:\.struct)?|range|noundef|nonnull|align)\s+!\d+`)
	reAttrOutsideQ = regexp.MustCompile(`"(?:\\.|[^"])*"| #\d+\b`)
	reLLUBIExits   = regexp.MustCompile(`before_exit=(-?\d+)\s+after_exit=(-?\d+)`)

	prosePre   = []rxRepl{{regexp.MustCompile(`(?i)&#(?:0*64|x0*40);?`), "@"}, {regexp.MustCompile(`(?i)&#(?:0*35|x0*23);?`), "#"}}
	prosePost  = []rxRepl{{reGHBlockURL, ""}, {reRepoNum, ""}, {regexp.MustCompile(`(?i)llvm/llvm-project`), "llvm-project"}, {rePRParen, ""}, {reGHNum, ""}, {regexp.MustCompile(`(^|[^\w&])#(\d+)`), "${1}${2}"}, {regexp.MustCompile(`([A-Za-z0-9])@+([A-Za-z0-9_-]+)`), "${1}[at]${2}"}, {reHandleAt, "${1}"}}
	proseClean = []rxRepl{{regexp.MustCompile("``([0-9a-f]{7,12})``"), "`$1`"}, {regexp.MustCompile(`[ \t]*\(\s*\)|<\s*>`), ""}, {regexp.MustCompile(`([^\s\n])[ \t]{2,}`), "${1} "}}
)

func pick(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func hexSHA(s string) string {
	s = strings.Trim(strings.TrimSpace(s), "`\"'")
	if !reHexSHA.MatchString(s) {
		return ""
	}
	return shortSHA(strings.ToLower(s))
}

func tickSHA(s string) string {
	if h := hexSHA(s); h != "" {
		return "`" + h + "`"
	}
	return ""
}

func sortedUnique(xs []string) []string { slices.Sort(xs); return slices.Compact(xs) }

func sanitizeText(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "```", "'''")
	for range 4 {
		next := s
		for _, r := range prosePre {
			next = r.re.ReplaceAllString(next, r.repl)
		}
		next = reMDGHLink.ReplaceAllStringFunc(next, func(m string) string {
			sub := reMDGHLink.FindStringSubmatch(m)
			if sha := hexSHA(sub[2]); sha != "" {
				return "`" + sha + "`"
			}
			lbl := strings.TrimSpace(sub[1])
			low := strings.ToLower(lbl)
			return pick(lbl != "" && !strings.Contains(low, "llvm/llvm-project") && !strings.Contains(low, "github.com"), lbl, "")
		})
		next = reGHCommitURL.ReplaceAllStringFunc(next, func(m string) string { return tickSHA(reGHCommitURL.FindStringSubmatch(m)[1]) })
		next = reRepoSHA.ReplaceAllStringFunc(next, func(m string) string { return tickSHA(reRepoSHA.FindStringSubmatch(m)[1]) })
		for _, r := range prosePost {
			next = r.re.ReplaceAllString(next, r.repl)
		}
		next = reHex40.ReplaceAllStringFunc(next, func(m string) string {
			sub := reHex40.FindStringSubmatch(m)
			return sub[1] + tickSHA(sub[2]) + sub[3]
		})
		for _, r := range proseClean {
			next = r.re.ReplaceAllString(next, r.repl)
		}
		lines := strings.Split(next, "\n")
		for i, l := range lines {
			lines[i] = strings.TrimRight(l, " \t")
		}
		if next = strings.Join(lines, "\n"); next == s {
			break
		}
		s = next
	}
	return s
}

func sanitizeCode(s string) string {
	for range 4 {
		next := reGHCommitURL.ReplaceAllStringFunc(s, func(m string) string { return hexSHA(reGHCommitURL.FindStringSubmatch(m)[1]) })
		next = reRepoSHA.ReplaceAllStringFunc(next, func(m string) string { return hexSHA(reRepoSHA.FindStringSubmatch(m)[1]) })
		if next = reGHNum.ReplaceAllString(reRepoNum.ReplaceAllString(reGHBlockURL.ReplaceAllString(next, ""), ""), ""); next == s {
			break
		}
		s = next
	}
	return s
}

func parseFence(line string, closing bool) (byte, int, bool) {
	line = strings.TrimRight(line, "\r")
	trim := strings.TrimLeft(line, " ")
	if len(line)-len(trim) >= 4 || len(trim) < 3 || (trim[0] != '`' && trim[0] != '~') {
		return 0, 0, false
	}
	ch, n := trim[0], 0
	for n < len(trim) && trim[n] == ch {
		n++
	}
	rest := trim[n:]
	return ch, n, n >= 3 && ((closing && strings.TrimSpace(rest) == "") || (!closing && (ch != '`' || !strings.ContainsRune(rest, '`'))))
}

func checkNoCrossRefs(s string) error {
	if strings.Contains(strings.ToLower(s), "github.com/llvm/") {
		return errors.New("disallowed github.com/llvm URL")
	}
	for _, re := range []*regexp.Regexp{reRepoNum, reRepoSHA, reGHNum} {
		if m := re.FindString(s); m != "" {
			return fmt.Errorf("disallowed cross-reference: %q", m)
		}
	}
	lines := strings.Split(s, "\n")
	for i := 0; i < len(lines); i++ {
		if ch, n, ok := parseFence(lines[i], false); ok {
			if j := slices.IndexFunc(lines[i+1:], func(l string) bool { c, m, ok := parseFence(l, true); return ok && c == ch && m >= n }); j >= 0 {
				i += j + 1
				continue
			}
		}
		if m := rePRParen.FindString(lines[i]); m != "" {
			return fmt.Errorf("disallowed (#N) PR trailer: %q", m)
		}
		if m := reHandleAt.FindString(lines[i]); m != "" {
			return fmt.Errorf("disallowed @mention: %q", m)
		}
	}
	return nil
}

func cleanIR(ir string) string        { return stripIR(ir, false) }
func cleanIRForDiff(ir string) string { return stripIR(ir, true) }

func stripIR(ir string, forDiff bool) string {
	ir = strings.ReplaceAll(ir, "\r\n", "\n")
	if strings.TrimSpace(ir) == "" {
		return ""
	}
	dropBase := []string{"; ModuleID =", "source_filename =", "!llvm.", "#dbg_", "call void @llvm.dbg.", "tail call void @llvm.dbg."}
	dropDiff := []string{"target datalayout =", "target triple =", "declare ", "; Function Attrs:", "attributes #"}
	hasPref := func(s string, ps []string) bool {
		return slices.ContainsFunc(ps, func(p string) bool { return strings.HasPrefix(s, p) })
	}
	var out []string
	prevBlank := true
	for _, raw := range strings.Split(ir, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trim := strings.TrimSpace(line)
		if trim != "" && (hasPref(trim, dropBase) || reMetaDefLine.MatchString(trim) || (forDiff && hasPref(trim, dropDiff))) {
			continue
		}
		if trim != "" && !strings.HasPrefix(trim, ";") {
			line = reInlineMeta.ReplaceAllString(line, "")
			if forDiff {
				line = reAttrOutsideQ.ReplaceAllStringFunc(line, func(m string) string { return pick(m[0] == '"', m, "") })
			}
		}
		line = strings.TrimRight(line, " \t")
		if strings.TrimSpace(line) == "" {
			if !prevBlank {
				prevBlank, out = true, append(out, "")
			}
			continue
		}
		prevBlank, out = false, append(out, line)
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return strings.Join(out, "\n")
}

func optCommand(pass string) string {
	p := sanitizeText(strings.TrimSpace(pass))
	if p == "" {
		return "opt -O2 -S"
	}
	return fmt.Sprintf(pick(strings.ContainsAny(p, " \t<>;()"), "opt -passes='%s' -S", "opt -passes=%s -S"), p)
}

func profileLabel(prof string) string {
	switch prof {
	case profDistroO2:
		return "-O2"
	case profReleaseLTO:
		return "-O3 -flto=thin"
	default:
		return prof
	}
}

func formatTargets(targets []affected, htmlMode bool) string {
	if len(targets) == 0 {
		return ""
	}
	sorted := slices.Clone(targets)
	slices.SortFunc(sorted, func(a, b affected) int {
		return cmp.Or(cmp.Compare(a.Package, b.Package), cmp.Compare(a.TestID, b.TestID), cmp.Compare(a.Platform, b.Platform), cmp.Compare(a.Profile, b.Profile))
	})
	wrap := func(s string) string {
		return pick(htmlMode, "<code>"+html.EscapeString(sanitizeText(s))+"</code>", "`"+escapeCell(s)+"`")
	}
	var out []string
	for i := 0; i < len(sorted); {
		pkg, test := sorted[i].Package, sorted[i].TestID
		var specs []string
		for i < len(sorted) && sorted[i].Package == pkg && sorted[i].TestID == test {
			plat := sorted[i].Platform
			var profs []string
			for i < len(sorted) && sorted[i].Package == pkg && sorted[i].TestID == test && sorted[i].Platform == plat {
				if p := profileLabel(sorted[i].Profile); p != "" {
					if lbl := wrap(p); !slices.Contains(profs, lbl) {
						profs = append(profs, lbl)
					}
				}
				i++
			}
			if plat != "" && len(profs) > 0 {
				specs = append(specs, wrap(plat)+": "+strings.Join(profs, ", "))
			} else if plat != "" {
				specs = append(specs, wrap(plat))
			} else if len(profs) > 0 {
				specs = append(specs, strings.Join(profs, ", "))
			}
		}
		head := wrap(pkg) + pick(test != "", " / "+wrap(test), "")
		out = append(out, head+pick(len(specs) > 0, " ("+strings.Join(specs, "; ")+")", ""))
	}
	return strings.Join(out, "; ")
}

func isSafeHTTPURL(u string) bool {
	low := strings.ToLower(strings.TrimSpace(u))
	return strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://")
}

func platformHasASan(plat string) bool {
	spec, err := lookupPlatform(plat)
	if err != nil {
		return true
	}
	flags, err := profileCompilerFlags(profDiagSan, spec)
	if err != nil {
		return true
	}
	return slices.ContainsFunc(flags, func(f string) bool { return strings.Contains(f, "address") })
}

func isUBSanOnlyIncident(inc *incident) bool {
	if inc == nil || len(inc.Affected) == 0 {
		return false
	}
	for _, a := range inc.Affected {
		if a.Platform == "" || platformHasASan(a.Platform) {
			return false
		}
	}
	return true
}

func incidentMetaRows(incs []*incident, htmlMode bool, siteURL string) [][2]string {
	primary := pickPrimary(incs)
	var hasASanClean, hasASanFail, hasUBSanOnly, consIndep bool
	for _, inc := range incs {
		if inc.ASanUBSanClean {
			hasASanClean = true
		} else if isUBSanOnlyIncident(inc) {
			hasUBSanOnly = true
		} else {
			hasASanFail = true
		}
		consIndep = consIndep || inc.ConservativeFlagIndependent
	}
	raw := func(s string) string {
		return pick(htmlMode, sanitizeText(strings.TrimSpace(s)), escapeCell(s))
	}
	txt := func(s string) string {
		return pick(htmlMode, html.EscapeString(raw(s)), raw(s))
	}
	code := func(s string) string { return pick(htmlMode, "<code>"+html.EscapeString(s)+"</code>", "`"+s+"`") }
	link := func(lbl, href string) string {
		if !isSafeHTTPURL(href) {
			return pick(htmlMode, html.EscapeString(lbl), lbl)
		}
		return pick(htmlMode, fmt.Sprintf(`<a href="%s">%s</a>`, html.EscapeString(href), html.EscapeString(lbl)), fmt.Sprintf("[%s](%s)", lbl, href))
	}
	sha := func(s string) string { return pick(htmlMode, cmp.Or(hexSHA(s), shortSHA(s)), hexSHA(s)) }
	var rows [][2]string
	add := func(k, v string) { rows = append(rows, [2]string{k, v}) }

	if htmlMode {
		f := sha(primary.FixedSHA)
		add("Status", pick(primary.Status == incidentResolved, pick(f != "", "resolved at "+code(f), "resolved"), "open"))
	}
	if c := sha(primary.CulpritSHA); c != "" {
		subj := txt(primary.CulpritSubject)
		add("Commit", code(c)+pick(subj != "", " ("+subj+")", ""))
	} else if bad := sha(primary.BadSHA); bad != "" {
		add("Commit", code(bad))
	}
	if g, bad := sha(primary.GoodSHA), sha(primary.BadSHA); g != "" && bad != "" {
		add("Range", code(g)+" .. "+code(bad))
	}
	if pass := raw(primary.CulpritPass); pass != "" {
		add("Pass", code(pass)+pick(primary.CulpritPassIndex > 0, " ("+code(fmt.Sprintf("-opt-bisect-limit=%d", primary.CulpritPassIndex))+")", ""))
	}
	if fn, tu := raw(primary.CulpritFunc), raw(primary.CulpritTU); fn != "" && tu != "" {
		add("Function", code(fn)+" ("+code(tu)+")")
	} else if v := cmp.Or(fn, tu); v != "" {
		add("Function", code(v))
	}
	if tgt := formatTargets(mergedAffected(incs), htmlMode); tgt != "" {
		add(pick(htmlMode, "Targets", "Target"), tgt)
	}
	sanVal := code("asan,ubsan") + " clean"
	if hasASanFail {
		sanVal = code("asan,ubsan") + " failed"
	} else if !hasASanClean && hasUBSanOnly {
		sanVal = code("ubsan") + " clean (asan disabled)"
	}
	add("Sanitizers", sanVal)
	add("Conservative", pick(consIndep, "reproduces ("+code("-fno-strict-aliasing -fwrapv -ftrivial-auto-var-init=zero")+")", "masked"))
	if !isOmittedFormalStatus(primary.AliveTVStatus) {
		add(code("alive-tv"), txt(primary.AliveTVStatus))
	}
	if m := reLLUBIExits.FindStringSubmatch(primary.LLUBIOutput); len(m) >= 3 {
		add(code("llubi"), code(m[1])+" (before)"+pick(htmlMode, " -&gt; ", " -> ")+code(m[2])+" (after)")
	} else if !isOmittedFormalStatus(primary.LLUBIStatus) {
		add(code("llubi"), txt(primary.LLUBIStatus))
	}
	var arts []string
	if u := strings.TrimSpace(primary.BundleURL); u != "" {
		arts = append(arts, link("reproducer.tar.zst", u))
	}
	if htmlMode {
		if u := strings.TrimSpace(primary.IssueURL); u != "" && primary.IssueNumber > 0 {
			arts = append(arts, link(fmt.Sprintf("issue #%d", primary.IssueNumber), u))
		} else if primary.IssueNumber > 0 {
			arts = append(arts, fmt.Sprintf("issue #%d", primary.IssueNumber))
		}
	} else {
		seen := make(map[string]bool, len(incs))
		for _, inc := range append([]*incident{primary}, incs...) {
			if inc.ID != "" && !seen[inc.ID] {
				seen[inc.ID] = true
				arts = append(arts, link(escapeCell(inc.ID), fmt.Sprintf("%s/incidents/%s/", siteURL, inc.ID)))
			}
		}
	}
	if len(arts) > 0 {
		add("Artifacts", strings.Join(arts, " · "))
	}
	return rows
}

type issueSyncCfg struct {
	Repo, Token, APIBase, SiteURL, HeadSHA, StoreDir string
	DryRun, Quiet                                    bool
	Out                                              io.Writer
	HTTPClient                                       *http.Client
}

type issueAction struct {
	Kind, DedupKey, IssueURL, Title, Body, Comment string
	IncidentIDs, Labels                            []string
	IssueNumber                                    int
}

type ghIssue struct {
	Number      int                     `json:"number"`
	HTMLURL     string                  `json:"html_url"`
	State       string                  `json:"state"`
	Title       string                  `json:"title"`
	Body        string                  `json:"body"`
	Labels      []struct{ Name string } `json:"labels"`
	PullRequest *struct{}               `json:"pull_request,omitempty"`
}

type ghClient struct {
	base, token string
	http        *http.Client
}

func (c *ghClient) do(ctx context.Context, method, path string, payload, dst any) error {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "llvm-miscompile-canary")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GitHub API %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if dst != nil && len(raw) > 0 {
		return json.Unmarshal(raw, dst)
	}
	return nil
}

func syncIssues(ctx context.Context, cfg issueSyncCfg, incs []*incident) ([]issueAction, error) {
	cfg.Repo = cmp.Or(strings.TrimSpace(cfg.Repo), defaultRepo)
	cfg.Token = cmp.Or(strings.TrimSpace(cfg.Token), strings.TrimSpace(os.Getenv("GITHUB_TOKEN")))
	cfg.APIBase = strings.TrimRight(cmp.Or(strings.TrimSpace(cfg.APIBase), defaultAPIBase), "/")
	cfg.SiteURL = strings.TrimRight(cmp.Or(strings.TrimSpace(cfg.SiteURL), defaultSiteURL), "/")
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.DryRun && cfg.Out == nil && !cfg.Quiet {
		cfg.Out = os.Stdout
	}
	if !cfg.DryRun && cfg.Token == "" {
		return nil, errors.New("GITHUB_TOKEN is required when -dry-run is false")
	}
	if o, n, ok := strings.Cut(cfg.Repo, "/"); !ok || o == "" || n == "" || strings.Contains(n, "/") {
		return nil, fmt.Errorf("invalid GitHub repository %q", cfg.Repo)
	}
	if strings.EqualFold(cfg.Repo, "llvm/llvm-project") {
		return nil, errors.New("refusing to target upstream llvm/llvm-project")
	}

	cli := &ghClient{cfg.APIBase, cfg.Token, cfg.HTTPClient}
	byNum, byKey := make(map[int]*ghIssue), make(map[string]*ghIssue)
	if !cfg.DryRun || (cfg.APIBase != defaultAPIBase && cfg.Token != "") {
		for page := 1; page <= 10; page++ {
			var batch []ghIssue
			if err := cli.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/issues?state=all&per_page=100&page=%d", cfg.Repo, page), nil, &batch); err != nil {
				if !cfg.DryRun {
					return nil, fmt.Errorf("list issues: %w", err)
				}
				break
			}
			for _, item := range batch {
				if item.PullRequest != nil {
					continue
				}
				iss := item
				byNum[iss.Number] = &iss
				if m := reDedupMarker.FindStringSubmatch(iss.Body); len(m) >= 2 {
					cur := byKey[m[1]]
					if cur == nil || (!strings.EqualFold(cur.State, "open") && strings.EqualFold(iss.State, "open")) {
						byKey[m[1]] = &iss
					}
				}
			}
			if len(batch) < 100 {
				break
			}
		}
	}

	byGroup := make(map[string][]*incident)
	var keys []string
	for _, inc := range incs {
		if inc == nil {
			continue
		}
		k := dedupKey(inc)
		if _, ok := byGroup[k]; !ok {
			keys = append(keys, k)
		}
		byGroup[k] = append(byGroup[k], inc)
	}
	slices.Sort(keys)

	var actions []issueAction
	for _, key := range keys {
		grp := byGroup[key]
		slices.SortFunc(grp, func(a, b *incident) int { return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.ID, b.ID)) })
		ex := byKey[key]
		for _, inc := range grp {
			if iss, ok := byNum[inc.IssueNumber]; inc.IssueNumber > 0 && ok {
				if ex == nil || strings.EqualFold(iss.State, "open") || !strings.EqualFold(ex.State, "open") {
					ex = iss
					if strings.EqualFold(iss.State, "open") {
						break
					}
				}
			}
		}
		act, err := syncGroup(ctx, cli, cfg, key, grp, ex)
		if err != nil {
			return nil, err
		}
		if act != nil {
			actions = append(actions, *act)
			if cfg.DryRun && cfg.Out != nil && act.Kind != "noop" {
				fmt.Fprintf(cfg.Out, "=== [DRY-RUN %s] key=%s incidents=%s ===\nTitle: %s\n", strings.ToUpper(act.Kind), act.DedupKey, strings.Join(act.IncidentIDs, ","), act.Title)
				if len(act.Labels) > 0 {
					fmt.Fprintf(cfg.Out, "Labels: %s\n", strings.Join(act.Labels, ", "))
				}
				if act.Comment != "" {
					fmt.Fprintf(cfg.Out, "Comment:\n\n%s\n", act.Comment)
				}
				if act.Body != "" {
					fmt.Fprintf(cfg.Out, "Body:\n\n%s\n", act.Body)
				}
			}
		}
	}
	return actions, nil
}

func syncGroup(ctx context.Context, cli *ghClient, cfg issueSyncCfg, key string, incs []*incident, ex *ghIssue) (*issueAction, error) {
	var ids []string
	recNum, recURL := 0, ""
	for _, inc := range incs {
		if inc.ID != "" {
			ids = append(ids, inc.ID)
		}
		recNum, recURL = cmp.Or(recNum, inc.IssueNumber), cmp.Or(recURL, inc.IssueURL)
	}
	act := &issueAction{DedupKey: key, IncidentIDs: ids, Title: formatGroupTitle(incs), IssueNumber: recNum, IssueURL: recURL}

	if !slices.ContainsFunc(incs, func(i *incident) bool { return i.Status != incidentResolved }) {
		if ex != nil {
			if strings.EqualFold(ex.State, "closed") {
				return nil, nil
			}
			act.IssueNumber, act.IssueURL = ex.Number, ex.HTMLURL
		} else if act.IssueNumber == 0 || !cfg.DryRun {
			return nil, nil
		}
		act.Kind, act.Comment = "close", formatCloseComment(incs, cfg.HeadSHA)
		if err := errors.Join(checkNoCrossRefs(act.Comment), checkNoCrossRefs(act.Title)); err != nil {
			return nil, fmt.Errorf("close %s: %w", key, err)
		}
		if !cfg.DryRun {
			base := fmt.Sprintf("/repos/%s/issues/%d", cfg.Repo, act.IssueNumber)
			if err := cli.do(ctx, http.MethodPost, base+"/comments", map[string]any{"body": act.Comment}, nil); err != nil {
				return nil, err
			}
			if err := cli.do(ctx, http.MethodPatch, base, map[string]any{"state": "closed", "state_reason": "completed"}, nil); err != nil {
				return nil, err
			}
		}
		return act, nil
	}

	if ex != nil && strings.EqualFold(ex.State, "closed") {
		propagateIssueRef(cfg.StoreDir, incs, ex.Number, ex.HTMLURL)
		act.Kind, act.IssueNumber, act.IssueURL = "noop", ex.Number, ex.HTMLURL
		return act, nil
	}

	act.Body, act.Labels = formatGroupBody(incs, key, cfg.SiteURL), groupLabels(incs)
	if err := errors.Join(checkNoCrossRefs(act.Title), checkNoCrossRefs(act.Body)); err != nil {
		return nil, fmt.Errorf("issue %s: %w", key, err)
	}
	method, path := http.MethodPost, fmt.Sprintf("/repos/%s/issues", cfg.Repo)
	if ex != nil {
		act.IssueNumber, act.IssueURL = ex.Number, ex.HTMLURL
		act.Labels = mergeLabels(ex, act.Labels)
		if ex.Title == act.Title && strings.TrimSpace(ex.Body) == strings.TrimSpace(act.Body) && sameLabels(ex, act.Labels) {
			propagateIssueRef(cfg.StoreDir, incs, ex.Number, ex.HTMLURL)
			act.Kind, act.Body = "noop", ""
			return act, nil
		}
		act.Kind, method, path = "update", http.MethodPatch, fmt.Sprintf("/repos/%s/issues/%d", cfg.Repo, ex.Number)
	} else {
		act.Kind = pick(cfg.DryRun && act.IssueNumber > 0, "update", "create")
	}
	if !cfg.DryRun {
		var res ghIssue
		if err := cli.do(ctx, method, path, map[string]any{"title": act.Title, "body": act.Body, "labels": act.Labels}, &res); err != nil {
			return nil, err
		}
		act.IssueNumber, act.IssueURL = res.Number, res.HTMLURL
		propagateIssueRef(cfg.StoreDir, incs, res.Number, res.HTMLURL)
	}
	return act, nil
}

func groupLabels(incs []*incident) []string {
	conf := confNeedsReview
	var plats []string
	for _, inc := range incs {
		if inc.Confidence == confConfirmed {
			conf = confConfirmed
		}
		for _, a := range inc.Affected {
			if a.Platform != "" {
				plats = append(plats, a.Platform)
			}
		}
	}
	return append([]string{conf}, sortedUnique(plats)...)
}

func formatGroupTitle(incs []*incident) string {
	var valid []*incident
	for _, inc := range incs {
		if inc != nil {
			valid = append(valid, inc)
		}
	}
	if len(valid) == 0 {
		return "unknown miscompile"
	}
	primary := pickPrimary(valid)
	pkgs := uniquePkgs(valid)
	pkgStr := strings.Join(pkgs, ", ")
	if len(pkgs) > 3 {
		pkgStr = fmt.Sprintf("%s (+%d more)", strings.Join(pkgs[:3], ", "), len(pkgs)-3)
	}
	var pass, culprit, bad string
	for _, inc := range append([]*incident{primary}, valid...) {
		pass = cmp.Or(pass, plainTitlePart(inc.CulpritPass))
		culprit = cmp.Or(culprit, hexSHA(inc.CulpritSHA))
		bad = cmp.Or(bad, hexSHA(inc.BadSHA))
	}
	subj := cmp.Or(plainTitlePart(pkgStr), plainTitlePart(primary.ID))
	if subj == "" && pass == "" && culprit == "" && bad == "" {
		return "unknown miscompile"
	}
	title := cmp.Or(subj, "unknown") + " miscompiled"
	if culprit != "" {
		title += " at " + culprit
	} else if bad != "" {
		title += " on " + bad
	}
	if pass != "" {
		title = fmt.Sprintf("[%s] %s", pass, title)
	}
	title = cmp.Or(plainTitlePart(title), "unknown miscompile")
	if r := []rune(title); len(r) > 240 {
		return string(r[:237]) + "..."
	}
	return title
}

func plainTitlePart(s string) string {
	s = sanitizeText(strings.Join(strings.Fields(strings.ReplaceAll(s, "`", "")), " "))
	if strings.ContainsRune(s, '`') {
		s = sanitizeText(strings.ReplaceAll(s, "`", ""))
	}
	return strings.TrimSpace(s)
}

func formatGroupBody(incs []*incident, key, siteURL string) string {
	if len(incs) == 0 {
		return ""
	}
	siteURL = strings.TrimRight(cmp.Or(strings.TrimSpace(siteURL), defaultSiteURL), "/")
	primary := pickPrimary(incs)
	var b strings.Builder
	b.WriteString("| | |\n| --- | --- |\n")
	for _, r := range incidentMetaRows(incs, false, siteURL) {
		fmt.Fprintf(&b, "| %s | %s |\n", r[0], r[1])
	}
	b.WriteByte('\n')
	if ir := clipCode(sanitizeCode(cleanIR(primary.ReducedIR)), 14000); ir != "" {
		f := fenceFor(ir)
		fmt.Fprintf(&b, "`%s`:\n\n%sllvm\n%s\n%s\n\n", optCommand(primary.CulpritPass), f, ir, f)
	}
	if diff := clipCode(sanitizeCode(strings.TrimSpace(primary.PassDiff)), 18000); diff != "" {
		f := fenceFor(diff)
		fmt.Fprintf(&b, "%sdiff\n%s\n%s\n\n", f, diff, f)
	}
	body := truncateBody(strings.TrimRight(b.String(), "\n")+"\n", maxIssueBodyBytes)
	var ids []string
	for _, inc := range incs {
		if inc.ID != "" {
			ids = append(ids, keyToken(inc.ID))
		}
	}
	return fmt.Sprintf("%s\n<!-- lmc-dedup-key: %s -->\n<!-- lmc-incidents: %s -->\n", body, keyToken(cmp.Or(key, dedupKey(incs[0]))), strings.Join(ids, ","))
}

func truncateBody(body string, maxBytes int) string {
	if len(body) <= maxBytes {
		return body
	}
	const suffix = "\n\n...(truncated)\n"
	limit := max(maxBytes-len(suffix)-32, 0)
	cut := body[:limit]
	if nl := strings.LastIndexByte(cut, '\n'); nl >= 0 {
		cut = cut[:nl]
	} else {
		for len(cut) > 0 && !utf8.ValidString(cut) {
			cut = cut[:len(cut)-1]
		}
	}
	var openCh byte
	var openN int
	for _, line := range strings.Split(cut, "\n") {
		if openN == 0 {
			if ch, n, ok := parseFence(line, false); ok {
				openCh, openN = ch, n
			}
		} else if ch, n, ok := parseFence(line, true); ok && ch == openCh && n >= openN {
			openCh, openN = 0, 0
		}
	}
	if openN > 0 {
		cut += "\n" + strings.Repeat(string(openCh), openN)
	}
	return strings.TrimRight(cut, "\n") + suffix
}

func formatCloseComment(incs []*incident, fallbackSHA string) string {
	for _, inc := range incs {
		if sha := tickSHA(inc.FixedSHA); sha != "" {
			return fmt.Sprintf("Fixed at %s.", sha)
		}
	}
	if sha := tickSHA(fallbackSHA); sha != "" {
		return fmt.Sprintf("Fixed at %s.", sha)
	}
	return "Fixed on `main`."
}

func mergedAffected(incs []*incident) []affected {
	var out []affected
	for _, inc := range incs {
		out = append(out, inc.Affected...)
	}
	sortAffected(out)
	return slices.CompactFunc(out, func(a, b affected) bool {
		return a.Package == b.Package && a.Platform == b.Platform && a.Profile == b.Profile && a.TestID == b.TestID
	})
}

func pickPrimary(incs []*incident) *incident {
	best := incs[0]
	for _, inc := range incs[1:] {
		if (best.Confidence != confConfirmed && inc.Confidence == confConfirmed) || (best.ReducedIR == "" && inc.ReducedIR != "") || (best.PassDiff == "" && inc.PassDiff != "") {
			best = inc
		}
	}
	return best
}

func uniquePkgs(incs []*incident) []string {
	var pkgs []string
	for _, inc := range incs {
		for _, a := range inc.Affected {
			if a.Package != "" {
				pkgs = append(pkgs, a.Package)
			}
		}
	}
	return sortedUnique(pkgs)
}

func propagateIssueRef(storeDir string, incs []*incident, num int, url string) {
	now := time.Now().UTC()
	for _, inc := range incs {
		if inc.IssueNumber == num && (url == "" || inc.IssueURL == url) {
			continue
		}
		inc.IssueNumber, inc.UpdatedAt = num, now
		if url != "" {
			inc.IssueURL = url
		}
		if storeDir != "" {
			_, _ = saveIncident(storeDir, inc)
		}
	}
}

func mergeLabels(iss *ghIssue, desired []string) []string {
	out := sortedUnique(slices.Clone(desired))
	if iss == nil {
		return out
	}
	hasConf := slices.Contains(out, confConfirmed)
	hasReview := slices.Contains(out, confNeedsReview)
	for _, l := range iss.Labels {
		name := strings.TrimSpace(l.Name)
		if name == "" {
			continue
		}
		if (strings.EqualFold(name, confNeedsReview) && hasConf) || (strings.EqualFold(name, confConfirmed) && hasReview) {
			continue
		}
		if !slices.ContainsFunc(out, func(s string) bool { return strings.EqualFold(s, name) }) {
			out = append(out, name)
		}
	}
	return sortedUnique(out)
}

func sameLabels(iss *ghIssue, desired []string) bool {
	if len(iss.Labels) != len(desired) {
		return false
	}
	got := make([]string, len(iss.Labels))
	for i, l := range iss.Labels {
		got[i] = strings.ToLower(strings.TrimSpace(l.Name))
	}
	want := make([]string, len(desired))
	for i, l := range desired {
		want[i] = strings.ToLower(strings.TrimSpace(l))
	}
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}

func fenceFor(s string) string {
	maxRun, cur := 2, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '`' {
			cur++
			maxRun = max(maxRun, cur)
		} else {
			cur = 0
		}
	}
	return strings.Repeat("`", maxRun+1)
}

func escapeCell(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(sanitizeText(s), "|", `\|`), "\n", " "))
}

func clipCode(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := s[:maxBytes]
	if nl := strings.LastIndexByte(cut, '\n'); nl > 0 {
		cut = cut[:nl]
	} else {
		for len(cut) > 0 && !utf8.ValidString(cut) {
			cut = cut[:len(cut)-1]
		}
	}
	return cut + "\n; ... [truncated]"
}
