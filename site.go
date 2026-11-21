package main

import (
	"bytes"
	"cmp"
	"embed"
	"fmt"
	"html"
	"html/template"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

//go:embed templates/*
var tmplFS embed.FS

var siteTmpl = template.Must(template.ParseFS(tmplFS, "templates/*.html"))

type corpusEntry struct{ Name, Category, Repo, Version, Lang, SmokeTest string }
type navHeader struct{ LatestSHA12, LatestCommitURL, UpdatedUTC, UpdatedISO string }
type matrixColumn struct{ Platform, Profile, Header string }
type matrixCell struct{ Kind, Text, Href string }
type sweepLogEntry struct{ Anchor, Heading, Status, FailedTests, Excerpt string }
type matrixRow struct {
	Package, Version string
	Cells            []matrixCell
}
type incidentRowView struct {
	ID, CulpritSHA, CulpritCommitURL, FixedSHA, FixedCommitURL, Pass, Function, Targets, IssueURL string
	IssueNumber                                                                                   int
}
type kvRow struct{ Label, Value template.HTML }
type profileSpecView struct {
	O2Flags, LTOFlags string
	TargetFlags       []string
}

var matrixCols = []matrixColumn{
	{platLinuxX86, profDistroO2, "x86_64 O2"},
	{platLinuxX86, profReleaseLTO, "x86_64 LTO"},
	{platLinuxARM64, profDistroO2, "aarch64 O2"},
	{platLinuxARM64, profReleaseLTO, "aarch64 LTO"},
	{platLinuxRISCV64, profDistroO2, "riscv64 O2"},
	{platLinuxRISCV64, profReleaseLTO, "riscv64 LTO"},
	{platDarwinARM, profDistroO2, "darwin-arm64 O2"},
	{platDarwinARM, profReleaseLTO, "darwin-arm64 LTO"},
}

func generateSite(storeDir, outDir, corpusDir string) error {
	st, err := loadState(storeDir)
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	sweeps, err := loadAllSweeps(storeDir)
	if err != nil {
		return fmt.Errorf("load sweeps: %w", err)
	}
	incs, err := loadAllIncidents(storeDir)
	if err != nil {
		return fmt.Errorf("load incidents: %w", err)
	}
	catalog, err := loadSiteCatalog(storeDir, corpusDir)
	if err != nil {
		return fmt.Errorf("load corpus: %w", err)
	}
	for _, dir := range []string{outDir, filepath.Join(outDir, "corpus"), filepath.Join(outDir, "incidents")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	css, err := tmplFS.ReadFile("templates/style.css")
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{"CNAME", []byte(siteDomain + "\n")}, {".nojekyll", nil}, {"style.css", css}} {
		if err := os.WriteFile(filepath.Join(outDir, f.name), f.data, 0o644); err != nil {
			return err
		}
	}
	idxData, logEntries := buildIndexData(st, sweeps, incs, catalog)
	if err := renderPage(filepath.Join(outDir, "index.html"), "index.html", idxData); err != nil {
		return err
	}
	logsDir := filepath.Join(outDir, "logs")
	if len(logEntries) > 0 {
		if err := os.MkdirAll(logsDir, 0o755); err != nil {
			return err
		}
		if err := renderPage(filepath.Join(logsDir, "index.html"), "logs.html", struct {
			Nav     navHeader
			Entries []sweepLogEntry
		}{resolveNav(st, sweeps), logEntries}); err != nil {
			return err
		}
	} else {
		_ = os.RemoveAll(logsDir)
	}
	if err := renderPage(filepath.Join(outDir, "corpus", "index.html"), "corpus.html", struct {
		Nav      navHeader
		Packages []corpusEntry
	}{resolveNav(st, sweeps), catalog}); err != nil {
		return err
	}
	incOutDir := filepath.Join(outDir, "incidents")
	keepIDs := make(map[string]bool, len(incs))
	for _, inc := range incs {
		if inc == nil || inc.ID == "" {
			continue
		}
		if err := validateSafeID("incident id", inc.ID); err != nil {
			return err
		}
		keepIDs[inc.ID] = true
		dir := filepath.Join(incOutDir, inc.ID)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := renderPage(filepath.Join(dir, "index.html"), "incident.html", buildIncidentData(st, sweeps, inc)); err != nil {
			return err
		}
	}
	if ents, err := os.ReadDir(incOutDir); err == nil {
		for _, ent := range ents {
			if ent.IsDir() && !keepIDs[ent.Name()] {
				_ = os.RemoveAll(filepath.Join(incOutDir, ent.Name()))
			}
		}
	}
	return nil
}

func loadSiteCatalog(storeDir, corpusDir string) ([]corpusEntry, error) {
	if corpusDir == "" {
		for _, cand := range []string{filepath.Join(filepath.Dir(storeDir), "corpus"), "corpus"} {
			if info, err := os.Stat(cand); err == nil && info.IsDir() {
				corpusDir = cand
				break
			}
		}
	}
	if corpusDir == "" {
		return nil, nil
	}
	recipes, err := loadCorpus(corpusDir)
	if err != nil {
		return nil, err
	}
	out := make([]corpusEntry, 0, len(recipes))
	for _, r := range recipes {
		lang := map[string]string{"c": "C", "cxx": "C++", "c++": "C++", "": "-"}[strings.ToLower(strings.TrimSpace(r.Lang))]
		out = append(out, corpusEntry{r.Name, r.Category, r.Repo, r.Version, cmp.Or(lang, r.Lang), r.SmokeTest})
	}
	slices.SortFunc(out, func(a, b corpusEntry) int {
		return cmp.Or(cmp.Compare(a.Category, b.Category), cmp.Compare(a.Name, b.Name))
	})
	return out, nil
}

func resolveNav(st *state, sweeps []*sweep) navHeader {
	sha, rawSHA := "-", ""
	var ts time.Time
	if len(sweeps) > 0 {
		rawSHA = sweeps[0].LLVMCommit
		sha, ts = cmp.Or(displaySHA(rawSHA), "-"), sweeps[0].CompletedAt
		if ts.IsZero() {
			ts = sweeps[0].StartedAt
		}
	} else if st != nil && st.LastSweepSHA != "" {
		rawSHA = st.LastSweepSHA
		sha, ts = cmp.Or(displaySHA(rawSHA), "-"), st.UpdatedAt
		if st.LastSweepAt != nil && !st.LastSweepAt.IsZero() {
			ts = *st.LastSweepAt
		}
	}
	commitURL := llvmCommitURL(rawSHA)
	if ts.IsZero() {
		return navHeader{sha, commitURL, "-", ""}
	}
	return navHeader{sha, commitURL, ts.UTC().Format("2006-01-02 15:04 UTC"), ts.UTC().Format(time.RFC3339)}
}

func buildIndexData(st *state, sweeps []*sweep, incs []*incident, catalog []corpusEntry) (any, []sweepLogEntry) {
	type cellKey struct{ pkg, plat, prof string }
	type linkKey struct {
		pkg, plat, prof string
		build           bool
	}
	latest := make(map[cellKey]pkgResult)
	inCat := make(map[string]bool, len(catalog))
	for _, p := range catalog {
		inCat[p.Name] = true
	}
	var extras []string
	if len(sweeps) > 0 {
		for _, r := range sweeps[0].Results {
			latest[cellKey{r.Package, r.Platform, r.Profile}] = r
			if r.Package != "" && !inCat[r.Package] {
				extras = append(extras, r.Package)
			}
		}
	}
	incExists := make(map[string]bool, len(incs))
	openByTarget := make(map[linkKey]string)
	closedByTarget := make(map[linkKey]string)
	var openRows, resolvedRows []incidentRowView
	for _, inc := range incs {
		if inc == nil {
			continue
		}
		if inc.ID != "" && validateSafeID("incident id", inc.ID) == nil {
			incExists[inc.ID] = true
		}
		rv := toIncidentRow(inc)
		if inc.Status != incidentOpen {
			resolvedRows = append(resolvedRows, rv)
			if inc.Status == incidentClosed {
				for _, a := range inc.Affected {
					curGood := st.targetGoodSHA(a.Package, a.Platform, a.Profile)
					if curGood != cmp.Or(a.GoodSHA, inc.GoodSHA) {
						continue
					}
					if k := (linkKey{a.Package, a.Platform, a.Profile, inc.isBuildFail()}); closedByTarget[k] == "" {
						closedByTarget[k] = inc.ID
					}
				}
			}
			continue
		}
		openRows = append(openRows, rv)
		for _, a := range inc.Affected {
			if k := (linkKey{a.Package, a.Platform, a.Profile, inc.isBuildFail()}); openByTarget[k] == "" {
				openByTarget[k] = inc.ID
			}
		}
	}
	ordered := slices.Clone(catalog)
	for _, name := range sortedUnique(extras) {
		ordered = append(ordered, corpusEntry{Name: name})
	}
	rows := make([]matrixRow, 0, len(ordered))
	var logEntries []sweepLogEntry
	usedAnchors := make(map[string]bool)
	for _, pkg := range ordered {
		row := matrixRow{Package: pkg.Name, Version: pkg.Version, Cells: make([]matrixCell, 0, len(matrixCols))}
		for _, col := range matrixCols {
			ck := cellKey{pkg.Name, col.Platform, col.Profile}
			res, ok := latest[ck]
			if !ok {
				row.Cells = append(row.Cells, matrixCell{"skip", "-", ""})
				continue
			}
			row.Version = cmp.Or(row.Version, res.Version)
			switch res.Status {
			case statusPass:
				row.Cells = append(row.Cells, matrixCell{"pass", formatDuration(res.DurationSec), ""})
			case statusTestFail, statusBuildFail, statusTimeout:
				isBuild := res.Status == statusBuildFail
				isTimeout := res.Status == statusTimeout
				kind := pick(isBuild || isTimeout, "err", "fail")
				text := pick(isTimeout, "timeout", pick(isBuild, "err", "fail"))
				lk := linkKey{pkg.Name, col.Platform, col.Profile, isBuild}
				incID := ""
				if !isTimeout {
					if incExists[res.IncidentID] {
						incID = res.IncidentID
					}
					incID = cmp.Or(incID, openByTarget[lk], closedByTarget[lk])
				}
				href := ""
				if incID != "" {
					href = "/incidents/" + incID + "/"
				} else {
					excerpt := clipCode(strings.TrimSpace(sanitizeCode(strings.ReplaceAll(res.ErrorExcerpt, "\r\n", "\n"))), 8000)
					var tests []string
					for _, t := range res.FailedTests {
						if s := sanitizeText(strings.TrimSpace(t)); s != "" {
							tests = append(tests, s)
						}
					}
					failed := strings.Join(tests, ", ")
					var tr triageRecord
					hasTriage := false
					if st != nil && st.LastTriage != nil {
						tr, hasTriage = st.LastTriage[targetKey(pkg.Name, col.Platform, col.Profile)]
						hasTriage = hasTriage && strings.TrimSpace(tr.Outcome) != ""
					}
					if hasTriage {
						if d := strings.TrimSpace(sanitizeCode(strings.ReplaceAll(tr.Detail, "\r\n", "\n"))); d != "" && (strings.ContainsRune(d, '\n') || len(d) > 80) {
							block := "[triage " + sanitizeText(tr.Outcome) + "]\n" + clipCode(d, 2000)
							excerpt = pick(excerpt != "", excerpt+"\n\n"+block, block)
						}
					}
					if excerpt != "" || failed != "" || hasTriage {
						anchor := logAnchor(pkg.Name, col.Platform, col.Profile)
						if usedAnchors[anchor] {
							anchor = uniqueIncidentID(anchor, usedAnchors)
						}
						usedAnchors[anchor] = true
						stLabel := "test failure"
						if isTimeout {
							stLabel = "timeout"
						} else if isBuild {
							stLabel = pick(isICEExcerpt(res.ErrorExcerpt), "compiler ICE", "build failure")
						}
						if hasTriage {
							stLabel += " · triage: " + sanitizeText(strings.TrimSpace(tr.Outcome))
							if d := sanitizeText(strings.TrimSpace(tr.Detail)); d != "" && !strings.ContainsRune(d, '\n') && len(d) <= 80 {
								stLabel += " (" + d + ")"
							}
						}
						logEntries = append(logEntries, sweepLogEntry{
							Anchor:      anchor,
							Heading:     fmt.Sprintf("%s (%s / %s)", sanitizeText(pkg.Name), col.Platform, profileLabel(col.Profile)),
							Status:      stLabel,
							FailedTests: failed,
							Excerpt:     excerpt,
						})
						href = "/logs/#" + anchor
					}
				}
				row.Cells = append(row.Cells, matrixCell{kind, text, href})
			default:
				row.Cells = append(row.Cells, matrixCell{"skip", "-", ""})
			}
		}
		rows = append(rows, row)
	}
	return struct {
		Nav               navHeader
		OpenIncidents     []incidentRowView
		ResolvedIncidents []incidentRowView
		ProfileSpec       profileSpecView
		Columns           []matrixColumn
		Rows              []matrixRow
	}{resolveNav(st, sweeps), openRows, resolvedRows, buildProfileSpec(), matrixCols, rows}, logEntries
}

func buildProfileSpec() profileSpecView {
	o2, _ := profileCompilerFlags(profDistroO2, platformSpec{})
	lto, _ := profileCompilerFlags(profReleaseLTO, platformSpec{})
	seen := make(map[string]bool, len(matrixCols))
	var targets []string
	for _, col := range matrixCols {
		if seen[col.Platform] {
			continue
		}
		seen[col.Platform] = true
		if flags := platformSpecs[col.Platform].BaselineFlags; len(flags) > 0 {
			targets = append(targets, strings.Join(flags, " "))
		}
	}
	return profileSpecView{
		O2Flags:     strings.Join(o2, " "),
		LTOFlags:    strings.Join(lto, " "),
		TargetFlags: targets,
	}
}

func logAnchor(pkg, plat, prof string) string {
	raw := strings.ToLower(pkg + "-" + plat + "-" + prof)
	var b strings.Builder
	b.WriteString("log-")
	prevDash := true
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteByte(c)
			prevDash = false
		} else if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

func buildIncidentData(st *state, sweeps []*sweep, inc *incident) any {
	rawRows := incidentMetaRows([]*incident{inc}, true, "")
	rows := make([]kvRow, len(rawRows))
	for i, r := range rawRows {
		rows[i] = kvRow{template.HTML(r[0]), template.HTML(r[1])}
	}
	nav := resolveNav(st, sweeps)
	if nav.LatestSHA12 == "-" {
		nav.LatestSHA12 = cmp.Or(displaySHA(inc.BadSHA), "-")
		nav.LatestCommitURL = llvmCommitURL(inc.BadSHA)
		if !inc.UpdatedAt.IsZero() {
			nav.UpdatedUTC, nav.UpdatedISO = inc.UpdatedAt.UTC().Format("2006-01-02 15:04 UTC"), inc.UpdatedAt.UTC().Format(time.RFC3339)
		}
	}
	pkgs := strings.Join(uniquePkgs([]*incident{inc}), ", ")
	pass := sanitizeText(strings.TrimSpace(inc.CulpritPass))
	target := cmp.Or(sanitizeText(strings.TrimSpace(inc.CulpritFunc)), sanitizeText(strings.TrimSpace(inc.CulpritTU)))
	heading := cmp.Or(sanitizeText(strings.TrimSpace(inc.Title)), pkgs, inc.ID)
	if pkgs != "" && pass != "" {
		heading = pkgs + ": " + pass + pick(target != "", " in "+target, "")
	} else if inc.isBuildFail() && strings.TrimSpace(inc.Title) == "" && pkgs != "" {
		heading = pkgs + ": " + pick(isICEExcerpt(inc.ErrorExcerpt), "compiler ICE", "build failure")
	}
	errExcerpt := clipCode(sanitizeCode(strings.ReplaceAll(strings.TrimSpace(inc.ErrorExcerpt), "\r\n", "\n")), 8000)
	errHeading := pick(inc.isBuildFail(), "Build Error", "Error Excerpt")
	aliveOut := formatAliveTVOutput(inc)
	cleanedIR := inlineReducedIR(inc.ReducedIR)
	irBundleURL := pick(hasNonInlinedReducedIR(inc), strings.TrimSpace(inc.BundleURL), "")
	return struct {
		Nav             navHeader
		ID, Heading     string
		Rows            []kvRow
		ErrorHeading    string
		ErrorExcerpt    string
		AliveTVOutput   string
		ReproCmd        string
		CleanedIR       string
		IRBundleURL     string
		HighlightedDiff template.HTML
	}{nav, inc.ID, heading, rows, errHeading, errExcerpt, aliveOut, reproCommand(inc), cleanedIR, irBundleURL, highlightDiffHTML(clipCode(sanitizeCode(strings.TrimSpace(inc.PassDiff)), 18000))}
}

func toIncidentRow(inc *incident) incidentRowView {
	var plats []string
	for _, a := range inc.Affected {
		if a.Platform != "" {
			plats = append(plats, a.Platform)
		}
	}
	plats = sortedUnique(plats)
	targets := strings.Join(uniquePkgs([]*incident{inc}), ", ")
	if len(plats) > 0 {
		targets = pick(targets != "", targets+" ("+strings.Join(plats, ", ")+")", strings.Join(plats, ", "))
	}
	dash := func(s string) string { return cmp.Or(sanitizeText(strings.TrimSpace(s)), "-") }
	issueURL := strings.TrimSpace(inc.IssueURL)
	if !isSafeHTTPURL(issueURL) {
		issueURL = ""
	}
	commitRaw := inc.CulpritSHA
	pass := inc.CulpritPass
	if inc.isBuildFail() {
		commitRaw = cmp.Or(inc.CulpritSHA, inc.BadSHA)
		pass = pick(isICEExcerpt(inc.ErrorExcerpt), "build (ice)", "build")
	}
	commit := displaySHA(commitRaw)
	fixed := displaySHA(inc.FixedSHA)
	fixedURL := ""
	if inc.Status == incidentClosed {
		var lbls []string
		for _, l := range inc.Labels {
			if s := sanitizeText(strings.TrimSpace(l)); s != "" {
				lbls = append(lbls, s)
			}
		}
		fixed = cmp.Or(strings.Join(lbls, ", "), "closed")
	} else {
		fixedURL = llvmCommitURL(inc.FixedSHA)
	}
	return incidentRowView{
		ID:               inc.ID,
		CulpritSHA:       dash(commit),
		CulpritCommitURL: llvmCommitURL(commitRaw),
		FixedSHA:         dash(fixed),
		FixedCommitURL:   fixedURL,
		Pass:             dash(pass),
		Function:         dash(cmp.Or(strings.TrimSpace(inc.CulpritFunc), strings.TrimSpace(inc.CulpritTU))),
		Targets:          dash(targets),
		IssueNumber:      inc.IssueNumber,
		IssueURL:         issueURL,
	}
}

func highlightDiffHTML(diff string) template.HTML {
	if diff == "" {
		return ""
	}
	var b strings.Builder
	for i, line := range strings.Split(diff, "\n") {
		if i > 0 {
			b.WriteByte('\n')
		}
		esc := html.EscapeString(line)
		switch {
		case strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "+++ ") || strings.HasPrefix(line, "@@"):
			b.WriteString(`<span class="muted">` + esc + `</span>`)
		case strings.HasPrefix(line, "+"):
			b.WriteString(`<span class="diff-add">` + esc + `</span>`)
		case strings.HasPrefix(line, "-"):
			b.WriteString(`<span class="diff-del">` + esc + `</span>`)
		default:
			b.WriteString(esc)
		}
	}
	return template.HTML(b.String())
}

func displaySHA(sha string) string { return cmp.Or(hexSHA(sha), shortSHA(sha)) }

func formatDuration(sec float64) string {
	if sec <= 0 {
		return "ok"
	}
	if sec < 1 {
		return fmt.Sprintf("%.1fs", sec)
	}
	return fmt.Sprintf("%ds", int(math.Round(sec)))
}

func renderPage(path, name string, data any) error {
	var buf bytes.Buffer
	if err := siteTmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}
