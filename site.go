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
type navHeader struct{ RootPrefix, LatestSHA12, UpdatedUTC, UpdatedISO string }
type matrixColumn struct{ Platform, Profile, Header string }
type matrixCell struct{ Kind, Text, IncidentID string }
type matrixRow struct {
	Package, Version string
	Cells            []matrixCell
}
type incidentRowView struct {
	ID, CulpritSHA, FixedSHA, Pass, Function, Targets, IssueURL string
	IssueNumber                                                 int
}
type kvRow struct{ Label, Value template.HTML }

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
	if err := renderPage(filepath.Join(outDir, "index.html"), "index.html", buildIndexData(st, sweeps, incs, catalog)); err != nil {
		return err
	}
	if err := renderPage(filepath.Join(outDir, "corpus", "index.html"), "corpus.html", struct {
		Nav      navHeader
		Packages []corpusEntry
	}{resolveNav(st, sweeps, "../"), catalog}); err != nil {
		return err
	}
	for _, inc := range incs {
		if inc == nil || inc.ID == "" {
			continue
		}
		if err := validateSafeID("incident id", inc.ID); err != nil {
			return err
		}
		dir := filepath.Join(outDir, "incidents", inc.ID)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := renderPage(filepath.Join(dir, "index.html"), "incident.html", buildIncidentData(st, sweeps, inc)); err != nil {
			return err
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

func resolveNav(st *state, sweeps []*sweep, prefix string) navHeader {
	sha := "-"
	var ts time.Time
	if len(sweeps) > 0 {
		sha, ts = cmp.Or(displaySHA(sweeps[0].LLVMCommit), "-"), sweeps[0].CompletedAt
		if ts.IsZero() {
			ts = sweeps[0].StartedAt
		}
	} else if st != nil && st.LastSweepSHA != "" {
		sha, ts = cmp.Or(displaySHA(st.LastSweepSHA), "-"), st.UpdatedAt
		if st.LastSweepAt != nil && !st.LastSweepAt.IsZero() {
			ts = *st.LastSweepAt
		}
	}
	if ts.IsZero() {
		return navHeader{prefix, sha, "-", ""}
	}
	return navHeader{prefix, sha, ts.UTC().Format("2006-01-02 15:04 UTC"), ts.UTC().Format(time.RFC3339)}
}

func buildIndexData(st *state, sweeps []*sweep, incs []*incident, catalog []corpusEntry) any {
	type cellKey struct{ pkg, plat, prof string }
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
	openByTarget := make(map[cellKey]string)
	var openRows, resolvedRows []incidentRowView
	for _, inc := range incs {
		if inc == nil {
			continue
		}
		rv := toIncidentRow(inc)
		if inc.Status == incidentResolved {
			resolvedRows = append(resolvedRows, rv)
			continue
		}
		openRows = append(openRows, rv)
		for _, a := range inc.Affected {
			if k := (cellKey{a.Package, a.Platform, a.Profile}); openByTarget[k] == "" {
				openByTarget[k] = inc.ID
			}
		}
	}
	ordered := slices.Clone(catalog)
	for _, name := range sortedUnique(extras) {
		ordered = append(ordered, corpusEntry{Name: name})
	}
	rows := make([]matrixRow, 0, len(ordered))
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
			case statusTestFail:
				row.Cells = append(row.Cells, matrixCell{"fail", "fail", cmp.Or(res.IncidentID, openByTarget[ck])})
			case statusBuildFail:
				row.Cells = append(row.Cells, matrixCell{"err", "err", ""})
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
		Columns           []matrixColumn
		Rows              []matrixRow
	}{resolveNav(st, sweeps, ""), openRows, resolvedRows, matrixCols, rows}
}

func buildIncidentData(st *state, sweeps []*sweep, inc *incident) any {
	rawRows := incidentMetaRows([]*incident{inc}, true, "")
	rows := make([]kvRow, len(rawRows))
	for i, r := range rawRows {
		rows[i] = kvRow{template.HTML(r[0]), template.HTML(r[1])}
	}
	nav := resolveNav(st, sweeps, "../../")
	if nav.LatestSHA12 == "-" {
		nav.LatestSHA12 = cmp.Or(displaySHA(inc.BadSHA), "-")
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
	}
	return struct {
		Nav             navHeader
		ID, Heading     string
		Rows            []kvRow
		OptCmd          string
		CleanedIR       string
		HighlightedDiff template.HTML
	}{nav, inc.ID, heading, rows, optCommand(inc.CulpritPass), cleanIR(inc.ReducedIR), highlightDiffHTML(strings.TrimSpace(inc.PassDiff))}
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
	return incidentRowView{
		ID:          inc.ID,
		CulpritSHA:  dash(displaySHA(inc.CulpritSHA)),
		FixedSHA:    dash(displaySHA(inc.FixedSHA)),
		Pass:        dash(inc.CulpritPass),
		Function:    dash(cmp.Or(strings.TrimSpace(inc.CulpritFunc), strings.TrimSpace(inc.CulpritTU))),
		Targets:     dash(targets),
		IssueNumber: inc.IssueNumber,
		IssueURL:    strings.TrimSpace(inc.IssueURL),
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
