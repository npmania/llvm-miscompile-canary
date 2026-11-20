package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	statusPass      = "pass"
	statusTestFail  = "test_fail"
	statusBuildFail = "build_fail"
	statusSkipped   = "skipped"

	incidentOpen     = "open"
	incidentResolved = "resolved"
	incidentClosed   = "closed"

	incidentKindMiscompile = "miscompile"
	incidentKindBuildFail  = "build_fail"

	confConfirmed   = "confirmed"
	confNeedsReview = "needs-review"
)

type pkgResult struct {
	Package      string   `json:"package"`
	Version      string   `json:"version,omitempty"`
	Platform     string   `json:"platform"`
	Profile      string   `json:"profile"`
	Status       string   `json:"status"`
	FailedTests  []string `json:"failed_tests,omitempty"`
	DurationSec  float64  `json:"duration_sec,omitempty"`
	ErrorExcerpt string   `json:"error_excerpt,omitempty"`
	IncidentID   string   `json:"incident_id,omitempty"`
}

type sweep struct {
	ID          string      `json:"id"`
	LLVMCommit  string      `json:"llvm_commit"`
	LLVMSubject string      `json:"llvm_subject,omitempty"`
	PreviousSHA string      `json:"previous_sha,omitempty"`
	StartedAt   time.Time   `json:"started_at"`
	CompletedAt time.Time   `json:"completed_at"`
	Results     []pkgResult `json:"results"`
}

type affected struct {
	Package  string `json:"package"`
	Version  string `json:"version,omitempty"`
	Platform string `json:"platform"`
	Profile  string `json:"profile"`
	TestID   string `json:"test_id"`
	GoodSHA  string `json:"good_sha,omitempty"`
}

type incident struct {
	ID                          string     `json:"id"`
	Kind                        string     `json:"kind,omitempty"`
	Title                       string     `json:"title"`
	Status                      string     `json:"status"`
	Confidence                  string     `json:"confidence"`
	GoodSHA                     string     `json:"good_sha"`
	BadSHA                      string     `json:"bad_sha"`
	CulpritSHA                  string     `json:"culprit_sha,omitempty"`
	CulpritSubject              string     `json:"culprit_subject,omitempty"`
	FixedSHA                    string     `json:"fixed_sha,omitempty"`
	CulpritTU                   string     `json:"culprit_tu,omitempty"`
	CulpritPass                 string     `json:"culprit_pass,omitempty"`
	CulpritPassIndex            int        `json:"culprit_pass_index,omitempty"`
	CulpritFunc                 string     `json:"culprit_func,omitempty"`
	DiagO0Status                string     `json:"diag_o0_status,omitempty"`
	ASanUBSanClean              bool       `json:"asan_ubsan_clean"`
	ConservativeFlagIndependent bool       `json:"conservative_flag_independent"`
	AliveTVStatus               string     `json:"alive_tv_status,omitempty"`
	AliveTVOutput               string     `json:"alive_tv_output,omitempty"`
	LLUBIStatus                 string     `json:"llubi_status,omitempty"`
	LLUBIOutput                 string     `json:"llubi_output,omitempty"`
	ReducedIR                   string     `json:"reduced_ir,omitempty"`
	StandaloneReproCmd          string     `json:"standalone_repro_cmd,omitempty"`
	PassDiff                    string     `json:"pass_diff,omitempty"`
	ErrorExcerpt                string     `json:"error_excerpt,omitempty"`
	BundleURL                   string     `json:"bundle_url,omitempty"`
	IssueNumber                 int        `json:"issue_number,omitempty"`
	IssueURL                    string     `json:"issue_url,omitempty"`
	Labels                      []string   `json:"labels,omitempty"`
	Affected                    []affected `json:"affected"`
	CreatedAt                   time.Time  `json:"created_at"`
	UpdatedAt                   time.Time  `json:"updated_at"`
	ResolvedAt                  *time.Time `json:"resolved_at,omitempty"`
}

type state struct {
	LastSweepSHA       string            `json:"last_sweep_sha,omitempty"`
	LastSweepID        string            `json:"last_sweep_id,omitempty"`
	LastSweepAt        *time.Time        `json:"last_sweep_at,omitempty"`
	LastGoodSHA        string            `json:"last_good_sha,omitempty"`
	LastGoodByTarget   map[string]string `json:"last_good_by_target,omitempty"`
	ActiveIncidentIDs  []string          `json:"active_incident_ids,omitempty"`
	RetainedToolchains []string          `json:"retained_toolchains,omitempty"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

func targetKey(pkg, plat, prof string) string { return pkg + "|" + plat + "|" + prof }

func formatSweepID(ts time.Time, sha string) string {
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	s := shortSHA(sha)
	if s == "" {
		s = "unknown"
	}
	return ts.UTC().Format("20060102T150405Z") + "-" + s
}

func (i *incident) isBuildFail() bool {
	return i != nil && i.Kind == incidentKindBuildFail
}

func isICEExcerpt(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), "[compiler ICE]") || detectICE(s)
}

func (s *state) targetGoodSHA(pkg, plat, prof string) string {
	if s == nil {
		return ""
	}
	return s.LastGoodByTarget[targetKey(pkg, plat, prof)]
}

func (s *state) goodSHAFor(pkg, plat, prof string) string {
	if sha := s.targetGoodSHA(pkg, plat, prof); sha != "" {
		return sha
	}
	if s == nil {
		return ""
	}
	return s.LastGoodSHA
}

func (i *incident) mergeAffected(targets ...affected) bool {
	changed := false
	for _, t := range targets {
		idx := slices.IndexFunc(i.Affected, func(c affected) bool {
			return c.Package == t.Package && c.Platform == t.Platform && c.Profile == t.Profile && c.TestID == t.TestID
		})
		if idx < 0 {
			i.Affected = append(i.Affected, t)
			changed = true
			continue
		}
		if i.Affected[idx].GoodSHA == "" && t.GoodSHA != "" {
			i.Affected[idx].GoodSHA = t.GoodSHA
			changed = true
		}
		if i.Affected[idx].Version == "" && t.Version != "" {
			i.Affected[idx].Version = t.Version
			changed = true
		}
	}
	return changed
}

func sortAffected(list []affected) {
	slices.SortFunc(list, func(a, b affected) int {
		return cmp.Or(
			cmp.Compare(a.Package, b.Package),
			cmp.Compare(a.Platform, b.Platform),
			cmp.Compare(a.Profile, b.Profile),
			cmp.Compare(a.TestID, b.TestID),
		)
	})
}

func dedupKey(inc *incident) string {
	if inc == nil {
		return ""
	}
	if inc.isBuildFail() {
		var pkg string
		good := shortSHA(inc.GoodSHA)
		if len(inc.Affected) > 0 {
			sorted := slices.Clone(inc.Affected)
			sortAffected(sorted)
			pkg = strings.TrimSpace(sorted[0].Package)
			if good == "" {
				good = shortSHA(sorted[0].GoodSHA)
			}
		}
		if pkg != "" && good != "" {
			return fmt.Sprintf("build:%s|%s", keyToken(pkg), keyToken(good))
		}
		if pkg != "" {
			return "build:" + keyToken(pkg)
		}
		return "incident:" + keyToken(inc.ID)
	}
	if sha := shortSHA(inc.CulpritSHA); sha != "" {
		return "culprit:" + keyToken(sha)
	}
	pass := strings.TrimSpace(inc.CulpritPass)
	if pass == "" {
		pass = "unknown-pass"
	}
	if len(inc.Affected) > 0 {
		sorted := slices.Clone(inc.Affected)
		sortAffected(sorted)
		f := sorted[0]
		return fmt.Sprintf("pass:%s|%s|%s", keyToken(f.Package), keyToken(f.TestID), keyToken(pass))
	}
	return fmt.Sprintf("incident:%s|%s", keyToken(inc.ID), keyToken(pass))
}

func keyToken(s string) string {
	s = sanitizeText(strings.TrimSpace(s))
	var b strings.Builder
	prevUnder := false
	for i := 0; i < len(s); {
		if s[i] == '-' {
			j := i
			for j < len(s) && s[j] == '-' {
				j++
			}
			if j-i == 1 {
				b.WriteByte('-')
				prevUnder = false
			} else if !prevUnder {
				b.WriteByte('_')
				prevUnder = true
			}
			i = j
			continue
		}
		r, sz := utf8.DecodeRuneInString(s[i:])
		i += sz
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'),
			r == '.', r == ':', r == '|', r == '/':
			b.WriteRune(r)
			prevUnder = false
		default:
			if !prevUnder {
				b.WriteByte('_')
				prevUnder = true
			}
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "unknown"
	}
	return out
}

func isOmittedFormalStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "unavailable", "not_run", "not run", "skipped", "skipped / unavailable", "skipped / not applicable":
		return true
	}
	return false
}

func shouldUpgradeFormal(cur, cand string) bool {
	if isOmittedFormalStatus(cand) {
		return false
	}
	return isOmittedFormalStatus(cur) || (cur == "unsupported" && cand != "unsupported")
}

func recordSweep(st *state, rec sweep, incidents []*incident) {
	if st.LastGoodByTarget == nil {
		st.LastGoodByTarget = make(map[string]string)
	}
	ts := rec.CompletedAt
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	st.LastSweepSHA, st.LastSweepID, st.LastSweepAt, st.UpdatedAt = rec.LLVMCommit, rec.ID, &ts, ts

	anyFail := false
	for _, r := range rec.Results {
		if r.Status == statusPass {
			st.LastGoodByTarget[targetKey(r.Package, r.Platform, r.Profile)] = rec.LLVMCommit
		} else {
			anyFail = true
		}
	}
	if !anyFail && len(rec.Results) > 0 && rec.LLVMCommit != "" {
		st.LastGoodSHA = rec.LLVMCommit
	}
	refreshStateIncidents(st, incidents, false)
}

func refreshStateIncidents(st *state, incidents []*incident, keepRetained bool) {
	var active []string
	retainedSet := make(map[string]struct{})
	if keepRetained {
		for _, sha := range st.RetainedToolchains {
			if sha != "" {
				retainedSet[sha] = struct{}{}
			}
		}
	}
	for _, inc := range incidents {
		if inc == nil || inc.Status != incidentOpen {
			continue
		}
		active = append(active, inc.ID)
		if inc.GoodSHA != "" {
			retainedSet[inc.GoodSHA] = struct{}{}
		}
		if inc.BadSHA != "" {
			retainedSet[inc.BadSHA] = struct{}{}
		}
		for _, a := range inc.Affected {
			if a.GoodSHA != "" {
				retainedSet[a.GoodSHA] = struct{}{}
			}
		}
	}
	st.ActiveIncidentIDs = active
	retained := make([]string, 0, len(retainedSet))
	for sha := range retainedSet {
		retained = append(retained, sha)
	}
	slices.Sort(retained)
	st.RetainedToolchains = retained
}

func loadState(dir string) (*state, error) {
	var st state
	err := readJSON(filepath.Join(dir, "state.json"), &st)
	if errors.Is(err, fs.ErrNotExist) {
		return &state{LastGoodByTarget: make(map[string]string)}, nil
	}
	if err != nil {
		return nil, err
	}
	if st.LastGoodByTarget == nil {
		st.LastGoodByTarget = make(map[string]string)
	}
	return &st, nil
}

func saveState(dir string, st *state) error {
	if st.UpdatedAt.IsZero() {
		st.UpdatedAt = time.Now().UTC()
	}
	return writeJSONAtomic(filepath.Join(dir, "state.json"), st)
}

func saveSweep(dir string, rec *sweep) (string, error) {
	if rec.ID == "" {
		ts := rec.CompletedAt
		if ts.IsZero() {
			ts = rec.StartedAt
		}
		rec.ID = formatSweepID(ts, rec.LLVMCommit)
	}
	if err := validateSafeID("sweep id", rec.ID); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "sweeps", rec.ID+".json")
	return path, writeJSONAtomic(path, rec)
}

func loadAllSweeps(dir string) ([]*sweep, error) {
	out, err := readJSONDir[sweep](filepath.Join(dir, "sweeps"))
	if err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b *sweep) int {
		return cmp.Or(b.CompletedAt.Compare(a.CompletedAt), b.StartedAt.Compare(a.StartedAt), cmp.Compare(b.ID, a.ID))
	})
	return out, nil
}

func saveIncident(dir string, inc *incident) (string, error) {
	if err := validateSafeID("incident id", inc.ID); err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if inc.CreatedAt.IsZero() {
		inc.CreatedAt = now
	}
	if inc.UpdatedAt.IsZero() {
		inc.UpdatedAt = now
	}
	path := filepath.Join(dir, "incidents", inc.ID+".json")
	return path, writeJSONAtomic(path, inc)
}

func loadAllIncidents(dir string) ([]*incident, error) {
	out, err := readJSONDir[incident](filepath.Join(dir, "incidents"))
	if err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b *incident) int {
		return cmp.Or(b.CreatedAt.Compare(a.CreatedAt), cmp.Compare(b.ID, a.ID))
	})
	return out, nil
}

func readJSONDir[T any](dir string) ([]*T, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*T
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		var item T
		if err := readJSON(filepath.Join(dir, ent.Name()), &item); err != nil {
			return nil, err
		}
		out = append(out, &item)
	}
	return out, nil
}

func mergeIncident(dir string, inc *incident) (*incident, error) {
	existing, err := loadAllIncidents(dir)
	if err != nil {
		return nil, err
	}
	usedIDs := make(map[string]bool, len(existing))
	for _, ex := range existing {
		if ex != nil && ex.ID != "" {
			usedIDs[ex.ID] = true
		}
	}
	key := dedupKey(inc)
	var target *incident
	for _, ex := range existing {
		if ex == nil || ex.Status != incidentOpen || key == "" || dedupKey(ex) != key {
			continue
		}
		targets := slices.Clone(inc.Affected)
		if inc.GoodSHA != "" && inc.GoodSHA != ex.GoodSHA {
			for i := range targets {
				targets[i].GoodSHA = cmp.Or(targets[i].GoodSHA, inc.GoodSHA)
			}
		}
		ex.mergeAffected(targets...)
		setIfEmpty(&ex.Kind, inc.Kind)
		if inc.ErrorExcerpt != "" && (ex.ErrorExcerpt == "" || (!isICEExcerpt(ex.ErrorExcerpt) && isICEExcerpt(inc.ErrorExcerpt))) {
			ex.ErrorExcerpt = inc.ErrorExcerpt
			if ex.isBuildFail() && isICEExcerpt(ex.ErrorExcerpt) {
				if pkgs := uniquePkgs([]*incident{ex}); len(pkgs) > 0 {
					ex.Title = sanitizeText(strings.Join(pkgs, ", ") + ": compiler ICE")
				}
			}
		}
		if ex.Confidence != confConfirmed && inc.Confidence == confConfirmed {
			ex.Confidence = confConfirmed
		}
		if inc.ASanUBSanClean {
			ex.ASanUBSanClean = true
		}
		if inc.ConservativeFlagIndependent {
			ex.ConservativeFlagIndependent = true
		}
		if ex.CulpritSHA == "" && inc.CulpritSHA != "" {
			ex.CulpritSHA, ex.CulpritSubject = inc.CulpritSHA, inc.CulpritSubject
		}
		if ex.CulpritPass == "" && inc.CulpritPass != "" {
			ex.CulpritPass, ex.CulpritPassIndex = inc.CulpritPass, inc.CulpritPassIndex
		}
		setIfEmpty(&ex.CulpritFunc, inc.CulpritFunc)
		setIfEmpty(&ex.CulpritTU, inc.CulpritTU)
		setIfEmpty(&ex.ReducedIR, inc.ReducedIR)
		setIfEmpty(&ex.PassDiff, inc.PassDiff)
		setIfEmpty(&ex.BundleURL, inc.BundleURL)
		if shouldUpgradeFormal(ex.AliveTVStatus, inc.AliveTVStatus) {
			ex.AliveTVStatus, ex.AliveTVOutput = inc.AliveTVStatus, inc.AliveTVOutput
		}
		if shouldUpgradeFormal(ex.LLUBIStatus, inc.LLUBIStatus) {
			ex.LLUBIStatus, ex.LLUBIOutput = inc.LLUBIStatus, inc.LLUBIOutput
		}
		ex.UpdatedAt = time.Now().UTC()
		target = ex
		break
	}
	if target == nil {
		if usedIDs[inc.ID] {
			inc.ID = uniqueIncidentID(inc.ID, usedIDs)
		}
		target = inc
	}

	if _, err := saveIncident(dir, target); err != nil {
		return nil, err
	}
	st, err := loadState(dir)
	if err != nil {
		return nil, err
	}
	all, err := loadAllIncidents(dir)
	if err != nil {
		return nil, err
	}
	refreshStateIncidents(st, all, true)
	st.UpdatedAt = time.Now().UTC()
	return target, saveState(dir, st)
}

func uniqueIncidentID(base string, used map[string]bool) string {
	for n := 2; ; n++ {
		cand := fmt.Sprintf("%s-%d", base, n)
		if !used[cand] {
			return cand
		}
	}
}

func setIfEmpty(dst *string, val string) {
	if *dst == "" && val != "" {
		*dst = val
	}
}

func writeResultFragment(path string, results []pkgResult) error {
	return writeJSONAtomic(path, results)
}

func readResultFragments(dir string) ([]pkgResult, error) {
	var all []pkgResult
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return walkErr
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var list []pkgResult
		if json.Unmarshal(data, &list) == nil {
			all = append(all, list...)
			return nil
		}
		var one pkgResult
		if err := json.Unmarshal(data, &one); err != nil {
			return fmt.Errorf("parse fragment %s: %w", path, err)
		}
		all = append(all, one)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(all, func(a, b pkgResult) int {
		return cmp.Or(cmp.Compare(a.Package, b.Package), cmp.Compare(a.Platform, b.Platform), cmp.Compare(a.Profile, b.Profile))
	})
	return all, nil
}

func validateSafeID(label, id string) error {
	if id == "" || id == "." || strings.Contains(id, "/") || strings.Contains(id, "\\") || strings.Contains(id, "..") {
		return fmt.Errorf("invalid %s %q", label, id)
	}
	return nil
}

func readJSON(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func writeJSONAtomic(path string, val any) error {
	data, err := json.MarshalIndent(val, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	ok = true
	return nil
}
