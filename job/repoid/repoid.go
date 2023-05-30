// Package repoid implements a survey job reporting on the dnf repositories
// recorded in Red Hat containers.
package repoid

import (
	"archive/tar"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	digest "github.com/opencontainers/go-digest"
	"golang.org/x/exp/slog"
	_ "modernc.org/sqlite" // db driver

	"github.com/quay/rhcc-survey/job"
)

func init() {
	job.Register(new(Job), true)
}

// Job is the main entrypoint.
type Job struct{}

var _ job.Job = (*Job)(nil)

// Name implements Job.
func (*Job) Name() string { return "repoid" }

// SelectImage implements Job.
func (r *Job) SelectImage(_ context.Context, image string) job.LayerSelector {
	return &Selector{image: image}
}

// Record implements Job.
func (*Job) Record() any { return &Record{} }

// Selector is the layer selector.
type Selector struct {
	image string
	n     int
}

// SelectLayer implements LayerSelector.
func (s *Selector) SelectLayer(ctx context.Context, l digest.Digest, h *tar.Header) (hit, load bool, err error) {
	const wantpath = `/var/lib/dnf/history.sqlite`
	defer func() {
		s.n++
	}()
	ok := path.Join("/", h.Name) == wantpath
	if ok {
		slog.DebugCtx(ctx, "found database", "image", s.image, "layer", l, "pos", s.n, "path", wantpath)
		return true, true, nil
	}
	return false, false, nil
}

// Close implements LayerSelector.
func (s *Selector) Close() error {
	return nil
}

// Record is the data saved for layers
type Record struct {
	Found   bool
	RepoIDs string
}

// Analyzer implements Job.
func (r *Job) Analyzer() (job.Analyzer, error) {
	f, err := os.CreateTemp("", "rhcc-survey.repoid.")
	if err != nil {
		return nil, fmt.Errorf("repoid: create spool: %w", err)
	}
	return &Analyzer{spool: f}, nil
}

// Analyzer examines dnf history databases.
type Analyzer struct {
	spool *os.File
}

// Analyze implements Analyzer.
func (r *Analyzer) Analyze(ctx context.Context, contents io.Reader) (any, error) {
	if _, err := r.spool.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("repoid: seek: %w", err)
	}
	n, err := io.Copy(r.spool, contents)
	if err != nil {
		return nil, fmt.Errorf("repoid: copy: %w", err)
	}
	if err := errors.Join(r.spool.Truncate(n), r.spool.Sync()); err != nil {
		return nil, fmt.Errorf("repoid: sync: %w", err)
	}
	db, err := sql.Open("sqlite", r.spool.Name())
	if err != nil {
		return nil, fmt.Errorf("repoid: open sqlite: %w", err)
	}
	defer db.Close()

	var out Record
	err = db.QueryRowContext(ctx, `SELECT coalesce(group_concat(repoid),'') FROM repo;`).Scan(&out.RepoIDs)
	if err != nil {
		return nil, job.StoreError(err)
	}
	out.Found = true
	return &out, nil
}

// Close implements Analyzer.
func (r *Analyzer) Close() error {
	return errors.Join(
		os.Remove(r.spool.Name()),
		r.spool.Close(),
	)
}

// Reporter implements Job.
func (r *Job) Reporter() (job.Reporter, error) {
	return &Reporter{}, nil
}

// Close implements Job.
func (r *Job) Close() error {
	return nil
}

// Reporter does repoid reporting.
type Reporter struct {
	stats struct {
		Total int64
		Found int64
		Clean int64
	}
	repos map[string]struct{}
}

func (r *Reporter) exists(n string) bool {
	_, ok := r.repos[n]
	return ok
}

// Begin implements Reporter.
func (r *Reporter) Begin(_ context.Context, w io.Writer) error {
	const url = "https://access.redhat.com/security/data/metrics/repository-to-cpe.json"
	name := filepath.Join(job.CacheDir, "repository-to-cpe.json")
	if _, err := os.Stat(name); errors.Is(err, os.ErrNotExist) {
		f, err := os.Create(name)
		if err != nil {
			return err
		}
		defer f.Close()
		res, err := http.Get(url)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected response to %q: %s", url, res.Status)
		}
		if _, err := io.Copy(f, res.Body); err != nil {
			return err
		}
		f.Sync()
	}
	f, err := os.Open(name)
	if err != nil {
		return fmt.Errorf("repoid: open repo map: %w", err)
	}
	defer f.Close()
	var rmap struct {
		Data map[string]struct{} `json:"data"`
	}
	if err := json.NewDecoder(f).Decode(&rmap); err != nil {
		return fmt.Errorf("repoid: unmarshal repo map: %w", err)
	}
	r.repos = rmap.Data
	if _, err := fmt.Fprintf(w, "# <image>[@<layer>]\t<known>\t<unknown>\t<error>\n"); err != nil {
		return fmt.Errorf("repoid: print header: %w", err)
	}
	return nil
}

// Record implements Reporter.
func (r *Reporter) Record(_ context.Context, w io.Writer, layer string, _ int, v any, e error) error {
	rec := v.(*Record)
	r.stats.Total++
	if rec.Found {
		r.stats.Found++
	}
	var known, unknown []string
	var errText string
	for _, id := range strings.Split(rec.RepoIDs, ",") {
		if id == "@System" {
			continue
		}
		if r.exists(id) {
			known = append(known, id)
		} else {
			unknown = append(unknown, id)
		}
	}
	if rec.Found && len(unknown) == 0 && len(known) > 0 {
		r.stats.Clean++
	}
	if e != nil {
		errText = e.Error()
	}
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", layer, strings.Join(known, ","), strings.Join(unknown, ","), errText)
	if err != nil {
		return fmt.Errorf("repoid: writing line: %w", err)
	}
	return nil
}

// End implements Reporter.
func (r *Reporter) End(_ context.Context, w io.Writer) error {
	if _, err := fmt.Fprintf(w, "# total images: %d\n",
		r.stats.Total); err != nil {
		return fmt.Errorf("repoid: writing footer: %w", err)
	}
	pctFound := (float64(r.stats.Found) / float64(r.stats.Total)) * 100
	if _, err := fmt.Fprintf(w, "# dnf history databases found: %d (%.02f%%)\n",
		r.stats.Found, pctFound); err != nil {
		return fmt.Errorf("repoid: writing footer: %w", err)
	}
	foundClean, pctClean := (float64(r.stats.Clean)/float64(r.stats.Found))*100, (float64(r.stats.Clean)/float64(r.stats.Total))*100
	if _, err := fmt.Fprintf(w, "# databases with only known repos: %d (%.02f%% of found, %.02f%% of total)\n",
		r.stats.Clean, foundClean, pctClean); err != nil {
		return fmt.Errorf("repoid: writing footer: %w", err)
	}
	withUnknown := r.stats.Found - r.stats.Clean
	foundUnknown, pctUnknown := (float64(withUnknown)/float64(r.stats.Found))*100, (float64(withUnknown)/float64(r.stats.Total))*100
	if _, err := fmt.Fprintf(w, "# databases with unknown repos: %d (%.02f%% of found, %.02f%% of total)\n",
		withUnknown, foundUnknown, pctUnknown); err != nil {
		return fmt.Errorf("repoid: writing footer: %w", err)
	}
	return nil
}
