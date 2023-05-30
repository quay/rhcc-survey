// Rhcc-survey is a tool and framework for running survey jobs across the Red
// Hat Container Catalog.
//
// This tool expects access to "registry.redhat.io" to be configured via the
// usual podman/docker means.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	digest "github.com/opencontainers/go-digest"
	"go.etcd.io/bbolt"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/rhcc-survey/job"
	_ "github.com/quay/rhcc-survey/job/repoid"
)

// LevelTrace is the lowest slog Level.
const LevelTrace slog.Level = -9

func main() {
	var app app
	var opts appOptions
	var loglevel = new(slog.LevelVar)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: loglevel,
	})))
	dir, err := os.UserCacheDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cachedir = filepath.Join(dir, "rhcc-survey")

	fset := flag.NewFlagSet("rhcc-survey", flag.ExitOnError)
	debugFlag := fset.Bool("D", false, "debug logging")
	traceFlag := fset.Bool("DD", false, "trace logging")
	fset.StringVar(&opts.HydraURL, "hydra", "https://access.redhat.com/hydra/rest/search/kcs", "`URL` of the hydra instance to query")
	fset.StringVar(&opts.RhccURL, "container-catalog", "https://catalog.redhat.com/api/containers/", "`URL` of the container catalog API to query")
	fset.StringVar(&opts.QueueDB, "queue-db", "todo.bolt", "`file` to read or record a queue of images")
	fset.StringVar(&opts.ResultsDB, "results-db", "results.bolt", "`file` to read or record results")
	fset.StringVar(&opts.RepoFilter, "repo-disallow", `beta|preview`, "disallow repositories matching `regexp`\n"+
		"(Needed because some container images are tagged incorrectly in hydra.)")
	fset.BoolVar(&opts.Steps.Enqueue, "step-enqueue", true, "build a queue of images to survey:\n"+
		"search hydra for container repos and resolve the latest layers via the container catalog API")
	fset.BoolVar(&opts.Steps.Analyze, "step-analyze", true, "run the analysis step:\n"+
		"stream layers found in the enqueue step and look for interesting files")
	fset.BoolVar(&opts.Steps.Report, "step-report", true, "run the reporting step:\n"+
		"read and format results recorded by the analysis step")
	fset.BoolVar(&opts.Steps.Clean, "step-clean", false, "run the clean step:\n"+
		"remove error results prior to running")
	fset.BoolVar(&opts.Steps.Compact, "step-compact", false, "run the compact step:\n"+
		"compact written data on exit")
	fset.StringVar(&opts.Jobs, "jobs", strings.Join(job.Defaults(), ","), "which survey `jobs` to run\n"+
		fmt.Sprintf("available: %s", strings.Join(job.Available(), ",")))
	fset.Usage = func() { usage(fset) }
	fset.Parse(os.Args[1:])

	opts.SearchPatterns = make([]string, fset.NArg())
	copy(opts.SearchPatterns, fset.Args())
	if len(opts.SearchPatterns) == 0 {
		opts.SearchPatterns = append(opts.SearchPatterns, "*")
	}

	if *debugFlag {
		loglevel.Set(slog.LevelDebug)
	}
	if *traceFlag {
		loglevel.Set(LevelTrace)
	}

	ctx := context.Background()
	ctx, done := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	go func() {
		<-ctx.Done()
		done() // Unregister the signal handler right away so repeated signals get the default behavior.
	}()
	if err := app.Init(ctx, &opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := app.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage(fset *flag.FlagSet) {
	fmt.Fprintln(fset.Output(), "Usage of rhcc-survey:")
	fmt.Fprintf(fset.Output(), "%s [<options>] [<patterns>...]\n", os.Args[0])
	fmt.Fprintln(fset.Output(), "")
	fmt.Fprintln(fset.Output(), "Patterns are Solr search patterns (https://solr.apache.org/guide/8_11/the-standard-query-parser.html).")
	fmt.Fprintln(fset.Output(), "The directory used for extracting files from layers can be controlled with `TMPDIR`.")
	fmt.Fprintln(fset.Output(), "The number of worker spawned can be controlled with `GOMAXPROCS`.")
	fmt.Fprintln(fset.Output(), "")
	fset.PrintDefaults()
}

type app struct {
	queue, results *bbolt.DB
	hydra, rhcc    *url.URL
	repoFilter     *regexp.Regexp
	pat            []string
	job            []job.Job
	steps          steps
}

func (a *app) Init(ctx context.Context, opt *appOptions) error {
	const dbMode = 0o644
	dbOpts := bbolt.Options{
		Timeout:         5 * time.Second,
		FreelistType:    bbolt.FreelistMapType,
		InitialMmapSize: 4 * (1 << 20),
	}
	a.pat = opt.SearchPatterns
	a.steps = opt.Steps

	var err error
	defer func() {
		if err == nil {
			return
		}
		err = errors.Join(err,
			func() error {
				if db := a.queue; db != nil {
					return db.Close()
				}
				return nil
			}(),
			func() error {
				if db := a.results; db != nil {
					return db.Close()
				}
				return nil
			}(),
		)
	}()
	a.job, err = job.Jobs(strings.Split(opt.Jobs, ","))
	if err != nil {
		return err
	}
	a.hydra, err = url.Parse(opt.HydraURL)
	if err != nil {
		return err
	}
	a.rhcc, err = url.Parse(opt.RhccURL)
	if err != nil {
		return err
	}
	a.repoFilter, err = regexp.Compile(opt.RepoFilter)
	if err != nil {
		return err
	}
	a.queue, err = bbolt.Open(opt.QueueDB, dbMode, &dbOpts)
	if err != nil {
		return err
	}
	err = setupQueue(ctx, a.queue)
	if err != nil {
		return err
	}
	a.results, err = bbolt.Open(opt.ResultsDB, dbMode, &dbOpts)
	if err != nil {
		return err
	}
	err = setupResults(ctx, a.results, a.job)
	if err != nil {
		return err
	}

	return nil
}

type appOptions struct {
	QueueDB        string
	ResultsDB      string
	HydraURL       string
	RhccURL        string
	RepoFilter     string
	Jobs           string
	SearchPatterns []string
	Steps          steps
}

func (a *app) Run(ctx context.Context) error {
	var wroteQueue, wroteResults bool
	defer func() {
		var errs []error
		compact := func(db *bbolt.DB) {
			p := db.Path()
			n := p + ".new"
			ndb, err := bbolt.Open(n, 0644, nil)
			if err != nil {
				errs = append(errs, err)
				return
			}
			defer func() { errs = append(errs, ndb.Close()) }()
			if err := bbolt.Compact(ndb, db, 65535); err != nil {
				errs = append(errs, err)
				return
			}
			errs = append(errs, os.Rename(n, p))
			slog.DebugCtx(ctx, "compacted database", "path", p)
		}
		if a.steps.Compact && wroteQueue {
			compact(a.queue)
		}
		if a.steps.Compact && wroteResults {
			compact(a.results)
		}
		if err := errors.Join(append(errs, a.queue.Close(), a.results.Close())...); err != nil {
			slog.ErrorCtx(ctx, "closing databases", "error", err)
		}
	}()

	if a.steps.Clean {
		slog.InfoCtx(ctx, "clean starting")
		errs := make([]error, 0, len(a.job))
		for _, j := range a.job {
			err := a.results.Update(func(tx *bbolt.Tx) error {
				job := tx.Bucket(keys.ResultsPerJob).
					Bucket([]byte(j.Name()))
				cur := job.
					Bucket(keys.ResultsPerJobError).
					Cursor()
				for k, v := cur.First(); k != nil; k, v = cur.Next() {
					if len(v) == 0 {
						continue
					}
					slog.DebugCtx(ctx, "removing result", "layer", fmt.Sprintf("%s@%s", k, job.Bucket(keys.ResultsPerJobLayer).Get(k)), "error", v)
					err := job.ForEachBucket(func(b []byte) error {
						return job.Bucket(b).Delete(k)
					})
					if err != nil {
						return err
					}
				}
				return nil
			})
			errs = append(errs, err)
		}
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("clean: %w", err)
		}
		slog.InfoCtx(ctx, "clean done")
	}

	var todo chan *fetchitem
	if a.steps.Enqueue && a.steps.Analyze {
		todo = make(chan *fetchitem, runtime.GOMAXPROCS(0))
	}
	step, stepCtx := errgroup.WithContext(ctx)
	if a.steps.Enqueue {
		queue := queueMaker{
			db:           a.queue,
			hydra:        a.hydra,
			rhcc:         a.rhcc,
			repoDisallow: a.repoFilter,
			pat:          a.pat,
		}
		wroteQueue = true
		step.Go(func() error {
			slog.InfoCtx(stepCtx, "enqueue starting")
			defer slog.InfoCtx(stepCtx, "enqueue done")
			if err := queue.Run(stepCtx, todo); err != nil {
				return fmt.Errorf("enqueue: %w", err)
			}
			return nil
		})
	}

	if a.steps.Analyze {
		wroteResults = true
		step.Go(func() error {
			eg, ctx := errgroup.WithContext(stepCtx)
			var stats analyzeStats
			// All the setup for the various goroutines:
			var pump func() error
			var work <-chan *fetchitem
			if todo == nil {
				work, pump = queuePump(ctx, &stats, a.queue)
			} else {
				work = todo
			}
			filtered, runFilter := filterResults(ctx, &stats, a.results, work, a.job)
			analysis, runSelect := selectLayers(ctx, &stats, filtered, a.job)
			runAnalysis := analyzeLayers(ctx, &stats, a.results, analysis, a.job)
			// Start everything:
			if pump != nil {
				eg.Go(pump)
			}
			eg.Go(runFilter)
			eg.Go(runSelect)
			eg.Go(runAnalysis)
			go stats.progress(ctx)

			slog.InfoCtx(ctx, "analysis starting")
			defer slog.InfoCtx(ctx, "analysis done")
			if err := eg.Wait(); err != nil {
				return fmt.Errorf("analysis: %w", err)
			}
			return nil
		})
	}
	switch err := step.Wait(); {
	case errors.Is(err, nil):
	case errors.Is(err, context.Canceled):
	default:
		return err
	}

	if a.steps.Report {
		out := os.Stderr
		var errd bool
		for _, j := range a.job {
			r, err := j.Reporter()
			if err != nil {
				errd = true
				fmt.Fprintln(out, "##", j.Name(), "--", err)
				continue
			}
			if err := runReporter(ctx, out, a.results, j, r); err != nil {
				errd = true
				fmt.Fprintln(out, "##", j.Name(), "--", err)
			}
		}
		if errd {
			return errors.New("errored generating report")
		}
	}

	return nil
}

type steps struct {
	Clean   bool
	Enqueue bool
	Analyze bool
	Report  bool
	Compact bool
}

func launchCt(nJobs int) int {
	ct := runtime.GOMAXPROCS(0) / nJobs
	if ct == 0 {
		ct = 1
	}
	return ct
}

type fetchitem struct {
	ID     string
	Image  string
	Layers []digest.Digest
	Jobs   []string
	Lying  bool
}

type analyzeitem struct {
	ID       string
	Image    string
	Index    int
	Layer    digest.Digest
	Contents []byte
	Err      error
}

var _ error = (*storedError)(nil)

type storedError struct {
	Inner error
}

func storedErr(err error) error {
	return &storedError{
		Inner: err,
	}
}

func (e *storedError) Error() string {
	return ""
}
func (e *storedError) Unwrap() error {
	return e.Inner
}

var (
	errSkip     = errors.New("skip this layer")
	errNotFound = errors.New("not found")

	cachedir string
)
