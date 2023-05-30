package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	digest "github.com/opencontainers/go-digest"
	"go.etcd.io/bbolt"
	"golang.org/x/exp/slices"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/rhcc-survey/job"
)

func queuePump(ctx context.Context, stats *analyzeStats, todo *bbolt.DB) (<-chan *fetchitem, func() error) {
	work := make(chan *fetchitem, runtime.GOMAXPROCS(0))

	if err := todo.View(func(tx *bbolt.Tx) error {
		stats.Total = uint64(tx.Bucket(keys.QueueID).Stats().KeyN)
		return nil
	}); err != nil {
		return nil, func() error {
			return fmt.Errorf("checking queue size: %w", err)
		}
	}

	return work, func() error {
		defer close(work)
		slog.DebugCtx(ctx, "queue pump start")
		defer slog.DebugCtx(ctx, "queue pump done")
		return todo.View(func(tx *bbolt.Tx) error {
			ids := tx.Bucket([]byte("id"))
			layers := tx.Bucket([]byte("layer"))
			lying := tx.Bucket([]byte("lying"))
			cur := ids.Cursor()
			for k, v := cur.First(); k != nil; k, v = cur.Next() {
				i := fetchitem{
					Image: string(k),
					ID:    string(v),
					Lying: bytes.Equal([]byte{'t'}, lying.Get(k)),
				}
				if err := json.Unmarshal(layers.Get(k), &i.Layers); err != nil {
					return fmt.Errorf("unmarshal layers: %w", err)
				}
				select {
				case <-ctx.Done():
					return context.Cause(ctx)
				case work <- &i:
					atomic.AddUint64(&stats.Enqueued, 1)
					slog.DebugCtx(ctx, "todo", "image", i.Image, "id", i.ID)
				}
			}
			return nil
		})
	}
}

func filterResults(ctx context.Context, stats *analyzeStats, results *bbolt.DB, in <-chan *fetchitem, jobs []job.Job) (<-chan *fetchitem, func() error) {
	out := make(chan *fetchitem, cap(in))
	return out, func() error {
		defer close(out)
		slog.DebugCtx(ctx, "filter goroutine start")
		defer slog.DebugCtx(ctx, "filter goroutine done")

		for {
			var i *fetchitem
			var ok bool
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case i, ok = <-in:
			}
			if !ok {
				return nil
			}
			log := slog.With("image", i.Image, "id", i.ID)

			imgb := []byte(i.Image)
			idb := []byte(i.ID)
			err := results.View(func(tx *bbolt.Tx) error {
				jb := tx.Bucket(keys.ResultsPerJob)
				for _, j := range jobs {
					n := j.Name()
					id := jb.Bucket([]byte(n)).
						Bucket(keys.ResultsPerJobID).
						Get(imgb)
					if !bytes.Equal(id, idb) {
						i.Jobs = append(i.Jobs, n)
					}
					log.DebugCtx(ctx, "results present", "job", n)
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("checking for results: %w", err)
			}

			if len(i.Jobs) == 0 {
				log.DebugCtx(ctx, "filtering")
				atomic.AddUint64(&stats.ResultsPresent, 1)
				continue
			}

			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case out <- i:
			}
		}
	}
}

func selectLayers(ctx context.Context, stats *analyzeStats, in <-chan *fetchitem, jobs []job.Job) ([]<-chan *analyzeitem, func() error) {
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(runtime.GOMAXPROCS(0))
	chs := make([]chan *analyzeitem, len(jobs))
	send, recv := make([]chan<- *analyzeitem, len(jobs)), make([]<-chan *analyzeitem, len(jobs))
	for i := range chs {
		ch := make(chan *analyzeitem, cap(in))
		chs[i] = ch
		send[i] = ch
		recv[i] = ch
	}
	return recv, func() error {
		defer func() {
			for i := range chs {
				close(chs[i])
			}
		}()
		var i int
		for eg.TryGo(func() error {
			return selectLayerWorker(ctx, stats, in, send, jobs)
		}) {
			i++
		}
		slog.Debug("launched layer selectors", "count", i)
		defer slog.Debug("ran layer selectors")
		return eg.Wait()
	}
}

func selectLayerWorker(ctx context.Context, stats *analyzeStats, in <-chan *fetchitem, out []chan<- *analyzeitem, jobs []job.Job) error {
	puller, err := remote.NewPuller(remote.WithContext(ctx),
		remote.WithUserAgent(`github.com/quay/rhcc-scanner@v1`),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
	if err != nil {
		return fmt.Errorf("puller create: %w", err)
	}
	for {
		var item *fetchitem
		var ok bool
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case item, ok = <-in:
		}
		if !ok { // Closed
			return nil
		}
		log := slog.With("image", item.Image, "id", item.ID)
		log.DebugCtx(ctx, "selecting layers")
		if len(item.Jobs) == 0 {
			log.WarnCtx(ctx, "zero-job item")
		}

		ij := make([]job.Job, len(jobs))
		for i, j := range jobs {
			if slices.Contains(item.Jobs, j.Name()) {
				ij[i] = j
			}
		}

		as, send, err := runSelectors(ctx, stats, puller, item, ij)
		if err != nil {
			return fmt.Errorf("run selectors: %w", err)
		}
		for i := range as {
			if send&uint64(1<<i) == 0 { // If not marked to send
				continue
			}
			a := &as[i]
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case out[i] <- a:
			}
		}
		log.DebugCtx(ctx, "selected layers")
	}
}

func runSelectors(ctx context.Context, stats *analyzeStats, puller *remote.Puller, item *fetchitem, jobs []job.Job) ([]analyzeitem, uint64, error) {
	// Set up for some per-layer stats.
	var counts struct {
		TotalLayers uint64
		HitLayers   uint64
	}
	// Defer doing the atomic writes until we're done with the image.
	defer func() {
		atomic.AddUint64(&stats.TotalLayers, counts.TotalLayers)
		atomic.AddUint64(&stats.HitLayers, counts.HitLayers)
	}()

	// Make a new set of selectors for this image.
	sel := make([]job.LayerSelector, len(jobs))
	for i, j := range jobs {
		if j != nil {
			sel[i] = jobs[i].SelectImage(ctx, item.Image)
		}
	}
	// Defer doing all the closes.
	defer func() {
		errs := make([]error, len(sel))
		for i, s := range sel {
			if s != nil {
				errs[i] = s.Close()
			}
		}
		if err := errors.Join(errs...); err != nil {
			slog.ErrorCtx(ctx, "error closing selectors", "error", err)
		}
	}()
	// Send is where we batch up every analyzeitem.
	//
	// This is the point in the pipeline where we have to split, as every job
	// can pick different features of different layers to forward to the next
	// step.
	items := make([]analyzeitem, len(jobs))
	for i := range items {
		a := &items[i]
		a.ID = item.ID
		a.Image = item.Image
		a.Index = -1
	}
	var se *job.StoredError
	// Bitset for indicating which items should be send onwards.
	var send uint64
	// BUG(hank) The survey tool can only currently run up to 64 different jobs
	// concurrently.
	err := item.ForEachLayer(ctx, puller, forEach(ctx, &counts.TotalLayers, &counts.HitLayers, sel, items, &send))
	switch {
	case errors.Is(err, nil):
	case errors.As(err, &se):
		// TODO(hank) Have the layer selector use a dedicated signal error. It's
		// currently using the StoredError as an internal signal.
		for i := range items {
			items[i].Err = se.Unwrap()
		}
		send = ^uint64(0)
	default:
		names := make([]string, len(jobs))
		for i, j := range jobs {
			names[i] = j.Name()
		}
		return nil, 0, fmt.Errorf("running job selectors %v: %w", names, err)
	}
	return items, send, nil
}

func forEach(ctx context.Context, total, hits *uint64, sel []job.LayerSelector, items []analyzeitem, send *uint64) func(int, digest.Digest, *tar.Reader) error {
	return func(li int, l digest.Digest, tr *tar.Reader) (err error) {
		(*total)++
		// Bitset for tracking when we're done.
		var done uint64
		// Nil selectors can never fire.
		var ignore uint64
		for i, s := range sel {
			if s == nil {
				ignore |= uint64(1 << i)
			}
		}
		var h *tar.Header
		for h, err = tr.Next(); err == nil && bits.OnesCount64(done) != len(sel); h, err = tr.Next() {
			select {
			case <-ctx.Done():
				err = context.Cause(ctx)
				break
			default:
			}
			var hit, load uint64
			var se *storedError

			for i, s := range sel {
				pos := uint64(1 << i)
				switch {
				case ignore&pos != 0: // Should ignore
					continue
				case done&pos != 0: // If this selector is done (i.e. hit previously)
					continue
				}
				didHit, doLoad, err := s.SelectLayer(ctx, l, h)
				switch {
				case errors.Is(err, nil):
				case errors.As(err, &se):
					// If a stored error is reported, update the analyze item
					// and the "done" map, but not the "hit" map. Falling
					// through to the hit map would mess up the hit count.
					items[i].Index = li
					items[i].Layer = l
					done |= pos
					continue
				default:
					return fmt.Errorf("running selector %d: %w", i, err)
				}
				if didHit {
					hit |= pos
				}
				if doLoad {
					load |= pos
				}
			}
			if hit != 0 { // If any selector hit
				(*hits)++
				for i := range sel {
					if hit&uint64(1<<i) != 0 { // If this selector hit
						items[i].Index = li
						items[i].Layer = l
					}
				}
			}
			if load != 0 { // If any selector wanted the file loaded
				b, err := io.ReadAll(tr)
				if err != nil {
					return fmt.Errorf("reading contents of %q: %w", h.Name, err)
				}
				for i := range sel {
					if load&uint64(1<<i) != 0 { // If this selector wanted the contents
						items[i].Contents = b
					}
				}
			}
			done |= hit // Update the "done" bitset.
		}
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, io.EOF):
		default:
			return fmt.Errorf("selecting layer: %w", err)
		}
		*send |= done
		return nil
	}
}

func (item *fetchitem) ForEachLayer(ctx context.Context, p *remote.Puller, f func(int, digest.Digest, *tar.Reader) error) error {
	img := item.Image
	if item.Lying {
		_, repo, ok := strings.Cut(item.Image, "/")
		if !ok {
			panic("programmer error: image name without '/': " + item.Image)
		}
		img = `registry.redhat.io/` + repo
	}
	for n, l := range item.Layers {
		d, err := name.NewDigest(img + "@" + l.String())
		if err != nil {
			return fmt.Errorf("error creating digest: %w", err)
		}
		rl, err := p.Layer(ctx, d)
		if err != nil { // Can have auth issues here, store it and short-circuit.
			return job.StoreError(err)
		}
		rc, err := rl.Uncompressed()
		if err != nil {
			return job.StoreError(err)
		}
		if err := func() error {
			defer rc.Close()
			tr := tar.NewReader(rc)
			return f(n, l, tr)
		}(); err != nil {
			return job.StoreError(err)
		}
	}
	return nil
}

func analyzeLayers(ctx context.Context, stats *analyzeStats, results *bbolt.DB, as []<-chan *analyzeitem, jobs []job.Job) func() error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(runtime.GOMAXPROCS(0))

	spawn := func(i int) func() error {
		job := jobs[i%len(jobs)]
		ch := as[i%len(as)]
		return func() error {
			log := slog.With(slog.String("job", job.Name()), slog.Int("id", i))
			a, err := job.Analyzer()
			if err != nil {
				return fmt.Errorf("creating analyzer for %q: %w", job.Name(), err)
			}
			defer func() {
				if err := a.Close(); err != nil {
					log.ErrorCtx(ctx, "error closing analyzer", "error", err)
				}
			}()
			log.Log(ctx, LevelTrace, "analyzer started")
			defer log.Log(ctx, LevelTrace, "analyzer done")
			for {
				var item *analyzeitem
				var ok bool
				select {
				case <-ctx.Done():
					return context.Cause(ctx)
				case item, ok = <-ch:
				}
				if !ok {
					return nil
				}
				log := log.With(
					slog.String("id", item.ID),
					slog.String("image", item.Image),
					slog.String("layer", item.Layer.String()),
				)
				log.DebugCtx(ctx, "analyzing")

				var mr []byte
				switch err := item.Err; {
				case errors.Is(err, nil):
					log.Log(ctx, LevelTrace, "OK")
					r, err := a.Analyze(ctx, bytes.NewReader(item.Contents))
					var se *storedError
					switch {
					case errors.Is(err, nil): // OK
					case errors.As(err, &se):
						item.Err = se.Unwrap()
						log.Log(ctx, slog.LevelInfo, "analyze errored", "error", err)
						atomic.AddUint64(&stats.Errored, 1)
					default:
						return fmt.Errorf("job %q: error: %w", job.Name(), err)
					}
					mr, err = json.Marshal(r)
					if err != nil {
						return fmt.Errorf("job %q: marshal error: %w", job.Name(), err)
					}
				case errors.Is(err, errNotFound):
					log.Log(ctx, LevelTrace, "not found")
					item.Err = nil
				default:
					log.Log(ctx, LevelTrace, "errored")
					atomic.AddUint64(&stats.Errored, 1)
				}

				idx, err := json.Marshal(item.Index)
				if err != nil {
					return fmt.Errorf("job %q: marshal error: %w", job.Name(), err)
				}
				var errText []byte
				if err := item.Err; err != nil {
					errText = []byte(err.Error())
				}
				jobKey := []byte(job.Name())
				if err := results.Batch(func(tx *bbolt.Tx) error {
					key := []byte(item.Image)
					id := []byte(item.ID)
					layer := []byte(item.Layer)
					b := tx.Bucket(keys.ResultsPerJob).Bucket(jobKey)
					return errors.Join(
						b.Bucket(keys.ResultsPerJobID).Put(key, id),
						b.Bucket(keys.ResultsPerJobLayer).Put(key, layer),
						b.Bucket(keys.ResultsPerJobPosition).Put(key, idx),
						b.Bucket(keys.ResultsPerJobError).Put(key, errText),
						b.Bucket(keys.ResultsPerJobRecord).Put(key, mr),
					)
				}); err != nil {
					return fmt.Errorf("writing result for %q: %w", job.Name(), err)
				}
				atomic.AddUint64(&stats.Recorded, 1)
			}
		}
	}

	return func() error {
		var i int
		for eg.TryGo(spawn(i)) {
			i++
		}
		slog.Debug("launched analyzers", "count", i)
		defer slog.Debug("ran analyzers")
		return eg.Wait()
	}
}
