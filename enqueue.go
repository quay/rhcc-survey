package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	digest "github.com/opencontainers/go-digest"
	"go.etcd.io/bbolt"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"
)

type hydraResponse struct {
	Response struct {
		Found json.Number `json:"numFound"`
		Start json.Number `json:"start"`
		Docs  []hydraDoc  `json:"docs"`
	} `json:"response"`
}

type hydraDoc struct {
	ID         string `json:"id"`
	Lying      bool   `json:"requires_terms"`
	Repository string `json:"repository"`
	Registry   string `json:"registry"`
}

type imagesResponse struct {
	Data []imagesEntry `json:"data"`
}
type imagesEntry struct {
	ID     string `json:"_id"`
	Arch   string `json:"architecture"`
	Parsed struct {
		Layers json.RawMessage `json:"layers"`
	} `json:"parsed_data"`
	Repositories []struct {
		Registry   string `json:"registry"`
		Repository string `json:"repository"`
		Tags       []struct {
			Added time.Time `json:"added_date"`
			Name  string    `json:"name"`
		} `json:"tags"`
	} `json:"repositories"`
}

type queueMaker struct {
	db           *bbolt.DB
	hydra, rhcc  *url.URL
	repoDisallow *regexp.Regexp
	pat          []string
}

// Populate the database at "q.db".
//
// If "ch" is provided, items will be sent as they're written to the database.
// The function will close the channel before it returns.
func (q *queueMaker) Run(ctx context.Context, ch chan *fetchitem) error {
	work := make(chan *hydraDoc, 500) // Sets request page size as well
	id := []byte(time.Now().UTC().Format(time.RFC3339))
	var searchStats searchStats
	var findStats findStats
	defer func() {
		slog.InfoCtx(ctx, "search stats",
			"total", searchStats.Total,
			slog.Group("ignored",
				"repository", searchStats.IgnoreRepo,
				"seen", searchStats.IgnoreSeen,
				"total", searchStats.IgnoreRepo+searchStats.IgnoreSeen),
			"candidates", searchStats.Total-(searchStats.IgnoreRepo+searchStats.IgnoreSeen))
		slog.InfoCtx(ctx, "find stats",
			"total", findStats.Total,
			slog.Group("discarded",
				"arch", findStats.DiscardedArch,
				"tag", findStats.DiscardedTag,
				"404", findStats.Discarded404,
				"total", findStats.DiscardedArch+findStats.DiscardedTag+findStats.Discarded404),
			"candidates", findStats.Total-(findStats.DiscardedArch+findStats.DiscardedTag+findStats.Discarded404))
		if ch != nil {
			close(ch)
		}
	}()
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(q.search(ctx, &searchStats, work))
	eg.Go(q.find(ctx, &findStats, ch, id, work))
	if err := eg.Wait(); err != nil {
		return err
	}
	return q.prune(ctx, id)
}

type searchStats struct {
	IgnoreRepo uint64
	IgnoreSeen uint64
	Total      uint64
}

func (q *queueMaker) search(ctx context.Context, stats *searchStats, work chan<- *hydraDoc) func() error {
	// The metadata in hydra is completely hosed. Don't use "<field>:false"
	// because that fails if the field is absent. Instead, use "!<field>:true".
	query := url.Values{
		"redhat_client": {"rhcc-scanner (hdonnay@redhat.com)"},
		"fq": {
			`documentKind:"ContainerRepository"`,
			"!beta:true AND !tech_preview:true AND !deprecated:true AND container_published:true",
			"registry:registry.access.redhat.com",
			"!eol_date:[* TO NOW]",
		},
		"sort": {"id asc"},
		"fl":   {"id,repository,registry,requires_terms"},
		"rows": {strconv.Itoa(cap(work))},
		"q":    {"*"},
	}
	hydra := *q.hydra
	return func() error {
		defer close(work)
		// Weird construct to avoid building up defers.
		var c io.Closer
		defer func() {
			if c != nil {
				c.Close()
			}
		}()
		seen := make(map[string]struct{})
		slog.InfoCtx(ctx, "searching", "patterns", q.pat)
		for _, pat := range q.pat {
			query.Add("fq", "repository:"+pat)
			for cur := 0; ; {
				if cur != 0 {
					query.Set("start", strconv.Itoa(cur))
				}
				hydra.RawQuery = query.Encode()
				slog.Log(ctx, LevelTrace, "hydra request", "url", &hydra)
				var searchRes hydraResponse
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, hydra.String(), nil)
				if err != nil {
					return err
				}
				setHeaders(&req.Header)
				res, err := http.DefaultClient.Do(req)
				if err != nil {
					return err
				}
				if c != nil {
					c.Close()
				}
				c = res.Body
				if res.StatusCode != http.StatusOK {
					return fmt.Errorf("unexpected response to %q: %s", hydra.String(), res.Status)
				}
				if err := json.NewDecoder(res.Body).Decode(&searchRes); err != nil {
					return err
				}
				for i := range searchRes.Response.Docs {
					stats.Total++
					doc := &searchRes.Response.Docs[i]
					name := path.Join(doc.Registry, doc.Repository)

					// There used to be more reasons to reject candidate images
					// but I figured out how to push them in to the search
					// parameters.
					var skip bool
					var reason string
					switch _, seen := seen[name]; {
					case q.repoDisallow.MatchString(doc.Repository):
						skip = true
						reason = "repository"
						stats.IgnoreRepo++
					case seen:
						skip = true
						reason = "seen"
						stats.IgnoreSeen++
					}
					seen[name] = struct{}{}
					if skip {
						slog.DebugCtx(ctx, "rejected", "image", name, "reason", reason)
						continue
					}

					slog.DebugCtx(ctx, "candidate", "image", name, "lying?", doc.Lying)
					select {
					case <-ctx.Done():
						return context.Cause(ctx)
					case work <- doc:
					}
				}
				cur += len(searchRes.Response.Docs)
				found, err := searchRes.Response.Found.Int64()
				if err != nil {
					return err
				}
				slog.InfoCtx(ctx, "searched", "count", cur, "total", found)
				if int64(cur) == found {
					break
				}
			}
		}
		return nil
	}
}

type findStats struct {
	DiscardedArch uint64
	DiscardedTag  uint64
	Discarded404  uint64
	Total         uint64
}

func (q *queueMaker) find(ctx context.Context, stats *findStats, send chan<- *fetchitem, runid []byte, work <-chan *hydraDoc) func() error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(runtime.GOMAXPROCS(0))
	var i int
	for eg.TryGo(q.findWorker(ctx, stats, runid, send, work)) {
		i++
	}
	slog.Debug("launched image finders", "count", i)
	defer slog.Debug("ran image finders")
	return eg.Wait
}

func (q *queueMaker) findWorker(ctx context.Context, stats *findStats, runid []byte, send chan<- *fetchitem, work <-chan *hydraDoc) func() error {
	rhcc := q.rhcc
	var counts struct {
		DiscardedArch uint64
		DiscardedTag  uint64
		Discarded404  uint64
		Total         uint64
	}
	return func() error {
		var c io.Closer
		defer func() {
			if c != nil {
				c.Close()
			}
			atomic.AddUint64(&stats.Total, counts.Total)
			atomic.AddUint64(&stats.DiscardedArch, counts.DiscardedArch)
			atomic.AddUint64(&stats.DiscardedTag, counts.DiscardedTag)
			atomic.AddUint64(&stats.Discarded404, counts.Discarded404)
		}()
		for {
			var doc *hydraDoc
			var ok bool
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case doc, ok = <-work:
				if !ok {
					return nil
				}
			}
			name := path.Join(doc.Registry, doc.Repository)
			u := rhcc.JoinPath("v1", "repositories", "registry", doc.Registry, "repository", doc.Repository, "images")
			slog.Log(ctx, LevelTrace, "rhcc request", "url", u)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			if err != nil {
				return err
			}
			setHeaders(&req.Header)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			if c != nil {
				c.Close()
			}
			c = res.Body
			if res.StatusCode != http.StatusOK {
				return fmt.Errorf("unexpected response to %q: %s", u.String(), res.Status)
			}
			var imgs imagesResponse
			if err := json.NewDecoder(res.Body).Decode(&imgs); err != nil {
				return err
			}
			counts.Total++
			if len(imgs.Data) == 0 {
				slog.DebugCtx(ctx, "discarding", "image", name, "reason", "404")
				counts.Discarded404++
				continue
			}
			var e *imagesEntry
			var last time.Time
			var tag string
			var arch bool
			for i, img := range imgs.Data {
				select {
				case <-ctx.Done():
					return context.Cause(ctx)
				default:
				}
				if img.Arch != "amd64" {
					continue
				}
				arch = true
				for _, r := range img.Repositories {
					if r.Registry != doc.Registry || r.Repository != doc.Repository {
						continue
					}
					for _, t := range r.Tags {
						if t.Added.After(last) {
							last = t.Added
							tag = t.Name
							e = &imgs.Data[i]
						}
					}
				}
			}
			if e == nil { // Found nothing.
				switch {
				case !arch:
					slog.DebugCtx(ctx, "discarding", "image", name, "reason", "arch")
					counts.DiscardedArch++
				case tag == "":
					slog.DebugCtx(ctx, "discarding", "image", name, "reason", "tag")
					counts.DiscardedTag++
				}
				continue
			}
			if len(e.Parsed.Layers) < 40 {
				slog.DebugCtx(ctx, "discarding", "image", name, "reason", "404 (no layers)")
				counts.Discarded404++
				continue
			}
			slog.DebugCtx(ctx, "found", "image", name, "id", e.ID, "tag", tag)
			err = q.db.Batch(func(tx *bbolt.Tx) error {
				layers := tx.Bucket(keys.QueueLayer)
				layers.FillPercent = 0.9
				ids := tx.Bucket(keys.QueueID)
				ids.FillPercent = 0.9
				run := tx.Bucket(keys.QueueRun)
				run.FillPercent = 0.9
				lying := tx.Bucket(keys.QueueAuth)
				lying.FillPercent = 0.9

				key := []byte(name)
				id := ids.Get(key)

				if err := run.Put(key, runid); err != nil {
					return err
				}
				switch {
				case id == nil:
					slog.DebugCtx(ctx, "novel", "image", name, "id", e.ID)
				case string(id) == e.ID:
					return nil
				case string(id) != e.ID:
					slog.DebugCtx(ctx, "updated", "image", name, "from", string(id), "to", e.ID)
				default:
					panic("unreachable")
				}
				l := []byte{'f'}
				if doc.Lying {
					l[0] = 't'
				}

				return errors.Join(
					ids.Put(key, []byte(e.ID)),
					layers.Put(key, e.Parsed.Layers),
					lying.Put(key, l),
				)
			})
			if err != nil {
				return err
			}
			if send != nil {
				var ls []digest.Digest
				if err := json.Unmarshal(e.Parsed.Layers, &ls); err != nil {
					return err
				}
				select {
				case <-ctx.Done():
					return context.Cause(ctx)
				case send <- &fetchitem{
					ID:     e.ID,
					Layers: ls,
					Image:  name,
					Lying:  doc.Lying,
				}:
				}
			}
		}
	}
}

func (q *queueMaker) prune(ctx context.Context, runid []byte) error {
	var stats struct {
		Kept    int64
		Removed int64
	}
	defer func() {
		slog.InfoCtx(ctx, "queue pruned", "removed", stats.Removed, "kept", stats.Kept)
	}()
	l := slog.With("current_runid", string(runid))
	return q.db.Update(func(tx *bbolt.Tx) error {
		layers := tx.Bucket([]byte("layer"))
		layers.FillPercent = 0.9
		ids := tx.Bucket([]byte("id"))
		ids.FillPercent = 0.9
		run := tx.Bucket([]byte("run"))
		run.FillPercent = 0.9
		lying := tx.Bucket([]byte("lying"))
		lying.FillPercent = 0.9
		return run.ForEach(func(k, v []byte) error {
			if bytes.Equal(runid, v) { // current run
				stats.Kept++
				return nil
			}
			l.Log(ctx, LevelTrace, "removing queue entry", "previous_runid", string(v))
			stats.Removed++
			return errors.Join(
				ids.Delete(k),
				layers.Delete(k),
				run.Delete(k),
				lying.Delete(k),
			)
		})
	})
}

func setHeaders(h *http.Header) {
	h.Set("user-agent", "rhcc-scanner/1 (see github.com/quay/rhcc-scanner)")
	h.Set("accept", "application/json")
}
