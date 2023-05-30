package main

import (
	"context"
	"fmt"
	"math"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/exp/slog"
	"golang.org/x/sys/unix"
)

type analyzeStats struct {
	Total          uint64
	Enqueued       uint64
	ResultsPresent uint64
	TotalLayers    uint64
	HitLayers      uint64
	Errored        uint64
	Recorded       uint64
}

func (s *analyzeStats) progress(ctx context.Context) {
	_, err := unix.IoctlGetTermios(int(os.Stderr.Fd()), unix.TCGETS)
	tty := err == nil && os.Getenv("TERM") != "dumb"
	slog.Log(ctx, LevelTrace, "progress reporter starting", "tty?", tty)
	defer slog.Log(ctx, LevelTrace, "progress reporter done")
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for first := true; ; first = false {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if tty && !first {
			fmt.Fprint(os.Stderr, "\x1B[1F\x1B[2K") // Move cursor 1 line up, clear line.
		}
		t, r, p := s.Total, atomic.LoadUint64(&s.Recorded), atomic.LoadUint64(&s.ResultsPresent)
		pct := math.Round((float64(r+p)/float64(t))*10000) / 100
		slog.InfoCtx(ctx, "analysis progress",
			slog.Uint64("total", t),
			slog.Uint64("enqueued", atomic.LoadUint64(&s.Enqueued)),
			slog.Uint64("skipped", p),
			slog.Group("layers",
				slog.Uint64("total", atomic.LoadUint64(&s.TotalLayers)),
				slog.Uint64("hits", atomic.LoadUint64(&s.HitLayers)),
			),
			slog.Uint64("errored", atomic.LoadUint64(&s.Errored)),
			slog.Uint64("recorded", r),
			slog.Float64("complete%", pct),
		)
	}
}
