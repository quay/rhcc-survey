package main

import (
	"context"
	"strings"

	"go.etcd.io/bbolt"
	"golang.org/x/exp/slog"

	"github.com/quay/rhcc-survey/job"
)

var keys = struct {
	QueueMeta  []byte
	QueueID    []byte
	QueueLayer []byte
	QueueAuth  []byte
	QueueRun   []byte

	ResultsMeta           []byte
	ResultsPerJob         []byte
	ResultsPerJobID       []byte
	ResultsPerJobLayer    []byte
	ResultsPerJobPosition []byte
	ResultsPerJobError    []byte
	ResultsPerJobRecord   []byte
}{
	QueueMeta:  []byte("_meta"),
	QueueID:    []byte("id"),
	QueueLayer: []byte("layer"),
	QueueAuth:  []byte("lying"),
	QueueRun:   []byte("run"),

	ResultsMeta:           []byte("_meta"),
	ResultsPerJob:         []byte("job"),
	ResultsPerJobID:       []byte("id"),
	ResultsPerJobLayer:    []byte("layer"),
	ResultsPerJobPosition: []byte("position"),
	ResultsPerJobError:    []byte("error"),
	ResultsPerJobRecord:   []byte("record"),
}

func setupQueue(ctx context.Context, db *bbolt.DB) error {
	tx, err := db.Begin(true)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, n := range [][]byte{
		keys.QueueMeta,
		keys.QueueID,
		keys.QueueLayer,
		keys.QueueAuth,
		keys.QueueRun,
	} {
		if _, err := tx.CreateBucketIfNotExists(n); err != nil {
			return err
		}
	}
	slog.Log(ctx, LevelTrace, "set up queue db")
	return tx.Commit()
}

func setupResults(ctx context.Context, db *bbolt.DB, js []job.Job) error {
	tx, err := db.Begin(true)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.CreateBucketIfNotExists(keys.ResultsMeta); err != nil {
		return err
	}
	jobs, err := tx.CreateBucketIfNotExists(keys.ResultsPerJob)
	if err != nil {
		return err
	}
	for _, j := range js {
		b, err := jobs.CreateBucketIfNotExists([]byte(j.Name()))
		if err != nil {
			return err
		}
		for _, n := range [][]byte{
			keys.ResultsPerJobID,
			keys.ResultsPerJobLayer,
			keys.ResultsPerJobPosition,
			keys.ResultsPerJobError,
			keys.ResultsPerJobRecord,
		} {
			if _, err := b.CreateBucketIfNotExists(n); err != nil {
				return err
			}
		}
	}
	var b strings.Builder
	for i := 0; i < len(js); i++ {
		if i != 0 {
			b.WriteByte(',')
		}
		b.WriteString(js[i].Name())
	}
	slog.Log(ctx, LevelTrace, "set up results db", "jobs", &b)
	return tx.Commit()
}
