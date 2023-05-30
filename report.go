package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"

	"go.etcd.io/bbolt"

	"github.com/quay/rhcc-survey/job"
)

func runReporter(ctx context.Context, out io.Writer, db *bbolt.DB, j job.Job, r job.Reporter) error {
	if reflect.TypeOf(j.Record()).Kind() != reflect.Pointer {
		return fmt.Errorf("job %q: bad record type %T", j.Name(), j.Record())
	}
	if err := r.Begin(ctx, out); err != nil {
		return err
	}
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(keys.ResultsPerJob).Bucket([]byte(j.Name()))
		cur := b.Bucket(keys.ResultsPerJobID).Cursor()
		for k, _ := cur.First(); k != nil; k, _ = cur.Next() {
			n, err := strconv.Atoi(string(b.Bucket(keys.ResultsPerJobPosition).Get(k)))
			if err != nil {
				return err
			}
			v := j.Record()
			if err := json.Unmarshal(b.Bucket(keys.ResultsPerJobRecord).Get(k), v); err != nil {
				return err
			}
			l := fmt.Sprintf("%s@%s", k, b.Bucket(keys.ResultsPerJobLayer).Get(k))
			if e := b.Bucket(keys.ResultsPerJobError).Get(k); len(e) != 0 {
				err = errors.New(string(e))
			}
			if err := r.Record(ctx, out, l, n, v, err); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return r.End(ctx, out)
}
