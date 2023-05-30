// Package job is the common types and machinery for survey jobs.
package job

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/opencontainers/go-digest"
)

// Job describes a single survey job.
type Job interface {
	// Name is the unique name for this job.
	//
	// Registration will panic if the name is not unique.
	// The reported name must be stable.
	Name() string
	// Record is an instance of the type that the Analyzer and Reporter
	// implementations returned by this Job will use.
	//
	// Must be a pointer to a struct.
	Record() any
	// Close frees any held resources.
	Close() error

	// SelectImage returns a LayerSelector for a given image.
	//
	// The returned object must be an independent instance.
	SelectImage(ctx context.Context, image string) LayerSelector
	// Analyzer returns an Analyzer instance.
	//
	// The returned object must be an independent instance.
	Analyzer() (Analyzer, error)
	// Reporter returns a Reporter instance.
	Reporter() (Reporter, error)
}

// LayerSelector is called for each layer on a given image, with the tar header
// of every file in that layer.
//
// Once a "hit" is reported, SelectLayer will stop being called.
type LayerSelector interface {
	SelectLayer(context.Context, digest.Digest, *tar.Header) (hit, load bool, err error)
	Close() error
}

// Analyzer does analysis on selected layers.
type Analyzer interface {
	// Analyze is called for every layer that was selected by a LayerSelector.
	//
	// "Contents" will be populated if the LayerSelector reported true for the
	// "load" boolean.
	Analyze(ctx context.Context, contents io.Reader) (record any, err error)
	Close() error
}

// Reporter writes out reports.
//
// By convention, any headers, footers, or comments start with "#" and the
// output is in tab-separated value format.
//
// The "Begin" and "End" methods work like the awk "BEGIN" and "END" actions.
type Reporter interface {
	Begin(ctx context.Context, w io.Writer) error
	Record(ctx context.Context, w io.Writer, layer string, pos int, record any, err error) error
	End(ctx context.Context, w io.Writer) error
}

// CacheDir is a precreated directory that Jobs can cache files underneath.
var CacheDir string

func init() {
	dir, err := os.UserCacheDir()
	if err != nil {
		panic(err)
	}
	CacheDir = filepath.Join(dir, "rhcc-survey")
	if err := os.MkdirAll(CacheDir, 0755); err != nil {
		panic(err)
	}
}

// StoreError marks the error returned from an Analyzer as one that should be
// recorded as a result and not stop the run.
func StoreError(err error) error {
	return &StoredError{
		inner: err,
	}
}

var _ error = (*StoredError)(nil)

// StoredError is the concrete type for StoreError.
//
// Job implementations should not need to care about this.
type StoredError struct {
	inner error
}

// Error implements error.
func (e *StoredError) Error() string {
	return fmt.Sprintf("to store: %v", e.inner)
}

// Unwrap implements error.
func (e *StoredError) Unwrap() error {
	return e.inner
}
