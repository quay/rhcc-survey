package job

import (
	"fmt"
	"sort"

	"golang.org/x/exp/slices"
)

var pkg registry

type registry struct {
	available []string
	job       []Job
	enable    []bool
}

// Register registers a Job to run and marks it to be default enabled or not.
func Register(j Job, enable bool) {
	n := j.Name()
	if slices.Contains(pkg.available, n) {
		panic(fmt.Sprintf("already registered job %q", n))
	}
	pkg.available = append(pkg.available, n)
	pkg.job = append(pkg.job, j)
	pkg.enable = append(pkg.enable, enable)
}

// Available reports the names of known Jobs.
func Available() []string {
	ret := make([]string, len(pkg.available))
	copy(ret, pkg.available)
	sort.Strings(ret)
	return ret
}

// Defaults reports the names of the default-enabled Jobs.
func Defaults() []string {
	ret := make([]string, 0, len(pkg.available))
	for i, ok := range pkg.enable {
		if ok {
			ret = append(ret, pkg.available[i])
		}
	}
	sort.Strings(ret)
	return ret
}

// Jobs returns the named Jobs.
func Jobs(ns []string) ([]Job, error) {
	ret := make([]Job, 0, len(ns))
	for _, n := range ns {
		i := slices.Index(pkg.available, n)
		if i == -1 {
			return nil, fmt.Errorf("unknown job %q", n)
		}
		ret = append(ret, pkg.job[i])
	}
	return ret, nil
}
