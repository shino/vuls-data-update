package cpematch

import (
	"path/filepath"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const baseURL = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"

type options struct {
	baseURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type baseURLOption string

func (u baseURLOption) apply(opts *options) {
	opts.baseURL = string(u)
}

func WithBaseURL(url string) Option {
	return baseURLOption(url)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type retryOption int

func (r retryOption) apply(opts *options) {
	opts.retry = int(r)
}

func WithRetry(retry int) Option {
	return retryOption(retry)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "nvd", "api", "cpematch"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	return nil
}
