package cpematch

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"path/filepath"

	"github.com/cheggaaa/pb/v3"
	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz"

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
		dir:     filepath.Join(util.CacheDir(), "nvd", "feed", "cpematch"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	cpeMatch, err := options.fetch()
	if err != nil {
		return errors.Wrap(err, "fetch cpe match")
	}

	dv := hash32([]byte("vendor:product"))

	bar := pb.StartNew(len(cpeMatch))
	for cpe, items := range cpeMatch {
		d := dv

		wfn, err := naming.UnbindFS(cpe)
		if err == nil {
			d = hash32([]byte(fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct))))
		}

		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%x", d), fmt.Sprintf("%x.json", hash64([]byte(cpe)))), items); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%x", d), fmt.Sprintf("%x.json", hash64([]byte(cpe)))))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (opts options) fetch() (map[string][]CpeMatchItem, error) {
	cpes := map[string][]CpeMatchItem{}

	log.Printf(`[INFO] Fetch NVD CPE Match`)
	bs, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch cpe match feed")
	}

	r, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "open cpe match as gzip")
	}
	defer r.Close()

	d := json.NewDecoder(r)
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "json.Delim: {"`)
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "string: matches"`)
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "json.Delim: ["`)
	}
	for d.More() {
		var e CpeMatchItem
		if err := d.Decode(&e); err != nil {
			return nil, errors.Wrap(err, "decode element")
		}
		cpes[e.Cpe23URI] = append(cpes[e.Cpe23URI], e)
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "json.Delim: ]"`)
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "json.Delim: }"`)
	}

	return cpes, nil
}

func hash32(message []byte) uint32 {
	h := fnv.New32()
	h.Write(message)
	return h.Sum32()
}

func hash64(message []byte) uint64 {
	h := fnv.New64()
	h.Write(message)
	return h.Sum64()
}
