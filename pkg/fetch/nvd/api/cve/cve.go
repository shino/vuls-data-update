package cve

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	// API reference page: https://nvd.nist.gov/developers/vulnerabilities
	baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// Should be <= 2,000
	keyResultsPerPage = "resultsPerPage"
	// So this implementation uses the max value
	resultsPerPageMax = 2_000

	// 0-origin index of results.
	// When the request with startIndex=100 and resultsPerPage in the corresponding response is 2000,
	// the next request should have startIndex=2100.
	keyStartInedex = "startIndex"
)

type options struct {
	baseURL string
	apiKey  string
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

type apiKeyOption string

func (a apiKeyOption) apply(opts *options) {
	opts.apiKey = string(a)
}

func WithAPIKey(apiKey string) Option {
	return apiKeyOption(apiKey)
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
		//  TODO(shino): Where to put the default value, cmd/fetch/fetch.go or here?
		dir:   filepath.Join(util.CacheDir(), "nvd", "api", "cve"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	url, err := url.Parse(options.baseURL)
	if err != nil {
		return errors.Wrapf(err, "parse base URL: %s", options.baseURL)
	}
	var startIndex int64 = 0
	//  TODO(shino): prevent infinite loop by any accidents
	for {
		result, err := callAPI(options, url, resultsPerPageMax, startIndex)
		if err != nil {
			return errors.Wrap(err, "call NVD CVE API")
		}
		if result.resultsPerPage != 0 {
			// Last page reached
			return nil
		}

		startIndex += result.resultsPerPage
		//  TODO(shino): sleep to secure the API rate limit
	}
}

type result struct {
	resultsPerPage int64
	totalResults   int64
}

func callAPI(opts *options, url *url.URL, resultsPerPage int64, startIndex int64) (*result, error) {

	log.Printf("[DEBUG] About to call NVD API CVE with startIndex=%d", startIndex)
	q := url.Query()
	q.Set(keyStartInedex, strconv.FormatInt(startIndex, 10))
	// q.Set(keyResultsPerPage, strconv.Itoa(opts.resultsPerPage))
	q.Set(keyResultsPerPage, strconv.FormatInt(1, 10))
	url.RawQuery = q.Encode()

	h := http.Header{}
	if strings.Compare(opts.apiKey, "") != 0 {
		h.Add("api-key", opts.apiKey)
	}

	bs, err := utilhttp.Get(url.String(), opts.retry, utilhttp.WithRequestHeader(h))
	if err != nil {
		return nil, errors.Wrap(err, "read response body")
	}
	fmt.Printf("bs: %s\n", bs)

	var cveAPI20 CVEAPI20
	if err := json.Unmarshal(bs, &cveAPI20); err != nil {
		return nil, errors.Wrapf(err, "unmarshal NVE API CVE with startIndex=%d", startIndex)
	}
	fmt.Printf("cveAPI20.Vulnerabilities[0]: %#v\n", cveAPI20.Vulnerabilities[0])
	fmt.Printf("cveAPI20.Vulnerabilities[0]: %#v\n", cveAPI20.Vulnerabilities[0])

	//  TODO(shino): temporal
	cveAPI20.Vulnerabilities = cveAPI20.Vulnerabilities[0:1]
	fmt.Printf("%#v\n", cveAPI20)
	return &result{resultsPerPage: cveAPI20.ResultsPerPage,
			totalResults: cveAPI20.TotalResults},
		nil
}
