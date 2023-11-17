package cpematch

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	// API reference page: https://nvd.nist.gov/developers/products
	apiURL = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"

	// resultsPerPage must be <= 5,000, this implementation almost uses the max value
	resultsPerPageMax = 5_000
)

type options struct {
	baseURL     string
	dir         string
	retry       int
	concurrency int
	wait        int
	apiKey      string

	// test purpose only
	resultsPerPage int
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

type concurrencyOption int

func (r concurrencyOption) apply(opts *options) {
	opts.concurrency = int(r)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type waitOption int

func (r waitOption) apply(opts *options) {
	opts.wait = int(r)
}

func WithWait(wait int) Option {
	return waitOption(wait)
}

type apiKeyOption string

func (a apiKeyOption) apply(opts *options) {
	opts.apiKey = string(a)
}

func WithAPIKey(apiKey string) Option {
	return apiKeyOption(apiKey)
}

type resultsPerPageOption int

func (r resultsPerPageOption) apply(opts *options) {
	opts.resultsPerPage = int(r)
}

func WithResultsPerPage(resultsPerPage int) Option {
	return resultsPerPageOption(resultsPerPage)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL:        apiURL,
		apiKey:         "",
		dir:            filepath.Join(util.CacheDir(), "nvd", "api", "cpematch"),
		retry:          3,
		resultsPerPage: resultsPerPageMax,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch NVD CPE match API. dir: %s", options.dir)

	checkRetry := func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		// do not retry on context.Canceled or context.DeadlineExceeded
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if err != nil {
			return false, errors.Wrap(err, "http client Do")
		}
		// NVD JSON API returns 403 in rate limit excesses, should retry.
		// Also, the API returns 408 infreqently.
		switch resp.StatusCode {
		case http.StatusForbidden, http.StatusRequestTimeout:
			log.Printf("[INFO] HTTP %d happened, may retry", resp.StatusCode)
			return true, nil
		}

		return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
	}

	c := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientCheckRetry(checkRetry))

	h := make(http.Header)
	if options.apiKey != "" {
		h.Add("apiKey", options.apiKey)
	}
	headerOption := utilhttp.WithRequestHeader(h)

	// Preliminary API call to get totalResults.
	// Use 1 as resultsPerPage to save time.
	u, err := fullURL(options.baseURL, 0, 1)
	if err != nil {
		return errors.Wrap(err, "full URL")
	}
	bs, err := c.Get(u, headerOption)
	if err != nil {
		return errors.Wrap(err, "preliminary API call")
	}
	var preliminary api20
	if err := json.Unmarshal(bs, &preliminary); err != nil {
		return errors.Wrap(err, "unmarshal json")
	}
	totalResults := preliminary.TotalResults
	preciselyPaged := (totalResults % options.resultsPerPage) == 0
	pages := totalResults / options.resultsPerPage
	if !preciselyPaged {
		pages++
	}

	// Actual API calls
	us := make([]string, 0, pages)
	for startIndex := 0; startIndex < totalResults; startIndex += options.resultsPerPage {
		url, err := fullURL(options.baseURL, startIndex, options.resultsPerPage)
		if err != nil {
			return errors.Wrap(err, "full URL")
		}
		us = append(us, url)
	}

	nextTask := func(resp utilhttp.Response) error {
		var response api20
		if err := json.Unmarshal(resp.Body, &response); err != nil {
			return errors.Wrap(err, "unmarshal json")
		}

		// Sanity check:
		// NVD's API document does not say that response item counts are equal to
		// request's resultsPerPage (in non-final pages).
		// If we don't check the counts, we may have incomplete results.
		actualResults := len(response.MatchData)
		finalStartIndex := options.resultsPerPage * (pages - 1)
		if response.StartIndex == finalStartIndex && !preciselyPaged {
			// Allow the last page have more than expected results,
			// because item may be added in the middle of command execution.
			expectedResults := totalResults % options.resultsPerPage
			if actualResults < expectedResults {
				return errors.Errorf("unexpected results at last page, startIndex: %d, expected: %d actual: %d", response.StartIndex, expectedResults, actualResults)
			}
		} else {
			// Non-final page or fully-populated final page, should have max count.
			if actualResults != options.resultsPerPage {
				return errors.Errorf("unexpected results at startIndex: %d, expected: %d actual: %d", response.StartIndex, options.resultsPerPage, actualResults)
			}
		}

		dv := hash32([]byte("vendor:product"))

		for _, m := range response.MatchData {
			d := dv

			wfn, err := naming.UnbindFS(m.MatchCriteria.Criteria)
			if err == nil {
				d = hash32([]byte(fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct))))
			}

			if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%x", d), fmt.Sprintf("%s.json", m.MatchCriteria.MatchCriteriaID)), m.MatchCriteria); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%x", d), fmt.Sprintf("%s.json", m.MatchCriteria.MatchCriteriaID)))
			}
		}
		return nil
	}
	if err := c.PipelineGet(us, options.concurrency, options.wait, nextTask, headerOption); err != nil {
		return errors.Wrap(err, "pipeline get")
	}
	return nil
}

func fullURL(baseURL string, startIndex, resultsPerPage int) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", errors.Wrapf(err, "parse base URL: %s", baseURL)
	}
	q := u.Query()
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func hash32(message []byte) uint32 {
	h := fnv.New32()
	h.Write(message)
	return h.Sum32()
}
