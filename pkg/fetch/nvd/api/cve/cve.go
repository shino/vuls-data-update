package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
	"math"
)

const (
	// API reference page: https://nvd.nist.gov/developers/vulnerabilities
	apiURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// resultsPerPage must be <= 2,000, this implementation almost uses the max value
	resultsPerPageMax = 2_000
)

type options struct {
	baseURL     string
	apiKey      string
	wait        int
	concurrency int
	dir         string
	retry       int

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

type apiKeyOption string

func (a apiKeyOption) apply(opts *options) {
	opts.apiKey = string(a)
}

func WithAPIKey(apiKey string) Option {
	return apiKeyOption(apiKey)
}

type waitOption int

func (r waitOption) apply(opts *options) {
	opts.wait = int(r)
}

func WithWait(wait int) Option {
	return waitOption(wait)
}

type concurrencyOption int

func (r concurrencyOption) apply(opts *options) {
	opts.concurrency = int(r)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
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
		dir:            filepath.Join(util.CacheDir(), "nvd", "api", "cve"),
		retry:          3,
		resultsPerPage: resultsPerPageMax,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch start, dir: %s", options.dir)

	checkRetry := func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		// do not retry on context.Canceled or context.DeadlineExceeded
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if err != nil {
			fmt.Printf("err: %#v\n", err)
			return false, errors.Wrap(err, "checkRetry")
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

	// 100 is just tentative
	bar := pb.Full.Start(100)
	urlChan := make(chan string, 100)
	finishedChan := make(chan finished, options.concurrency)

	//  TODO(shino): errorgroup needed?
	workers, workersCtx := errgroup.WithContext(context.Background())
	for i := 0; i < options.concurrency; i++ {
		workers.Go(func() error { return worker(options, c, workersCtx, urlChan, finishedChan, bar) })
	}

	//  TODO(shino): errogroup is overkill?
	coordG, coordCtx := errgroup.WithContext(context.Background())
	//  TODO(shino): cleanup task?
	coordG.Go(func() error { return coordinator(options, coordCtx, urlChan, finishedChan, bar) })
	if err := coordG.Wait(); err != nil {
		return errors.Wrap(err, "err in goroutine")
	}
	if err := workers.Wait(); err != nil {
		return errors.Wrap(err, "err in goroutine")
	}
	bar.Finish()
	return nil
}

type finished struct {
	startIndex     int
	resultsPerPage int
	totalResults   int
}

func coordinator(options *options, ctx context.Context, urlChan chan<- string, finishedChan <-chan finished, bar *pb.ProgressBar) error {
	firstURL, err := fullURL(options.baseURL, 0, options.resultsPerPage)
	if err != nil {
		return errors.Wrapf(err, "fullURL")
	}
	urlChan <- firstURL
	currentTotalPages := 1
	finishedCount := 0

	for {
		select {
		case <-ctx.Done():
			return errors.Wrapf(ctx.Err(), "interrupted too early")
		case finished := <-finishedChan:
			finishedCount++
			pages := int(math.Ceil(float64(finished.totalResults) / float64(options.resultsPerPage)))
			if delta := pages - currentTotalPages; delta > 0 {
				newURLs := make([]string, 0, delta)
				bar.AddTotal(int64(pages) - bar.Total())

				for i := currentTotalPages; i < pages; i++ {
					url, err := fullURL(options.baseURL, i*options.resultsPerPage, options.resultsPerPage)
					if err != nil {
						return errors.Wrapf(err, "fullURL")
					}
					newURLs = append(newURLs, url)
				}
				// sending data to urlChan may block, spawn a new goroutine
				//  TODO(shino): life monitoring
				go func(newURLs []string) {
					for _, u := range newURLs {
						urlChan <- u
					}
				}(newURLs)

				currentTotalPages = pages
			}
			if finished.totalResults <= finished.startIndex+options.resultsPerPage {
				// Final page fetched, no more new URLs
				close(urlChan)
				// Flush finished channel to not block workers
				for finishedCount < currentTotalPages {
					select {
					case <-finishedChan:
						finishedCount++
					}
				}
				return nil
			} else {
				// Sanity check for non-final pages, should have full count
				if finished.resultsPerPage != options.resultsPerPage {
					return errors.Errorf("unexpected resultsPerPage, expected: %d, actual: %d", options.resultsPerPage, finished.resultsPerPage)
				}
			}
		}
	}
}

func worker(options *options, c *utilhttp.Client, ctx context.Context, urlChan <-chan string, finishedChan chan<- finished, bar *pb.ProgressBar) error {
	h := make(http.Header)
	if options.apiKey != "" {
		h.Add("apiKey", options.apiKey)
	}
	headerOption := utilhttp.WithRequestHeader(h)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case u := <-urlChan:
			if u == "" {
				return nil
			}

			bs, err := c.Get(u, headerOption)
			if err != nil {
				return errors.Wrapf(err, "get %s", u)
			}
			var response api20
			if err := json.Unmarshal(bs, &response); err != nil {
				return errors.Wrap(err, "unmarshal json")
			}

			for _, v := range response.Vulnerabilities {
				splitted, err := util.Split(v.CVE.ID, "-", "-")
				if err != nil {
					log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.CVE.ID)
					continue
				}
				if _, err := time.Parse("2006", splitted[1]); err != nil {
					log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.CVE.ID)
					continue
				}

				if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", v.CVE.ID)), v); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", v.CVE.ID)))
				}
			}

			finishedChan <- finished{
				startIndex:     response.StartIndex,
				resultsPerPage: response.ResultsPerPage,
				totalResults:   response.TotalResults,
			}
			bar.Increment()
			time.Sleep(time.Duration(options.wait) * time.Second)
		}
	}

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
