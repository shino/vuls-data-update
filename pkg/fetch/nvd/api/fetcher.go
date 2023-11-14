package api

import (
	"context"
	"log"
	"math"
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
)

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

type Finished struct {
	StartIndex     int
	ResultsPerPage int
	TotalResults   int
}

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

// afterGetFunc is executed after API Get operation suceeded.
// It's typical usage is transform body to JSON and store data to files.
type afterGetFunc func(string, []byte) (*Finished, error)

// PagedFetch executes API calls and afterGet function concurrently.
// The implementation is basically single-producer and multi-consumer pattern.
// However, it has feedbacks from consumer side because full set of API URLs
// is determined *after* some API calls finished.
// Moreover API URLs may be added at any time in corner cases, this function
// handles such cases properly.
func PagedFetch(apiURL string, resultsPerPageMax int, afterGet afterGetFunc, opts ...Option) error {
	options := &options{
		baseURL:        apiURL,
		apiKey:         "",
		dir:            filepath.Join(util.CacheDir(), "nvd", "api"),
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

	// The number of tasks are unknown at this point, 100 is tentatively used here.
	bar := pb.Full.Start(100)

	urlChan := make(chan string, 100)
	finishedChan := make(chan Finished, options.concurrency)

	//  TODO(shino): errorgroup needed?
	workers, workersCtx := errgroup.WithContext(context.Background())
	for i := 0; i < options.concurrency; i++ {
		workers.Go(func() error { return worker(options, c, workersCtx, urlChan, finishedChan, afterGet, bar) })
	}

	//  TODO(shino): errogroup is overkill?
	coordG, coordCtx := errgroup.WithContext(context.Background())
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

func coordinator(options *options, ctx context.Context, urlChan chan<- string, finishedChan <-chan Finished, bar *pb.ProgressBar) error {
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
			pages := int(math.Ceil(float64(finished.TotalResults) / float64(options.resultsPerPage)))
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
			if finished.TotalResults <= finished.StartIndex+options.resultsPerPage {
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
				if finished.ResultsPerPage != options.resultsPerPage {
					return errors.Errorf("unexpected resultsPerPage, expected: %d, actual: %d", options.resultsPerPage, finished.ResultsPerPage)
				}
			}
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

func worker(options *options, c *utilhttp.Client, ctx context.Context, urlChan <-chan string, finishedChan chan<- Finished, afterGet afterGetFunc, bar *pb.ProgressBar) error {
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

			finished, err := afterGet(options.dir, bs)
			if err != nil {
				return errors.Wrap(err, "afterGet %s")
			}
			finishedChan <- *finished
			bar.Increment()
			time.Sleep(time.Duration(options.wait) * time.Second)
		}
	}

}
