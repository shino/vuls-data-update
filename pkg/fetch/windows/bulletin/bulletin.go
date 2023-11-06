package bulletin

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"github.com/tealeg/xlsx"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

var dataURLs = []string{
	"https://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx",
	"https://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch2001-2008.xlsx",
}

type options struct {
	dataURLs []string
	dir      string
	retry    int
}

type Option interface {
	apply(*options)
}

type dataURLsOption []string

func (u dataURLsOption) apply(opts *options) {
	opts.dataURLs = u
}

func WithDataURLs(urls []string) Option {
	return dataURLsOption(urls)
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
		dataURLs: dataURLs,
		dir:      filepath.Join(util.CacheDir(), "windows", "bulletin"),
		retry:    3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Windows Bulletin")

	bulletins := map[string][]Bulletin{}
	for _, u := range options.dataURLs {
		bs, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
		if err != nil {
			return errors.Wrap(err, "fetch bulletin data")
		}

		f, err := xlsx.OpenBinary(bs)
		if err != nil {
			return errors.Wrap(err, "failed to open xlsx binary")
		}
		for _, sheet := range f.Sheets {
			for i, row := range sheet.Rows {
				// skip header
				if i == 0 {
					continue
				}

				var line Bulletin
				if err := row.ReadStruct(&line); err != nil {
					return errors.Wrap(err, "failed to read xlsx line")
				}

				if line.DatePosted == "" {
					continue
				}

				bulletins[line.BulletinID] = append(bulletins[line.BulletinID], line)
			}
		}
	}

	bar := pb.StartNew(len(bulletins))
	for bid, bs := range bulletins {
		log.Printf("[INFO] Fetched Windows Bulletin %s", bid)

		y := strings.TrimPrefix(strings.ToLower(strings.Split(bid, "-")[0]), "ms")

		if err := util.Write(filepath.Join(options.dir, y, fmt.Sprintf("%s.json", bid)), bs); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, y, fmt.Sprintf("%s.json", bid)))
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}
