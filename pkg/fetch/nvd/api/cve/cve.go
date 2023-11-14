package cve

import (
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const (
	// API reference page: https://nvd.nist.gov/developers/vulnerabilities
	apiURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// resultsPerPage must be <= 2,000, this implementation uses the max value (if specified otherwise)
	resultsPerPageMax = 2_000
)

func Fetch(opts ...api.Option) error {
	afterGet := func(dir string, bs []byte) (*api.Finished, error) {
		var response api20
		if err := json.Unmarshal(bs, &response); err != nil {
			return nil, errors.Wrap(err, "unmarshal json")
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

			if err := util.Write(filepath.Join(dir, splitted[1], fmt.Sprintf("%s.json", v.CVE.ID)), v); err != nil {
				return nil, errors.Wrapf(err, "write %s", filepath.Join(dir, splitted[1], fmt.Sprintf("%s.json", v.CVE.ID)))
			}
		}
		return &api.Finished{
			StartIndex:     response.StartIndex,
			ResultsPerPage: response.ResultsPerPage,
			TotalResults:   response.TotalResults,
		}, nil
	}

	if err := api.PagedFetch(apiURL, resultsPerPageMax, afterGet, opts...); err != nil {
		return errors.Wrap(err, "paged fetch")
	}
	return nil
}
