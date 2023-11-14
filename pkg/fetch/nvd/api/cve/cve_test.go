package cve_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cve"
	"github.com/google/go-cmp/cmp"

	"path/filepath"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name           string
		apiKey         string
		fixturePrefix  string
		expectedCounts int
		hasError       bool
	}{
		{
			name:           "empty",
			fixturePrefix:  "empty",
			expectedCounts: 0,
		},
		{
			name:           "1 item",
			fixturePrefix:  "1_item",
			expectedCounts: 1,
		},
		{
			name:           "Precisely single page",
			fixturePrefix:  "3_items",
			expectedCounts: 3,
		},
		{
			name:           "Multiple pages",
			fixturePrefix:  "3_pages",
			expectedCounts: 8,
		},
		{
			name:           "Total count increase in the middle of command execution",
			fixturePrefix:  "increase",
			expectedCounts: 8,
		},
		{
			name:           "With API Key",
			apiKey:         "foobar",
			fixturePrefix:  "3_pages",
			expectedCounts: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				startIndex := "0"
				if value := r.URL.Query().Get("startIndex"); value != "" {
					startIndex = value
				}
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.fixturePrefix, fmt.Sprintf("%s.json", startIndex)))
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "/rest/json/cves/2.0")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			opts := []cve.Option{
				cve.WithBaseURL(u), cve.WithDir(dir), cve.WithAPIKey(tt.apiKey),
				cve.WithConcurrency(2), cve.WithWait(0), cve.WithRetry(0),
				cve.WithResultsPerPage(3),
			}
			err = cve.Fetch(opts...)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			counts := 0
			if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if info.IsDir() {
					return nil
				}

				dir, file := filepath.Split(path)
				want, err := os.ReadFile(filepath.Join("testdata", "golden", tt.fixturePrefix, filepath.Base(dir), file))
				if err != nil {
					return err
				}

				got, err := os.ReadFile(path)
				if err != nil {
					return err
				}

				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("Fetch(). %s (-expected +got):\n%s", file, diff)
				}

				counts++
				return nil

			}); err != nil {
				t.Error("walk error:", err)
			}

			if counts != tt.expectedCounts {
				t.Errorf("mismatched #(files), expected: %d, actual: %d", tt.expectedCounts, counts)

			}
		})
	}
}
