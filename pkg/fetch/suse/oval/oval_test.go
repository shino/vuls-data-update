package oval_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/oval"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		indexof  string
		hasError bool
	}{
		{
			name:    "happy path",
			indexof: "testdata/fixtures/indexof_valid.html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/") {
					http.ServeFile(w, r, tt.indexof)
				} else if strings.HasSuffix(r.URL.Path, ".xml.gz") {
					_, f := path.Split(r.URL.Path)
					http.ServeFile(w, r, fmt.Sprintf("testdata/fixtures/%s", f))
				} else {
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := oval.Fetch(oval.WithBaseURL(ts.URL), oval.WithDir(dir), oval.WithRetry(0), oval.WithConcurrency(1), oval.WithWait(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					return nil
				}

				want, err := os.ReadFile(filepath.Join(append([]string{"testdata", "golden"}, strings.Split(strings.TrimPrefix(path, dir), string(os.PathSeparator))...)...))
				if err != nil {
					return err
				}
				got, err := os.ReadFile(path)
				if err != nil {
					return err
				}

				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("Fetch(). (-expected +got):\n%s", diff)
				}

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
