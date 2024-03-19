package errata

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/reference"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/alma/errata"
)

type options struct {
	dir string
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "alma", "errata"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract AlmaLinux Errata")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		dir, y := filepath.Split(filepath.Dir(path))
		v := filepath.Base(filepath.Clean(dir))

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		var fetched errata.Erratum
		if err := json.NewDecoder(f).Decode(&fetched); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		extracted := extract(fetched, v)

		if err := util.Write(filepath.Join(options.dir, v, y, fmt.Sprintf("%s.json", extracted.ID)), extracted); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, y, fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	return nil
}

func extract(fetched errata.Erratum, osver string) types.Data {
	extracted := types.Data{
		ID: fetched.ID,
		Advisories: []types.Advisory{{
			ID:          fetched.ID,
			Title:       fetched.Title,
			Description: fetched.Description,
			Severity: []severity.Severity{{
				Type:   severity.SeverityTypeVendor,
				Source: "errata.almalinux.org",
				Vendor: &fetched.Severity,
			}},
			Published: func() *time.Time { t := time.Unix(int64(fetched.IssuedDate), 0); return &t }(),
			Modified:  func() *time.Time { t := time.Unix(int64(fetched.UpdatedDate), 0); return &t }(),
		}},
		DataSource: source.AlmaErrata,
	}

	rm := map[string]struct{}{fmt.Sprintf("https://errata.almalinux.org/%s/%s.html", osver, strings.ReplaceAll(fetched.ID, ":", "-")): {}}
	vm := map[string]types.Vulnerability{}
	for _, r := range fetched.References {
		rm[r.Href] = struct{}{}

		if r.Type == "cve" {
			vm[r.ID] = types.Vulnerability{
				ID: r.ID,
				References: []reference.Reference{{
					Source: "errata.almalinux.org",
					URL:    r.Href,
				}},
			}
		}
	}

	extracted.Advisories[0].References = func() []reference.Reference {
		rs := make([]reference.Reference, 0, len(rm))
		for r := range rm {
			rs = append(rs, reference.Reference{
				Source: "errata.almalinux.org",
				URL:    r,
			})
		}
		return rs
	}()
	extracted.Vulnerabilities = maps.Values(vm)

	modules := map[string]string{}
	for _, m := range fetched.Modules {
		modules[fmt.Sprintf("%s:%s:%s:%s:%s", m.Name, m.Stream, m.Version, m.Context, m.Arch)] = fmt.Sprintf("%s:%s", m.Name, m.Stream)
	}

	packages := map[string]map[string][]string{}
	for _, p := range fetched.Packages {
		n := p.Name
		if prefix, ok := modules[p.Module]; ok {
			n = fmt.Sprintf("%s::%s", prefix, n)
		}
		if packages[n] == nil {
			packages[n] = map[string][]string{}
		}
		packages[n][fmt.Sprintf("%s:%s-%s", p.Epoch, p.Version, p.Release)] = append(packages[n][fmt.Sprintf("%s:%s-%s", p.Epoch, p.Version, p.Release)], p.Arch)
	}

	for n, vras := range packages {
		for vr, as := range vras {
			extracted.Detection = append(extracted.Detection, detection.Detection{
				Ecosystem:  fmt.Sprintf(detection.EcosystemTypeAlma, osver),
				Vulnerable: true,
				Package: detection.Package{
					Name:          n,
					Architectures: as,
				},
				Affected: &detection.Affected{
					Type:  detection.RangeTypeRPM,
					Range: []detection.Range{{LessThan: vr}},
					Fixed: []string{vr},
				},
			})
		}
	}

	return extracted
}
