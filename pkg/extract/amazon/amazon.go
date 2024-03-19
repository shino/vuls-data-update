package amazon

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/reference"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/amazon"
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
		dir: filepath.Join(util.CacheDir(), "extract", "amazon"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Amazon Linux")
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

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		var fetched amazon.Update
		if err := json.NewDecoder(f).Decode(&fetched); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		extracted := extract(fetched)

		dir, y := filepath.Split(filepath.Dir(path))
		dir, repo := filepath.Split(filepath.Clean(dir))
		if filepath.Base(dir) == "extras" {
			dir = filepath.Dir(filepath.Clean(dir))
			repo = filepath.Join("extras", repo)
		}
		if err := util.Write(filepath.Join(options.dir, filepath.Base(dir), repo, y, fmt.Sprintf("%s.json", extracted.ID)), extracted); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, filepath.Base(dir), repo, y, fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	return nil
}

func extract(fetched amazon.Update) types.Data {
	data := types.Data{
		ID: fetched.ID,
		Advisories: []types.Advisory{{
			ID:          fetched.ID,
			Title:       fetched.Title,
			Description: fetched.Description,
			Severity: []severity.Severity{{
				Type:   severity.SeverityTypeVendor,
				Source: fetched.Author,
				Vendor: &fetched.Severity,
			}},
			References: []reference.Reference{{
				Source: fetched.Author,
				URL: func() string {
					switch {
					case strings.HasPrefix(fetched.ID, "ALAS2023"):
						return fmt.Sprintf("https://alas.aws.amazon.com/AL2023/ALAS%s.html", strings.TrimPrefix(fetched.ID, "ALAS2023"))
					case strings.HasPrefix(fetched.ID, "ALAS2022"):
						return fmt.Sprintf("https://alas.aws.amazon.com/AL2022/ALAS%s.html", strings.TrimPrefix(fetched.ID, "ALAS2022"))
					case strings.HasPrefix(fetched.ID, "ALAS2"):
						return fmt.Sprintf("https://alas.aws.amazon.com/AL2/ALAS%s.html", strings.TrimPrefix(fetched.ID, "ALAS2"))
					default:
						return fmt.Sprintf("https://alas.aws.amazon.com/ALAS%s.html", strings.TrimPrefix(fetched.ID, "ALAS"))
					}
				}(),
			}},
			Published: utiltime.Parse([]string{"2006-01-02T15:04:05Z"}, fetched.Issued.Date),
			Modified:  utiltime.Parse([]string{"2006-01-02T15:04:05Z"}, fetched.Updated.Date),
		}},
		DataSource: source.Amazon,
	}

	for _, r := range fetched.References.Reference {
		switch r.Type {
		case "cve":
			data.Advisories[0].References = append(data.Advisories[0].References, reference.Reference{
				Source: fetched.Author,
				URL:    r.Href,
			})
			data.Vulnerabilities = append(data.Vulnerabilities, types.Vulnerability{
				ID: r.ID,
				References: []reference.Reference{{
					Source: fetched.Author,
					URL:    r.Href,
				}},
			})
		default:
			data.Advisories[0].References = append(data.Advisories[0].References, reference.Reference{
				Source: fetched.Author,
				URL:    r.Href,
			})
		}
	}

	pkgs := map[string]map[string][]string{}
	for _, p := range fetched.Pkglist.Collection.Package {
		if pkgs[p.Name] == nil {
			pkgs[p.Name] = map[string][]string{}
		}
		pkgs[p.Name][fmt.Sprintf("%s:%s-%s", p.Epoch, p.Version, p.Release)] = append(pkgs[p.Name][fmt.Sprintf("%s:%s-%s", p.Epoch, p.Name, p.Release)], p.Arch)
	}

	for n, evras := range pkgs {
		for evr, as := range evras {
			data.Detection = append(data.Detection, detection.Detection{
				Ecosystem: fmt.Sprintf(detection.EcosystemTypeAmazon, func() string {
					switch {
					case strings.HasPrefix(fetched.ID, "ALAS2023"):
						return "2023"
					case strings.HasPrefix(fetched.ID, "ALAS2022"):
						return "2022"
					case strings.HasPrefix(fetched.ID, "ALAS2"):
						return "2"
					default:
						return "1"
					}
				}()),
				Vulnerable: true,
				Package: detection.Package{
					Name: n,
					Repositories: func() []string {
						switch {
						case strings.HasPrefix(fetched.ID, "ALAS2023"):
							if repo, ok := strings.CutPrefix(fetched.Pkglist.Collection.Short, "amazon-linux-2023---"); ok {
								return []string{repo}
							}
							return []string{"amazonlinux"}
						case strings.HasPrefix(fetched.ID, "ALAS2022"):
							return []string{"amazonlinux"}
						case strings.HasPrefix(fetched.ID, "ALAS2"):
							if repo, ok := strings.CutPrefix(fetched.Pkglist.Collection.Short, "amazon-linux-2---"); ok {
								return []string{fmt.Sprintf("amzn2extra-%s", repo)}
							}
							return []string{"amzn2-core"}
						default:
							return []string{"amzn-main", "amzn-updates"}
						}
					}(),
					Architectures: as,
				},
				Affected: &detection.Affected{
					Type:  detection.RangeTypeRPM,
					Range: []detection.Range{{LessThan: evr}},
					Fixed: []string{evr},
				},
			})
		}
	}

	return data
}
