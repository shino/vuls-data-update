package vulnrichment

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/MaineK00n/vuls-data-update/pkg/cmd/vulnrichment/goodver"
	v5 "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/v5"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	"github.com/MakeNowJust/heredoc"
	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type base struct {
	dir string
}

func NewCmdVulnrichment() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vulnrichment <kind of exploration>",
		Short: "Explore vulnrichment data",
		Example: heredoc.Doc(`
			$ vuls-data-update vulnrichment <subcommand>
		`),
	}

	cmd.AddCommand(newCmdCountCpe(), newCmdOrg(), newCmdCpePart(), newCmdVendor(), newCmdVendorProduct(),
		newCmdCpeRemoval(), newCmdFieldVendorProductDiff(), newJoinFvulsCPE())
	return cmd
}

func newCmdCountCpe() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "vulnrichment"),
	}

	cmd := &cobra.Command{
		Use:   "count-cpe",
		Short: "Count CVEs with CPE information",
		Example: heredoc.Doc(`
			$ vuls-data-update vulnrichment cpe-count
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := countCpe(options.dir); err != nil {
				return errors.Wrap(err, "failed to count-cpe")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "vulnrichment"), "working directory")
	return cmd
}

func countCpe(cacheDir string) error {
	var total, cnaWithCpe, cisaWithCpe int

	walk(cacheDir, "vulnrichment", func(cve v5.CVE) error {
		total++

		for _, a := range cve.Containers.CNA.Affected {
			for _, c := range a.Cpes {
				if !strings.HasPrefix(c, "cpe:") {
					continue
				}
				cnaWithCpe++
				return nil
			}
		}
		return nil
	})

	walkCISAADP(cacheDir, "vulnrichment", func(cve v5.CVE, adp v5adp) error {
		for _, a := range adp.Affected {
			for _, c := range a.Cpes {
				if !strings.HasPrefix(c, "cpe:") {
					continue
				}
				cisaWithCpe++
				return nil
			}
		}
		return nil
	})

	fmt.Println("===================")
	fmt.Printf("Total CVEs        : %d\n", total)
	fmt.Printf("CNA with CPE      : %d\n", cnaWithCpe)
	fmt.Printf("CISA ADP with CPE : %d\n", cisaWithCpe)
	return nil
}

func newCmdCpePart() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "vulnrichment"),
	}

	cmd := &cobra.Command{
		Use:   "cpe-part",
		Short: "Count part of CPE information in CISA-ADP",
		Example: heredoc.Doc(`
			$ vuls-data-update vulnrichment cpe-part
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := countPart(options.dir); err != nil {
				return errors.Wrap(err, "failed to cpe-part")
			}
			return nil
		},
	}

	return cmd
}

func countPart(cacheDir string) error {
	partCount := map[string]int{}
	walkCISAADP(cacheDir, "vulnrichment", func(cve v5.CVE, adp v5adp) error {
		uniqPart := map[string]struct{}{}
		for _, a := range adp.Affected {
			for _, c := range a.Cpes {
				wfn, err := naming.UnbindFS(c)
				if err != nil {
					return errors.Wrapf(err, "UnbindFS %s", c)
				}
				uniqPart[wfn.GetString(common.AttributePart)] = struct{}{}
			}
		}
		for p := range uniqPart {
			partCount[p]++
		}
		return nil
	})

	for p, c := range partCount {
		fmt.Printf("%s %d\n", p, c)
	}
	return nil
}

func newCmdOrg() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "vulnrichment"),
	}

	cmd := &cobra.Command{
		Use:   "org",
		Short: "Summerize Org ID and Names",
		Example: heredoc.Doc(`
			$ vuls-data-update vulnrichment org
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := summarizeOrg(options.dir); err != nil {
				return errors.Wrap(err, "failed to summarize org")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "vulnrichment"), "working directory")
	return cmd
}

func summarizeOrg(cacheDir string) error {
	adpCounts := map[int]int{}
	ids := map[string]int{}
	names := map[string]int{}
	idNames := map[string]int{}

	walk(cacheDir, "vulnrichment", func(cve v5.CVE) error {
		adps := cve.Containers.ADP
		adpCounts[len(adps)]++

		if len(adps) == 0 && cve.CVEMetadata.State != "REJECTED" {
			log.Printf("No adp: %s", cve.CVEMetadata.CVEID)
		}
		for _, a := range adps {
			if a.ProviderMetadata.OrgID == "" {
				log.Printf("orgId is empty: %s", cve.CVEMetadata.CVEID)
			}
			if *a.ProviderMetadata.ShortName == "" {
				log.Printf("shortName is empty: %s", cve.CVEMetadata.CVEID)
			}

			ids[a.ProviderMetadata.OrgID]++
			if a.ProviderMetadata.ShortName != nil {
				names[*a.ProviderMetadata.ShortName]++
				idNames[fmt.Sprintf("%s@%s", *a.ProviderMetadata.ShortName, a.ProviderMetadata.OrgID)]++
			}
		}

		return nil
	})

	fmt.Printf("\n=== Org ID counts ===\n")
	for k, v := range ids {
		fmt.Printf("%s : %d\n", k, v)
	}
	fmt.Printf("\n=== Org name counts ===\n")
	for k, v := range names {
		fmt.Printf("%s : %d\n", k, v)
	}
	fmt.Printf("\n== Org name@ID counts ===\n")
	for k, v := range idNames {
		fmt.Printf("%s : %d\n", k, v)
	}
	return nil
}

func newCmdVendor() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "vulnrichment"),
	}

	cmd := &cobra.Command{
		Use:   "adp-vendor",
		Short: "Summarize CPE vendor information in CISA ADP",
		Example: heredoc.Doc(`
			$ vuls-data-update vulnrichment vendor
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := listVendor(options.dir); err != nil {
				return errors.Wrap(err, "failed to list adp-vendor")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "vulnrichment"), "working directory")
	return cmd
}

func listVendor(cacheDir string) error {
	vendorCounts := map[string]int{}
	walkCISAADP(cacheDir, "vulnrichment", func(cve v5.CVE, adp v5adp) error {
		uniqVendors := map[string]struct{}{}
		for _, a := range adp.Affected {
			for _, c := range a.Cpes {
				wfn, err := naming.UnbindFS(c)
				if err != nil {
					return errors.Wrapf(err, "UnbindFS %s", c)
				}
				partVendor := fmt.Sprintf("%s:%s", wfn.GetString(common.AttributePart), wfn.GetString(common.AttributeVendor))
				uniqVendors[partVendor] = struct{}{}
			}
		}
		for v := range uniqVendors {
			vendorCounts[v]++
		}
		return nil
	})

	for _, i := range sortKeyAndCount(vendorCounts) {
		fmt.Printf("%d %s\n", i.count, i.key)
	}
	return nil
}

func newCmdVendorProduct() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "vulnrichment"),
	}

	cmd := &cobra.Command{
		Use:   "adp-vendor-product",
		Short: "Summarize CPE vendor/product information in ADP with part=a",
		Example: heredoc.Doc(`
			$ vuls-data-update vulnrichment adp-vendor-product
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := listVendorProduct(options.dir); err != nil {
				return errors.Wrap(err, "failed to list adp-vendor-product")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "vulnrichment"), "working directory")
	return cmd
}

func listVendorProduct(cacheDir string) error {
	vendorProductCounts := map[string]int{}
	validVendorProductCounts := map[string]int{}

	walkCISAADP(cacheDir, "vulnrichment", func(cve v5.CVE, adp v5adp) error {
		uniqVendorProducts := map[string]struct{}{}
		uniqValidVendorProducts := map[string]struct{}{}
		for _, a := range adp.Affected {
			var valid bool
			for _, v := range a.Versions {
				if validVersions(cve.CVEMetadata.CVEID, v.Version, v.LessThan, v.LessThanOrEqual) {
					valid = true
				}
			}

			for _, c := range a.Cpes {
				wfn, err := naming.UnbindFS(c)
				if err != nil {
					return errors.Wrapf(err, "UnbindFS %s", c)
				}
				if wfn.GetString(common.AttributePart) != "a" {
					continue
				}
				key := strings.Join([]string{wfn.GetString(common.AttributePart), wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct)}, ":")
				uniqVendorProducts[key] = struct{}{}
				if valid {
					uniqValidVendorProducts[key] = struct{}{}
				}
			}
		}
		for v := range uniqVendorProducts {
			vendorProductCounts[v]++
		}
		for v := range uniqValidVendorProducts {
			validVendorProductCounts[v]++
		}

		return nil
	})

	for _, i := range sortKeyAndCount(vendorProductCounts) {
		var validCount = validVendorProductCounts[i.key]
		fmt.Printf("%d %d %s\n", i.count, validCount, i.key)
	}
	return nil
}

func newCmdCpeRemoval() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "vulnrichment"),
	}

	cmd := &cobra.Command{
		Use:   "cpe-removal",
		Short: "List CPE information removed in ADP",
		Example: heredoc.Doc(`
			$ vuls-data-update vulnrichment cpe-removal
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := listCpeRemoval(options.dir); err != nil {
				return errors.Wrap(err, "failed to list cpe-removal")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "vulnrichment"), "working directory")
	return cmd
}

func listCpeRemoval(cacheDir string) error {
	latestCommit, err := gitCloneOrPull(cacheDir, "latest")
	if err != nil {
		return errors.Wrapf(err, "gitCloneOrPull")
	}

	twoWeelsAgoGitDir, oldCommit, err := prepareOld(cacheDir, "latest", 14)
	if err != nil {
		return errors.Wrapf(err, "prepareOld, %d days", 14)
	}

	// CVE ID -> CPE names
	latestCPEs := map[string]map[string]struct{}{}
	walkCISAADP(cacheDir, "latest", func(cve v5.CVE, adp v5adp) error {
		for _, a := range adp.Affected {
			for _, c := range a.Cpes {
				if _, ok := latestCPEs[cve.CVEMetadata.CVEID]; !ok {
					latestCPEs[cve.CVEMetadata.CVEID] = map[string]struct{}{}
				}
				vendorProd, err := pvp(c)
				if err != nil {
					return err
				}
				latestCPEs[cve.CVEMetadata.CVEID][vendorProd] = struct{}{}
			}
		}
		return nil
	})
	twoWeeksAgoCPEs := map[string]map[string]struct{}{}
	walkCISAADP(cacheDir, twoWeelsAgoGitDir, func(cve v5.CVE, adp v5adp) error {
		for _, a := range adp.Affected {
			for _, c := range a.Cpes {
				if _, ok := twoWeeksAgoCPEs[cve.CVEMetadata.CVEID]; !ok {
					twoWeeksAgoCPEs[cve.CVEMetadata.CVEID] = map[string]struct{}{}
				}
				vendorProd, err := pvp(c)
				if err != nil {
					return err
				}
				twoWeeksAgoCPEs[cve.CVEMetadata.CVEID][vendorProd] = struct{}{}
			}
		}
		return nil
	})

	for cveID, oldCPEs := range twoWeeksAgoCPEs {
		latestCPEs := latestCPEs[cveID]
		// fmt.Printf("%s ========\n", cveID)
		// fmt.Printf("%s\n", strings.Join(maps.Keys(oldCPEs), ", "))
		// fmt.Printf("%s\n", strings.Join(maps.Keys(latestCPEs), ", "))
		// TODO: Show all cpes for old and latest
		for oldCPE := range oldCPEs {
			if _, ok := latestCPEs[oldCPE]; !ok {
				fmt.Printf("%s: %s -> N/A\n", cveID, oldCPE)
				fmt.Printf("  old   : %s\n", cveURL(cveID, oldCommit))
				fmt.Printf("  latest: %s\n\n", cveURL(cveID, latestCommit))
			}
		}
	}
	return nil
}

func newCmdFieldVendorProductDiff() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "vulnrichment"),
	}

	cmd := &cobra.Command{
		Use:   "field-vendor-product-diff",
		Short: "List difference between CPE's and fields' vendor/product information",
		Example: heredoc.Doc(`
			$ vuls-data-update vulnrichment field-vendor-product-diff
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := listFieldVendorProductDiff(options.dir); err != nil {
				return errors.Wrap(err, "failed to list field-vendor-product-diff")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "vulnrichment"), "working directory")
	return cmd
}

func listFieldVendorProductDiff(cacheDir string) error {
	commit, err := gitCloneOrPull(cacheDir, "latest")
	if err != nil {
		return errors.Wrapf(err, "gitCloneOrPull")
	}

	walkCISAADP(cacheDir, "latest", func(cve v5.CVE, adp v5adp) error {
		for _, a := range adp.Affected {
			var fieldVendor = "[empty]"
			var fieldProduct = "[empty]"
			if a.Vendor != nil {
				fieldVendor = *a.Vendor
			}
			if a.Product != nil {
				fieldProduct = *a.Product
			}
			fieldVp := strings.Join([]string{fieldVendor, fieldProduct}, ":")
			for _, c := range a.Cpes {
				cpeVp, err := vp(c)
				if err != nil {
					return err
				}

				// Ignore backslach characters
				if strings.ReplaceAll(cpeVp, "\\", "") != strings.ReplaceAll(fieldVp, "\\", "") {
					fmt.Printf("%s: field %s, cpe: %s, %s\n", cve.CVEMetadata.CVEID, fieldVp, cpeVp, cveURL(cve.CVEMetadata.CVEID, commit))
				}
			}
		}
		return nil
	})
	return nil
}

func newJoinFvulsCPE() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "vulnrichment"),
	}

	cmd := &cobra.Command{
		Use:   "join-fvuls-cpe",
		Short: "List joined results between vulnrichment and fvuls CPEs",
		Example: heredoc.Doc(`
			$ vuls-data-update vulnrichment join-fvuls-cpe
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := joinFvulsCPE(options.dir); err != nil {
				return errors.Wrap(err, "failed to list join-fvuls-cpe")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "vulnrichment"), "working directory")
	return cmd
}

func joinFvulsCPE(cacheDir string) error {
	fvulsCPEPath := "/home/shino/sb/fvuls-cpe/fvuls-cpe.csv"
	fvulsCPEs := map[string]int{}
	file, err := os.Open(fvulsCPEPath)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		if scanner.Text() == "cpe_uri" {
			continue
		}
		cpe := scanner.Text()
		vendorProduct, err := pvp(cpe)
		if err != nil {
			return err
		}
		key := strings.ReplaceAll(vendorProduct, "\\", "")
		fvulsCPEs[key]++
	}

	if err := scanner.Err(); err != nil {
		return errors.Wrapf(err, "fvuls cpe scan")
	}

	foundCPEs := map[string]int{}

	walkCISAADP(cacheDir, "latest", func(cve v5.CVE, adp v5adp) error {
		for _, a := range adp.Affected {
			for _, c := range a.Cpes {
				cpeVendorProduct, err := pvp(c)
				if err != nil {
					return err
				}

				key := strings.ReplaceAll(cpeVendorProduct, "\\", "")
				if c, ok := fvulsCPEs[key]; ok {
					foundCPEs[key] = c
				}
			}
		}
		return nil
	})

	walk(cacheDir, "latest", func(cve v5.CVE) error {
		for _, a := range cve.Containers.CNA.Affected {
			for _, c := range a.Cpes {
				cpeVendorProduct, err := pvp(c)
				if err != nil {
					return err
				}

				key := strings.ReplaceAll(cpeVendorProduct, "\\", "")
				if c, ok := fvulsCPEs[key]; ok {
					foundCPEs[key] = c
				}
			}
		}
		return nil
	})

	for k, c := range foundCPEs {
		fmt.Printf("%3d %s\n", c, k)
	}

	return nil
}

type keyAndCount struct {
	count int
	key   string
}

func sortKeyAndCount(m map[string]int) []keyAndCount {
	var res = make([]keyAndCount, 0, len(m))
	for k, c := range m {
		res = append(res, keyAndCount{c, k})
	}
	slices.SortFunc(res, func(l, r keyAndCount) int {
		return r.count - l.count
	})
	return res
}

func cveURL(cveID, commitHash string) string {
	ss := strings.Split(cveID, "-")
	return fmt.Sprintf("https://github.com/cisagov/vulnrichment/blob/%s/%s/%sxxx/%s.json", commitHash[0:7], ss[1], ss[2][0:(len(ss[2])-3)], cveID)
}

func validVersions(cveID, version string, lt, le *string) bool {
	if version == "" {
		log.Printf("[%s] empty version is empty", cveID)
		return false
	}

	ok, v := goodver.Parse(version)
	if !ok {
		if version != "*" && version != "-" {
			log.Printf("[%s] invalid version: %q", cveID, version)
		}
		return false
	}

	if lt != nil {
		ok, vlt := goodver.Parse(*lt)
		if !ok {
			log.Printf("[%s] invalid lessThan: %q", cveID, *lt)
			return false
		}
		if goodver.Compare(vlt, v) <= 0 {
			log.Printf("[%s] invalid version: %q and lessThan: %q", cveID, version, *lt)
			return false
		}
	}

	if le != nil {
		ok, vle := goodver.Parse(*le)
		if !ok {
			log.Printf("[%s] invalid lessThanOrEqual: %q", cveID, *le)
			return false
		}
		if goodver.Compare(vle, v) < 0 {
			log.Printf("[%s] invalid version: %q and lessThanOrEqual: %q", cveID, version, *le)
			return false
		}

	}
	return true
}

func walkCISAADP(cacheDir, subDir string, cveFun func(cve v5.CVE, adp v5adp) error) error {
	walk(cacheDir, subDir, func(cve v5.CVE) error {
		for _, adp := range cve.Containers.ADP {
			if adp.ProviderMetadata.OrgID != "8c464350-323a-4346-a867-fc54517fa145" && adp.ProviderMetadata.OrgID != "134c704f-9b21-4f2e-91b3-4a467353bcc0" {
				continue
			}
			if err := cveFun(cve, adp); err != nil {
				return err
			}
		}
		return nil
	})
	return nil
}

func walk(cacheDir, subDir string, cveFun func(cve v5.CVE) error) error {
	gitDir := filepath.Join(cacheDir, subDir)
	if err := filepath.WalkDir(gitDir, func(path string, d fs.DirEntry, err error) error {
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

		var cve v5.CVE
		if err := json.NewDecoder(f).Decode(&cve); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		if err := cveFun(cve); err != nil {
			return errors.Wrapf(err, "cvdFun(): %#v", cve)
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", gitDir)
	}

	return nil
}

func gitCloneOrPull(cacheDir, subDir string) (string, error) {
	gitDir := filepath.Join(cacheDir, subDir)
	_, err := os.Stat(gitDir)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err != nil {
		// clone
		cmd := exec.Command("git", "clone", "https://github.com/cisagov/vulnrichment.git", subDir)
		cmd.Dir = cacheDir
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", errors.Wrapf(err, "git clone: %s", string(out))
		}
		return "", nil
	}

	// pull
	cmd := exec.Command("git", "pull")
	cmd.Dir = gitDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", errors.Wrapf(err, "git pull: %s", string(out))
	}

	cmd = exec.Command("git", "show", "--format=%h", "--no-patch")
	cmd.Dir = gitDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", errors.Wrapf(err, "git pull: %s", string(out))
	}
	commit := strings.ReplaceAll(string(out), "\n", "")
	return commit, nil
}

func prepareOld(cacheDir, latestSubdir string, days int) (string, string, error) {
	subDir := fmt.Sprintf("old-%d-days", days)
	gitDir := filepath.Join(cacheDir, subDir)
	_, err := os.Stat(gitDir)
	if err != nil && !os.IsNotExist(err) {
		return "", "", err
	}

	if err != nil {
		// copy latest
		cmd := exec.Command("cp", "-a", filepath.Join(cacheDir, latestSubdir), gitDir)
		cmd.Dir = cacheDir
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", "", errors.Wrapf(err, "copy from latest: %s", string(out))
		}
	}

	cmd := exec.Command("git", "rev-list", "-n", "1", "--first-parent",
		"--before", fmt.Sprintf("'%d days ago'", days), "develop")
	cmd.Dir = gitDir
	out, err := cmd.CombinedOutput()
	commit := strings.ReplaceAll(string(out), "\n", "")
	// fmt.Println(string(out))
	if err != nil {
		return "", "", errors.Wrapf(err, "%s: %s", cmd.String(), string(out))
	}
	cmd = exec.Command("git", "checkout", commit)
	cmd.Dir = gitDir
	if out, err := cmd.CombinedOutput(); err != nil {
		// fmt.Println(string(out))
		return "", "", errors.Wrapf(err, "%s: %s", cmd.String(), string(out))
	}
	return subDir, commit, nil
}

func pvp(cpe string) (string, error) {
	var wfn common.WellFormedName
	wfn, err := naming.UnbindFS(cpe)
	if err != nil {
		wfn, err = naming.UnbindURI(cpe)
		if err != nil {
			return "", errors.Wrap(err, "CPE unbind FS or URI")
		}
	}
	return strings.Join([]string{wfnGetString(wfn, common.AttributePart), wfnGetString(wfn, common.AttributeVendor), wfnGetString(wfn, common.AttributeProduct)}, ":"), nil
}

func vp(cpe string) (string, error) {
	wfn, err := naming.UnbindFS(cpe)
	if err != nil {
		return "", errors.Wrapf(err, "UnbindFS %s", cpe)
	}
	return strings.Join([]string{wfnGetString(wfn, common.AttributeVendor), wfnGetString(wfn, common.AttributeProduct)}, ":"), nil
}

func wfnGetString(wfn common.WellFormedName, attribute string) string {
	s := wfn.GetString(attribute)
	switch s {
	case "NA":
		return "-"
	case "ANY":
		return "*"
	default:
		return s
	}
}
