package vulnrichment

import v5 "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/v5"

type v5adp struct {
	ProviderMetadata v5.ProviderMetadata `json:"providerMetadata"`
	Title            *string             `json:"title,omitempty"`
	Descriptions     []v5.Description    `json:"descriptions,omitempty"`
	Affected         []v5.Product        `json:"affected,omitempty"`
	ProblemTypes     []v5.ProblemType    `json:"problemTypes,omitempty"`
	Impacts          []v5.Impact         `json:"impacts,omitempty"`
	Metrics          []v5.Metric         `json:"metrics,omitempty"`
	Workarounds      []v5.Description    `json:"workarounds,omitempty"`
	Solutions        []v5.Description    `json:"solutions,omitempty"`
	Exploits         []v5.Description    `json:"exploits,omitempty"`
	Configurations   []v5.Description    `json:"configurations,omitempty"`
	References       []v5.Reference      `json:"references,omitempty"`
	Timeline         v5.Timeline         `json:"timeline,omitempty"`
	Credits          v5.Credits          `json:"credits,omitempty"`
	Source           interface{}         `json:"source,omitempty"`
	Tags             []string            `json:"tags,omitempty"`
	TaxonomyMappings v5.TaxonomyMappings `json:"taxonomyMappings,omitempty"`
	DatePublic       *string             `json:"datePublic,omitempty"`
}
