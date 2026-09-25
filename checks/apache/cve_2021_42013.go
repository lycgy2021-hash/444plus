package apache

import (
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

type CVE202142013 struct{ checker }

func NewCVE202142013(client httpx.Probe, mode model.Mode, canary model.CanaryConfig) *CVE202142013 {
	return &CVE202142013{checker{
		meta:     model.Metadata{ID: "CVE-2021-42013", Name: "Apache HTTP Server Path Traversal (Incomplete Fix)", Product: "apache", Severity: "critical", References: []string{reference + "#CVE-2021-42013"}},
		versions: map[string]bool{"2.4.49": true, "2.4.50": true}, segment: ".%%32%65", client: client, mode: mode, canary: canary,
	}}
}
