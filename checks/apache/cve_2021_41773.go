package apache

import (
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

type CVE202141773 struct{ checker }

func NewCVE202141773(client httpx.Probe, mode model.Mode, canary model.CanaryConfig) *CVE202141773 {
	return &CVE202141773{checker{
		meta:     model.Metadata{ID: "CVE-2021-41773", Name: "Apache HTTP Server Path Traversal", Product: "apache", Severity: "critical", References: []string{reference + "#CVE-2021-41773"}},
		versions: map[string]bool{"2.4.49": true}, segment: ".%2e", client: client, mode: mode, canary: canary,
	}}
}
