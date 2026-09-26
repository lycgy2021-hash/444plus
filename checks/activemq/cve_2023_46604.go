package activemq

import (
	"context"
	"fmt"

	"gopoc/checks/activemq/protocol"
	"gopoc/checks/detect"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

type checker struct {
	meta   model.Metadata
	client httpx.Probe
}

func NewCVE202346604(client httpx.Probe) *checker {
	return &checker{
		meta: model.Metadata{
			ID:       "CVE-2023-46604",
			Name:     "Apache ActiveMQ OpenWire Protocol Marshaller RCE",
			Product:  "activemq",
			Severity: "critical",
			References: []string{
				"https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt",
				"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-46604",
			},
		},
		client: client,
	}
}

func (c *checker) ID() string   { return c.meta.ID }
func (c *checker) Name() string { return c.meta.Name }
func (c *checker) Metadata() model.Metadata {
	m := c.meta
	m.Capabilities = c.Capabilities().Names()
	return m
}

// Detection-only: a single passive TCP read of the OpenWire handshake the
// broker sends unsolicited. We never write the crafted class-name packet that
// triggers the marshaller vulnerability — that write IS the exploit.
func (c *checker) Capabilities() model.Capability {
	return model.CapPassive | model.CapTCPProbe
}

// Check implements the ladder fixed in docs/activemq-attack-surface.md:
//
//	OpenWire probe ambiguous (dial/read error, policy block, short read) -> unknown, openwire_unverified
//	real bytes read, magic absent                                        -> not_found, product_not_activemq
//	magic present, ProviderVersion missing/unparseable                   -> unknown, version_unknown
//	magic present, version outside every affected branch                 -> not_found, version_not_affected
//	magic present, version inside an affected branch                     -> likely, openwire_exposed_affected_version
//	confirmed                                                             -> never; would require sending the trigger
//
// Unlike every other product line here, there is no separable `detected` tier:
// the only way to read ProviderVersion is a fully-completed OpenWire handshake,
// which is itself proof the vulnerable listener is live. Version and exposure
// arrive from the same probe, so affected-version goes straight to `likely`.
func (c *checker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}

	identified, ver, obs := protocol.OpenWire(ctx, c.client, target)
	f.Evidence = model.Evidence{Observations: []model.Observation{obs}}

	if obs.Error != "" {
		f.Confidence, f.Reason = 30, "openwire_unverified"
		f.Evidence.Message = "The OpenWire handshake could not be completed (blocked, timed out, or the read was too short); ActiveMQ presence and CVE-2023-46604 status are unknown"
		return f
	}
	if !identified {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 65, "product_not_activemq"
		f.Evidence.Message = "The OpenWire handshake completed but carried no ActiveMQ magic bytes; this CVE does not apply"
		return f
	}
	f.Evidence.Version = ver
	if ver == "" {
		f.Confidence, f.Reason = 40, "version_unknown"
		f.Evidence.Message = "ActiveMQ OpenWire fingerprint confirmed but no ProviderVersion was read from the handshake; affected status is unknown"
		return f
	}
	v, ok := detect.ParseVersion(ver)
	if !ok {
		f.Confidence, f.Reason = 40, "version_unparseable"
		f.Evidence.Message = fmt.Sprintf("ActiveMQ OpenWire fingerprint confirmed but ProviderVersion %q did not parse as major.minor.patch; affected status is unknown", ver)
		return f
	}
	if aff, fixed := affected(v); aff {
		f.Verdict, f.Confidence, f.Reason = model.VerdictLikely, 85, "openwire_exposed_affected_version"
		f.Evidence.Message = fmt.Sprintf(
			"ActiveMQ %s is in CVE-2023-46604's affected range (fixed in %s). The single passive read that gave us the version is itself proof the vulnerable OpenWire listener is live — there is no separate reachability probe for this CVE. The crafted class-instantiation packet was NOT sent; confirming exploitability would require triggering the marshaller vulnerability itself",
			ver, fixed)
		return f
	}
	f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 80, "version_not_affected"
	f.Evidence.Message = fmt.Sprintf("ActiveMQ %s is outside CVE-2023-46604's affected branches", ver)
	return f
}
