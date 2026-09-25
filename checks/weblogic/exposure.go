// Package weblogic holds a detection-only, multi-protocol checker for Oracle
// WebLogic Server. It fingerprints WebLogic, reads its version from a T3
// handshake, and detects which protocols (HTTP / T3 / IIOP / SOAP) are actually
// exposed via protocol-level probes — never inferring a protocol from an open
// port. It caps at `likely`: confirming the T3/IIOP deserialization RCE would
// require sending an exploit.
package weblogic

import (
	"context"

	"gopoc/checks/weblogic/protocol"
	"gopoc/internal/assesscache"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

type assessment struct {
	isWebLogic bool
	version    string
	http       bool
	t3         bool
	iiop       bool
	soap       bool
	obs        []model.Observation
}

// exposed returns the list of exposed protocol names, for evidence.
func (a assessment) exposed() []string {
	var names []string
	for _, p := range []struct {
		on   bool
		name string
	}{{a.http, "HTTP"}, {a.t3, "T3"}, {a.iiop, "IIOP"}, {a.soap, "SOAP"}} {
		if p.on {
			names = append(names, p.name)
		}
	}
	return names
}

// assess returns the shared WebLogic assessment, memoized per scan so all
// WebLogic CVE checkers reuse one HTTP+SOAP+T3+IIOP probe set instead of N.
func assess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	if c := assesscache.From(ctx); c != nil {
		return c.GetOrRun(assesscache.Key{Target: target.BaseURL, Product: "weblogic"}, func() any {
			return doAssess(ctx, client, target)
		}).(assessment)
	}
	return doAssess(ctx, client, target)
}

// doAssess runs every protocol probe once and combines the results. T3's HELO is
// the definitive WebLogic signal and the preferred version source.
func doAssess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	var a assessment
	httpExposed, httpWL, httpObs := protocol.HTTP(ctx, client, target)
	a.http = httpExposed
	a.obs = append(a.obs, httpObs)

	t3Exposed, t3Ver, t3Obs := protocol.T3(ctx, client, target)
	a.t3 = t3Exposed
	a.obs = append(a.obs, t3Obs)

	iiopExposed, iiopObs := protocol.IIOP(ctx, client, target)
	a.iiop = iiopExposed
	a.obs = append(a.obs, iiopObs)

	soapExposed, soapObs := protocol.SOAP(ctx, client, target)
	a.soap = soapExposed
	a.obs = append(a.obs, soapObs...)

	a.isWebLogic = httpWL || t3Exposed
	a.version = t3Ver
	return a
}
