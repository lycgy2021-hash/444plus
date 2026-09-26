package jbosswildfly

import (
	"context"
	"fmt"

	"gopoc/internal/assesscache"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// unauthManagementID is not a CVE: there is no recent unauthenticated-RCE CVE
// in this product worth chasing (see docs/jboss-wildfly-attack-surface.md).
// The reproducible, high-value condition is a misconfiguration — the HTTP
// management interface answering without authentication — which grants full
// server control (deploy, read secrets) and is the genuine differentiator
// between a default-secure instance and an exposed one.
const unauthManagementID = "MISCONFIG-JBOSSWILDFLY-UNAUTH-MGMT"

type assessment struct {
	isProduct bool
	version   string
	mgmt      managementProbe
	obs       []model.Observation
}

// assess returns the shared JBoss/WildFly assessment, memoized per scan.
func assess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	if c := assesscache.From(ctx); c != nil {
		return c.GetOrRun(assesscache.Key{Target: target.BaseURL, Product: "jbosswildfly"}, func() any {
			return doAssess(ctx, client, target)
		}).(assessment)
	}
	return doAssess(ctx, client, target)
}

func doAssess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	var a assessment
	// A plain GET, not client.Fingerprint: Fingerprint's shared cache always
	// nils out the response Body (by design, to keep a large target list
	// cheap), so a body-based fingerprint check against it never matches
	// anything — confirmed on a live WildFly image, where this silently made
	// the welcome-page signal dead code end to end. checks/jenkins avoids this
	// class of bug entirely by fingerprinting on headers only.
	fp, fpErr := client.Get(ctx, target, "/")
	fpObs := fp.Observation("fingerprint", fpErr)
	if fpErr == nil {
		a.isProduct = looksLikeProduct(fp)
	}

	mgmt, mgmtObs := probeManagement(ctx, client, target)
	a.mgmt = mgmt
	a.obs = append([]model.Observation{fpObs}, mgmtObs...)

	if mgmt.err == nil {
		// The management response itself can be the only signal (e.g. the app
		// port is unreachable, but 9990 answers directly): a Digest challenge
		// naming ManagementRealm, or unauthenticated product/version data, is
		// on its own as strong a product signal as the welcome page.
		if requiresAuth(mgmt.response) || unauthenticatedData(mgmt.response) {
			a.isProduct = true
		}
		if v, ok := extractVersion(mgmt.response); ok {
			a.version = v
		}
	}
	return a
}

type unauthManagementChecker struct {
	meta   model.Metadata
	client httpx.Probe
}

// NewUnauthenticatedManagement detects a JBoss/WildFly HTTP management
// interface reachable without authentication.
func NewUnauthenticatedManagement(client httpx.Probe) *unauthManagementChecker {
	return &unauthManagementChecker{
		meta: model.Metadata{
			ID:       unauthManagementID,
			Name:     "JBoss/WildFly Unauthenticated Management Interface",
			Product:  "jbosswildfly",
			Severity: "critical",
			Family:   "misconfiguration",
			References: []string{
				"https://docs.wildfly.org/32/Admin_Guide.html",
			},
		},
		client: client,
	}
}

func (c *unauthManagementChecker) ID() string   { return c.meta.ID }
func (c *unauthManagementChecker) Name() string { return c.meta.Name }
func (c *unauthManagementChecker) Metadata() model.Metadata {
	m := c.meta
	m.Capabilities = c.Capabilities().Names()
	return m
}

// Detection-only: HTTP fingerprint plus a plain GET on the management API.
// Reading the root resource's own version attributes is not "deploying" or
// "modifying" anything, so this stays a passive-mode capability.
func (c *unauthManagementChecker) Capabilities() model.Capability {
	return model.CapPassive | model.CapHTTPGet
}

func (c *unauthManagementChecker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	a := assess(ctx, c.client, target)
	f.Evidence = model.Evidence{Observations: a.obs, Version: a.version}

	if !a.isProduct {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 70, "product_not_jbosswildfly"
		f.Evidence.Message = "No JBoss/WildFly fingerprint on the application port or the conventional management ports (9990/9993); this check does not apply"
		return f
	}
	if a.mgmt.err != nil {
		f.Confidence, f.Reason = 30, "management_unreachable"
		f.Evidence.Message = "JBoss/WildFly fingerprint present, but no management HTTP interface answered on the scanned port or the conventional management ports (9990/9993); unauthenticated exposure could not be determined"
		return f
	}

	resp := a.mgmt.response
	f.Evidence.StatusCode = resp.StatusCode
	f.Evidence.Headers = resp.Headers
	mgmtURL := a.mgmt.target.Origin() + managementPath

	switch {
	case requiresAuth(resp):
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 80, "management_requires_auth"
		f.Evidence.Message = fmt.Sprintf("JBoss/WildFly management interface found at %s and requires authentication (WWW-Authenticate names ManagementRealm); this is the secure default, not a misconfiguration", mgmtURL)
	case unauthenticatedData(resp):
		f.Verdict, f.Confidence, f.Reason = model.VerdictLikely, 90, "unauthenticated_management_exposed"
		msg := fmt.Sprintf("JBoss/WildFly management interface at %s returned product/version data with NO authentication challenge. This grants an unauthenticated caller full server control (deploy, read datasource/vault secrets) via the management API", mgmtURL)
		if a.version != "" {
			msg += fmt.Sprintf(" (product-version %s)", a.version)
		}
		msg += ". Deploy/config-change capability was NOT exercised"
		f.Evidence.Message = msg
	default:
		f.Confidence, f.Reason = 35, "management_state_unclear"
		f.Evidence.Message = fmt.Sprintf("JBoss/WildFly fingerprint present, but the response from %s matched neither the authenticated-challenge nor the unauthenticated-data pattern; management exposure is unknown", mgmtURL)
	}
	return f
}
