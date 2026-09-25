package tomcat

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"gopoc/checks/detect"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

type checker struct {
	meta   model.Metadata
	client httpx.Probe
}

func NewCVE202524813(client httpx.Probe) *checker {
	return &checker{
		meta: model.Metadata{
			ID:         "CVE-2025-24813",
			Name:       "Apache Tomcat Partial PUT Path-Equivalence RCE",
			Product:    "tomcat",
			Severity:   "critical",
			References: []string{"https://tomcat.apache.org/security-9.html", "https://tomcat.apache.org/security-10.html", "https://tomcat.apache.org/security-11.html"},
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

// Detection-only: a GET fingerprint plus a safe OPTIONS writability check.
func (c *checker) Capabilities() model.Capability {
	return model.CapPassive | model.CapHTTPGet
}

func (c *checker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	// A random path forces Tomcat's 404 page, which carries the version banner.
	var b [8]byte
	_, _ = rand.Read(b[:])
	r, err := c.client.Get(ctx, target, "/gopoc-"+hex.EncodeToString(b[:]))
	f.Evidence = model.Evidence{StatusCode: r.StatusCode, Headers: r.Headers, Observations: []model.Observation{r.Observation("fingerprint", err)}}
	if err != nil {
		f.Verdict, f.Reason = model.VerdictError, "request_failed"
		f.Evidence.Message = "Fingerprint request failed: " + err.Error()
		return f
	}
	if !isTomcat(r) {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 60, "product_not_tomcat"
		f.Evidence.Message = "No Apache Tomcat fingerprint; this CVE does not apply"
		return f
	}
	ver, known := version(r)
	f.Evidence.Version = ver
	if !known {
		f.Confidence, f.Reason = 40, "version_unknown"
		f.Evidence.Message = "Tomcat detected but no version banner was exposed; affected status is unknown"
		return f
	}
	v, _ := detect.ParseVersion(ver)
	aff, fixed := affected(v)
	if !aff {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 75, "version_not_affected"
		f.Evidence.Message = fmt.Sprintf("Tomcat %s is outside CVE-2025-24813's affected range", ver)
		return f
	}

	writable, obs := writableDefaultServlet(ctx, c.client, target)
	f.Evidence.Observations = append(f.Evidence.Observations, obs)
	if writable {
		f.Verdict, f.Confidence, f.Reason = model.VerdictLikely, 80, "writable_default_servlet"
		f.Evidence.Message = fmt.Sprintf(
			"Tomcat %s is affected (fixed in %s) and the DefaultServlet is writable (OPTIONS advertises PUT). Unverified prerequisites — partial PUT: %s; session persistence: %s; gadget: %s. Exploit (partial PUT + deserialization) NOT attempted",
			ver, fixed, partialPUTStatus, persistenceStatus, gadgetStatus)
	} else {
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 70, "affected_version"
		f.Evidence.Message = fmt.Sprintf("Tomcat %s is affected (fixed in %s) but the DefaultServlet writable prerequisite is not established; exploit prerequisites not confirmed", ver, fixed)
	}
	return f
}
