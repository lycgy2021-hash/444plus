// Package ingressnginx holds a detection-only checker for IngressNightmare in
// the Kubernetes ingress-nginx controller. The exploit chain (CVE-2025-1974 with
// the annotation-injection flaws CVE-2025-1097 / 1098 / 24514) requires the
// admission webhook to be network-reachable and to process AdmissionReview
// requests from clients other than the API server. The controller version is not
// exposed to unauthenticated HTTP clients, so this checker detects the
// exploitable *exposure* using one benign, non-destructive AdmissionReview.
package ingressnginx

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"gopoc/checks/detect"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// admissionPath is ingress-nginx's default validating-webhook path.
const admissionPath = "/networking/v1/ingresses"

func NewCVE20251974(client httpx.Probe, mode model.Mode) *detect.ProbeChecker {
	return &detect.ProbeChecker{
		Meta: model.Metadata{
			ID:       "CVE-2025-1974",
			Name:     "ingress-nginx Admission Webhook Exposure (IngressNightmare)",
			Product:  "ingress-nginx",
			Severity: "critical",
			References: []string{
				"https://www.cve.org/CVERecord?id=CVE-2025-1974",
				"https://www.cve.org/CVERecord?id=CVE-2025-1097",
				"https://www.cve.org/CVERecord?id=CVE-2025-1098",
				"https://www.cve.org/CVERecord?id=CVE-2025-24514",
			},
		},
		Client:         client,
		Mode:           mode,
		Kind:           "admission_probe",
		Path:           admissionPath,
		Build:          buildReview,
		PassiveMessage: "ingress-nginx exposes no version to unauthenticated clients; run --mode active-probe against the admission webhook (https, :8443, --insecure) to test its reachability",
		Classify:       classifyAdmission,
	}
}

// buildReview generates a benign AdmissionReview (an Ingress with no rules and no
// annotations) and the probe uid the response must echo.
func buildReview() (body []byte, contentType, token string) {
	var raw [16]byte
	uid := "gopoc-probe"
	if _, err := rand.Read(raw[:]); err == nil {
		uid = hex.EncodeToString(raw[:])
	}
	return []byte(fmt.Sprintf(benignReview, uid)), "application/json", uid
}

func classifyAdmission(status int, body, uid string) (model.Verdict, int, string, string) {
	switch {
	case status == 401 || status == 403:
		return model.VerdictNotFound, 70, "webhook_not_reachable",
			"The admission endpoint refused the unauthenticated caller; it is not openly reachable from this position"
	case isAdmissionReview(body, uid):
		return model.VerdictLikely, 80, "admission_webhook_exposed",
			"The ingress-nginx admission webhook processed an unauthenticated AdmissionReview and returned an admission response. This network exposure is the precondition for IngressNightmare (CVE-2025-1974 + CVE-2025-1097/1098/24514). No configuration was injected and no command was executed; the controller's exact patch level is not exposed remotely"
	default:
		return model.VerdictUnknown, 20, "inconclusive",
			"Endpoint responded but not with a recognizable AdmissionReview; admission-webhook exposure could not be confirmed"
	}
}

// isAdmissionReview reports whether the body is an AdmissionReview response that
// echoes our probe uid, i.e. a real admission controller answered us. It parses
// JSON rather than matching substrings: the real ingress-nginx webhook returns
// whitespace-formatted JSON, which an exact substring match would miss.
func isAdmissionReview(body, uid string) bool {
	var ar struct {
		Kind     string `json:"kind"`
		Response struct {
			UID string `json:"uid"`
		} `json:"response"`
	}
	if json.Unmarshal([]byte(body), &ar) != nil {
		return false
	}
	return ar.Kind == "AdmissionReview" && ar.Response.UID == uid
}

// benignReview is an AdmissionReview for an Ingress with no rules and no
// annotations: nothing to inject, nothing to execute. %s is the probe uid.
const benignReview = `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"%s","kind":{"group":"networking.k8s.io","version":"v1","kind":"Ingress"},"resource":{"group":"networking.k8s.io","version":"v1","resource":"ingresses"},"operation":"CREATE","object":{"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":"gopoc-probe","namespace":"default"},"spec":{"rules":[]}}}}`
