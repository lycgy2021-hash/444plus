// Package gitlab holds detection for GitLab CE/EE: an attack-surface base
// (product fingerprint, a reliable anonymous version from the /help page's gon
// object, the forgotten-password surface) plus two version-bounded CVEs. Unlike
// WildFly — and like Jenkins — GitLab leaks its exact version to an
// unauthenticated caller, so version-bounded CVE detection is reliable.
//
//  1. CVE-2023-7028 — unauthenticated account takeover via the forgotten-password
//     flow accepting an array of emails (CVSS 10.0). The primary rule.
//  2. CVE-2023-2825 — unauthenticated arbitrary file read affecting exactly
//     16.0.0 (CVSS 10.0). A clean, version-only signal sharing the assessment.
//
// See docs/gitlab-attack-surface.md. All checkers here are detection-only: the
// password reset is never POSTed and the traversal is never attempted, so they
// cap at `likely` (CVE-2023-7028) / `detected` (CVE-2023-2825).
package gitlab

import (
	"regexp"
	"strings"

	"gopoc/internal/httpx"
)

const (
	// signInPath is GitLab's login page; its HTML carries the product markers we
	// pair with the X-Gitlab-Meta header for the ≥2-signal lock.
	signInPath = "/users/sign_in"
	// helpPath renders the anonymously-readable version in its gon object.
	helpPath = "/help"
	// manifestPath is the GitLab PWA manifest at the reserved /-/ namespace; a
	// tiebreaker signal when only one of {header, sign-in body} is present.
	manifestPath = "/-/manifest.json"
	// resetNewPath is the forgotten-password form; its reachability is the
	// CVE-2023-7028 surface. We only ever GET it — never POST the reset.
	resetNewPath = "/users/password/new"
)

// metaHeader is emitted by workhorse/Rails on every GitLab response (including
// redirects, 401s and 404s). Uniquely named, so a strong signal — but never
// enough alone (a reverse proxy could forge one header), so product identity
// requires it PLUS an independent body/manifest signal.
const metaHeader = "X-Gitlab-Meta"

// railsCSRFRE matches the Rails forgery-protection meta pair GitLab renders. On
// its own it only says "a Rails app"; it becomes a GitLab signal only alongside a
// GitLab-specific token (gitlabBodyMarkerRE).
var railsCSRFRE = regexp.MustCompile(`(?i)<meta\s+name=["']csrf-param["']\s+content=["']authenticity_token["']`)

// gitlabBodyMarkerRE matches a token specific to a real GitLab page: the
// OpenGraph site name, the login-page QA selector, the edition string, or the
// tanuki logo class. Confirmed on live 16.6.0's /users/sign_in and /help.
var gitlabBodyMarkerRE = regexp.MustCompile(`(?i)property=["']og:site_name["']\s+content=["']GitLab|content=["']GitLab["']\s+property=["']og:site_name|data-qa-selector=["']login_page["']|GitLab (?:Community|Enterprise) Edition|tanuki-(?:logo|shape)`)

// bodyLooksLikeGitLab reports whether an HTML body is a real GitLab page: it
// requires BOTH the Rails CSRF meta pair AND a GitLab-specific marker, so a plain
// Rails app (CSRF only) or a page that merely says "gitlab" (marker only, no
// Rails pair) does not qualify.
func bodyLooksLikeGitLab(body []byte) bool {
	s := body
	return railsCSRFRE.Match(s) && gitlabBodyMarkerRE.Match(s)
}

// manifestIsGitLab reports whether a /-/manifest.json body is GitLab's PWA
// manifest. To pass, BOTH name AND short_name must be "GitLab" (with or without
// spacing around the colon). This tighter check prevents spoofing with a manifest
// that claims only one field.
func manifestIsGitLab(body []byte) bool {
	s := string(body)
	hasName := strings.Contains(s, `"name": "GitLab"`) || strings.Contains(s, `"name":"GitLab"`)
	hasShortName := strings.Contains(s, `"short_name": "GitLab"`) || strings.Contains(s, `"short_name":"GitLab"`)
	return hasName && hasShortName
}

// resetFormRE matches the forgotten-password form: a POST to /users/password
// carrying the user[email] field. Confirmed on live 16.6.0's /users/password/new.
// Its presence means the vulnerable reset flow (CVE-2023-7028) is live; we read
// it, we never submit it.
var resetFormRE = regexp.MustCompile(`(?i)action=["']/users/password["'][^>]*method=["']post["']`)
var resetEmailRE = regexp.MustCompile(`(?i)name=["']user\[email\]["']`)

// resetFlowReachable reports whether the forgotten-password flow is live: a 200
// carrying the reset form. A redirect to sign-in, a 404, or any page without the
// form means the flow is not exposed.
func resetFlowReachable(r httpx.Response, err error) bool {
	if err != nil || r.StatusCode != 200 {
		return false
	}
	return resetFormRE.Match(r.Body) && resetEmailRE.Match(r.Body)
}
