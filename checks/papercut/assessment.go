package papercut

import (
	"context"

	"gopoc/internal/assesscache"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// assessment is the shared, per-scan PaperCut assessment. The single checker
// reads from it and only judges — it issues no requests of its own. (The struct
// is ready to be shared should a second PaperCut rule ever land.)
type assessment struct {
	isPaperCut bool
	version    string // exact major.minor.patch, from the SetupCompleted product span
	hasVersion bool
	ver        pcVersion

	// setupCompleted is the CVE-2023-27350 oracle: the SetupCompleted page was
	// actually rendered to us unauthenticated (the access-control bypass), with the
	// real PaperCut setup-page features. setupStatus is that GET's HTTP status.
	setupCompleted bool
	setupStatus    int

	observations []model.Observation
}

// assess returns the shared PaperCut assessment, memoized per scan.
func assess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	if c := assesscache.From(ctx); c != nil {
		return c.GetOrRun(assesscache.Key{Target: target.BaseURL, Product: "papercut"}, func() any {
			return doAssess(ctx, client, target)
		}).(assessment)
	}
	return doAssess(ctx, client, target)
}

func doAssess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	var a assessment

	// Two read-only GETs. The login page carries product identity on a configured
	// server (including a patched one); SetupCompleted is the CVE oracle and, on an
	// affected server, also carries identity + the exact version. Both are needed:
	// a patched server gives no SetupCompleted body, an affected one may 302 its
	// login page during initial setup.
	login, loginErr := client.Get(ctx, target, loginPath)
	a.observations = append(a.observations, login.Observation("login", loginErr))

	setup, setupErr := client.Get(ctx, target, setupCompletedPath)
	a.observations = append(a.observations, setup.Observation("setup_completed", setupErr))
	a.setupStatus = setup.StatusCode

	// Product identity: >= 2 independent signals across whatever bodies we have.
	var loginBody, setupBody []byte
	if loginErr == nil {
		loginBody = login.Body
	}
	if setupErr == nil {
		setupBody = setup.Body
	}
	a.isPaperCut = countSignals(loginBody, setupBody) >= 2

	if !a.isPaperCut {
		return a
	}

	// The CVE-2023-27350 oracle and the exact version (affected servers only).
	a.setupCompleted = isSetupPageRendered(setup, setupErr)
	if setupErr == nil && setup.StatusCode == 200 {
		if v, raw, ok := parseProductVersion(setup.Body); ok {
			a.ver, a.version, a.hasVersion = v, raw, true
		}
	}
	return a
}
