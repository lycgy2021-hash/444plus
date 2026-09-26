# Regression baseline (v0.1.0-evidence-engine)

The highest-value real-target regressions. Recreate the labs with the scripts in
[`scripts/lab/`](../scripts/lab/), then scan and confirm the expected verdicts.
These exercise the condition-based tiering (Tomcat) and the multi-protocol TCP/T3
base (WebLogic) — the two areas most affected by changes to `httpx`, the TCP
probe, the evidence renderer, or the verdict model.

## Tomcat 3-state (CVE-2025-24813)

`scripts/lab/tomcat.sh` → three instances of the same affected version, differing
only in configuration. Same version must NOT mean same verdict.

| Target | Config | Expected verdict | reason |
| --- | --- | --- | --- |
| `http://127.0.0.1:8180` | 9.0.97, DefaultServlet writable | `likely` | `writable_default_servlet` |
| `http://127.0.0.1:8181` | 9.0.97, read-only (default) | `detected` | `affected_version` |
| `http://127.0.0.1:8182` | 9.0.99 (fixed) | `not_found` | `version_not_affected` |

```
gopoc scan 127.0.0.1:8180 --discover   # -> [LIKELY]  CVE-2025-24813
gopoc scan 127.0.0.1:8181 --discover   # -> [DETECTED]
gopoc scan 127.0.0.1:8182 --discover   # -> (not_found, hidden)
```

## WebLogic T3 multi-protocol (CVE-2023-21839 + CPU-2026-07)

`scripts/lab/weblogic.sh` → WebLogic 12.2.1.3 on 7001 (HTTP + T3).

| Checker | Expected | Notes |
| --- | --- | --- |
| CVE-2023-21839 | `likely` / `dangerous_protocol_exposed` | version `12.2.1.3.0`, "Exposed protocols: HTTP, T3" |
| CPU-2026-07 family (CVE-2026-60198/60199/60200/60202/60291/60292/60294) | `not_found` / `version_not_affected` | 12.2.1.3 is below the 12.2.1.4+ affected range |

Protocol-probe expectations: `t3_handshake` returns a `HELO`; `iiop_giop`
returns 0 bytes → IIOP correctly **not** reported (no false positive from an open
port); `soap_endpoint` 404 → SOAP not exposed.

Deterministic (no live target needed): `go test ./checks/weblogic/ -run
TestSharedAssessmentCache` proves the 8 WebLogic CVEs share one assessment
(2 TCP + 3 GET) vs 8× uncached.

## JBoss/WildFly management interface (two-state, real-validated)

Real WildFly (`quay.io/wildfly/wildfly:latest`, 41.0.1.Final; mgmt on 9990). Probe
from **inside WSL** (Docker-Desktop Windows→WSL forwarding is flaky; the container
itself is stable). `MISCONFIG-JBOSSWILDFLY-UNAUTH-MGMT`:

| Management config | `/management` response | Expected verdict |
| --- | --- | --- |
| default (secure) | `401 WWW-Authenticate: Digest realm="ManagementRealm"` | `detected` / `management_requires_auth` |
| auth removed (open) | `200` + bare DMR JSON (`product-version`, `management-major-version`) | `likely` / `unauthenticated_management_exposed` |

Open it on a running container:
```
docker exec gopoc-wildfly sed -i 's/ http-authentication-factory="[^"]*"//' \
  /opt/jboss/wildfly/standalone/configuration/standalone.xml
docker restart gopoc-wildfly
```
Note: real GET /management returns the DMR root **without** an `"outcome"` wrapper
(that only wraps POST results) — the checker must match the bare-GET shape.

**Reconciliation fix (found on a sibling branch, ported here):** two real bugs
survived the acceptance above because it never isolated the paths that
trigger them. (1) `doAssess` fingerprinted via `client.Fingerprint()`, whose
shared cache always nils out `Body` — so the welcome-page signal was dead
code the whole time; a target whose app port serves the welcome page but
whose `/management` doesn't answer at all still needs that body to identify
the product. Fixed to a plain `Get("/")`. (2) `probeManagement` returned on
the first candidate port that answered AT ALL, even the app port's own
irrelevant 404 — so scanning the app port alone (the realistic single-IP
case: app on 8080, management on a separate 9990) never even tried 9990.
Fixed to keep trying every candidate until one gives the definitive signal.
Both are covered by dedicated regression tests
(`TestProbeManagementTriesEveryCandidate`,
`welcome_page_alone_is_read_by_a_real_client`) precisely because the
four-state acceptance above didn't exercise either path.

## Jenkins two lines (four-state, real-validated)

`scripts/lab/jenkins.sh` → two real containers. Probe from **inside** each
container (`docker exec … /tmp/gopoc scan http://localhost:8080 --discover`);
Docker-Desktop Windows→WSL forwarding is flaky, the containers are stable.
Product ID requires **≥2 Jenkins headers** (`X-Jenkins` + `X-Hudson`/`X-Jenkins-Session`),
so a single forged header never elevates.

| Target | Config | Checker | Expected verdict |
| --- | --- | --- | --- |
| `gopoc-jenkins` (2.x LTS, wizard off) | Script Console open (anonymous) | `MISCONFIG-JENKINS-ANON-SCRIPT-CONSOLE` | `likely` / `anonymous_script_console_exposed` |
| `gopoc-jenkins` (same) | version above fix line | `CVE-2024-23897` | `not_found` / `version_not_affected` |
| `gopoc-jenkins-cve` (2.426.2, secure default) | Script Console 403 | `MISCONFIG-JENKINS-ANON-SCRIPT-CONSOLE` | `detected` / `script_console_protected` |
| `gopoc-jenkins-cve` (same) | affected LTS + CLI reachable | `CVE-2024-23897` | `likely` / `affected_surface_exposed` |

The CVE caps at `likely`: the message reads "Exploit execution was NOT attempted …
Arbitrary file read was NOT attempted". A confirmation that actually exercises the
`@file` read exists only as a controlled lab test (a benign marker file), never on
the default single-IP path. Version boundary (`go test ./checks/jenkins/ -run
TestVersionBoundary`) pins weekly 2.441/2.442 and LTS 2.426.2/2.426.3.

**Reconciliation fix:** `classifyScript` handled a bare `403`/`401` as the
secure default but not the other browser-facing form, a redirect to
`/login` — that response fell through to `scriptUnclear` (`detected` via a
different, weaker reason) instead of `scriptProtected`. Fixed; see
`script_protected_login_redirect` in `checker_test.go`.

## Standing gates (must stay green on every change)

- `go build ./... && go vet ./... && go test ./...`
- False-positive corpus: `go test ./checks/ -run
  'TestFalsePositiveCorpus|TestVerdictElevationGuards|TestVersionMalformed'` →
  **0 confirmed FP, 0 likely FP**.
