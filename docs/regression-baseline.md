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

## PaperCut MF/NG CVE-2023-27350 (two-state, real-validated)

Two real PaperCut binaries (containerized genuine installer,
`tomcat2111/papercut-mf`), probed **unauthenticated, read-only (GET only)** on
`:9191`. The official installer is egress-blocked in cloud, so these images are
the lab; re-confirm on an operator instance before relying on it. Product ID
requires **≥2 independent signals** (the `?<build>papercut-mf` asset param plus an
app-server/login/product marker), so a bare "PaperCut" title never elevates.

| Target | Version | Checker | Expected verdict |
| --- | --- | --- | --- |
| `tomcat2111/papercut-mf:22.0.7` (affected) | 22.0.7 (Build 64927) | `CVE-2023-27350` | `likely` / `setup_completed_bypass_exposed` |
| `tomcat2111/papercut-mf:22.1.1` (fixed, configured) | 22.1.1 (Build 66714) | `CVE-2023-27350` | `not_found` / `patched_setup_access_control` |

The affected server renders `GET /app?service=page/SetupCompleted` (HTTP 200 + the
real setup page + `<span>x.y.z</span>`) — the access-control bypass, observed
read-only; the fixed server redirects that GET (302 → `page/Home`). The CVE caps
at `likely`: the message reads "Exploit / RCE / admin session was NOT attempted
(read-only GET; no POST, no wizard step)". No POST is ever sent to `/app`.
Version boundary (`go test ./checks/papercut/ -run TestVersionBoundary`) pins
20.1.6/20.1.7, 21.2.10/21.2.11, 22.0.8/22.0.9.

Validation coverage (tier: **live**; tested 22.0.7, 22.1.1):

```yaml
tier: live
tested_versions: [22.0.7, 22.1.1]
coverage:
  product_identity: true
  positive_path:    true   # affected -> likely (SetupCompleted rendered)
  fixed_path:       true   # patched  -> not_found (SetupCompleted redirect)
  negative_path:    false  # no "affected but surface safely disabled" state exists:
                           # the bypass is version-bound with no disabling config
```

`negative_path=false` is expected and honest: CVE-2023-27350 has no config toggle
that leaves an affected version present but the surface closed, so there is no
"affected + safe" third state to validate (unlike Tomcat's writable-vs-readonly).

Note (cloud lab caveat): a **fresh, not-yet-configured** fixed container serves no
login/setup body, so it reports `not_found` via `product_not_papercut` rather than
`patched_setup_access_control`; the configured-fixed → `patched_setup_access_control`
path is pinned deterministically by `go test ./checks/papercut/ -run
TestRealServerTwoState`.

## Standing gates (must stay green on every change)

- `go build ./... && go vet ./... && go test ./...`
- False-positive corpus: `go test ./checks/ -run
  'TestFalsePositiveCorpus|TestVerdictElevationGuards|TestVersionMalformed'` →
  **0 confirmed FP, 0 likely FP**.
