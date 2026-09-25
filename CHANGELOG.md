# Changelog

## v0.1.0-evidence-engine — 2026-09-26

First V1 cut: gopoc is no longer "a set of HTTP CVE checkers" but a single-IP,
low-false-positive, evidence-graded vulnerability assessment engine.

### Verdict model
- Three positive evidence tiers: `detected` (version/fingerprint match) →
  `likely` (a dangerous endpoint/protocol/service surface is actually exposed) →
  `confirmed` (vulnerability-specific behavior proven).
- `error` is an **orthogonal** state (request failed, cancelled, checker panic,
  contract violation), reported and counted separately from the evidence tiers —
  never conflated with `unknown`.

### Confirmation contract (mandatory)
- `detect.Confirm` is the only way to earn `confirmed`: positive probe repeated,
  ≥1 clean negative control, an explainable positive/negative diff, body/behavior
  matching (not status-code alone). Default policy: 2 positive, 1 negative, diff,
  repeat.
- The engine **rejects** any `confirmed` finding without a passing `Confirmation`
  (→ `error/confirmation_missing`), so no checker can mint `confirmed` from weak
  evidence. Version/fingerprint evidence can never be a Confirm positive.

### Multi-protocol
- Raw TCP probe capability (`httpx.Client.TCP`, `model.CapTCPProbe`) for
  protocol-level handshakes. WebLogic checkers do a real T3 handshake (exposure +
  version from `HELO`) and a conservative IIOP/GIOP check — never inferring a
  protocol from an open port. `OPTIONS` support added for safe writability checks
  (Tomcat DefaultServlet).
- Response-header capture broadened (all non-cookie headers, bounded) to read
  product headers such as `MicrosoftSharePointTeamServices`.

### Zero-false-positive audit (Phase A)
- Permanent false-positive corpus + verdict-elevation and version-boundary guards
  (`checks/fp_corpus_test.go`): adversarial negative targets (spoofed banners,
  plain IIS/Apache/Citrix, WAF/SPA/uniform-error sites, random TCP banners,
  malformed versions) must never reach `likely`/`confirmed`. Result: **0 confirmed
  FP, 0 likely FP**. Fixed one real `likely` FP (nginx-ui matched a too-generic
  `multipart/form-data`).

### Single-IP mode & performance (Phase A6)
- `gopoc scan <ip> --discover`: low-noise asset discovery → run only the relevant
  product's checkers (asset routing), instead of firing all checkers at every IP.
- Per-scan shared assessment cache (`internal/assesscache`): a product's many CVE
  checkers reuse one fingerprint/version/exposure assessment. WebLogic's 8 CVEs
  drop from 8× probes to 1×.

### Reporting
- Grouped single-IP report: **Target / Discovered / High-Risk Findings** (by
  action priority: Immediate = confirmed+likely, Review = detected, Scanner issues
  = error; `not_found`/`unknown` hidden by default) / **Scan Quality** (routing
  efficiency, request counts, shared assessments).
- Three outputs: default clean human report (stdout); `--evidence`/`-v` expands the
  evidence chain; `--json`/`-o` emits machine JSON. Bare IP/host accepted.

### Coverage
25 checkers across 10 product lines: Apache httpd, nginx, nginx-ui,
ingress-nginx (IngressNightmare), Fortinet (FG-IR-24-535 / FG-IR-25-254),
SharePoint (ToolShell family), Tomcat (CVE-2025-24813), WebLogic
(CVE-2023-21839 + Oracle CPU 2026-07 batch), Oracle HTTP Server / WebLogic proxy
plug-in, Citrix NetScaler (CVE-2025-7775 / CVE-2025-6543).

Real-target validated: Apache (vulhub 2.4.49/2.4.50), ingress-nginx (k3d
v1.11.2), Tomcat (writable/readonly/fixed 3-state), WebLogic (T3 12.2.1.3). The
device/mock lines (Fortinet, SharePoint, Oracle proxy, NetScaler) are
unit/corpus validated; their fingerprints are heuristic pending real appliances.
