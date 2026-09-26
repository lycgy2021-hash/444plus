# GitLab attack-surface audit (research, pre-checker)

Goal: decide *what* is worth detecting before writing any checker. Conclusion up
front: GitLab behaves like **Jenkins, not WildFly** — it *does* leak its exact
version to an unauthenticated caller (via the `/help` page's embedded `gon`
object), so a **version-bounded CVE** is the strongest, lowest-FP line. The
flagship is:

1. **CVE-2023-7028** — unauthenticated account takeover via the forgotten-password
   flow accepting an *array* of emails (CVSS **10.0**). Cleanly version-bounded
   across the 16.1–16.7 maintenance branches. Detection = version in range (+ the
   reset flow reachable); the reset is **never** triggered.
2. **CVE-2023-2825** — unauthenticated arbitrary file read (path traversal), CVSS
   **10.0**, affecting **exactly 16.0.0** (fixed 16.0.1). Ultra-narrow, so a clean
   `detected`-by-version signal that shares GitLab's assessment for free.

Empirically grounded on a live `gitlab/gitlab-ce:16.6.0-ce.0` = **GitLab CE
16.6.0** (container reports `gitlab-ce 16.6.0`), HTTP on `127.0.0.1:8929`, probed
**unauthenticated** (no session cookie) from this cloud container's Docker. 16.6.0
sits inside CVE-2023-7028's affected range (16.6.0–16.6.3), so it is a true
*positive* two-state anchor; the *fixed*/negative side is pinned by version-boundary
unit tests (there is no cheap way to boot every patch level).

> Sourcing note: this environment's egress proxy blocks `about.gitlab.com`,
> `docs.gitlab.com` and `nvd.nist.gov`. Version boundaries below were corroborated
> across ≥3 independent secondary sources quoting the GitLab advisory verbatim,
> plus the reachable `gitlab.com` issue tracker and vulhub. Re-verify the exact
> per-branch fix lines against the GitLab release posts before any change to the
> boundary constants; the unit tests pin whatever we ship.

## Table 1 — Product / version / surface fingerprints (empirical, unauthenticated, 16.6.0)

| Signal | What it means | Notes (live 16.6.0) |
| --- | --- | --- |
| Response header **`X-Gitlab-Meta: {"correlation_id":"…","version":"1"}`** | **The strongest single GitLab tell.** Emitted by workhorse/Rails on *every* response — `/` 302, sign_in 200, 404s, `/favicon.ico` 301. | Confirmed on all of them. `"version":"1"` is the *meta schema* version, **not** the GitLab version. Uniquely-named header a random app won't emit — but by the ≥2-signal rule it never identifies the product alone. |
| `Server: nginx` | Bundled nginx fronts workhorse | Confirmed. Carries **no version**, and `gitlab-workhorse` is not surfaced here → useless as a version source. |
| `X-Request-Id: 01M3E7…` (ULID) | workhorse correlation id, always present | Confirmed. Corroborating, but ULID request-ids are not GitLab-exclusive. |
| `/users/sign_in` body: `<meta content="GitLab" property="og:site_name">`, `<meta name="csrf-param" content="authenticity_token">`, `data-qa-selector="login_page"`, `GitLab Community Edition`, hashed `/assets/*-<64hex>.css/js` | HTML product fingerprint | Confirmed. The Rails `csrf-param` **plus** a GitLab-specific token together are distinctive; neither alone is enough. |
| `/-/manifest.json` → `{"name":"GitLab","short_name":"GitLab",…}` | GitLab PWA manifest at the GitLab-reserved `/-/` namespace | Confirmed 200. Good tiebreaker signal. |
| **`/help` body `gon` → `"gitlab_version":{"major":16,"minor":6,"patch":0,"suffix_s":""}`** | **Exact version, readable ANONYMOUSLY** | **Confirmed** (HTML-entity-escaped in the page; unescape `&quot;`→`"` then parse). This is the key finding: version detection is *reliable* on a default install, unlike the header/API vectors. If the instance restricts public access, `/help` redirects to sign_in and the version is unreadable → we return **unknown**, never "not affected". |
| `/api/v4/version`, `/api/v4/metadata` | Version APIs | Confirmed **401 Unauthorized** for anon → **not** a usable version source. |
| `/users/password/new` → 200, `<form action="/users/password" method="post">` with `name="user[email]"`, "Reset password" | The CVE-2023-7028 attack surface (forgotten-password flow) is live | Confirmed. Reachable-and-live raises the CVE to `likely`. We **read** this form; we never POST it. |
| `/assets/*-<64hex>.(css|js)`, `/assets/webpack/manifest.json` | Build-hash fingerprint | Confirmed present. In principle a hash→version map (the Censys/Shodan technique, GitLab issue #345191) recovers the version, but it is fragile (CDN/proxy rewrites, custom builds) and needs a maintained table — **we prefer the `/help` gon version** and fall back to `unknown`. |

**Version reliability verdict: RELIABLE on a default install** via `/help` gon
(major/minor/patch), the deciding factor that makes a version-bounded CVE checker
viable. Header/API vectors are dead ends. When `/help` does not yield a version →
**unknown** (the framework rule: never treat unreadable version as "not affected").

## Table 2 — Priority surfaces (real-machine reproducible)

| # | Surface | Secure / default (live 16.6.0) | Vulnerable state | Verdict ceiling | Reproducible? |
| --- | --- | --- | --- | --- | --- |
| 1 | **Forgotten-password flow** (`/users/password`, form at `/users/password/new`) → **CVE-2023-7028** | Form reachable 200; a *patched* version is simply not vulnerable | version ∈ 16.1.0–16.7.x per-branch range → reset accepts an email **array** → token sent to attacker address = **account takeover** | `likely` (affected version **and** reset flow reachable; the reset is **never** POSTed) | **Yes** — real 16.6.0 is affected (positive); fixed lines pinned by unit tests |
| 2 | **Object-storage upload path** → **CVE-2023-2825** | Not applicable off 16.0.0 | **exactly 16.0.0**: unsanitized `@filename` in `retrieve_from_store()` → `../` arbitrary file read | `detected` (version-only; no safe reachability probe, traversal never attempted) | Partial — boundary is a single release; pinned by unit test |
| 3 | **Version disclosure** (`/help` gon) | Version readable by anon on default install | (not a vuln itself — it is the *enabler* for #1/#2) | n/a (evidence) | **Yes** — confirmed 16.6.0 |
| 4 | **Open registration** (`/users/sign_up` reachable, "Register" link) | Present on this image | Anyone can self-register → foothold on internal/public projects | `detected` at most — **often intentional**, so low value / high FP; **not built** | Yes, but noisy |
| 5 | **Anonymous `/explore`** (public project browsing) | 200 on this image | Information exposure | `detected` at most — usually intentional; **not built** | Yes, but noisy |

Ladder (mirrors Jenkins/WildFly): not GitLab → `not_found`; GitLab but no readable
version → `unknown`; affected version → `detected`; affected version **and** the
CVE's surface reachable → `likely`; **never** `confirmed` (account takeover / file
read are never exploited — the report states "Exploit / account takeover NOT
attempted"). Fingerprint-and-surface-without-version → `unknown` (elevation guard).

## Table 3 — Recent (≤2y) CVE candidates: do / don't

| CVE | What | Verdict on doing it |
| --- | --- | --- |
| **CVE-2023-7028** (password-reset email array → account takeover) | **Unauth** ATO, CVSS **10.0**. Introduced **16.1.0**; affected per branch **16.1.0–16.1.5 / 16.2.0–16.2.8 / 16.3.0–16.3.6 / 16.4.0–16.4.4 / 16.5.0–16.5.5 / 16.6.0–16.6.3 / 16.7.0–16.7.1**; fixed **16.1.6 / 16.2.9 / 16.3.7 / 16.4.5 / 16.5.6 / 16.6.4 / 16.7.2**. `<16.1` and `≥16.8` not affected. | **DO — flagship.** Remote, unauth, cleanly version-bounded, version reliably readable (`/help` gon), actively exploited (CISA KEV). Detect by version (+ reset flow reachable) → `likely`. **Never** POST `user[email][]` — that sends real reset emails. |
| **CVE-2023-2825** (path-traversal arbitrary file read) | **Unauth**, CVSS **10.0**. Affected **exactly 16.0.0**; fixed **16.0.1**. `retrieve_from_store()` `@filename` `../` traversal. | **DO — cheap, ultra-clean boundary.** Shares GitLab's assessment; `detected` on version match only. Exploiting reads server files → never attempt; no `likely` elevation (no safe reachability probe). |
| **CVE-2021-22205** (ExifTool/DjVu unauth RCE) | **Unauth** RCE, CVSS **10.0**. Affected **≥11.9 through 13.8.7 / 13.9.0–13.9.5 / 13.10.0–13.10.2**; fixed **13.8.8 / 13.9.6 / 13.10.3**. vulhub ships 13.10.1. | **Defer.** Legit and critical, but the affected generation is **13.x** (2021); the `/help`-gon version-source reliability was only verified on 16.x here, so shipping a 13.x boundary without a real 13.x anchor risks a wrong version-source assumption. Add later with a real 13.x two-state. Never upload an image to verify. |
| **CVE-2024-45409** (ruby-saml SAML auth bypass) | **Unauth** login-as-anyone, CVSS ~10. Needs SAML configured. | **Don't (core rule).** The SAML precondition is **not cleanly observable** unauthenticated (group vs instance SAML, disabled SAML → FPs/FNs), and verification means **forging SAML assertions**. Fails the low-FP/safely-verifiable bar. |
| CVE-2024-6385 / CVE-2024-5655 (pipeline execution as another user) | CVSS 9.6 | **Don't.** Require project access / specific pipeline state; not clean-unauth; no safe verification. Version-only at best, low priority. |

## Recommendation

1. Build `checks/gitlab/` as an attack-surface base, same shape as
   `checks/jenkins/`: **fingerprint** (`X-Gitlab-Meta` header + `/users/sign_in`
   body markers, ≥2 signals) → **version** (from `/help` gon `gitlab_version`,
   *reliable* — parse `major.minor.patch`) → **reset-flow surface**
   (`/users/password/new` reachable, read-only).
2. Ship two version-bounded checkers sharing one assessment (demonstrating the
   `assesscache` reuse — one `/help` + fingerprint probe serves both):
   - **`CVE-2023-7028`**: affected version → `detected`; affected **and** the
     forgotten-password flow reachable → `likely`. Read-only GETs only; never POST
     `user[email]`, never trigger a reset. Caps at `likely`.
   - **`CVE-2023-2825`**: version **== 16.0.0** → `detected`. Version-only; caps at
     `detected`; traversal never attempted.
3. Do **not** chase SAML, pipeline, or registration/`/explore` misconfig as core
   rules — they fail "remote / high-risk / low-FP / safely verifiable". Reserve
   CVE-2021-22205 for a future add once a real 13.x version anchor exists.
4. Every rule passes the gates: version-boundary tests (each 16.x branch's fix
   line, the 16.0 vs 16.1 introduction edge, the 16.7→16.8 upper edge, and the
   16.0.0-only bound), FP-corpus entries (a page that merely says "gitlab", a bare
   forged `X-Gitlab-Meta`, a generic Rails `csrf-param` page, a proxy uniform 200,
   an instance that hides `/help`), a verdict-elevation guard (GitLab fingerprinted
   + reset flow reachable but no readable version → `unknown`), and real
   positive validation (live 16.6.0 → CVE-2023-7028 `likely`). Verdict骨架
   unchanged.
