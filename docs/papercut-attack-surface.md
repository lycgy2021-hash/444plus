# PaperCut MF/NG attack-surface audit (research, pre-checker)

Goal: decide *what* can be **safely** proven before writing any checker, and answer
one question honestly — **CVE-2023-27350: can we prove it to `detected`, `likely`,
or `confirmed`?** Conclusion up front:

> **Safe ceiling = `likely`.** The vulnerability *is* an access-control bypass on
> the `SetupCompleted` page, and that bypass is directly observable with a single
> **read-only GET** — no POST, no wizard step, no exploitation. The same response
> hands us the exact `major.minor.patch`, so `likely` is both surface-confirmed
> and version-confirmed. We never reach `confirmed`: proving RCE would require the
> exploit chain (enable print scripts, inject a script, execute a command), which
> we never perform. If the surface is inconclusive but identity + an affected
> version hold → `detected`; if the version cannot be read → `unknown`.

## Empirical basis (real binaries, containerized)

The official `papercut.com` installer is egress-blocked in this environment, so
validation used community images that bundle the **genuine PaperCut installer**
(`tomcat2111/papercut-mf`), probed **unauthenticated** over HTTP on port 9191:

| Box | Version (ground truth from `/papercut/server/version.txt`) | CVE-2023-27350 |
| --- | --- | --- |
| `tomcat2111/papercut-mf:22.0.7` | `PaperCut MF 22.0.7 (Build 64927)` | **affected** (22.x < 22.0.9) |
| `tomcat2111/papercut-mf:22.1.1` | `PaperCut MF 22.1.1 (Build 66714)` | **fixed** (> 22.0.9) |

Both were in the same fresh (setup-not-completed) state, so any behavioral
difference between them is **version-driven**, not configuration-driven. The
containerized binary is genuine PaperCut; a real operator instance should be
re-confirmed before shipping, but the HTTP surface below is authentic.

## Table 1 — Product / version / surface fingerprints (empirical, anonymous)

| Signal | What it means | Notes (live 22.0.7 / 22.1.1) |
| --- | --- | --- |
| Static asset cache-param **`/css/style.css?<build>papercut-mf`** (also `-ng`) | **Strong, structural product signal + build number.** | Confirmed on every page (`?64927papercut-mf` on 22.0.7, `?66714papercut-mf` on 22.1.1). The literal `papercut-mf` appears even on NG builds, so it identifies PaperCut but **not** MF-vs-NG. Yields the **build number**, not `x.y.z`. |
| HTML comment **`<!-- Application: app-server -->`** + `<!-- Page: <Name> -->` | PaperCut's page-framework signature | Confirmed on every rendered page. A reverse proxy or a page that merely says "papercut" does not emit this. |
| `<title>PaperCut Login` and/or a `content="PaperCut…"` tag on `/app` | Login-page product marker | The configured login page (`/app` → `page/Login`) carries these (nuclei `papercut-ng-panel.yaml`, corroborated). A bare "PaperCut" substring is explicitly **too weak**. |
| Footer `Copyright 1999-20xx. PaperCut Software Pty Ltd.` | Product string | Confirmed on setup/error pages. |
| Java classes `papercut.pcng.web.*` (CsrfOriginFilter, WebEngine, …) | Framework tell (leaks on error pages) | Confirmed on the 500 error page. |
| Ports **9191 (http) / 9192 (https)** | PaperCut app-server defaults | Confirmed exposed. |
| Favicon hash `-1142586156` (shodan/fofa) | Passive-recon signal | From nuclei metadata; not independently re-hashed here. |
| **Error page** `PaperCut MF  22.0.7 (Build 64927)` under "Version Details" | Exact version leaks anonymously on a 500 | Confirmed on both boxes. Not a *clean* source (needs a 500), so secondary. |
| **`GET /app?service=page/SetupCompleted` → `class="product"` + `<span>22.0.7</span> <span>(Build 64927</span>`** | **Exact `x.y.z` + build, anonymous — but ONLY on affected servers** | Confirmed on 22.0.7. On 22.1.1 this GET **302-redirects to `page/Home`** with no version span. So this vector is simultaneously the exact-version source AND the affected/fixed oracle (Table 2). |

**Version reliability verdict: PARTIAL, and asymmetric.**
- The **build number** (`?<build>papercut-mf`) is always anonymously readable but coarse (build → `x.y.z` needs an out-of-band map; monotonic but fragile).
- The **exact `x.y.z`** is anonymously readable *for free* on affected servers (the SetupCompleted span) and on error pages, but a **patched** server exposes only the build number on its login page.
- Therefore: a version-bounded verdict on a *patched* box would need the build→version map; but a patched box's SetupCompleted redirect already answers "not vulnerable", so we don't need it. **If no version can be read at all → `unknown`.** Never treat "looks like PaperCut" as a CVE finding.

## Table 2 — CVE-2023-27350: preconditions and the read-only oracle

Affected/fixed (CISA AA23-131A, nuclei, ExploitDB 51391; matches our boxes):

| Branch | Affected | Fixed |
| --- | --- | --- |
| ≤ 19.x | 8.0 – 19.2.7 (all) | — |
| 20.x | 20.0.0 – 20.1.6 | **20.1.7** |
| 21.x | 21.0.0 – 21.2.10 | **21.2.11** |
| 22.x | 22.0.0 – 22.0.8 | **22.0.9** |
| 23.x+ | — | not affected |

- **Precondition: purely version-bounded.** The flaw is improper access control in
  the `SetupCompleted` class; it is present in every affected version regardless
  of configuration. No config toggle enables/disables the bypass. (The full RCE
  *chain* additionally needs a printer + the print-script engine — irrelevant to
  detection, and never exercised.)
- **The read-only oracle (empirically validated, both boxes):**

  | State | `GET /app?service=page/SetupCompleted` |
  | --- | --- |
  | **affected (22.0.7)** | **200** + `<title>Configuration Wizard : Setup Complete`, `class="product"`, `<span>x.y.z</span>`, `<span>(Build N</span>` |
  | **fixed (22.1.1)** | **302 → `/app…?service=page/Home`**, no setup body, no version span |

- **GET-only is side-effect-free.** A bare GET renders the page and sets a
  throwaway anonymous `JSESSIONID`; it does **not** complete setup and does **not**
  create an admin session. Only a **POST** (`$Submit=…`) advances the wizard or
  establishes the bypassed admin session (horizon3ai/kprobe PoCs). We send **no
  POST to `/app`**.

**Three real states (as required):**
1. *affected + vulnerable surface* — 22.0.7 → SetupCompleted 200 + `<span>x.y.z</span>` → **likely**.
2. *fixed version* — 22.1.1 → SetupCompleted 302 → **not_found**.
3. *affected + "safe/default"* — **does not exist for this CVE**: the bypass is
   version-bound with no disabling config, so an affected server always exposes the
   surface. (The honest degraded case is instead *identity + affected build but
   surface inconclusive* → `detected`, and *version unreadable* → `unknown`.)

## Table 3 — do / don't

| Item | Verdict |
| --- | --- |
| **CVE-2023-27350** (SetupCompleted access-control bypass → unauth RCE, CVSS 9.8, CISA KEV) | **DO — flagship, ceiling `likely`.** Read-only GET oracle proves the bypass + reads exact version; version cross-checked ≤ fix line. Never POST, never run the print-script RCE chain → never `confirmed`. |
| **CVE-2023-27351** (SecurityRequestFilter auth bypass, CVSS 8.2) | **Don't as a probe.** The nuclei detection **creates a user** via `POST /rpc/api/rest/master/user/createInternalUser;/keepalive` — state-changing. Forbidden. Mention as related surface only. |
| Build→version fingerprint of *patched* boxes | **Optional/later.** Needs a maintained build→version table; fragile. Not required (patched boxes self-report via the SetupCompleted redirect). |
| Any exploitation (create admin, modify auth, run command, write file, download payload, get shell) | **Never.** Scanner stops at "high-confidence proof the risk exists". |

## Recommendation (checker shape, when we build it)

Mirror `checks/jenkins/` — a shared assessment then the verdict ladder:

1. **Product identity (≥2 independent signals):** the `/css/style.css?<build>papercut-(mf|ng)` asset param **AND** one of {`<!-- Application: app-server -->`, `<title>PaperCut Login`, `content="PaperCut`, `PaperCut Software Pty Ltd`}. Reject bare "papercut" substrings, a lone `JSESSIONID`, port 9191 alone, and honeypots echoing markers without the structural asset param.
2. **Read-only CVE oracle:** `GET /app?service=page/SetupCompleted`.
   - 200 + `class="product"` + `<span>x.y.z</span>` → parse `x.y.z`; if ≤ fix line → **likely** (`Exploit / RCE NOT attempted`). (Consistency: an affected span should always be ≤ fix line, since fixed boxes redirect.)
   - 302 / no setup span → the bypass is patched → **not_found**.
   - identity holds but oracle is unreachable/ambiguous, and a build/version places it in an affected range → **detected**; version unreadable → **unknown**.
3. **Capabilities:** `CapPassive | CapHTTPGet` only. No POST to `/app`.
4. **Gates to add later:** version-boundary tests (20.1.6/20.1.7, 21.2.10/21.2.11, 22.0.8/22.0.9); FP corpus (bare "papercut" text, generic Java app on 9191 issuing JSESSIONID, a WordPress "papercut" theme, a proxy uniform-200, a page titled PaperCut without the asset param); elevation guard (identity + SetupCompleted 200 in *setup mode* on a **fixed** build must NOT elevate — validated: fixed redirects even when fresh).

## The core question, answered

**PaperCut CVE-2023-27350 is safely provable to `likely`** — product identity + an
exact anonymous version + a read-only observation of the actual access-control
bypass — and **not to `confirmed`**, because confirming code execution requires the
exploit chain we deliberately never run. Where the version cannot be read, the
honest verdict is `unknown`, never an unversioned CVE claim.

> Structure observed: Product Identity → Version → Auth/Admin Surface → CVE
> Precondition → Safe Verdict. This matches the Jenkins/JBoss shape, but the
> abstraction stays deferred: PaperCut's version source (asset build param vs
> SetupCompleted span) and its surface oracle are product-specific enough that a
> shared `ProductAssessment` is not yet warranted — let more real products decide.
