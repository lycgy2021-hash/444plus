# Jenkins attack-surface audit (research, pre-checker)

Goal: decide *what* is worth detecting before writing any checker. Conclusion up
front: unlike JBoss/WildFly, Jenkins gives us **two** solid, low-FP,
safely-verifiable lines —

1. **Misconfiguration / anonymous exposure** (Script Console, `/manage`, API read,
   or "anyone can do anything") = effectively unauth RCE. This is the highest-value,
   most reproducible finding and the primary rule, exactly like WildFly's
   unauth-management interface.
2. **A genuine recent unauth critical CVE**: **CVE-2024-23897** (CLI arbitrary file
   read, CVSS 9.8, unauthenticated, cleanly version-bounded, and verifiable with a
   *benign* read). Jenkins — unlike WildFly — advertises its exact version in the
   `X-Jenkins` response header, so version-boundary CVE detection is reliable.

Empirically grounded on a live `jenkins/jenkins:lts` = **Jenkins 2.568.3** (HTTP
8080, agent 50000), probed from inside WSL (Docker-Desktop→Windows forwarding is
flaky; the container is stable). The image comes up in a *secured* default
(anonymous → 403), which is exactly the negative/secure state we want as the FP
floor.

## Table 1 — Product / version / surface fingerprints (empirical)

| Signal | What it means | Notes (live 2.568.3 unless marked) |
| --- | --- | --- |
| Response header **`X-Jenkins: <ver>`** | **Definitive Jenkins + exact version** | Confirmed `X-Jenkins: 2.568.3` on both `/` (403) and `/login` (200). Present even when anonymous is denied → **reliable version source** (the key difference vs WildFly). |
| `X-Hudson: 1.395` | Legacy Hudson protocol marker, always present | Confirmed. Jenkins-defining; the constant `1.395` is emitted regardless of version. |
| `X-Jenkins-Session: <hex>` | Jenkins controller session id | Confirmed. Corroborating fingerprint. |
| `X-You-Are-Authenticated-As: anonymous` + `X-Required-Permission: hudson.model.Hudson.Administer` | Auth boundary leaked on a 403 | Confirmed on `/`. Tells us anonymous identity **and** what permission was needed — directly useful for the misconfig ladder. |
| `Server: Jetty(12.1.x)` (Winstone) | Jenkins' bundled servlet container | Confirmed. Supportive, not definitive (Jetty is generic). |
| `/login` body `<title>Sign in - Jenkins</title>`, `data-version="2.568.3"` | HTML fingerprint + version fallback | Confirmed. Backup if headers are stripped by a proxy. |
| `/whoAmI/api/json` → `{"anonymous":true,"authorities":["anonymous"],...}` | **Anonymous-readable even in the secured default** | Confirmed 200 while `/api/json` was 403. Best single probe to measure the *anonymous boundary* without guessing. |
| `/jnlpJars/jenkins-cli.jar` → 200 | CLI transport present (client jar downloadable) | Confirmed 200 even secured. Signals the CLI attack surface (CVE-2024-23897 vector) exists. |
| `/cli` → 302/200 | HTTP CLI endpoint | Confirmed 302. The modern CLI transport (TCP CLI port is disabled by default; header `X-Jenkins-CLI2-Port` absent here). |

## Table 2 — The 5 priority surfaces (real-machine reproducible)

| # | Surface | Secure default (live) | Misconfig / vulnerable state | Verdict ceiling | Reproducible? |
| --- | --- | --- | --- | --- | --- |
| 1 | **Anonymous admin/API** (`/api/json`, `/manage`, `/computer/api/json`, `/whoAmI`) | `/api/json` **403**, `/manage` **403**; `/whoAmI` shows `anonymous` only | "Anyone can do anything" or anon-read → `/api/json` **200**, `/manage` **200**, `/whoAmI` authorities include real perms | `likely` (read-only GETs; never mutate) | **Yes** — flip auth strategy to "Anyone can do anything" (two-state) |
| 2 | **Script Console `/script`** (Groovy = instant RCE) | **403** (needs Administer) | **200** with a Groovy `<form>`/`_.groovy` textarea reachable unauth | `likely` (detect the *reachable console*, never POST Groovy) | **Yes** — same open-auth toggle |
| 3 | **CLI** (`/cli`, `jenkins-cli.jar`) → **CVE-2024-23897** | jar 200, `/cli` 302; CLI present | version ≤ 2.441 / LTS ≤ 2.426.2 → `@file` arg expansion reads controller files unauth | `likely` (version + CLI reachable; a *benign* file-read is the strongest safe confirm — see Table 3) | **Yes** — vulhub `jenkins/CVE-2024-23897` (2.426.1) |
| 4 | **Remoting / Agent** (TCP 50000 JNLP) | inbound agent port; needs a valid agent secret | agent-to-controller file read (CVE-2024-43044) needs an agent connection; JNLP4 handshake observable | `detected` (port/handshake only; the file-read path needs agent-level access) | Partial — port reachable easily; the CVE precondition is not clean-unauth |
| 5 | **Plugin exposure** (100s of plugins, most CVEs live here) | plugin list needs read perm | e.g. Git Parameter **CVE-2025-53652** command injection; WSO2 OAuth **CVE-2025-47889** auth bypass | `detected` at most | Weak — plugin presence usually not anonymously enumerable; heavy preconditions |

Ladder (mirrors WildFly): not Jenkins → `not_found`; Jenkins but anonymous
denied everywhere and version patched → `detected` (fingerprint/version only);
anonymous can reach `/script` or `/api/json` (or "anyone can do anything") →
`likely` (misconfig); affected version + CLI reachable → `likely` (CVE-2024-23897).
Jenkins with no readable version and no reachable surface → `unknown`.

## Table 3 — Recent (≤2y) CVE candidates: do / don't

| CVE | What | Verdict on doing it |
| --- | --- | --- |
| **CVE-2024-23897** (CLI `@file` arg expansion, args4j) | **Unauth** arbitrary file read on the controller; RCE via leaked secrets. CVSS **9.8**. Affected **≤ 2.441 / LTS ≤ 2.426.2**; fixed **2.442 / LTS 2.426.3 / 2.440.1** (disabled `expandAtFiles`). | **DO — primary CVE rule.** Remote, unauth, cleanly version-bounded (reliable `X-Jenkins`), and *safely* verifiable: the file-read reads only the first line(s), and we can target a **benign, always-present file** (or just confirm CLI reachability + affected version) → `likely`. Never read secrets, never chain to RCE. |
| **Misconfig: anonymous Script Console / open auth** (not a CVE) | `/script` Groovy RCE, or "anyone can do anything" | **DO — primary misconfig rule** (surface #1/#2). Highest value, lowest FP, trivially reproducible two-state. This is Jenkins' analogue of WildFly's unauth-management interface. |
| CVE-2024-43044 (agent-to-controller arbitrary file read) | File read from controller **via a connected agent** | **Defer / `detected` at most.** Needs the ability to connect/act as an agent — not clean remote-unauth. Note agent port as attack surface, don't build a confirm. |
| CVE-2025-53652 (Git Parameter plugin cmd injection) | Injection into shell Git commands → RCE | **Don't (core rule).** Plugin-specific; needs the plugin + a job with a Git parameter + build/trigger access. High preconditions, not anonymously detectable without auth. At most a future `detected` if plugin is enumerable. |
| CVE-2025-47889 (WSO2 OAuth plugin auth bypass) | Log in as any user | **Don't.** Only if that niche plugin + realm is configured; can't tell remotely without probing auth. |
| CVE-2025-67635 (HTTP CLI DoS) | Unauth thread-exhaustion DoS | **Don't.** DoS is off our compromise line and verification would be destructive. |
| CVE-2024-23898 (CLI WebSocket CSRF hijack) | Cross-site WebSocket hijacking | **Don't.** Needs victim interaction + cross-site; not a server-observable condition. |

## Recommendation

1. Build `checks/jenkins/` as an attack-surface base, same shape as
   `checks/jbosswildfly/`: **fingerprint** (`X-Jenkins`/`X-Hudson` headers, `/login`
   body) → **version** (from `X-Jenkins`, *reliable* — parse to a comparable form) →
   **anonymous-boundary probe** (`/whoAmI`, `/api/json`, `/manage`, `/script`) →
   **CLI surface** (`jenkins-cli.jar`/`/cli`).
2. First two rules are the high-value, low-FP, reproducible ones:
   - **`MISCONFIG-JENKINS-ANON-*`**: anonymous can reach `/script` (Script Console)
     or `/api/json`/`/manage` (open auth) → `likely`. Read-only GETs only; never
     POST Groovy, never mutate.
   - **`CVE-2024-23897`**: affected version (`X-Jenkins` ≤ 2.441 / LTS ≤ 2.426.2) +
     CLI reachable → `likely`. Optional safe confirm = a single `@`-expansion read
     of a benign file's first line; never a secret, never chained to RCE.
3. Do **not** chase plugin CVEs, agent-path CVEs, DoS, or CSRF as core rules —
   they fail the "remote / high-risk / low-FP / safely verifiable" bar. Reserve
   plugin/agent items as future `detected` signals only.
4. Every rule passes the gates: version-boundary test (2.442/2.426.3 boundary,
   weekly-vs-LTS numbering), FP-corpus entry (plain Jetty app, a non-Jenkins page
   that echoes "jenkins", a *secured* Jenkins must stay ≤ `detected`),
   verdict-elevation guard (fingerprint/version alone never exceeds `detected`),
   and real two-state validation (secured 2.568.3 → `detected`; open-auth →
   `likely`; vulhub 2.426.1 → CVE-2024-23897 `likely`). Judgement骨架 unchanged.
