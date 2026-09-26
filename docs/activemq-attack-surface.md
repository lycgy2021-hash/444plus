# Apache ActiveMQ attack-surface audit (research, pre-checker)

Goal: decide *what* is worth detecting before writing any checker. Conclusion up
front: ActiveMQ behaves **unlike any product line we have** — its unauthenticated
version source is not HTTP at all, it's the OpenWire wire protocol itself, and
reading it requires **zero bytes written by us** (the broker speaks first). The
flagship is:

1. **CVE-2023-46604** — unauthenticated RCE via the OpenWire protocol marshaller
   (CWE-502, deserialization of untrusted data). CVSS **10.0**, in **CISA KEV since
   2023-11-02** with SSVC `Exploitation: active`. Cleanly version-bounded across
   four maintenance branches. Detection = version in range + the OpenWire listener
   itself being live (these two facts arrive from the **same** probe — see Table 2).
   The actual class-instantiation trigger is **never sent**.

Empirically grounded on **four real Apache ActiveMQ binaries**, downloaded
directly from `archive.apache.org` and run locally (no pre-built vulnerable Docker
image exists — the official `apache/activemq-classic` image starts at 5.17.6,
already past the fix):

- **5.16.6** (last vulnerable, 5.16 branch)
- **5.17.5** (last vulnerable, 5.17 branch) — primary anchor
- **5.18.2** (last vulnerable, 5.18 branch)
- **5.17.6** (first *fixed*, 5.17 branch) — negative control

All four probed unauthenticated, raw TCP, port 61616 (default OpenWire), no
Docker image involved — the actual `bin/activemq console` process. Broker logs
checked after every probe: **zero warnings/errors triggered** by our connect-and-read.

> Sourcing note: this environment's egress proxy blocks `nvd.nist.gov` and
> `activemq.apache.org` directly. Version boundaries and KEV status below are from
> the authoritative CVE record via `raw.githubusercontent.com/CVEProject/cvelistV5`
> (the CVE Program's own JSON, same org as NVD/MITRE) — not a secondary source.

## Table 1 — Product / version / surface fingerprints (empirical, unauthenticated)

| Signal | What it means | Notes (confirmed on 5.16.6 / 5.17.5 / 5.17.6 / 5.18.2) |
| --- | --- | --- |
| **Raw TCP connect to :61616 → broker sends an unsolicited `WireFormatInfo` frame** | OpenWire is **server-speaks-first**: the broker writes this frame immediately on accept, before the client sends anything. Confirmed by writing zero bytes to the socket in all 4 tests. | This is *stronger* than WebLogic's T3 (which requires the client to send a HELO first). A generic non-ActiveMQ HTTP server on the same port sends nothing until asked (confirmed negative control: port 8161 gave zero unsolicited bytes on raw connect). |
| **8-byte ASCII magic `"ActiveMQ"`** at a fixed offset (byte 5, right after the 4-byte length prefix + 1-byte frame-type) | **Definitive, single-signal product identity.** A protocol-level literal, not a guessable string. | Byte-identical across all 4 versions: `...01 41637469766554 51...` (`\x01ActiveMQ`). Essentially zero FP risk — nothing else would spontaneously emit this exact 8-byte sequence unprompted on connect. |
| **`ProviderVersion` property inside the same frame's property map**, e.g. `ProviderVersion` → `"5.17.5"` | **Exact broker semver, readable with zero writes.** | Confirmed: 5.16.6→`"5.16.6"`, 5.17.5→`"5.17.5"`, 5.17.6→`"5.17.6"`, 5.18.2→`"5.18.2"` — exact match every time. Parseable as `find("ProviderVersion") → skip 15 bytes → 2-byte big-endian length → UTF-8 string`. |
| `ProviderName` → `"ActiveMQ"` | Secondary corroborating signal in the same property map | Confirmed present alongside `ProviderVersion`. Redundant with the magic bytes; not needed as a second signal since the magic is already definitive. |
| HTTP admin console (Jetty, port 8161) `/`, `/admin/`, `/api/jolokia/` | Web console + JMX-over-HTTP bridge | **All three returned `401 Unauthorized`, `WWW-Authenticate: basic realm="ActiveMQRealm"`, on the DEFAULT config.** No version string in the 401 body. Confirmed on 5.17.5. **Unlike GitLab's `/help`, this is auth-gated by default** — the HTTP side gives us a realm-name hint (`ActiveMQRealm`) for coarse discovery routing, but never a version. |
| Protocol version int (`0x0000000c` = 12) in the same frame | OpenWire *wire-format* version, not the broker's software version | Confirmed identical (12) across 5.16.6, 5.17.5, 5.17.6, 5.18.2 — as expected, wire-format version doesn't bump on patch releases. **This is why the OpenWire handshake alone would NOT have given us a usable version if `ProviderVersion` weren't in the property map** — worth recording since it's the one assumption from memory that turned out to need the live check to resolve either way. |

**Version reliability verdict: RELIABLE, and cheaper than any HTTP-based product
we have** — the *only* probe needed (a passive read on the default OpenWire port)
gives product identity and exact version in the same frame, with zero writes.
The HTTP console is the *unreliable* side here (auth-gated by default), inverting
the usual "HTTP good, protocol port maybe-not" pattern from GitLab/Jenkins.

## Table 2 — Priority surfaces (real-machine reproducible)

| # | Surface | Secure/default state (live) | Vulnerable state | Verdict ceiling | Reproducible? |
| --- | --- | --- | --- | --- | --- |
| 1 | **OpenWire marshaller** (:61616) → **CVE-2023-46604** | Broker answers with `WireFormatInfo` regardless of version (the vulnerability is in *unmarshalling a crafted client packet*, not in this handshake) | Version in an affected branch **and** the OpenWire listener answered the handshake (same probe, see below) | `likely` — see the open design question below; **never `confirmed`** — the only way to prove exploitability is to send the actual crafted `ExceptionResponse`/class-name packet, which **is** the exploit itself. There is no partial, safe trigger. | **Yes** — 4/4 real binaries, 3 branches + 1 fixed negative control |
| 2 | HTTP admin console (:8161) | `401` + `WWW-Authenticate: realm="ActiveMQRealm"` by default | Console left open (no Basic Auth) → anonymous JMX/broker management via Jolokia | `detected` at most if built later — **not built in v1**: this is a *separate* misconfiguration surface (like JBoss's unauth-management), orthogonal to CVE-2023-46604, and needs its own real two-state validation before we'd ship it. Noted for a future ticket, not this one. | Not tested this round — out of scope |
| 3 | OpenWire+SSL (typically :61617) | Same marshaller, TLS-wrapped | Same CVE, same trigger, over TLS | Same ceiling as #1 | **Not tested** — same code path per the advisory ("Java-based OpenWire broker", transport-agnostic), but no live SSL-configured instance was stood up this round. Flag as a same-CVE variant to add once a TLS-configured broker is anchored, not a reason to hold back the plain-TCP v1. |

### Open design question: there is no separable "detected" tier for this CVE

Every other product line in this codebase gets its version from one probe and
its "is the vulnerable surface reachable" answer from a **different** probe
(GitLab: `/help` gon vs. `/users/password/new` reachability; JBoss: app-port
fingerprint vs. `/management` reachability). That's what makes their four-tier
ladder (`not_found` / `unknown` / `detected` / `likely`) meaningful — `detected`
means "affected version, but we haven't separately confirmed the risky surface is
live."

**ActiveMQ doesn't have that separation.** The *only* way to get `ProviderVersion`
at all is a fully-completed OpenWire handshake read on the listener that IS the
vulnerable surface. By the time we have an affected version, we have already
necessarily proven the OpenWire listener is live and answering. There's no cheaper
partial probe that yields version without also proving reachability.

Two ways to resolve this, and I'd rather you pick than have me guess:

- **(A) Recommended.** Affected version (which only ever arrives together with a
  live, completed OpenWire handshake) → go straight to `likely`. Never emit
  `detected` for this specific CVE rule — there is no intermediate state to
  observe. `unknown` is still reachable (magic-bytes-but-no-`ProviderVersion` —
  never observed in 4/4 tests, but kept as a defensive fallback, matching how we
  never treat "fingerprinted but version unreadable" as anything but `unknown`
  elsewhere). Fixed version → the normal not-affected `not_found` shape.
- **(B)** Reserve `detected` for a *weaker*, HTTP-only signal: if discovery only
  sees the admin-console hint (`realm="ActiveMQRealm"` on :8161) and a sibling
  OpenWire preflight on :61616 fails/is blocked/times out, report `detected`
  ("this host smells like ActiveMQ, version and exposure unconfirmed") rather than
  silently reporting nothing — the same "discovery must be a superset of product
  identity, degrade gracefully rather than disappear" principle we just spent this
  whole thread enforcing for JBoss/GitLab. This adds a real state (sibling-preflight
  found the HTTP hint but the OpenWire probe itself was blocked by policy or
  unreachable) that (A) has no slot for.

I lean toward needing **both**: (A) for the direct-hit case (version+handshake
arrive together → `likely`), plus (B)'s weaker `detected` tier specifically for
the sibling-preflight-blocked/unreachable case — not as alternatives but as two
different observed states. Confirm before I code the ladder.

## Table 3 — Recent (≤2y) CVE candidates: do / don't

| CVE | What | Verdict on doing it |
| --- | --- | --- |
| **CVE-2023-46604** (OpenWire marshaller RCE) | **Unauth** RCE, CVSS **10.0**, CWE-502. CISA KEV (added 2023-11-02, `Exploitation: active`). Affected: **5.18.0–5.18.2**, **5.17.0–5.17.5**, **5.16.0–5.16.6**, **<5.15.16** (incl. the whole 5.15.x/earlier legacy line down to 5.8.0 per the `activemq-openwire-legacy` module record). Fixed: **5.15.16 / 5.16.7 / 5.17.6 / 5.18.3**. | **DO — flagship.** Remote, unauth, cleanly version-bounded (CVE Program record, cross-checked against 4 real binaries), version reliably readable with a single passive read, actively exploited (KEV). Never send the crafted class-name packet — that IS the exploit. |
| Unauth open admin console / Jolokia (no CVE — misconfig) | Console left without Basic Auth → anonymous JMX read/write, broker control | **Defer, not this round.** Real and valuable (same shape as JBoss's unauth-management rule), but needs its own live two-state (default-secured vs. opened) before shipping — this audit only anchored the *default* (secured) state. Separate ticket. |
| OpenWire+SSL variant (:61617) | Same CVE, TLS transport | **Defer.** Same trigger per the advisory's wording ("Java-based OpenWire broker or client", transport-agnostic), but no live TLS-configured broker was anchored this round. Add once anchored — likely a thin wrapper reusing the same magic/version parser over a TLS-dialed socket. |
| CVE-2022-41678 (Jolokia-adjacent, authenticated RCE via JMX) | Needs valid admin credentials already | **Don't.** Requires authenticated access as a precondition — fails the unauth bar outright. |

## Recommendation

1. Build `checks/activemq/` mirroring `checks/weblogic/protocol/t3.go`'s shape
   exactly — this is the cleanest possible fit for that pattern, since it's *also*
   "connect over raw TCP, read a fixed-shape reply, parse a version out of it":
   - `protocol.OpenWire(ctx, client, target) (exposed bool, version string, obs model.Observation)` —
     `client.TCP(ctx, target, nil, <limit>)` (**empty payload — we never write**),
     check for the `"ActiveMQ"` magic at the expected offset, then locate
     `ProviderVersion` and parse its length-prefixed string.
2. Discovery routing, designed with the JBoss lessons already applied rather than
   re-learned the hard way:
   - Direct hit: `target.Port == 61616` (or a small `activemqPorts` single-source
     table if we add 61617 later) → always try the OpenWire probe, mirroring
     WebLogic's `target.Port == 7001` rule.
   - Sibling hint: HTTP response carries `WWW-Authenticate: ...realm="ActiveMQRealm"`
     (on any port, most commonly 8161) → sibling-preflight the conventional OpenWire
     port on the same host, sharing one short time budget (same shape as
     `jbosswildfly.ManagementDiscoveryHint` — total budget, not per-probe; every
     probe returned as an `Observation` so a policy-blocked attempt is visible, not
     silently "not found"). This is exactly the "discovery must be a superset of
     product identity" principle from the JBoss/GitLab rounds, applied from the
     start instead of retrofitted.
3. Ship **one** version-bounded checker, `CVE-2023-46604`, ladder pending your call
   on the open question above (I recommend (A)+(B) combined — see Table 2).
   **Never** send the crafted OpenWire packet that triggers class instantiation;
   the affected-version-plus-live-handshake state is the ceiling, and it's `likely`,
   never `confirmed`.
4. Do **not** build the open-console/Jolokia misconfig rule or the SSL variant this
   round — both need their own live two-state anchor first, exactly the discipline
   already applied to every other product line here.
5. Gates before shipping: version-boundary unit tests for all four branch edges
   (5.15.15→5.15.16, 5.16.6→5.16.7, 5.17.5→5.17.6, 5.18.2→5.18.3), an FP-corpus
   entry (a plain TCP echo/HTTP service on 61616 that sends nothing unsolicited —
   already empirically confirmed as the negative baseline), a verdict-elevation
   guard (magic-without-`ProviderVersion` → `unknown`, never higher), and the real
   two-state validation already done this round (5.17.5 → `likely`; 5.17.6 →
   not-affected `not_found`).
