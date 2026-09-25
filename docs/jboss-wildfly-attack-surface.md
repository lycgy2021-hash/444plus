# JBoss / WildFly attack-surface audit (research, pre-checker)

Goal: decide *what* is worth detecting before writing any checker. Conclusion up
front: for JBoss/WildFly the value is **attack-surface + misconfiguration
detection** (chiefly an *unauthenticated management interface*), NOT a hot recent
unauthenticated-RCE CVE — there isn't a Fortinet/WebLogic-class one in the last
two years. Build the product base as fingerprint → management-surface auth
behavior → protocol exposure, and attach CVEs only where they clear our bar.

Empirically grounded on a live `quay.io/wildfly/wildfly:latest` = **WildFly
41.0.1.Final** (HTTP 8080, management 9990). Docker-Desktop-on-WSL port
forwarding was flaky; probes below were taken from inside WSL where the
container is stable.

## Table 1 — Product / version / management-surface fingerprints

| Signal | What it means | Notes (empirical / documented) |
| --- | --- | --- |
| HTTP `/` welcome body contains "Welcome to WildFly" / "The WildFly Authors" | WildFly app HTTP face | Confirmed on 41.0.1. JBoss EAP shows Red Hat / "JBoss EAP" branding instead. |
| **No `Server` header** on the app port | Modern WildFly/EAP | Confirmed absent on 41.0.1; EAP 7.2+ removed the server-identifying header. So Server-header fingerprinting/versioning is unreliable. |
| `:9990/management` → `401 WWW-Authenticate: Digest realm="ManagementRealm"` | **Definitive** JBoss/WildFly management API, auth **required** (secure) | Confirmed on 41.0.1. `ManagementRealm` + Digest is JBoss/WildFly-specific. |
| `:9990/management` → `200` + JSON `product-version` **without auth** | **Unauthenticated management = critical misconfig** | The high-value finding (see Table 2). Not the default. |
| `:9990/console` (HAL console) | Management console face | Present on modern WildFly. |
| Version | Often **unknown** unauth on modern versions | Not in Server header, not in welcome page (confirmed), management API needs auth. Report `unknown`, don't guess. Legacy JBoss (AS 5/6/7, EAP 6) leaked version via jmx-console / error pages. |
| Legacy paths `/jmx-console`, `/web-console`, `/admin-console`, `/invoker/JMXInvokerServlet` | Old JBoss AS/EAP surfaces | Only on legacy; strong signal when present. |

## Table 2 — Real-machine-reproducible high-value exposure surfaces

| Surface | Why high value | Verdict ceiling | Reproducible? |
| --- | --- | --- | --- |
| **Unauthenticated management API** (`:9990/management` answers read-attribute without auth) | Full server control (deploy, read secrets) = effectively RCE | `likely` (config-level; we read `product-version`, never deploy) | Yes — configure WildFly mgmt open / broken RBAC; default is 401 so this is the meaningful differentiator |
| Management console reachable + auth behavior | Attack surface + secure/insecure differentiation | `detected`/`likely` | Yes (mgmt bound to 0.0.0.0 vs 127.0.0.1) |
| **EJB remoting** exposed (http-upgrade on 8080, or legacy 4447/9999) | Deserialization attack surface (CVE-2025-2251 et al.) | `detected`/`likely` (protocol handshake, never send a gadget) | Yes (default WildFly exposes http-remoting); needs a protocol-level handshake, not a port guess |
| Legacy `JMXInvokerServlet` / `jmx-console` reachable unauth | Classic unauth deserialization RCE (old JBoss) | `likely` | Only on legacy JBoss images (vulhub has old ones) |

Auth-behavior contrast to build the ladder: management bound & requires auth (401
ManagementRealm) → `detected`; management reachable **without** auth → `likely`;
not JBoss/WildFly → `not_found`; JBoss/WildFly but no version and mgmt not
reachable → `unknown`.

## Table 3 — Recent (≤2y) CVE candidates: do / don't

| CVE | What | Verdict on doing it |
| --- | --- | --- |
| **CVE-2025-2251** (wildfly-ejb3 EJB deserialization) | RCE via JBoss Marshalling in EJB remote invocation | **Defer / low priority.** Authoritative CVSS is 6.2 `AV:N/AC:H/PR:H/UI:N` — needs **high privileges + high complexity**, i.e. NOT a clean unauth RCE despite some write-ups saying "no auth". Fixed in WildFly 36.0.0.Final. At most contributes to a "detected: affected version + EJB remoting exposed" signal, never `confirmed`. |
| CVE-2025-12543 (Undertow Host-header validation bypass) | Header validation bypass | **Don't.** Not RCE; low value for our line. |
| Undertow DoS CVEs (various) | Denial of service | **Don't.** DoS is off our RCE/compromise line and would need destructive verification. |
| Legacy CVE-2017-12149 / CVE-2015-7501 (JBoss AS/EAP unauth deserialization) | Unauth RCE via JMXInvoker/HTTPInvoker | **Optional legacy detector**, not "recent". High value *if* targeting old JBoss; encode as "legacy invoker surface reachable unauth" → `likely`. vulhub has old JBoss envs to validate. |

## Recommendation

1. Build `checks/jbosswildfly/` as an attack-surface base: fingerprint (WildFly
   vs JBoss EAP vs plain Undertow/Tomcat) → management-surface probe (`/management`
   auth behavior) → version (best-effort, else `unknown`) → EJB-remoting protocol
   handshake.
2. First "rule" is not a CVE but the **unauthenticated-management-interface**
   misconfiguration finding (`likely`), which is the genuinely high-value,
   low-FP, reproducible condition.
3. Add CVE-2025-2251 only as a supporting `detected` signal (version + EJB
   remoting), never `confirmed`. Optionally a legacy-invoker detector for old
   JBoss. Do not chase Undertow DoS/header CVEs.
4. Every rule still passes the gates: version-boundary test, FP-corpus entry
   (plain Undertow/Tomcat/Java app must not be flagged), verdict-elevation guard,
   real WildFly validation (managed vs open mgmt, auth on vs off).
