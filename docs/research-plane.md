# AI Research Plane (S1–S9 frozen; S10 contract-only)

This is an **additive** plane beside the deterministic detection plane, not a
rewrite of it. The detection base — `--discover`, fingerprint, assessment cache,
the CVE checker contract, `not_found/detected/likely/confirmed` + `unknown/error`,
the FP corpus, the protocol probes — is **frozen** and authoritative. The research
plane only proposes leads and hands them to deterministic validators.

```
┌──────────── Detection Plane (frozen, authoritative) ────────────┐
│ Target → Discovery → Facts → Checker → Evidence → Verdict        │
└───────────────────────────┬─────────────────────────────────────┘
                            │ facts (research.FromModelEvidence)
                            ↓
┌──────────── Research Plane ─────────────────────────────────────┐
│ research.Evidence → ai.Provider.Analyze → Candidate(hypothesis)  │  S1,S2,S4
│                                              │                    │
│                              Registry.Match(candidate)            │  S5
│                                              │                    │
│              Validator.Validate → ValidationResult{Outcome,facts} │  S5
│                                              │                    │
│                   Engine (state machine) → Candidate.Promote      │  S3,S5
│                                              ↓                    │
│                       Reproducible → ImpactConfirmed → …          │
└──────────────────────────────────────────────────────────────────┘
```

Three roles are kept structurally separate, so authority lives in exactly one
place: **AI ≠ Validator ≠ State machine.** The model proposes hypotheses; a
registered Validator decides *how* to safely test one and reports facts + an
`Outcome` (never a state); the Engine alone reads those facts and calls the sole
`Promote`.

## The one rule: AI ≠ Authority

- `ai.Provider.Analyze` returns `AnalysisResult`, which has **no** verdict / state
  / severity / "confirmed" field. A model cannot express a decision through it;
  unknown JSON keys (a model inventing `"verdict":"confirmed"`) are dropped on
  unmarshal.
- `research.Analyzer` turns proposals into `research.Candidate`s **only** at
  `Hypothesis`, tagged with their AI origin (provider name recorded).
- `Candidate.Promote` advances one rung at a time and **requires a named
  (deterministic) validator plus justifying evidence**. A Provider has neither, so
  it can never move a candidate past `Hypothesis`. There is no method anywhere
  that converts a `Candidate` into a detection `Verdict`.
- `Evidence` is truth; the model reasons over facts, never raw dumps.

## What landed

**S1 — `internal/ai/`** (generic gateway; imports neither the detection plane nor
`research`, so it has no verdict vocabulary and no import cycle):
- `provider.go` — the `Provider` interface (the only seam to any model backend).
- `openai_compat.go` — one OpenAI-compatible implementation that serves local
  vLLM / llama.cpp / KoboldCpp / Ollama and cloud alike (only BaseURL/Model/APIKey
  differ). Uses stdlib `net/http`, deliberately **not** `internal/httpx` (the model
  endpoint is infrastructure, not a scan target under the policy allowlist).
- `schema.go` — `Task`, `AnalysisRequest` (payload as opaque JSON), `AnalysisResult`
  / `Proposal` (propose + name gaps only).
- `prompt.go` — the standing system prompt that states the authority boundary.
- `budget.go` — `Budget`/`Tracker` (request/token/wall-clock/USD caps; zero = no
  limit, since local models are free).

**S2 — `research/evidence.go`** — model-consumable structured facts:
`Observation` (product/protocol facts, bounded request/response, `NetworkAction`
that is read-only/probe, never "exploit"), `Evidence`, and `FromModelEvidence`, the
one-way adapter that derives research evidence from a frozen `model.Evidence`.

**S3 — `research/candidate.go`** — `State` ladder (`hypothesis → reproducible →
impact_confirmed → vendor_confirmed → cve_assigned`), `Candidate`, `NewHypothesis`
(the only entry point), and `Promote` (single-rung, requires a named validator +
evidence; mutex-guarded so concurrent promotes cannot skip a rung). `Origin` is
`{Kind, ID}` — the Research Plane is the core and a local LLM is only ONE producer
(`ai/fuzz/diff/source_audit/passive/human`).

**S4 — `research/analyzer.go`** — three narrow tasks only, no omni-analysis and no
severity/confidence: `finding_analysis` (`AnalyzeFinding` → hypothesis
candidates), `evidence_gap_analysis` (`EvidenceGaps` → a gap list, proposes
nothing), `candidate_deduplication` (`Deduplicate` → advisory groups, filtered to
real ids, nothing merged). Every proposal becomes a `Hypothesis` candidate tagged
with its AI origin — regardless of anything the model says.

**S5 — `research/validator.go` + `research/http_differential.go`** — the
deterministic tier. `Validator` (`Supports`/`Validate`, **no** "execute these
actions" entry point — a validator owns and bounds its own probes), `Outcome`
(`no_signal`/`observed`/`reproduced`), `ValidationResult` (facts + `Outcome`, **no
`State` field**), a compile-time `Registry` (no dynamic validators), and the
`Engine` state machine that is the *only* caller of `Promote`
(`reproduced` + validator identity + required-evidence satisfied → one rung).
`HTTPDifferentialValidator` is the first real validator: read-only GETs of its own
fixed baseline/normalized paths, never anything from the candidate text.

**Provenance (lineage, locked before S6/S8)** — `research/evidence.go` defines
`Provenance{ProducerKind, ProducerID, Tool, Timestamp, RawInputHash}`, held in an
**unexported** field on both `Evidence` and `Candidate` and read only through a
`Provenance()` getter that returns a copy — so no other package can rewrite where
a candidate came from (real data immutability, not just an API convention;
`Candidate.MarshalJSON` still emits it). `RawInputHash` is the **byte-for-byte**
SHA-256 of the *original* input (the raw diff, the raw crash, the exact bytes sent
to a model) taken *before* any parser/normalization, so newline/encoding/parser
quirks can't break traceability. Combined with the append-only `History` (each
`Promote` records its validator + time) and **content-hash evidence refs** — every
ref is `validator:kind:<sha256 of the retained observation>`, and the Engine keeps
that observation on the candidate — the full lineage `diff → AI → validator →
reproduced` is answerable and tamper-evident: where it came from, which raw input,
which validator, and whether any evidence was later swapped (the hash would no
longer match).

**S6 v1 — `research/diff.go`** — the first non-AI producer: a deterministic
`DiffProducer` reads a unified git diff and classifies security-relevant ADDED
changes (`added_bounds_check`, `added_auth_check`, `added_canonicalization`,
`added_type_validation`, `added_length_validation`, `dangerous_api_replaced`,
`added_reject_path`) into hypothesis candidates tagged `Origin{Kind: "diff"}`.
They flow into the **same** Registry → Validator → Engine spine; with no diff
validator registered yet they correctly stay `hypothesis` (no second pipeline, no
auto-promotion). An AI diff pass can later enrich these candidates, never replace
the deterministic classification.

**S8 v1 — `research/fuzz.go`** — the fuzz/crash producer, deterministic and
volume-controlled. Pipeline: `CrashArtifact → Normalize → CrashSignature → dedup
within a FuzzScope into a CrashGroup → deterministic CrashInterest → (only
non-noise groups) → Candidate{Origin{Kind:"fuzz"}}`. Core principle: **a
`CrashSignature` is a crash fingerprint, not a global bug id; a `CrashGroup` is
scoped by build/harness; a Candidate traces the whole group, not one crash.**
- **Distinct hashes, never mixed.** `TestcaseHash` (crashing input bytes),
  `CrashOutputHash` (raw crash output), `SignatureHash` (normalized type + access
  + top stable frames — the *fingerprint*), `GroupHash` (`ScopeHash +
  SignatureHash` — the group's logical *identity*), `MembersDigest` (a commitment
  over ALL members' `CrashOutputHash`, sorted — full-set tamper-evidence without
  storing every hash), and `GroupArtifactHash` (SHA-256 of the canonical
  serialized group — the exact producer-input artifact). A fuzz candidate's
  `Provenance.RawInputHash` is the **`GroupArtifactHash`** — the raw producer-input
  artifact, *not* the derived `GroupHash` — so `RawInputHash` keeps its frozen
  meaning ("byte-for-byte hash of the raw input the producer ingested")
  consistently across the AI, diff and fuzz producers. Structured `Refs`
  (scope/signature/group/artifact hashes, members digest, count, type) make the
  candidate queryable — not just prose.
- **Signature discriminates.** It includes sanitizer **access type/size** and
  `StableFrame{Module,Function,Source-basename}`, so two independent faults in one
  function (READ-of-1 vs WRITE-of-4) or different crash types don't merge — while
  addresses/PIDs/timestamps/temp paths/line:col are normalized away so the same
  bug across runs collapses.
- **Scope prevents over-merge.** Grouping is keyed by `ScopeHash + SignatureHash`,
  so the same signature under a different `BuildID`/`HarnessID` is a different
  group — old vs new build, or two harnesses, are never silently merged.
- **Deterministic, conservative classification.** sanitizer → memory_safety; bare
  SIGSEGV/SIGBUS *without* sanitizer evidence → **unknown** (not over-claimed as
  memory_safety); Go index/slice/nil panic → panic; timeout → hang; **OOM →
  resource_exhaustion** (kept distinct from hang); assertion/abort →
  invariant_violation; no crash marker → noise. An AI pass may later
  explain/enrich/suggest-merges — never decide state.
- **Group before candidate.** Crashes dedup into scoped groups first with an exact
  `Count` and capped, still-traceable member hashes; only non-noise groups become
  candidates, so 100k crashes of one bug yield one candidate. `GroupHash` is
  representative-independent (input order can't change it).

Fuzz candidates flow into the **same** Registry → Validator → Engine spine; with
no fuzz validator registered they stay `hypothesis` (no auto-promotion, no
exploitability judgment).

**S9 v1 — `research/differential.go`** — the differential producer, the third
research source (runtime differences). It is a deterministic PRODUCER (not a
prober): it consumes a `DifferentialCase` — the responses to the SAME semantic
request under different encoding/normalization/boundary/protocol variants,
collected elsewhere — compares them against the case's OWN DECLARED CONTRACT,
filters run-noise, and classifies disagreements into `status_differential`,
`header_differential`, `body_shape_differential`, `accept_reject_differential`,
`normalization_differential`, `boundary_differential`. Core principle: **a mere
difference is never itself an anomaly — only a difference that violates what the
case declared should hold is.**
- **Judged only against a declared `Expectation`.** `ExpectEquivalent` (encoding/
  protocol variants should match baseline; a difference is reported per
  dimension), `ExpectNormalizeEqual` (normalization variants should match
  baseline; any difference is one `normalization_differential`), or
  `ExpectBoundaryMonotonic` (each boundary variant carries its own `Expected`
  accept/reject outcome; only a variant whose *observed* outcome contradicts its
  *own declared* `Expected` is an anomaly — correct fail-closed behavior at a
  boundary, e.g. "1024B accepted, 1025B rejected" under a 1024-byte limit, is
  never flagged, since it matches what was declared). A case with **no declared
  `Expectation` produces zero candidates** — it is recorded, never judged
  (zero-FP-first).
- **Body compared structurally, not just by length bucket.** `BodyShape` adds a
  JSON `StructuralHash` (key names + value *kinds*, never concrete values, sorted,
  recursive) alongside media-type + length-bucket, so `{"admin":false}` vs
  `{"admin":true}` share a shape (a value changed) while a login-failure JSON and
  a profile-success JSON in the same length bucket do not (the keys differ).
- **Security-relevant header VALUES compared, not just key presence.** A small
  fixed whitelist (`WWW-Authenticate`, `Location` — scheme/host/path only, query
  ignored —, `Allow`, `Content-Type`, the CORS `Access-Control-Allow-*` pair) is
  value-compared, so `Basic`→`Bearer` or `/login`→`/admin` is caught even with an
  identical header key-set. Every other header stays key-set-only or fully
  excluded (volatile: Date/Set-Cookie/X-Request-Id/ETag/Content-Length/…) — this
  is not a "diff all header values" escape hatch.
- **Two hashes, never mixed (same discipline as S8).**
  `caseArtifactHash` is the **lossless** canonical serialization — every variant
  in its given order, every header including volatile ones, exact values; map
  keys are sorted only because Go maps have no defined order (sorting drops no
  information). This is what `Provenance.RawInputHash` points at, keeping
  `RawInputHash`'s frozen, cross-producer meaning ("hash of the raw input the
  producer ingested, before any denoising") consistent with the diff and fuzz
  producers. `comparisonHash` is the **denoised**, order-independent identity
  (volatile headers excluded, body-as-shape, variants sorted) used to recognize
  "the same differential finding" — it lives only in `Refs.comparison_hash`,
  never in `Provenance`. Changing a volatile header (e.g. `Date`) changes
  `caseArtifactHash` but never `comparisonHash`.
- **Narrow v1.** Only the six anomaly types above; no attack-input generation, no
  live probing in the producer (collection is deliberately deferred to a future,
  registered-template collector — never an LLM choosing arbitrary URLs/requests
  for the collector to send, mirroring the S5 Validator principle).
- **Judgment authority is closed, not just the judgment logic.** `Expectation`
  and `Expected` are only usable when the case declares an `ExpectationSource`
  from a fixed whitelist — `spec`, `deterministic_rule`, `human_config`,
  `detection_fact` (an already-verified fact from the frozen detection plane, not
  a research Candidate). This closes an INDIRECT authority bypass: AI never
  writes `Verdict`/`State`, but if it could author what a protocol "should" do,
  it would control what counts as an anomaly just as effectively — "this should
  be `accepted=true`" from a model, paired with an observed rejection, would
  auto-produce a candidate without the model ever touching a verdict field. Because
  this is a whitelist (not a blacklist), `"ai"`, `"llm"`, `"proposal"`,
  `"candidate_text"`, or any kind nobody thought to name are rejected by
  construction; an empty `ExpectationSource` is rejected the same way a missing
  `Expectation` is. `DifferentialCase.validate()` also refuses to judge a
  malformed case — fewer than 2 variants, duplicate/empty variant names, a
  `BaselineID` that doesn't exist, `Expected` set on an equivalence-style case
  (contract mixing), or a boundary case with no variant carrying a comparable
  declared outcome — so bad input can't manufacture a candidate either.

Differential candidates flow into the same spine and stay `hypothesis` until a
validator reproduces the difference safely.

Nothing here touches the 28 checkers or the engine; `go build/vet/test ./...`
(and `-race`) stays green.

## Boundary audit (all green)

The chain runs end to end — `Evidence → Provider → Proposal → Candidate(hypothesis)
→ Registry → Validator → ValidationResult → Engine → Promote → reproducible` — and
the guarantees hold under test:

| Attempt | Result |
| --- | --- |
| AI reply says `"verdict":"confirmed"` / `"severity":"critical"` | dropped on unmarshal (no such field) |
| AI proposal → candidate | always born `hypothesis`, AI origin recorded |
| AI-supplied text drives a request | impossible — validators use only their own fixed probes |
| candidate with no matching validator | stays `hypothesis` |
| validator reports `reproduced` but no evidence | not promoted |
| validator evidence misses a required token | not promoted |
| validator `reproduced` + evidence satisfies requirements | promoted exactly one rung |
| repeated validation | idempotent (one transition) |
| concurrent `Promote` | one wins; never skips a rung |

## Status / roadmap

- **S1–S5: foundation frozen.**
- **Provenance: locked.**
- **S6 (patch/diff intelligence): v1 landed & audited** (deterministic
  `DiffProducer`; an AI diff pass can enrich later). Contract frozen.
- **S8 (fuzz/crash intelligence): v1 frozen** (deterministic `FuzzProducer`;
  scope-bounded groups, discriminating signatures, `RawInputHash =
  GroupArtifactHash` (raw producer artifact, not the derived identity),
  `MembersDigest` full-set commitment, structured refs, conservative classifier).
  No AI fuzz-input generation, no auto-exploitability. Contract frozen.
- **S9 (differential engine): frozen.** Deterministic `DifferentialProducer`;
  judged only against a declared `Expectation` from a whitelisted
  `ExpectationSource` (`spec`/`deterministic_rule`/`human_config`/
  `detection_fact` — AI/proposal/candidate-text kinds structurally rejected); JSON
  structural body comparison; security-header value comparison;
  `RawInputHash = caseArtifactHash` (lossless) distinct from `comparisonHash`
  (denoised); malformed-case guards.
- **S10 (state-machine explorer): DESIGN CONTRACT ONLY, still under audit**
  (`research/state_machine.go` + `internal/actionauth/capability.go` +
  `internal/stateauth/`) — no explorer, no registry, no `ActionPolicy`, no
  concrete `StateProjector`, no execution logic, no `Origin` kind yet. Twelve
  boundaries are locked into the TYPE SHAPES themselves — and, for the two
  authority-bearing ones, into an actual PACKAGE boundary and constructor-only
  hashing, at PARITY with each other — not left to comments alone, because a
  boundary a later change can route around by adding one field, or one file to
  the same package, or one caller-supplied hash, is not a boundary:
  1. **No executable content anywhere.** `ActionID{RegistryKey, VariantID}` and
     `RecoveryPlanRef{RegistryKey}` are opaque lookups — there is no Method, URL,
     Headers, Body, or Command field in any of the three files. `RegisteredAction.
     Reversible` is registry metadata, declared once by the registering code. The
     v1 registry (once implemented) is also IMMUTABLE for the lifetime of a
     process — no hot reload — a deliberate scope decision: `BoundAction`
     briefly carried a `registryRevision` field for a hot-reload future, but
     `ValidFor` (boundary 4) never checked it, and an unchecked field is worse
     than no field — it looks like enforced protection that isn't actually
     enforced. Removed rather than wired up; if the registry ever needs to
     support revisions, `ValidFor`'s signature must grow a revision parameter
     AT THAT TIME, not before.
  2. **An AI-supplied `ActionID` is never itself an execution credential** — the
     same "AI is not authority" bypass as S9's `ExpectationSource`, moved from
     judgment to execution. `research.ActionSuggestion{ActionID, Rationale}` is
     the ADVISORY shape AI output may take — freely constructible, authorizes
     nothing. Only a `BoundAction` may ever be executed.
  3. **BOTH authority boundaries this contract needs are PACKAGE boundaries, at
     the SAME level — not merely an unexported field in one package.** Who may
     authorize an ACTION (`actionauth.BoundAction`/`BoundRecovery`) and who may
     declare an authoritative STATE (`stateauth.Fingerprint`) each live in their
     own package — `internal/actionauth` and `internal/stateauth` respectively —
     separate from `research`, specifically so Go's compiler, not convention,
     stops any file `research` will ever contain (a future Explorer, AI-glue
     code, a candidate producer) from constructing either one with a real
     identity. An unexported field (or an unexported constructor) inside
     `research` alone would not have survived `research` itself growing an
     Explorer in a sibling file, since Go visibility is package-scoped, not
     file-scoped — a separate package does. The future `ActionPolicy` (in
     `actionauth`) and the future concrete `StateProjector` (in `stateauth`) are
     the sole places their respective constructors are ever added, and — for the
     identical reason — BOTH must be implemented inside their own authority
     package rather than in `research`, even though their logic needs
     scope/state/target-specific knowledge that might otherwise seem to belong
     "closer to" `research`.
  4. **A `BoundAction`/`BoundRecovery` is bound to the SCOPE AND STATE it was
     authorized for, not just to an action identity** — closing a
     stale-capability / cross-state-replay gap: without this, a capability
     issued while the system was in "Scope X, State A" would be a bare
     `ActionID` with no record of that context, and could be replayed after the
     scope changed or the state moved to "State B", since nothing about the
     value itself would say it had gone stale. `BoundAction.ValidFor(scopeHash,
     stateFingerprintHash)` (and `BoundRecovery.ValidFor(scopeHash)`) is how a
     future Executor is REQUIRED to re-verify this immediately before running
     anything — never trusting that a capability obtained earlier is still good
     for the *current* scope/state. On today's zero-value capability, `ValidFor`
     always returns false.
  5. **Raw evidence vs identity, never conflated** (the S8/S9 discipline again):
     `stateauth.Fingerprint` splits `RawStateArtifactHash` from
     `StateFingerprintHash` — and carries its own `ScopeHash`, so a fingerprint
     is self-describing wherever it travels (disk, replay, a different worker).
  6. **`Fingerprint` is immutable AND internally consistent — two DIFFERENT
     guarantees.** Immutable only means nothing can edit it after construction;
     internally consistent means it could never be *born* wrong. All fields are
     unexported — and `stateauth`'s `newFingerprint` computes BOTH
     `RawStateArtifactHash` (from the actual raw bytes) and `StateFingerprintHash`
     (via `canonicalFactsHash` — sorted keys, deterministic) itself; there is no
     parameter through which a caller could supply either hash directly. The
     same "artifact bytes → a deterministic canonicalizing function → a hash"
     discipline as S6/S8/S9, never "caller asserts this is the hash".
     `StateTransition.ScopeConsistent()` recomputes (never stores) whether a
     transition's own `ScopeHash` agrees with both fingerprints it references.
  7. **Internally consistent is STILL not AUTHORITATIVE — and this is now closed
     COMPLETELY, not merely by review discipline.** A `Fingerprint` could be
     self-consistent (boundary 6) and still describe FABRICATED facts, if
     whatever called the constructor were free to invent the facts map — and a
     fabricated fingerprint feeding a future `ActionPolicy`'s
     `AllowedActions(scope, state)` decision would let whoever fabricated it
     indirectly control action authorization, the same class of bypass as
     boundaries 2 and 4, moved one step further upstream (to defining the STATE
     itself, not just the action or the judgment). An earlier round closed this
     with a `StateProjector` interface living IN `research` itself, alongside an
     unexported `newStateFingerprint`, and had to document an honest residual
     caveat: unexported only fully stops OTHER packages, so a future file added
     to `research` itself could still call it directly. That caveat is now
     eliminated, not merely narrowed: `Fingerprint`, `StateArtifact`,
     `ProjectorID`, `StateProjector`, and the constructor all moved into
     `internal/stateauth` (boundary 3). Nothing in `research` — today or in any
     file it will ever contain — can call `stateauth`'s unexported constructor or
     write a `Fingerprint` struct literal, because neither identifier is visible
     outside `internal/stateauth`. A `StateProjector` implementation, once
     written, must itself live inside `stateauth` for the same reason a future
     `ActionPolicy` must live inside `actionauth`: its `Project` method has to
     call the unexported constructor, so an implementation written anywhere else
     could satisfy the interface's shape but could only ever return the
     zero-value `Fingerprint` from its own `Project` method. This is now the SAME
     compiler-enforced guarantee as boundary 3's `BoundAction` treatment, not the
     weaker whitelist-check style of S9's `ExpectationSource` — the two authority
     boundaries are at parity.
  8. **Recovery is registry-backed (boundary 3/4) and `stateauth.RecoveryOutcome`
     is FACTS ONLY** — no `Verified`/conclusion field. It holds the FULL
     `Baseline`/`Result` `Fingerprint`, and `stateauth.Recovered(o)` checks BOTH
     that baseline and result actually belong to the outcome's own declared
     `ScopeHash` AND that their `StateFingerprintHash` values match — proving
     "same scope AND same state", not merely "two strings happened to be equal"
     (which two fingerprints from genuinely different scopes could satisfy by
     coincidence, especially after crossing a disk/replay/worker boundary — a
     bare string comparison alone would wrongly call that recovered).
     `RecoveryOutcome`/`Recovered` live in `internal/stateauth`, not in
     `research`, because recovery verification is fundamentally a state-authority
     question — it never touches an `actionauth.BoundAction`. `Recovered==false`
     means exploration STOPS, never continues on the assumption a rollback
     worked.
  9. **`StateTransition` carries facts only** — no `Unexpected`/`Vulnerable`/
     `Severity`/`State` field. `Action` is a `BoundAction` (boundary 2–4) — a
     transition can only ever reference something that WAS actually authorized
     and executed. `StateTransition` is the one type that legitimately spans both
     authority packages (`stateauth.Fingerprint` + `actionauth.BoundAction`) — a
     pure coordination record, not itself an authority. Whether a transition is
     worth a hypothesis is a future producer's judgment against an authoritative
     `ExpectationSource` (boundary 11). `TransitionArtifactHash` is the lossless
     record hash (the S9 `caseArtifactHash` analogue) — never the denoised
     `StateFingerprintHash`.
  10. **No "0 = unlimited" in `ExplorationBudget`.** Every one of
     `MaxStates/MaxTransitions/MaxDepth/MaxRequests/MaxVisitsPerState/
     MaxBranching/MaxWallTime` must be strictly positive or `Valid()` reports the
     whole budget invalid.
  11. **No second authority system.** Whatever future producer judges a
     `StateTransition` worth a hypothesis reuses S9's `ExpectationSource`
     unchanged.
  12. **Single-session, serial v1** — no corresponding type, since it
     constrains execution behavior rather than data shape: within one
     `ExplorationScope`, at most one in-flight action at a time, so "which
     action produced this `AfterFingerprint`" is never ambiguous. Recorded here
     for the eventual Explorer to honor.
  - **Test-suite proof of the boundary, not just documentation of it:**
     `research`'s own test file can no longer construct a non-zero
     `stateauth.Fingerprint` at all (`TestFingerprintIsOpaqueFromResearch`) —
     the same way it has never been able to construct a non-zero
     `actionauth.BoundAction`. The richer hash-derivation/immutability/
     determinism tests, and `Recovered`'s own test matrix, now live inside
     `internal/stateauth`'s own test file, the only place `newFingerprint` can
     be called.
  - **S10 CONTRACT = FROZEN.** No further changes to the S10 data shapes above
     unless Explorer v1's own implementation proves the contract cannot
     express something real — not merely "could be nicer".
- **S10 Explorer v1 (`research/explorer.go`), plus the two authority packages'
  first real constructors (`internal/actionauth/policy.go`'s `ActionPolicy`,
  `internal/stateauth/rawlen_projector.go`'s `RawLenProjector`): the first
  EXECUTION code S10 has. This is orchestration filling in slots the frozen
  contract always reserved for it (`ActionPolicy` in `actionauth`, a concrete
  `StateProjector` in `stateauth`) — it changes no data shape above.
  - **The locked v1 loop:** `Baseline` (`Collector` → `StateArtifact` →
    `StateProjector` → `Fingerprint`) once; then any number of `Step()` calls
    (`ActionPolicy.Select(scope, current, tried)` → `BoundAction` → re-verify
    `ValidFor` → `Executor.Execute` → collect/project again → `StateTransition`);
    then `Recover()` (`ActionPolicy.BindRecovery` against this Explorer's ONE
    fixed, construction-time `RecoveryPlanRef` → `BoundRecovery` →
    `Executor.ExecuteRecovery` → collect/project → `stateauth.Recovered` →
    true allows continuing, false is a HARD, PERMANENT STOP).
  - **Regression found and fixed after the first cut: `Step` took a
    caller-supplied `actionauth.ActionID` and asked the policy "is this
    registered?"** That reopened the exact bypass S10 exists to close, one
    level down: whoever supplies the `ActionID` — a human, or indirectly an AI
    `ActionSuggestion` — would be choosing WHICH action runs, with the
    registry doing nothing but rubber-stamp membership. That is still "AI
    action selection" even though the AI never writes a request. Fixed by
    removing the parameter entirely: `Step()` takes no action-identifying
    input at all. `ActionPolicy.Bind(id, ...)` was replaced with
    `ActionPolicy.Select(scopeHash, fingerprint, exclude)`, which is the ONLY
    way an action gets chosen: it walks the registry's own
    `Registration{Action, Requirements}` entries — see the next bullet for
    `Requirements`'s own shape — collects the RegistryKeys that MATCH the
    given Fingerprint and are not already in `exclude`, sorts them, and binds
    the first one. "Registered != Allowed" is now a real, enforced
    relationship, not a slogan: being in the registry only means the key
    exists; `Requirements` is what makes it APPLICABLE to a specific state.
    `exclude` is FACTS Explorer supplies (which action keys have already been
    tried from this exact `StateFingerprintHash`) — never a decision; v1
    deliberately does not wire any AI-authored suggestion into `Select` at
    all, not even as an advisory tie-breaker.
    `TestExplorerStepSelectionIsDeterministicNotCallerChosen` proves two
    independently constructed Explorers, given identical
    scope/collector/policy, select the identical action — the choice comes
    entirely from (scope, state, registry), never from a caller.
  - **Second regression, found on the very next audit round: the first
    version of `Requirements` was `Supports func(stateauth.Fingerprint) bool`
    — a Go closure.** From the type system's point of view that looked like a
    deterministic predicate, but nothing stops a closure body from reading
    the wall clock, a global, an environment variable, a feature flag, a
    random source, or doing I/O — so "Registered != Allowed" would still have
    rested on an arbitrary function body, not on something that can be read
    and matched, and the same `(registry, fingerprint)` pair was not
    actually guaranteed to select the same action every time. Fixed by making
    `Requirements` pure DATA: `actionauth.StateRequirements{ProjectorID
    stateauth.ProjectorID, Facts map[string]string}`, matched by a private,
    pure `matches` function — exact `ProjectorID` equality plus a Facts
    subset match, no callback, nothing to audit beyond the struct's own
    fields. A zero-value `StateRequirements` (empty `ProjectorID`) matches
    NOTHING — fail-closed. Pinning `ProjectorID` (which
    `stateauth.Fingerprint` already exposed) also closes a narrower gap:
    different `StateProjector` implementations could otherwise produce
    similarly-shaped `Facts` for entirely different meanings, and a
    `Registration` could accidentally (or be crafted to) match a state it was
    never written for.
  - **`Explorer` holds no authority of its own — it is pure orchestration.** It
    never decides what the state IS (delegated to the injected
    `stateauth.StateProjector`), never decides WHICH action MAY run (delegated
    entirely to `ActionPolicy.Select`), and never decides whether a transition
    is WORTH a hypothesis (left to a future producer against an authoritative
    `ExpectationSource` — not implemented here).
  - **Serial, single-scope, single-session (boundary 12):** `Explorer` holds a
    `sync.Mutex` across the whole of `Step`/`Recover`, so at most one action is
    ever in flight — proved, not just documented, by
    `TestExplorerSerializesConcurrentSteps` (five concurrent `Step` calls, an
    executor that records whether it was ever entered while already running).
  - **Defense in depth on `ValidFor`:** `Step` re-verifies
    `action.ValidFor(scope, state)` immediately before calling `Executor.Execute`,
    in addition to (never instead of) whatever check a real `Executor`
    implementation must do itself.
  - **Regression found and fixed in the same audit round: a post-action budget
    violation was treated as an ordinary stopping point, leaving Explorer
    sitting in the over-budget state.** If `MaxStates=10` and the 11th state
    is what a step actually produces, exploration has already gone one state
    too far — that observed transition is kept (it is real evidence), but the
    state it landed in must never become a point to continue from. Fixed:
    `MaxTransitions`/`MaxDepth`/`MaxRequests`/`MaxWallTime` are still checked
    BEFORE any side effect (a preflight failure never calls the `Executor`),
    but `MaxStates`/`MaxVisitsPerState` — which depend on the state actually
    observed, so they can only be known after — now trigger MANDATORY recovery
    the instant they are exceeded: `Step` immediately runs this Explorer's
    fixed recovery ref (bypassing the request-budget preflight, since an
    already-exhausted budget must never block the one safety mechanism meant
    to run exactly when the budget is exhausted), then stops permanently
    regardless of whether that recovery verified — never a continuation from a
    state already known to exceed the budget the moment it was observed.
    `TestExplorerMaxVisitsPerStateTriggersMandatoryRecoveryThenStops` proves
    the executor actually recorded a recovery call, not merely that `Stopped()`
    became true. `MaxBranching` is now enforced, not merely validated:
    `NewExplorer` REQUIRES it to be exactly 1, not merely positive — v1 never
    branches at all (`Select` always picks at most one action), so a budget
    claiming to allow anything else would be configuration that lies about a
    capability this Explorer does not provide; `MaxBranching` stays reserved
    for a future multi-branch Explorer to actually use.
  - **Recovery failure is a permanent stop, proved by test:**
    `TestExplorerRecoverySuccessAndFailure/failure_stops_exploration` drives a
    `Recover` call whose re-collected state does not match the baseline and
    checks that every subsequent `Step` and `Recover` call is refused with
    `ErrExplorerStopped`.
  - **Third regression, closed in the same audit round: scope continuity was
    checked (`collectAndProjectLocked` already rejected a cross-scope
    `StateArtifact`/`Fingerprint`), but a rejection only returned an error —
    it did not stop the explorer.** A caller ignoring that specific error
    could keep calling `Step`/`Recover` as if nothing had happened. This
    matters because nothing else structurally prevents the underlying target
    from silently becoming a DIFFERENT session mid-exploration (a dropped
    connection, a load balancer routing a probe to a different backend, a
    misconfigured test double) — without a hard stop, Explorer could keep
    recording "transitions" that are really "old session state A -> unrelated
    new session state B", never a legitimate observation. Fixed: EVERY
    collection/projection failure — in `Baseline`, after an action in `Step`,
    and inside a recovery attempt — now calls the same permanent-stop path any
    other fatal condition uses, never merely returning a retryable error.
    Three tests pin this at each of the three call sites:
    `TestExplorerBaselineScopeMismatchStopsPermanently`,
    `TestExplorerPostActionScopeDriftFailsStop` (the action itself ran
    against a still-valid scope; the drift is caught on the collection
    immediately after, and the step is never recorded in `History`), and
    `TestExplorerRecoveryScopeDriftFailsStop` (the recovery WAS dispatched to
    the executor — a real side effect happened — but verifying it is refused
    once the re-collection disagrees on scope). Because `e.baseline` and
    `e.current` are therefore ALWAYS the result of a successful
    (same-scope) collection for the entire lifetime of a non-stopped
    Explorer, a "same `StateFingerprintHash` but different scope" scenario —
    already covered by `stateauth`'s own `Recovered` tests
    (`matching_hash_but_wrong_scope`) — can never actually arise inside
    Explorer's orchestration: the drift is caught and stopped at the moment
    it is observed, before anything could ever compare it against something
    else.
  - **Fourth lock, not a regression but tightened before E5: mandatory
    recovery bypassing the request-budget preflight (deliberate — an
    exhausted budget must never block the one safety mechanism meant to run
    exactly when it's exhausted) needed its OWN hard bound, independent of
    `ExplorationBudget.MaxWallTime`, so a hung recovery could not turn
    "bounded exploration" into an unbounded wait.** `NewExplorer` now takes a
    `recoveryTimeout time.Duration` (REQUIRED, strictly positive), and every
    recovery attempt runs the `Executor.ExecuteRecovery` call under a
    `context.WithTimeout` derived from it.
    `TestExplorerRecoveryTimeoutStopsAHungRecovery` drives a cooperative fake
    executor whose recovery call blocks for 200ms against a 10ms
    `recoveryTimeout` and checks `Recover` returns well before the full delay
    and stops the explorer. **Caveat, corrected on the next audit round:** Go's
    `ctx` cancellation is COOPERATIVE, not forceful — Explorer provides the
    deadline and stops trusting the call once it expires, but cannot
    physically kill an `Executor` implementation that ignores `ctx.Done()`
    and never returns. Every real `Executor` v1 plugs in MUST itself be
    context-cooperative (e.g. a future HTTP-based one must build requests
    with `http.NewRequestWithContext`, not `http.NewRequest`, or the timeout
    does nothing to the underlying network I/O).
  - **Fifth regression, found on the next audit round: `Registration`'s
    declarative `Requirements` (the fix for the earlier closure blocker) still
    stored the CALLER'S OWN `Facts` map by reference.** `NewRegistry`
    rebuilding its `map[string]Registration` did not stop a caller who still
    held the original `StateRequirements.Facts` map (or the `regs` slice
    passed in) from mutating it AFTER construction and silently changing what
    `ActionPolicy.Select` would consider applicable from then on — an
    "immutable registry" that can still be edited through a live reference is
    not actually immutable, reopening a narrower version of the same class of
    gap boundary 3 and boundary 6 close elsewhere (a value that LOOKS
    locked down but has a live path to being changed after the fact). Fixed:
    `NewRegistry` now rebuilds every `Registration` field-by-field and
    deep-copies `Requirements.Facts` into a fresh map via `copyFacts` — the
    registry never stores a reference the caller still holds.
    `TestNewRegistryDeepCopiesRequirementsAndIsUnaffectedByLaterMutation`
    mutates both the original `Facts` map and the original `regs` slice after
    construction and checks `Select`'s result is completely unaffected.
  - **Sixth regression — the deepest one found so far, a genuine
    authorization TOCTOU: every action was authorized against `e.current`, a
    Fingerprint left over from a PAST collection** (`Baseline`, or the
    previous `Step`'s own post-action collect) — not one taken at the moment
    of authorization. Even with scope continuity and a fully deterministic,
    closure-free `Select`, nothing stopped the real target from changing on
    its own, for reasons this Explorer never caused, in the window between
    that past observation and the actual `Execute` call — a classic
    check-then-act gap on the state the check was performed against. Fixed:
    `Step` now collects and projects a FRESH `Fingerprint` FIRST, before
    `Select` is ever consulted, and compares it against `e.current`; any
    disagreement is EXTERNAL STATE DRIFT and an immediate permanent stop,
    with the action never selected or executed — never silently accepted as
    a new baseline to continue from. `TestExplorerFreshStateDriftBeforeActionPreventsExecution`
    is the direct proof: a drifted fresh-before collection stops the explorer
    with the executor never invoked at all, distinct from
    `TestExplorerPostActionScopeDriftFailsStop`, which drives the OTHER
    collection point (no drift before the action — it legitimately runs —
    drift is only observed on the collection immediately after). v1 has no
    revision/ETag/session-nonce freshness primitive, so this is the
    deliberately blunt v1 answer — no asynchronous network system eliminates
    a TOCTOU window entirely, but authorizing off a fresh observation instead
    of a historical cache closes the part of it this Explorer itself
    controls; binding a real protocol's own freshness primitive into
    `BoundAction`/`StateArtifact` is future work, not required to close v1's
    own responsibility here.
  - **Seventh regression, closing a subtler bypass OF THE FIX ABOVE:
    fresh-state authorization only works if the Fingerprint Step re-collects
    is actually fresh — and Explorer held a bare `stateauth.StateProjector`
    interface value.** Any package can write a type satisfying that
    interface; it can never forge a NEW `Fingerprint` (the constructor is
    unexported to `stateauth`), but nothing stopped it from CAPTURING a
    `Fingerprint` from one genuinely earlier `Project` call and REPLAYING it
    on every later call, ignoring the `StateArtifact` it was actually asked
    to project. Fresh-state authorization's own drift check would see a
    perfectly self-consistent `Fingerprint` and never suspect it was minted
    for different bytes — the state-authority analogue of exactly the TOCTOU
    fresh-state authorization closes for actions. Fixed the same way
    `actionauth` closes action selection: `internal/stateauth/registry.go`
    adds an unexported `registry` type plus `BoundRegistry`, which pairs a
    registry with the ONE `ProjectorID` a given profile is authorized to use.
    There is no exported constructor an external package could hand a fake
    or replaying projector to — nor, critically, one that lets a caller pick
    which registered `ProjectorID` to pair with a registry.
  - **Ninth regression, found on the very next round, one level up from the
    fix above: the first cut of this still took the registry and a
    `ProjectorID` as TWO SEPARATE `NewExplorer` parameters.** That let
    Explorer's own caller choose WHICH registered projector interprets the
    same raw evidence — the state-authority analogue of the "caller picks
    ActionID" bypass S10-E1 closed for actions, one layer further upstream
    (choosing which authority explains the state, not just which action runs
    against it). If a registry ever holds both a minimal fixture projector
    and a real protocol-specific one, a caller choosing the weaker one could
    turn "authoritative state" into "whichever state semantics the caller
    finds convenient" — e.g. mapping `{"authenticated":"false"}` and
    `{"authenticated":"true"}` onto the identical `Fingerprint` via a
    length-only projector, while a real HTTP-state projector would have told
    them apart. Fixed: `BoundRegistry` (above) is now the ONLY parameter —
    `Explorer` holds a single `*stateauth.BoundRegistry` field, with no
    separate `ProjectorID` a caller could swap in.
    `stateauth.FixtureRegistry()` is the one named profile constructor that
    exists today, and its own doc is explicit that it is TEST/FIXTURE ONLY —
    there is deliberately no generically named `DefaultRegistry()` a
    production caller might reach for out of habit; a future real profile
    (an HTTP target, say) gets its own equally explicit, equally named
    constructor, built the same way, never a parameter filled in by whoever
    constructs the `Explorer`. This closes cleanly at the type level (nothing
    to runtime-test beyond what `internal/stateauth/registry_test.go` already
    pins: unknown IDs and nil/zero values all fail safely, never panic).
  - **Tenth regression: `ExplorationBudget.MaxRequests` was enforced by
    Explorer GUESSING a fixed number of "requests" per `Step`/`Recover` call
    (3 and 2) — an assumption that breaks the moment a real `Collector`'s
    single `Collect()` call issues several actual requests internally (a
    status check, a session check, a metadata fetch), or an `Executor`
    retries once.** Fixed: `research/meter.go` adds `RequestMeter`
    (`Acquire() error`, `Used() int`) plus `ContextWithRequestMeter`/
    `RequestMeterFromContext`. Explorer attaches a bounded meter to `ctx`
    before every `Collector`/`Executor` call and no longer counts anything
    itself — a real implementation MUST call `Acquire` once for EACH actual
    request it issues, and `MaxRequests` is enforced the instant `Acquire`
    is called past the bound, not by Explorer's own arithmetic.
    `TestExplorerRequestMeterCountsRealAcquireCallsNotGuessedCost` drives a
    fake `Collector` that acquires 3 units per `Collect()` call against
    `MaxRequests=5` and checks the SECOND call fails on the real count (3+3 >
    5), not on any per-call guess. Recovery gets its OWN separate, bounded
    "emergency allowance" (`recoveryRequestAllowance`, a new required
    `NewExplorer` parameter — not a change to the frozen `ExplorationBudget`
    type) — deliberately never blocked by the main exploration meter being
    exhausted (`TestExplorerRecoveryUsesSeparateAllowanceNotBlockedByExhaustedExplorationBudget`),
    but still a real, enforced bound of its own, never unlimited
    (`TestExplorerRecoveryAllowanceIsBoundedNotUnlimited`).
  - **Eleventh regression, found immediately after: `RequestMeter` (above) was
    still purely COOPERATIVE — nothing stopped a real `Collector`/`Executor`
    implementation from forgetting to call `Acquire`, or from calling it
    fewer times than it actually issued requests (an internal retry, a
    redirect follow-up), silently reopening the exact "guessed/undercounted
    cost" problem the previous fix closed at the Explorer level, one layer
    further down.** Fixed for HTTP specifically:
    `research/http_meter.go`'s `BudgetedRoundTripper` wraps an
    `http.RoundTripper` and calls `Acquire` (via
    `RequestMeterFromContext(req.Context())`) BEFORE forwarding to its `Base`
    — a real I/O CHOKE POINT, not business-logic discipline. Any future
    HTTP-based `Collector`/`Executor`/recovery implementation MUST build its
    `*http.Client` with this as its `Transport` and issue requests via
    `http.NewRequestWithContext(ctx, ...)` using the SAME `ctx` Explorer
    passed it; metering then happens at the actual network call regardless
    of whether the business logic above remembers to account for it.
    `TestBudgetedRoundTripperMetersAndBlocksBeforeNetwork` proves this with a
    real `httptest.Server`: with a 2-unit meter, a third request is refused
    BEFORE reaching the network, and the server's own received-request count
    (not just the meter's internal count) confirms exactly 2 requests ever
    went out. This is the metered analogue of `http.NewRequestWithContext`
    already being required for `recoveryTimeout` — for a REAL http-based
    executor, cancellation and metering both ride the same context, and both
    are enforced by the stdlib transport layer itself, not merely "hoped
    for" cooperative code.
  - **Twelfth regression, found on the very next round, closing the last gap
    in the choke point itself: a request whose context carried NO
    `RequestMeter` at all was let through unmetered (fail-OPEN), rather than
    refused.** That would have quietly defeated the whole point: a future
    real `Collector` that built its `*http.Request` with plain
    `http.NewRequest` instead of `http.NewRequestWithContext(ctx, ...)` — the
    context Explorer actually attached a meter to — would silently escape
    `MaxRequests` entirely, even with `BudgetedRoundTripper` correctly
    installed as its `Transport`. Fixed: `RoundTrip` now returns
    `ErrNoRequestMeter` and never calls `Base` at all when no meter is
    present — FAIL-CLOSED, not a graceful pass-through.
    `TestBudgetedRoundTripperFailsClosedWithoutMeter` proves the request
    never reaches the network (the test server's own received-request count
    is 0, and the `Base` test double's call count is 0) — "missing meter"
    now means "refuse", never "proceed anyway".
  - **`S10-E4 = PASS`.** Twelve regressions found and closed across five audit
    rounds since Explorer v1 first landed (`a08cb5e`) — caller-chosen action
    identity, post-budget continuation, arbitrary applicability closures,
    scope/session drift, cached-state authorization, external projector
    injection, caller-chosen projector identity, guessed request cost,
    cooperative-only metering, and a fail-open gap in the metering choke
    point itself — none of which required changing the frozen S10 data
    contract. The next stage, S10-E5, is the first REAL (non-mock) target: a
    local read-only HTTP fixture, exercising all of state authority, action
    authority, scope continuity, budget/metering, and recovery together
    against real network I/O for the first time.
  - **Small hardening pass, not a regression:** `History()` was already
    proven, not just documented, to return a copy
    (`TestHistoryReturnsIndependentCopy` mutates the returned slice and
    checks Explorer's own record is unaffected) — the same discipline
    `Fingerprint.Facts()` and `stateauth`'s own getters already followed.
    `e.tried` (the exclude set `Select` receives) is built ENTIRELY from
    Explorer's own private bookkeeping and is never exposed by any getter or
    accepted as a parameter from any caller, so there is no path for a caller
    to influence action selection by tampering with history.
  - **`RawLenProjector`** is the first concrete `StateProjector` — deliberately
    minimal (one fact, the raw byte length), proving the contract end-to-end
    without claiming to model any real protocol's state. It is a fixture/test
    projector, not meant to carry real security-research weight (two
    responses of identical length can differ completely, e.g. an
    `admin=false`/`admin=true` flip) — reachable ONLY through
    `stateauth.FixtureRegistry()`, never a generically named production
    default. A real protocol-specific projector (status, content-type,
    stable headers, auth state, body structural shape) is future work and
    must live inside `internal/stateauth`, behind its own equally explicit
    named `BoundRegistry` constructor, for the same reason `RawLenProjector`
    does.
  - **v1 explicitly does NOT do:** concurrent actions, multiple sessions, AI
    action selection (now closed at the API level, not just by convention —
    `Step` has no parameter to carry one), AI-generated network requests,
    dynamic registry / hot reload, arbitrary `StateProjector` injection (closed
    at the API level — `Explorer` cannot accept one), caller-chosen
    `ProjectorID` (closed — `Explorer` holds one bound `*stateauth.BoundRegistry`,
    never a registry and an ID as separate parameters), a guessed/estimated/
    undercounted request cost (closed — `MaxRequests` is enforced by real
    `Acquire` calls at the HTTP transport layer itself, not business-logic
    discipline),
    irreversible actions, exploration without a recovery check, "different
    state = vulnerability", automatic exploitability judgment, or unlimited
    depth/budget. None of these have any code path in `research/explorer.go`
    today.
- **S10-E5 (`research/http_collector.go`, `research/http_executor.go`,
  `internal/stateauth/http_projector.go`): the first REAL, non-mock target.**
  Everything through S10-E4 was proven against fakes; this is the same
  authority/scope/budget/recovery machinery run against a real local
  `httptest.Server` over real HTTP I/O for the first time.
  - **`HTTPStateProjector`** (`stateauth.HTTPFixtureRegistry()`) projects
    Facts `{status, content_type, body_sha256}` from a marshaled
    `HTTPArtifact{Status, ContentType, Body}` — meaningfully stronger than
    `RawLenProjector` (a body hash tells apart two same-length bodies with
    different content, e.g. `{"authenticated":false}` vs
    `{"authenticated":true}`, which length alone cannot) while still being
    named and documented as fixture-grade, not a claim to model a real
    protocol's full state (cookies, TLS, headers beyond content-type are all
    future work).
  - **`HTTPCollector`** always GETs ONE FIXED base URL + path, given at
    construction in Go code — never a parameter at call time. **`HTTPExecutor`**
    runs ONLY the FIXED `RegistryKey -> path` map it was constructed with (the
    fixture registers exactly two: `get-root` → `/`, `get-health` → `/health`)
    — `Execute` looks up `action.ID().RegistryKey` in that map and refuses
    anything else, proven by `TestHTTPExecutorRefusesUnregisteredAction`. No
    URL, method, header, or body ever comes from an AI proposal, a candidate,
    or even this Executor's own caller at call time — everything is fixed
    Go-code configuration. `ExecuteRecovery` is a documented no-op: every
    action this fixture can run is a read-only GET, so nothing ever mutates
    target state and there is nothing to reverse — a future Executor whose
    actions DO mutate state must not copy this.
  - **Both `HTTPCollector` and `HTTPExecutor` build their own internal
    `*http.Client`** (`newBudgetedHTTPClient`, `http_collector.go`) — callers
    cannot substitute one, so neither can accidentally end up missing the two
    things this profile requires: `BudgetedRoundTripper` as `Transport` (real
    request metering, S10-E4h) and a `CheckRedirect` that REFUSES every
    redirect via `http.ErrUseLastResponse` — a 3xx response is observed AS
    ITSELF (its own status code becomes a Fact), never followed. This closes
    the audit's explicit redirect concern: a fixed `GET /state` target that
    started returning `302 → http://some-other-host/...` could otherwise have
    walked a probe straight out of its own `ExplorationScope`.
    `TestHTTPCollectorNeverFollowsRedirects` drives a fixture endpoint that
    redirects to `http://example.invalid/...` and checks the observed
    Fingerprint's `status` Fact is `302`, never anything from a followed
    request.
  - **`TestS10E5RealHTTPExplorationEndToEnd`** wires all of the above into a
    real `Explorer` against a real `httptest.Server` and runs
    `Baseline` → `Step` (twice, exercising both real registered actions) →
    (`ErrNoApplicableAction` once both are tried from the unchanging state) →
    `Recover`, asserting real, scope-consistent transitions and a
    real-network-verified recovery — the first time this session's audit has
    verified these boundaries hold under actual network I/O rather than only
    against fakes built to cooperate.
  - **Three runtime-hardening fixes, requested before S10-E5 is pointed at any
    real external target (E5 PASS itself did not depend on them):**
    1. **HTTP body size cap, confirmed by test rather than only asserted in a
       doc comment.** `HTTPCollector` already read the response body through
       `io.LimitReader(resp.Body, maxHTTPBodyBytes+1)` and rejected anything
       over the cap — a malicious or malfunctioning target returning an
       unbounded body could otherwise exhaust memory before
       `HTTPStateProjector` ever got to hash it.
       `TestHTTPCollectorRejectsOversizedBody` drives a fixture endpoint that
       writes past the cap and checks `Collect` fails outright, never
       succeeding with a silently truncated body.
    2. **`MaxWallTime` now bounds the ACTIVE network call, not just the gap
       between `Baseline`/`Step` calls.** The existing preflight check
       (`time.Since(startTime) > MaxWallTime`) only runs BETWEEN calls — a
       single request that simply never returns (a hung connection, a target
       that accepts a socket and never responds) would defeat it entirely,
       since nothing would ever reach the next preflight to notice. Fixed:
       `Baseline` and `Step` both derive a `context.WithDeadline` from the
       session's absolute wall-clock budget (`e.startTime +
       budget.MaxWallTime`, set once at `Baseline`, never renewed per call)
       and pass it to every real-I/O call they make
       (`collectAndProjectLocked`, `Executor.Execute`) — the same
       cooperative-cancellation caveat `recoveryTimeout` already documents
       applies here too (a real implementation must itself be
       context-aware). Recovery deliberately keeps its OWN separate
       `recoveryTimeout` deadline — this does not change that; the two
       remain independent, matching `recoveryMeter`'s own independence from
       `explorationMeter`. `TestExplorerMaxWallTimeCancelsHangingRealRequest`
       drives a fixture endpoint that hangs for 5 seconds against a 50ms
       `MaxWallTime` and checks `Baseline` fails within ~2 seconds, not after
       waiting out the server's full delay.
    3. **`research/http_profile.go`'s `HTTPProfile` binds one
       `ExplorationScope` to exactly one HTTP origin.** `HTTPCollector` and
       `HTTPExecutor` were previously constructed independently, each taking
       its own `baseURL` — nothing stopped a caller from building them
       against two DIFFERENT origins and wiring both, plus an unrelated
       scope, into the same `Explorer` (e.g. `scopeHash = target-A` while
       `HTTPExecutor.baseURL = target-B`). `ExplorationScope`'s fields are
       deliberately abstract identifiers with no URL to literally validate
       an origin against — S10's frozen contract never gave them one — so
       the fix is structural: `NewHTTPProfile(scope, baseURL, path,
       actions)` is the ONE place a scope and an HTTP origin are ever
       paired, building both the `Collector` and the `Executor` from the
       SAME `baseURL` argument inside one constructor call, so they can
       never silently diverge. `TestNewHTTPProfileBuildsCollectorAndExecutorFromSameOrigin`
       pins the shape; the end-to-end test now wires through
       `profile.Scope()`/`profile.Collector()`/`profile.Executor()` rather
       than three independently constructed values.
  - **Design discipline to hold, not a fix:** `HTTPExecutor`'s
    `RegistryKey -> path` catalog must stay CODE-LEVEL FIXED for the
    lifetime of this design — never a value read from configuration, an
    environment variable, or (worst of all) something a candidate or LLM
    output could influence. `ActionID`'s meaning must never be reinterpreted
    after a policy has already authorized it; the whole chain
    (`ActionID` → an immutable executable catalog → a fixed `GET` path)
    depends on that staying true.
- **S10-E6 (`research/state_machine_producer.go`): the state-machine Candidate
  Producer — the first time S10's real `StateTransition`s feed the
  `Producer → Candidate → Validator → Engine` spine.** Scoped deliberately
  narrow, exactly as specified: answer ONLY "does a real observed
  `StateTransition` violate an explicit, pre-declared, authoritative
  expectation?", emit a `hypothesis` `Candidate` when it does, and stop —
  **no replay validator, no LLM judgment, and no new execution capability
  live in this file.** The core rule the whole design exists to enforce:
  `State A != State B` is never itself an anomaly; only
  `observed transition + explicit authorized expectation + deterministic
  comparison` is.
  - **`OriginStateMachine = "state_machine"`** is a new `Origin.Kind`,
    added to `research/candidate.go` beside `diff`/`fuzz`/`differential`/`ai`
    at the exact same level — a SOURCE label, never a higher-confidence
    marker.
  - **`TransitionCase` is the producer's per-observation input: just the
    observed `StateTransition`** (Explorer's own output) — it carries no
    `Expectation`/`ExpectationSource` of its own. What it is judged against
    is resolved INTERNALLY, from the producer's own `TransitionRuleRegistry`
    (below), by the transition's actual `(ActionID, ProjectorID)` pair.
  - **First regression, found on audit before freeze: v1's first cut let a
    caller pair ANY `TransitionExpectation`/`ExpectationSource` directly with
    ANY `TransitionCase`, checking only that the `ExpectationSource` was
    authoritative — never that it was the RIGHT expectation for the action
    that actually ran.** A legitimately spec-authored `Expectation` written
    for action A could be paired, at the call site, with a transition whose
    real `Action` was B, and nothing would catch the mismatch — an
    authoritative source is not the same guarantee as "this rule applies to
    this transition". Fixed: `TransitionRule{RuleID, ActionID, ProjectorID,
    Expectation, ExpectationSource}` plus `TransitionRuleRegistry` — a
    compile-time-only, closed set (the S10/E6 analogue of `actionauth.Registry`
    and S5's Validator registry) — is now the ONLY place an `Expectation` and
    `ExpectationSource` are ever paired. `NewStateMachineProducer(rules
    *TransitionRuleRegistry)` binds a producer to exactly one registry;
    `Produce`/`Analyze` resolve the ONE rule registered for a transition's own
    `Action.ID()` and `BeforeFingerprint.ProjectorID()` — never accept one
    supplied alongside the transition. No rule registered for that pair means
    no judgment at all (`TransitionInsufficientEvidence`, zero candidates) —
    covering both "no `ExpectationSource`" and "differing states with no
    declared expectation" from the original gate list, since both are now
    simply "nothing is registered for this action". `TestE6RuleRegisteredForOneActionNeverAppliesToAnother`
    proves the fix directly: a rule registered for action `action-a` never
    applies to a transition whose actual action is `action-b`, even with a
    status that would have violated `action-a`'s rule.
    `TestE6ZeroValueBoundActionRejectedEvenIfRuleRegisteredForItsID` and
    `TestE6AIOrLLMSourceRejectedEvenIfSomehowRegistered` prove defense in
    depth: `validate()` (below) still independently re-checks authority and
    authorization even for a rule the registry did resolve — a phantom rule
    mistakenly registered against the zero-value `ActionID`, or one built
    with a non-authoritative `ExpectationSource`, still produces nothing.
    `validate()` also newly requires both `BeforeFingerprint` and
    `AfterFingerprint` to have been produced by the SAME `ProjectorID` the
    rule itself names — a transition straddling two different state-authority
    models is rejected, never judged.
  - **`TransitionExpectation` is PLAIN DATA, never a callback.** The same
    declarative-not-closure lesson `actionauth.Registration.Requirements`
    already forced (a closure can silently capture anything — a candidate,
    an AI-authored predicate, a live reference — a fixed data shape cannot):
    a closed `TransitionExpectationKind` enum (`state_unchanged`,
    `fact_unchanged`, `fact_equals`, `fact_transition`) plus `Fact`,
    `BeforeValue`, `AfterValue` string fields is the entire vocabulary v1
    supports.
  - **Fact absence is never silently treated as an empty string.** Every
    `analyzeFact*` helper reads `value, ok := facts[key]` and returns
    `TransitionInsufficientEvidence` — never `TransitionViolated` — the
    instant a fact the rule needs is simply ABSENT. This is the same
    zero-false-positive discipline S9's boundary judgment already follows:
    absence of evidence must never manufacture a violation.
  - **Second regression, found on the same audit: `fact_transition`'s
    original v1 treated "before doesn't even match the declared BeforeValue"
    as a plain mismatch, collapsing it into the same `violated` bucket as an
    actual after-side deviation.** `fact_transition`'s own contract — "IF
    before==BeforeValue THEN after must==AfterValue" — is a rule with an
    explicit precondition; a transition that never started at BeforeValue
    isn't violating it, the rule simply never engaged. Treating every
    precondition-mismatch as a violation would flag every transition the
    rule was never written for. Fixed: `TransitionAssessment` grew a FOURTH
    state, `TransitionNotApplicable`, used ONLY by `analyzeFactTransition`.
    Its check order is precondition-first: `before` fact absent →
    `insufficient_evidence`; `before` present but `!= BeforeValue` →
    `not_applicable` (checked and returned BEFORE ever looking at `after` —
    so a precondition mismatch is decisive even if `after`'s fact happens to
    be absent for an unrelated reason); `before == BeforeValue` and `after`
    absent → `insufficient_evidence`; `before == BeforeValue` and `after !=
    AfterValue` → `violated`; both match → `satisfied`. Only `violated` ever
    produces a candidate. `TestE6FactTransitionPreconditionNeverHeldIsNotApplicable`
    pins the fix; `TestE6FactTransitionBeforeMissingIsInsufficientEvidenceNotNotApplicable`
    and `TestE6FactTransitionAfterMissingIsInsufficientEvidence` pin the two
    absence cases distinctly from it (the latter exercises the analyzer
    helper directly with two independently-projected real `Fingerprint`
    values, since both projectors this codebase has today populate a FIXED
    Facts key set regardless of content, making "present before, absent
    after" for the SAME key unreachable through Explorer's own validated
    path — the check is still real defensive code, proven correct in
    isolation).
  - **`TransitionAnomaly` is FACTS ONLY** — `Type`, `RuleKind`, `Fact`,
    `ExpectedBefore/After`, `ObservedBefore/After`, `EvidenceRefs`; no
    `Severity`/`Confidence`/`Exploitability`/`Vulnerable`/`Confirmed`/`State`
    field anywhere, and deliberately not called `Finding` — it is what the
    deterministic analyzer found, nothing about what it means.
    `StateMachineProducer.Produce` is the only thing that wraps it into a
    hypothesis `Candidate`, and it is kept BORING on purpose: resolve the
    registered rule → validate authority → hash the raw case artifact →
    analyze deterministically → take only `violated` → `NewHypothesis`. It
    never re-executes the action, re-collects state, calls an LLM, decides a
    validator, or promotes anything.
  - **Third regression, found on the same audit: nothing PROVED
    `transitionCaseArtifactHash` actually read through
    `stateauth.Fingerprint`/`actionauth.BoundAction`'s real fields rather than
    (say) silently hashing an opaque struct's zero-exported-field JSON
    (`"{}"`) — both types keep their real fields unexported specifically so
    no outside package can construct OR serialize them directly.** The
    original gate list only proved the hash was sensitive to `Expectation`
    and `ExpectationSource.ID`; it never independently proved sensitivity to
    `BeforeFingerprint`, `AfterFingerprint`, the action identity, or
    `ScopeHash` — exactly the fields most likely to be silently dropped by an
    unsafe serialization. `transitionCaseArtifactHash` already read every
    value through the correct exported accessor methods
    (`Fingerprint.ScopeHash/RawStateArtifactHash/StateFingerprintHash/
    ProjectorID/Facts`, `BoundAction.ID`) rather than `json.Marshal`-ing
    either opaque type — the audit asked for this to be PROVEN, not
    redesigned. Fixed by adding six direct, single-field-diff tests
    (`TestE6CaseArtifactHashChangesWhen{BeforeFingerprint,AfterFingerprint,
    ActionIdentity,ScopeHash,Expectation,ExpectationSourceID}Changes`), each
    holding every other field fixed and proving the hash moves. Provenance/
    hash discipline otherwise unchanged from the S8/S9 lossless-vs-denoised
    split: `StateTransition.TransitionArtifactHash` (Explorer's OWN record)
    is never what `Candidate.Provenance().RawInputHash` points at;
    `transitionCaseArtifactHash` — now covering the resolved `Transition` +
    `TransitionRule` pair, including `RuleID` — is. Both, plus
    `expectation_source_kind/id`, `expectation_kind`, `rule_id`, and
    `action_registry_key/variant_id`, are recorded in `Refs`.
  - **E6 registers no second "define correct behavior after the fact"
    escape hatch.** A `TransitionRule` must be registered BEFORE the
    `Explorer` session that produces the `StateTransition` it will be judged
    against ever runs — E6 has no code path that looks at an observed
    transition and invents what "should" have happened; that would be
    hindsight bias wearing a detection hat.
  - **Fourth regression, found on a THIRD audit round, closing the last gap
    before freeze: `NewTransitionRuleRegistry` accepted two DIFFERENT rules
    registered for the SAME `(ActionID, ProjectorID)` pair, silently letting
    the later one win via ordinary map assignment.** Which rule "won" for
    that pair would then depend on registration order — a slice-order/
    map-iteration-order dependency, never a deterministic authority — which
    would have made `lookup`'s "exactly one match" a convention callers were
    expected to follow, not a guarantee the registry itself enforced. Fixed:
    `NewTransitionRuleRegistry` now returns `(*TransitionRuleRegistry,
    error)` and REJECTS construction outright on: two rules sharing one
    `(ActionID, ProjectorID)` key; an empty `RuleID`; a `RuleID` reused by
    more than one rule; a non-authoritative `ExpectationSource`; or an
    invalid `TransitionExpectation` (an unknown `Kind`, or an empty `Fact`
    for a `Kind` that requires one) — via a new `TransitionExpectation.valid()`
    helper, also now reused by `resolvedTransitionCase.validate()` itself.
    A *successfully built* `*TransitionRuleRegistry` is therefore itself the
    proof that `(ActionID, ProjectorID) -> exactly one rule` holds for every
    entry it contains, not something `Produce`/`Analyze` have to hope is
    true. `validate()` still independently re-checks `ExpectationSource`
    authority and `BoundAction.ValidFor` at judgment time regardless
    (`TestE6ValidateItselfRejectsNonAuthoritativeSource` isolates that
    defense-in-depth layer directly, since a non-authoritative source can no
    longer reach it through the registry's own public constructor).
    `TestE6DuplicateActionProjectorPairRejectedAtRegistration`,
    `TestE6DuplicateRuleIDRejectedAtRegistration`, and
    `TestE6EmptyRuleIDRejectedAtRegistration` pin the three registration-time
    rejections; `TestE6RuleRegistryUnaffectedByMutatingCallersSliceAfterConstruction`
    proves a built registry is independent of the slice it was built from
    (every `TransitionRule` is range-copied by value into the registry's own
    map — it holds no pointers or slices, so nothing about it can alias the
    caller's original values) by mutating the caller's slice element AFTER
    construction and confirming the registry still resolves against the
    ORIGINAL rule. `Refs["rule_id"]` (recorded since the second audit round)
    now doubles as a genuinely unambiguous audit handle: a successfully
    built registry guarantees no two rules ever share one.
  - **`S10-E6 = FROZEN`** after this third audit round. 29-item freeze-gate
    battery (`research/state_machine_producer_test.go`), every fixture built
    through the REAL authority packages (`stateauth.HTTPFixtureRegistry()`/
    `stateauth.FixtureRegistry()` for `Fingerprint`, `actionauth.ActionPolicy.
    Select` for `BoundAction` — never a struct literal, since neither type
    can be constructed with a real identity from outside its own package):
    no rule registered → 0 candidates (covers both "no `ExpectationSource`"
    and "differing states with no declared expectation"); an
    `ai`/`llm`/`candidate`/`proposal`/`fuzz`/`diff`/`state_machine` source
    rejected AT REGISTRATION (plus `validate()`'s own independent
    defense-in-depth check, isolated directly); a rule registered for one
    action never applies to another action's transition; a zero-value
    `BoundAction`, even with a rule registered for its zero `ActionID` →
    reject; two rules sharing one `(ActionID, ProjectorID)` pair, a
    duplicate `RuleID`, or an empty `RuleID` → registration rejected; a
    registry is unaffected by mutating the caller's rule slice after
    construction; `state_unchanged` violated → exactly 1 hypothesis,
    satisfied → 0; `fact_unchanged` with an absent fact →
    `insufficient_evidence`; `fact_equals` satisfied → 0, violated → 1;
    `fact_transition` A→B as declared → 0 (`satisfied`), A→C → 1
    (`violated`), precondition never held → 0 (`not_applicable`),
    before/after fact absent → 0 (`insufficient_evidence`, distinct from
    `not_applicable`); a scope-inconsistent transition → reject; produced
    `Candidate.State` is always `Hypothesis`; `Provenance().RawInputHash`
    equals the resolved case hash and never equals `TransitionArtifactHash`
    alone; the case hash is stable across repeated calls; and the case hash
    independently changes when `BeforeFingerprint`, `AfterFingerprint`, the
    action identity, `ScopeHash`, `Expectation`, or `ExpectationSource.ID`
    alone changes. All 29 pass.
  - **v1 explicitly does NOT do:** a replay validator, LLM-based judgment of
    what counts as an anomaly, any new execution capability, auto-generating
    an `Expectation` from an observed transition, a `Check func(before,
    after) bool` callback, treating "fact absent" as `""`, letting a caller
    pair an `Expectation` with an unrelated transition, letting two rules
    ambiguously claim the same `(ActionID, ProjectorID)` pair or the same
    `RuleID`, or advancing a `Candidate` past `Hypothesis`. None of these
    have any code path in `research/state_machine_producer.go` today. A
    state-machine replay validator is explicitly deferred to a future stage.
- **S10-E7 (`research/state_machine_replay.go`): the state-machine Replay
  Validator — the first time an `OriginStateMachine` hypothesis is
  independently re-tested, closing `hypothesis → reproducible` for real.**
  Scoped exactly as specified: replay the SAME authorized rule, in a
  genuinely FRESH session, against the SAME target — one action, no new
  exploration capability, no state preparation, and it never Promotes.
  - **E6 grew three small, additive fields to make E7 possible — nothing
    about E6's own frozen behavior changed.** `StateTransition` itself
    carries only an opaque `ScopeHash`, with no recoverable
    `TargetID`/`BuildID`/`Protocol`/`HarnessID` a later replay validator
    could check a target's identity against. `TransitionCase` therefore
    grew a `Scope ExplorationScope` field (the exact scope a transition was
    collected under), and `resolvedTransitionCase.validate()` grew ONE more
    check: `Scope.Hash() == Transition.ScopeHash` — proving the claimed
    Scope actually IS the one that produced this ScopeHash, so a caller
    cannot pair a real transition with a fabricated Scope. `Produce`'s
    `Refs` gained `projector_id` and `replay_target_hash` (the new
    `ReplayTarget` type's own `Hash()` — `TargetID`/`BuildID`/`Protocol`/
    `HarnessID`, DELIBERATELY WITHOUT `SessionID`), and
    `transitionCaseArtifactHash` now covers every Scope field losslessly.
    `TransitionRuleRegistry` gained `LookupByRuleID` (a second index,
    populated at construction, alongside the existing `(ActionID,
    ProjectorID)` index) — E7's actual entry point into a trusted registry.
    All 29 existing E6 tests still pass against real fixtures rebuilt with a
    real `ExplorationScope` (`e6ScopeHash` is now `ExplorationScope{...}.Hash()`,
    never an arbitrary literal string) — 3 new tests
    (`TestE6FabricatedScopeRejected`, `TestE6LookupByRuleIDResolvesRegisteredRule`,
    `TestE6CaseArtifactHashChangesWhenScopeChanges`) plus one Refs-completeness
    assertion cover the additions themselves. `research/explorer.go`'s
    `collectAndProjectLocked` was also extracted into a package-level
    `collectAndProject` (pure refactor, all Explorer tests still pass
    unchanged) so a replay session — which has no `Explorer` instance of its
    own — turns evidence into a `Fingerprint` through the exact SAME
    scope-checked path, never a hand-rolled shortcut.
  - **INDEPENDENT EVIDENCE, never old data.** `Replay` treats a Candidate's
    identity purely as "what to test" — never as evidence itself. Every fact
    a `ValidationResult` reports comes from a FRESH `collectAndProject` call,
    a FRESH authorized action bind, and a FRESH `Execute`, through the SAME
    `Collector`/`stateauth.BoundRegistry`/`Executor` triple a real Explorer
    session would use.
  - **First regression, found on a second audit round before freeze: rule
    authority was substituting for action authority.** v1's first cut
    resolved the trusted rule, then bound `rule.ActionID` by building its
    OWN throwaway, single-entry `actionauth.Registry`/`ActionPolicy` scoped
    to exactly that key — which meant `TransitionRuleRegistry` (whose job is
    defining what a transition is judged AGAINST) was effectively also
    deciding whether an action may execute RIGHT NOW, a decision that
    belongs to `actionauth.ActionPolicy` alone, per S10's own original
    separation of authorities. Fixed: `NewStateMachineReplayValidator` now
    takes a `*actionauth.ActionPolicy` — the SAME trusted policy a real
    Explorer session for this target would use — and `Replay` calls
    `v.policy.Select(scope.Hash(), before, nil)` against the FRESH baseline,
    exactly like `Explorer.Step`. It proceeds ONLY if the policy's own
    selection happens to equal `rule.ActionID`; if `Select` returns nothing
    applicable, or a DIFFERENT action, `Replay` reports `OutcomeNoSignal` and
    executes NOTHING — it never falls back to forcing `rule.ActionID`
    through a registry it built for itself. A rule never grants an execution
    credential on its own; only the policy that would have authorized it
    during real exploration does. `TestE7ActionPolicySelectsDifferentActionProducesNoSignal`
    (a policy that would select a different, equally-applicable action) and
    `TestE7ActionPolicySelectFailsProducesNoSignal` (nothing applicable at
    all) both prove `Replay` executes nothing in either case, via the
    fixture's own action-hit counter staying unchanged.
  - **Second regression, found on the same audit: `Replay` resolved its
    authority-bearing identity (`rule_id`, action/projector identity, the
    target hash) from `Candidate.Refs` — an ORDINARY, MUTABLE map any caller
    holding `*Candidate` can rewrite after construction.** Even with every
    individual rule trustworthy, a caller could retarget a replay to a
    DIFFERENT — still individually trusted — rule after E6 had already
    produced the Candidate, simply by editing `Refs["rule_id"]` in place;
    Refs was never meant to be authority (`Refs`'s own doc already said so),
    but nothing stopped `Replay` from treating it as such. Fixed:
    `Candidate` gained an unexported `stateMachineBinding
    *StateMachineBinding` field, settable only by
    `StateMachineProducer.Produce` (this package's own S10/E6 code — there
    is no exported setter, matching exactly how `provenance` is already
    unexported), and a new `StateMachineBinding{RuleID, ActionID,
    ProjectorID, ReplayTargetHash, CaseArtifactHash}` accessor type whose
    only constructor is `Candidate.StateMachineBinding()`, returning a VALUE
    COPY (all plain strings and an `actionauth.ActionID` — no pointers,
    slices, or maps to alias). `Replay` now resolves EXCLUSIVELY from this
    binding; `Refs` is kept, unchanged, for human-readable audit convenience
    only, and is provably irrelevant to resolution:
    `TestE7RefsMutationDoesNotAffectReplayResolution` corrupts every
    replay-relevant `Refs` entry after a real Candidate is produced and
    proves `Replay` still resolves and reproduces correctly regardless.
    `TestE7MissingBindingRejected`/`TestE7EmptyRuleIDInBindingRejected` cover
    the (never reachable via `Produce`, kept as real defensive checks)
    missing/malformed-binding cases; `TestE7ActionMismatchRejected`/
    `TestE7ProjectorMismatchRejected` now prove the cross-check against a
    validator whose OWN trusted registry has since diverged from the one
    that produced the candidate — a realistic scenario Refs mutation never
    was.
  - **Third regression, same audit: no post-replay recovery semantics were
    specified for an action that might not truly be side-effect-free** —
    first fixed by giving `TransitionRule` a `ReadOnlyAction bool` field,
    the rule AUTHOR's own attestation. **Fourth regression, found on a THIRD
    audit round: that field put the safety attestation in the wrong
    authority.** S10's whole design already separates "what to expect"
    (`TransitionRuleRegistry`) from "what may execute, and how safely"
    (`actionauth`'s Registry/`ActionPolicy`) — `TransitionRule.ReadOnlyAction`
    let RULE authority vouch for ACTION safety, meaning a rule author could
    in principle write `TransitionRule{ActionID: <an action with real side
    effects>, ReadOnlyAction: true}` and have `Replay` take their word for
    it. Fixed: **`ReadOnlyAction` is REMOVED from `TransitionRule` entirely**
    (not merely deprecated). `internal/actionauth` gained the authority
    instead: a new `ActionSafety` type (`ActionStrictReadOnly`/
    `ActionReversible`) replaces the old, NEVER-actually-checked
    `RegisteredAction.Reversible bool` (exactly the "unenforced field is
    worse than no field" lesson this codebase already learned once);
    `Registration`/`RegisteredAction` declare it once, at registry-build
    time; `ActionPolicy.Select` stamps the MATCHED registration's own
    `Safety` onto the `BoundAction` it returns
    (`BoundAction.Safety()`) — read from the SAME immutable registry that
    decided the action was applicable at all, never supplied by a caller of
    `Select` or by anything a `TransitionRule` declares about itself.
    `Replay` now checks `boundAction.Safety() ==
    actionauth.ActionStrictReadOnly` on the FRESH `BoundAction` its own
    trusted `v.policy.Select` just produced (`ErrReplayActionNotReadOnly`
    unchanged as the error, `TestE7NonReadOnlyActionRejected` rebuilt around
    a policy whose "deny" registration declares `ActionReversible` instead).
  - **Fifth regression, same third audit round: "the policy's own selection
    happens to equal `rule.ActionID`" (E7-A, above) is necessary but not
    sufficient — two DIFFERENT `ActionPolicy` instances (one permissive, one
    strict) could still agree on an `ActionID` for the same state by pure
    coincidence, which would let a caller wire a weaker policy into a
    replay validator without `Replay` ever noticing.** Fixed:
    `ActionPolicy` gained `PolicyID()` — a deterministic identity computed
    once, at construction, over its own registry's ENTIRE canonical content
    (every registered action's Key, `Safety`, and `StateRequirements`,
    sorted) — and `BoundAction.PolicyID()`, stamped by `Select` from that
    same value. `StateMachineBinding` (E6) gained a `policyID` field,
    recorded from `rc.Transition.Action.PolicyID()` at `Produce` time (also
    added to `Refs["policy_id"]` for human audit, and to
    `transitionCaseArtifactHash` alongside a new `action_safety` line —
    both purely additive to the already-lossless hash). `Replay` now checks
    `v.policy.PolicyID() == binding.PolicyID()`
    (`ErrReplayPolicyMismatch`) BEFORE any I/O, alongside the other identity
    checks — not merely "same ActionID selected", but "the same
    action-authority semantics selected it".
    `TestE7PolicyMismatchRejected` proves the rejection (and that it costs
    no real request — the fixture's own action-hit counter stays
    unchanged); `internal/actionauth/policy_test.go` gained five focused
    unit tests at the primitive's own level
    (`TestActionPolicyIDStableForIdenticalRegistryContent`,
    `TestActionPolicyIDChangesWhenRegistryContentChanges`,
    `TestActionPolicyIDUnaffectedByRecoveryRegistry`,
    `TestSelectStampsSafetyAndPolicyIDFromMatchedRegistration`,
    `TestZeroValueBoundActionHasEmptySafetyAndPolicyID`) before ever relying
    on it from `research`. The E7-A action-authority tests
    (`TestE7ActionPolicySelectsDifferentActionProducesNoSignal`/
    `TestE7ActionPolicySelectFailsProducesNoSignal`) needed rebuilding too,
    now that ANY registry content difference also changes `PolicyID`:
    both use one SHARED, unchanged policy with two `status`-fact-gated
    registrations (`deny` when `status=="200"`, `aaa-other-action` when
    `status=="403"`), so the SAME `PolicyID` genuinely selects a different
    (or no) action purely because the FRESH baseline's own facts differ
    from the original's — never because the policy itself changed.
  - **Sixth regression, found on a FOURTH audit round: `PolicyID` (Key +
    `Safety` + `StateRequirements` only) proved "same ActionID selected AND
    same PolicyID" was still not sufficient — it says nothing about WHAT
    ACTUALLY EXECUTES for a RegistryKey. Two Executor implementations/
    versions could agree on Key/Safety/Requirements (and therefore on
    `PolicyID`) while performing genuinely different real-world operations
    (e.g. `GET /health` vs `GET /admin/status`), which would have made
    "PolicyID matches" a false proof of "same action-authority semantics".**
    Fixed: `actionauth.RegisteredAction` gained `SpecID string` — a stable
    identity for the actual executable spec, declared by whoever registers
    the action, alongside `BoundAction.specID`/`SpecID()`, stamped by
    `Select` from the same matched registration and folded into
    `Registry.canonicalHash()`'s per-action serialization (so `PolicyID`
    now covers `ActionID + SpecID + Safety + StateRequirements`, exactly
    the composition asked for). `HTTPActionSpecID(path string) string`
    (`research/http_executor.go`) canonicalizes "a read-only GET to path,
    redirects refused, no body" (`http_action_v1\nmethod=GET\npath=<path>\n
    redirect=disabled\nbody=none`, SHA-256'd via the same `RawInputHash`
    every other producer uses); `HTTPExecutor.Execute` independently
    RE-VERIFIES `action.SpecID()` against `HTTPActionSpecID` for the path
    its OWN fixed map resolves for that RegistryKey, BEFORE issuing any
    request, and refuses on any mismatch — never trusting the registry/
    policy side's declared `SpecID` as sufficient on its own, the same
    defense-in-depth discipline as `ValidFor`. This check deliberately
    lives ONLY in the concrete Executor (documented as a REQUIRED
    independent re-verification on the `research.Executor` interface in
    `explorer.go`) — neither `Explorer` nor `Replay` pre-check it
    themselves, since only the concrete Executor knows what its own
    "correct" SpecID actually is.
    `TestHTTPExecutorRefusesSpecIDMismatch` (`research/http_e5_test.go`)
    proves a real request never reaches the network on a mismatch, mirroring
    `TestBudgetedRoundTripperFailsClosedWithoutMeter`'s style;
    `TestSelectStampsSpecIDFromMatchedRegistration` and
    `TestActionPolicyIDChangesWhenSpecIDChanges`
    (`internal/actionauth/policy_test.go`) prove the primitive itself.
    `StateMachineBinding` (E6) gained a `specID` field (recorded from
    `rc.Transition.Action.SpecID()` at `Produce` time, purely for evidence
    traceability — a `PolicyID` mismatch already implies a `SpecID`
    mismatch, since `SpecID` is now folded into it), plus
    `Refs["action_spec_id"]` and an `action_spec_id=` line in
    `transitionCaseArtifactHash`; `replaySummaryObservation` gained an
    `action_spec_id` artifact. Every `HTTPExecutor`-backed test registration
    (`research/http_e5_test.go`'s `get-root`/`get-health`,
    `research/state_machine_replay_test.go`'s `deny`/`aaa-other-action`) now
    sets a matching `SpecID`, since `Execute` fails closed without one.
  - **Seventh regression, same fourth audit round: even with byte-identical
    registry data, a future change to `StateRequirements.matches`'s own
    comparison, `Select`'s selection/sort order, or its fail-closed
    behavior would change what a registry actually AUTHORIZES without
    changing a pure data-hash `PolicyID` at all — silently letting an old
    binding and a new one claim "the same policy" across a semantics
    change.** Fixed: `actionauth.ActionPolicySemanticsVersion =
    "action-policy-v1"` is now the FIRST line hashed by
    `Registry.canonicalHash()`, so any future deliberate change to
    matching/selection/fail-closed semantics is forced to bump it (to
    `"action-policy-v2"`, and so on), which changes every `PolicyID`
    derived from it. `TestActionPolicySemanticsVersionIsFoldedIntoPolicyID`
    pins the current frozen value so an accidental edit is caught as a test
    failure, not a silent behavior change.
  - **Fresh session, same target, never a substituted one.** `ReplayTarget`
    (`TargetID`/`BuildID`/`Protocol`/`HarnessID`, no `SessionID`) is fixed at
    a validator's construction; each `Replay` call takes a caller-supplied
    `sessionID` and builds the full `ExplorationScope` from
    `target.Scope(sessionID)`. `Replay` rejects a Candidate whose
    `StateMachineBinding().ReplayTargetHash()` does not match
    `v.target.Hash()` (`ErrReplayTargetMismatch`) — proven by
    `TestE7TargetMismatchRejected`; `TestE7ViolatedProducesReproducedWithIndependentEvidence`
    proves the positive case with a session ID that is deliberately
    DIFFERENT from the original transition's own.
  - **No state preparation.** If `ExpectFactTransition`'s own precondition
    does not hold against the FRESH baseline, `Replay` stops immediately
    with `OutcomeNoSignal` — it never runs an extra action to force it to
    hold. `TestE7PreconditionNotMetProducesNoSignalWithoutExecutingAction`
    proves this against a REAL server: the fixture's own action-hit counter
    stays at exactly 1 (the original run) after the replay attempt, never 2.
  - **Outcome mapping is conservative by construction, not by convention.**
    `replayOutcomeFor` (a pure, no-I/O function, unit-tested directly via
    `TestE7ReplayOutcomeMapping` across all four `TransitionAssessment`
    values plus an unrecognized one) is the ONLY place an assessment becomes
    an `Outcome`: `satisfied`/`not_applicable` → `no_signal`; `violated` →
    `reproduced` (the ONLY assessment that is ever a signal);
    `insufficient_evidence`, or anything unrecognized → `Replay` returns an
    ERROR, never silently upgrading "we don't know" into "no signal" (which
    would misreport incomplete validation as a checked-and-clean result).
  - **Same E5 safety boundaries, no exceptions, because it is the SAME
    code.** `Replay` uses the SAME `Collector`/`Executor` implementations
    (and therefore the SAME `BudgetedRoundTripper`, fail-closed-without-a-
    meter, redirect-refusal, and body-size cap already proven in S10-E5/
    hardening) through the SAME `collectAndProject` path — never a parallel,
    less-audited code path. `ReplayBudget{MaxRequests, MaxWallTime}` is its
    OWN independent budget (both fields strictly positive, the same "no
    zero-means-unlimited" discipline as `ExplorationBudget`) — deliberately
    with no `MaxDepth`/`MaxStates`/`MaxVisitsPerState`/`MaxBranching`, since
    v1 replays exactly one already-authorized action, once, never branching
    or looping. `TestE7RequestBudgetExhaustedIsError` (a full replay needs 3
    real requests; `MaxRequests=2` must fail on the third) and
    `TestE7WallTimeTimeoutIsError` (a real hanging endpoint, cut short well
    under its 5s delay) prove both bounds are real against real I/O, exactly
    like the analogous S10-E5 hardening tests. Redirect-refusal and the body
    cap are inherited structurally (same `HTTPCollector`/`HTTPExecutor`
    types S10-E5 already proved these for) rather than re-tested per
    mechanism through this one more layer.
  - **`Replay` never Promotes.** It returns a `ValidationResult` — the
    Engine's own input — and nothing else; `Candidate.State` is asserted to
    still be exactly `Hypothesis` immediately after a `Replay` call that
    returned `OutcomeReproduced`
    (`TestE7ViolatedProducesReproducedWithIndependentEvidence`). Wiring a
    replay's `ValidationResult` into the Engine's existing
    `shouldPromote`/`Promote` pipeline (S5's `Engine.Validate` already owns
    that decision generically) is future work, not required to prove this
    stage's own contract.
  - **20-item freeze-gate battery** (`research/state_machine_replay_test.go`),
    plus 8 focused unit tests on the `PolicyID`/`Safety`/`SpecID` primitive
    itself in `internal/actionauth/policy_test.go`, plus a dedicated
    `HTTPExecutor` SpecID-mismatch test in `research/http_e5_test.go`: a
    non-`OriginStateMachine` Candidate, a missing/malformed binding, a
    `rule_id` unregistered in this validator's own registry, a diverged
    action/projector identity, a mismatched target, a mismatched
    `PolicyID`, an action whose FRESH `Safety` is not
    `ActionStrictReadOnly`, and an empty `sessionID` are all rejected before
    any I/O; Refs corruption (now including `policy_id` and
    `action_spec_id`) is proven irrelevant to resolution; a SHARED,
    unchanged policy that genuinely selects a different (or no) action for
    a different fresh baseline never falls back to the rule's own
    `ActionID`; a real fresh baseline that doesn't satisfy
    `fact_transition`'s precondition produces `no_signal` without ever
    executing the action; a real fresh replay that satisfies the rule
    produces `no_signal`; a real fresh replay that violates the rule again
    produces `reproduced`, with Evidence proven to carry fresh before/after
    fingerprints plus a `replay_summary` whose `rule_id`/`projector_id`/
    `action_registry_key`/`policy_id`/`action_spec_id`/`action_safety`/
    `assessment`/`request_count` all match expectations, a
    `replay_case_artifact_hash` provably distinct from the original
    Candidate's own `CaseArtifactHash()`, and a Candidate left at exactly
    `Hypothesis`; a real `HTTPExecutor` proven to refuse (before any request
    reaches the network) a `BoundAction` whose `SpecID` doesn't match its
    own registered spec for the resolved path; the pure outcome-mapping
    table is proven for all four assessments plus an unrecognized one; a
    real request-budget exhaustion and a real wall-time timeout both fail
    as errors; and construction itself rejects a nil dependency or an
    invalid `ReplayBudget`. All pass, every fixture built through the REAL
    E6 pipeline (a real `StateMachineProducer.Produce` against a real
    transition observed over real HTTP) rather than a hand-built Candidate.
  - **v1 explicitly does NOT do:** state preparation to satisfy a
    precondition, trusting `Candidate.Refs` for any authority decision,
    letting a rule's own `ActionID` (or any field a `TransitionRule`
    declares about itself) substitute for `actionauth`'s authority over
    what may execute or how safely, replaying an action whose FRESH
    `Safety` is not `ActionStrictReadOnly`, replaying under a differently-
    identified `ActionPolicy` (by content, executable spec, OR semantics
    version) than the one that originally authorized the action, executing
    an action whose `SpecID` the concrete Executor cannot independently
    verify against its own wiring, replaying against the same recorded
    session, LLM judgment of what counts as reproduction, any new
    exploration capability, or Promoting a Candidate itself. None of these
    have any code path in `research/state_machine_replay.go` today.
  - **`S10-E7 = FROZEN`** after this fourth audit round. The final Evidence-
    traceability set an `OutcomeReproduced` `ValidationResult` carries is
    now: `rule_id`, `action_id` (`action_registry_key`/`action_variant_id`),
    `action_spec_id`, `policy_id`, before fingerprint, after fingerprint,
    replay scope/session (`replay_target_hash`/`replay_scope_hash`),
    `assessment=violated`, and the replay's own `replay_case_artifact_hash`
    — every one of them read from the FRESH `BoundAction`/`Fingerprint`s
    this Replay attempt itself produced, never from the original
    Candidate's own recorded copies. The next stage — wiring
    `OutcomeReproduced` and its fresh Evidence into the Engine's existing
    `shouldPromote`/`Promote` pipeline to complete `hypothesis → independent
    replay → reproducible` — is deliberately NOT part of this pass; no
    further expansion of Replay's own architecture is needed to get there.
- **Deferred:** `S7` large-scale source audit — the local-model signal-to-noise on
  a whole repo is lower than the diff/fuzz/differential sources already built.
  Wiring S10-E7's `ValidationResult` into the Engine's existing promotion
  pipeline, and any future state-preparation capability, are both deferred —
  each needs its own explicit, separately reviewed design.

Four independent unknown-issue sources now feed the plane: **patch difference
(S6), crash behavior (S8), runtime differential (S9), state-machine transition
(S10/E6)** — all deterministic producers on the one
`Producer → Candidate → Validator → Engine` spine. S10/E6+E7 together are the
first of the four to run a hypothesis all the way to an independently
reproduced result: `Explorer → StateTransition → TransitionRule →
Candidate(hypothesis) → Replay Validator(fresh session) →
ValidationResult{reproduced}` — the AI stays a producer (or, later, an
explainer positioned strictly AFTER this point), never the authority that
decides reproduction.

Every source is a new `Origin.Kind` feeding the one spine
`Producer → Candidate → Registered Validator → ValidationResult → Engine → state`.
The LLM stays one producer, never the engine.
