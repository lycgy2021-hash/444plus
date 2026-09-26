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
    way an action gets chosen: it walks the registry's own COMPILE-TIME
    `Registration{Action, Supports func(stateauth.Fingerprint) bool}`
    entries — `Supports` is Go code written by whoever builds the registry,
    never data, never something an AI/candidate can supply — collects the
    RegistryKeys that are both applicable (`Supports(fp)==true`) and not
    already in `exclude`, sorts them, and binds the first one. "Registered !=
    Allowed" is now a real, enforced relationship, not a slogan: being in the
    registry only means the key exists; `Supports` is what makes it
    APPLICABLE to a specific state. `exclude` is FACTS Explorer supplies
    (which action keys have already been tried from this exact
    `StateFingerprintHash`) — never a decision; v1 deliberately does not wire
    any AI-authored suggestion into `Select` at all, not even as an advisory
    tie-breaker. `TestExplorerStepSelectionIsDeterministicNotCallerChosen`
    proves two independently constructed Explorers, given identical
    scope/collector/policy, select the identical action — the choice comes
    entirely from (scope, state, registry), never from a caller.
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
    became true. `MaxBranching` still has no runtime check — v1 never branches
    at all (`Select` always picks at most one action), so there is nothing for
    it to bound yet; it stays reserved for a future multi-branch Explorer.
  - **Recovery failure is a permanent stop, proved by test:**
    `TestExplorerRecoverySuccessAndFailure/failure_stops_exploration` drives a
    `Recover` call whose re-collected state does not match the baseline and
    checks that every subsequent `Step` and `Recover` call is refused with
    `ErrExplorerStopped`.
  - **`RawLenProjector`** is the first concrete `StateProjector` — deliberately
    minimal (one fact, the raw byte length), proving the contract end-to-end
    without claiming to model any real protocol's state. It is a fixture/test
    projector, not meant to carry real security-research weight (two
    responses of identical length can differ completely, e.g. an
    `admin=false`/`admin=true` flip) — a real protocol-specific projector
    (status, content-type, stable headers, auth state, body structural shape)
    is future work and must live inside `internal/stateauth` for the same
    reason `RawLenProjector` does.
  - **v1 explicitly does NOT do:** concurrent actions, multiple sessions, AI
    action selection (now closed at the API level, not just by convention —
    `Step` has no parameter to carry one), AI-generated network requests,
    dynamic registry / hot reload, irreversible actions, exploration without a
    recovery check, "different state = vulnerability", automatic
    exploitability judgment, or unlimited depth/budget. None of these have any
    code path in `research/explorer.go` today.
- **Deferred:** `S7` large-scale source audit — the local-model signal-to-noise on
  a whole repo is lower than the diff/fuzz/differential sources already built.

Three independent unknown-issue sources now feed the plane: **patch difference
(S6), crash behavior (S8), runtime differential (S9)** — all deterministic
producers on the one `Producer → Candidate → Validator → Engine` spine.

Every source is a new `Origin.Kind` feeding the one spine
`Producer → Candidate → Registered Validator → ValidationResult → Engine → state`.
The LLM stays one producer, never the engine.
