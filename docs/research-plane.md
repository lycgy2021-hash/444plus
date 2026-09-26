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
  (`research/state_machine.go`) — no explorer, no registry, no execution logic,
  no `Origin` kind yet. Five boundaries are locked into the TYPE SHAPES
  themselves (not left to comments alone), because a boundary a later change can
  route around by adding one field is not a boundary:
  1. **No executable content anywhere.** `ActionRef{RegistryKey, VariantID}` and
     `RecoveryPlanRef{RegistryKey}` are opaque lookups — there is no Method, URL,
     Headers, Body, or Command field in this file. What an action or recovery
     procedure actually does exists only in a future compile-time registry (the
     S10 analogue of S5's Validator registry); AI or candidate text can at most
     name a `RegistryKey`/`VariantID` to try, never supply what it does.
     `RegisteredAction.Reversible` is registry metadata, declared once by the
     registering code — not a field any instance, candidate, or AI output can set.
  2. **Raw evidence vs identity, never conflated** (the S8/S9 discipline again):
     `StateFingerprint` splits `RawStateArtifactHash` (the actual collected
     artifact, undenoised) from `StateFingerprintHash` (the denoised projection
     state-equality is judged on); `ExplorationScope.Hash()` (target+build+
     session+protocol+harness) bounds which fingerprints are even comparable —
     there is no method to compare across scopes.
  3. **Recovery is registry-backed and must be VERIFIED, never assumed.**
     `RecoveryOutcome{Baseline, ResultFingerprint, Verified}` is a fact: did the
     post-recovery fingerprint actually match baseline. `Verified=false` means
     exploration stops — there is no continuing on the assumption a rollback
     worked.
  4. **`StateTransition` carries facts only** — no `Unexpected`/`Vulnerable`/
     `Severity`/`State` field, exactly like `Observation`/`DiffAnomaly`
     elsewhere. Whether a transition is worth a hypothesis is a future
     producer's judgment against an authoritative `ExpectationSource` — **S9's,
     reused verbatim, no second "who defines correct behavior" system for S10**.
     `TransitionArtifactHash` is the lossless record hash (the S9
     `caseArtifactHash` analogue); it is never the denoised
     `StateFingerprintHash`.
  5. **No "0 = unlimited" in `ExplorationBudget`**, unlike `ai.Budget` (where
     unlimited is a cost tradeoff for a free local model). Unbounded state
     exploration is a live-system risk, not a cost concern: every one of
     `MaxStates/MaxTransitions/MaxDepth/MaxRequests/MaxVisitsPerState/
     MaxBranching/MaxWallTime` must be strictly positive or `Valid()` reports the
     whole budget invalid.
  One v1 rule has no corresponding type, since it constrains execution behavior
  rather than data shape: within one `ExplorationScope`, v1 is **single-session,
  serial** — at most one in-flight action at a time, so "which action produced
  this `AfterFingerprint`" is never ambiguous. Recorded here for the eventual
  Explorer to honor.
- **Deferred:** `S7` large-scale source audit — the local-model signal-to-noise on
  a whole repo is lower than the diff/fuzz/differential sources already built.

Three independent unknown-issue sources now feed the plane: **patch difference
(S6), crash behavior (S8), runtime differential (S9)** — all deterministic
producers on the one `Producer → Candidate → Validator → Engine` spine.

Every source is a new `Origin.Kind` feeding the one spine
`Producer → Candidate → Registered Validator → ValidationResult → Engine → state`.
The LLM stays one producer, never the engine.
