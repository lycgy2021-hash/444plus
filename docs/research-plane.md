# AI Research Plane (S1–S5)

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
- **Four hashes, never mixed.** `TestcaseHash` (crashing input bytes),
  `CrashOutputHash` (raw crash output), `SignatureHash` (normalized type + access
  + top stable frames — the fingerprint), `GroupHash` (`ScopeHash + SignatureHash`
  — the group identity). A fuzz candidate's `Provenance.RawInputHash` is the
  **GroupHash** (the whole producing group), and structured `Refs`
  (scope/signature/group hashes, count, type) make it queryable — not just prose.
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
- **S8 (fuzz/crash intelligence): v1 landed + audited** (deterministic
  `FuzzProducer`; scope-bounded groups, discriminating signatures, four-hash
  group-level provenance, structured refs, conservative classifier). No AI
  fuzz-input generation, no auto-exploitability. Ready to freeze.
- **Deferred:** `S7` large-scale source audit, `S9` differential engine, `S10`
  state-machine explorer — not until S6/S8 are stable.

Every source is a new `Origin.Kind` feeding the one spine
`Producer → Candidate → Registered Validator → ValidationResult → Engine → state`.
The LLM stays one producer, never the engine.
