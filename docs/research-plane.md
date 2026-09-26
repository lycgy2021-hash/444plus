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

**Provenance (lineage, locked before S6/S8)** — `research/evidence.go` defines an
immutable `Provenance{ProducerKind, ProducerID, Tool, Timestamp, InputHash}` set
once at birth on both `Evidence` and `Candidate`. `InputHash` (SHA-256 of the
exact input — the evidence bundle, the diff blob, the crash) ties a candidate to
what produced it; combined with the append-only `History` (each `Promote` records
its validator + evidence refs + time) and content-addressed evidence, the full
lineage `diff → AI → validator → reproduced` is answerable and tamper-evident:
where it came from, which input, which validator, and whether evidence was later
swapped.

**S6 v1 — `research/diff.go`** — the first non-AI producer: a deterministic
`DiffProducer` reads a unified git diff and classifies security-relevant ADDED
changes (`added_bounds_check`, `added_auth_check`, `added_canonicalization`,
`added_type_validation`, `added_length_validation`, `dangerous_api_replaced`,
`added_reject_path`) into hypothesis candidates tagged `Origin{Kind: "diff"}`.
They flow into the **same** Registry → Validator → Engine spine; with no diff
validator registered yet they correctly stay `hypothesis` (no second pipeline, no
auto-promotion). An AI diff pass can later enrich these candidates, never replace
the deterministic classification.

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
- **S6 (patch/diff intelligence): v1 landed** (deterministic `DiffProducer`; an AI
  diff pass can enrich later).
- **S8 (fuzz/crash intelligence): next** — v1 stays small: fuzzer output → crash
  normalization → stack hash → dedup → security-interesting classification →
  `Candidate{Origin{Kind:"fuzz"}}`. The fuzz engine discovers; the LLM only
  understands/classifies — no LLM-generated fuzz inputs yet.
- **Deferred:** `S7` large-scale source audit, `S9` differential engine, `S10`
  state-machine explorer — not until S6/S8 are stable.

Every source is a new `Origin.Kind` feeding the one spine
`Producer → Candidate → Registered Validator → ValidationResult → Engine → state`.
The LLM stays one producer, never the engine.
