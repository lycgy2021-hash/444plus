package ai

import "context"

// Provider is the single seam between the Go program and any model backend. A
// local Qwen/Gemma on vLLM, llama.cpp or KoboldCpp, an Ollama OpenAI-compatible
// endpoint, or a cloud model are all just Providers; nothing above this
// interface knows or depends on which one answered.
//
// Analyze reasons over the request and returns proposals plus missing-evidence
// notes. It must never be treated as authoritative: its result becomes, at most,
// hypothesis-level research candidates, and only a deterministic validator can
// advance those. A Provider must honor context cancellation and stay within any
// budget it was constructed with.
type Provider interface {
	// Name identifies the provider for provenance (e.g. "openai-compat:qwen2.5").
	// It is recorded on every AI-suggested candidate so an AI origin is always
	// visible and never mistaken for authority.
	Name() string
	Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error)
}
