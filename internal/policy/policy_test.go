package policy

import (
	"gopoc/internal/model"
	"testing"
)

func TestAllowlistUsesExactOriginsHostsAndLiteralCIDRs(t *testing.T) {
	p, err := New(model.ModePassive, []string{"https://exact.test:8443", "host.test", "192.0.2.0/24", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	for raw, allow := range map[string]bool{
		"https://exact.test:8443": true, "http://exact.test:8443": false,
		"https://exact.test": false, "http://host.test:8080": true,
		"http://sub.host.test": false, "http://host.test.evil.test": false,
		"http://192.0.2.50": true, "http://192.0.3.50": false,
		"http://[::1]": true, "http://[::2]": false,
	} {
		target, err := model.ParseTarget(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.CheckTarget(target) == nil; got != allow {
			t.Errorf("%s allowed=%v, want %v", raw, got, allow)
		}
	}
	for _, entry := range []string{"", "*.test", "https://host/path", "host:8080", "192.0.2.0/33"} {
		if _, err := New(model.ModePassive, []string{entry}); err == nil {
			t.Errorf("invalid allowlist accepted: %s", entry)
		}
	}
}

func TestCapabilitiesFailClosed(t *testing.T) {
	for _, mode := range []model.Mode{model.ModePassive, model.ModeActiveCanary} {
		p, _ := New(mode, nil)
		if p.CheckCapabilities(model.CapPassive|model.CapHTTPGet) != nil {
			t.Fatal("passive denied")
		}
		for _, cap := range []model.Capability{0, model.CapCommandExecution, model.CapStateChange, model.Capability(1 << 40)} {
			if p.CheckCapabilities(cap) == nil {
				t.Fatalf("capability %d accepted", cap)
			}
		}
		if got := p.CheckCapabilities(model.CapCanaryRead) == nil; got != (mode == model.ModeActiveCanary) {
			t.Fatal("incorrect canary capability")
		}
	}
}
