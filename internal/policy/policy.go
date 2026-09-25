package policy

import (
	"fmt"
	"net/netip"
	"strings"

	"gopoc/internal/model"
)

type Policy struct {
	Allowed model.Capability
	origins map[string]bool
	hosts   map[string]bool
	nets    []netip.Prefix
}

// Empty allowlist entries mean the explicit input targets define the scope.
// Entries may further narrow that scope to exact origins, hosts, IPs or CIDRs.
func New(mode model.Mode, entries []string) (*Policy, error) {
	// TCP protocol handshakes are non-destructive banner grabs on the target's own
	// port, so they are permitted alongside passive HTTP in every mode.
	p := &Policy{Allowed: model.CapPassive | model.CapHTTPGet | model.CapTCPProbe, origins: map[string]bool{}, hosts: map[string]bool{}}
	switch mode {
	case model.ModePassive:
	case model.ModeActiveCanary:
		p.Allowed |= model.CapCanaryRead
	case model.ModeActiveProbe:
		p.Allowed |= model.CapHTTPPost
	default:
		return nil, fmt.Errorf("unsupported mode %q", mode)
	}
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			p.nets = append(p.nets, prefix.Masked())
			continue
		}
		if strings.Contains(entry, "://") {
			t, err := model.ParseTarget(entry)
			if err != nil || (t.BaseURL != t.Origin()+"/") {
				return nil, fmt.Errorf("allowlist origin must have no path: %q", entry)
			}
			p.origins[t.Origin()] = true
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			p.hosts[addr.Unmap().String()] = true
			continue
		}
		t, err := model.ParseTarget("http://" + entry)
		if err != nil || strings.ContainsAny(entry, "/:?#@") || entry == "" {
			return nil, fmt.Errorf("invalid allowlist host %q", entry)
		}
		p.hosts[t.Host] = true
	}
	return p, nil
}

func (p *Policy) CheckCapabilities(required model.Capability) error {
	if required == 0 || required & ^p.Allowed != 0 {
		return fmt.Errorf("blocked by policy: required capabilities %v (mask %d), allowed %v", required.Names(), required, p.Allowed.Names())
	}
	return nil
}

func (p *Policy) CheckTarget(t model.Target) error {
	if len(p.origins)+len(p.hosts)+len(p.nets) == 0 || p.origins[t.Origin()] || p.hosts[t.Host] {
		return nil
	}
	if addr, err := netip.ParseAddr(t.Host); err == nil {
		addr = addr.Unmap()
		if p.hosts[addr.String()] {
			return nil
		}
		for _, prefix := range p.nets {
			if prefix.Contains(addr) {
				return nil
			}
		}
	}
	return fmt.Errorf("blocked by policy: target is outside allowlist")
}
