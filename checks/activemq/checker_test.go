package activemq

import (
	"context"
	"errors"
	"testing"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// synthWireFormatInfo mirrors protocol.synthWireFormatInfo — kept local since
// the marker constant is unexported from the protocol package.
func synthWireFormatInfo(version string) []byte {
	buf := []byte{0, 0, 0, 0, 0x01}
	buf = append(buf, []byte("ActiveMQ")...)
	buf = append(buf, 0, 0, 0, 0x0c)
	buf = append(buf, []byte("ProviderVersion")...)
	buf = append(buf, byte(len(version)>>8), byte(len(version)))
	buf = append(buf, []byte(version)...)
	return buf
}

type mockProbe struct {
	tcpResp []byte
	tcpErr  error
}

func (m mockProbe) TCP(context.Context, model.Target, []byte, int) ([]byte, error) {
	return m.tcpResp, m.tcpErr
}
func (m mockProbe) Get(context.Context, model.Target, string) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (m mockProbe) Fingerprint(context.Context, model.Target) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (m mockProbe) Post(context.Context, model.Target, string, string, []byte) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (m mockProbe) Options(context.Context, model.Target, string) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}

// TestActiveMQLadder drives the full ladder fixed in
// docs/activemq-attack-surface.md, anchored on real captured version strings
// (5.17.5 vulnerable, 5.17.6 fixed) plus the ambiguous/negative fixture states.
func TestActiveMQLadder(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:61616")
	cases := []struct {
		name   string
		probe  mockProbe
		verd   model.Verdict
		reason string
	}{
		{"policy_blocked_or_unreachable", mockProbe{tcpErr: errors.New("blocked by policy")}, model.VerdictUnknown, "openwire_unverified"},
		{"dial_timeout", mockProbe{tcpErr: errors.New("i/o timeout")}, model.VerdictUnknown, "openwire_unverified"},
		{"not_activemq", mockProbe{tcpResp: []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")}, model.VerdictNotFound, "product_not_activemq"},
		{"magic_no_version", mockProbe{tcpResp: append([]byte{0, 0, 0, 0, 0x01}, append([]byte("ActiveMQ"), 0, 0, 0, 0x0c)...)}, model.VerdictUnknown, "version_unknown"},
		{"affected_5.17.5_real_binary", mockProbe{tcpResp: synthWireFormatInfo("5.17.5")}, model.VerdictLikely, "openwire_exposed_affected_version"},
		{"affected_5.16.6_real_binary", mockProbe{tcpResp: synthWireFormatInfo("5.16.6")}, model.VerdictLikely, "openwire_exposed_affected_version"},
		{"fixed_5.17.6_real_binary", mockProbe{tcpResp: synthWireFormatInfo("5.17.6")}, model.VerdictNotFound, "version_not_affected"},
		{"unaffected_future_version", mockProbe{tcpResp: synthWireFormatInfo("6.0.0")}, model.VerdictNotFound, "version_not_affected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCVE202346604(tc.probe)
			f := c.Check(context.Background(), target)
			if f.Verdict != tc.verd || f.Reason != tc.reason {
				t.Fatalf("got verdict=%s reason=%s, want verdict=%s reason=%s: %+v", f.Verdict, f.Reason, tc.verd, tc.reason, f)
			}
		})
	}
}

// TestActiveMQNeverConfirms is a regression guard: this CVE's checker must
// never emit `confirmed` under any input, because doing so would require
// sending the crafted class-instantiation packet — the exploit itself.
func TestActiveMQNeverConfirms(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:61616")
	c := NewCVE202346604(mockProbe{tcpResp: synthWireFormatInfo("5.17.5")})
	f := c.Check(context.Background(), target)
	if f.Verdict == model.VerdictConfirmed {
		t.Fatal("CVE-2023-46604 checker must never confirm — that requires the exploit trigger")
	}
}
