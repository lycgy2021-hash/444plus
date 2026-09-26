package protocol

import (
	"context"
	"errors"
	"testing"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// synthWireFormatInfo builds a minimal synthetic OpenWire WireFormatInfo frame:
// magic at the real offset, a protocol-version int, then just the
// ProviderVersion property. This mirrors the byte shape empirically captured
// from four real Apache ActiveMQ binaries (see docs/activemq-attack-surface.md)
// without needing the full property set those binaries actually send.
func synthWireFormatInfo(version string) []byte {
	buf := []byte{0, 0, 0, 0, 0x01} // length prefix (unchecked) + WireFormatInfo type tag
	buf = append(buf, []byte("ActiveMQ")...)
	buf = append(buf, 0, 0, 0, 0x0c) // OpenWire protocol version int (unused by the parser)
	buf = append(buf, []byte(providerVersionMarker)...)
	buf = append(buf, byte(len(version)>>8), byte(len(version)))
	buf = append(buf, []byte(version)...)
	return buf
}

// fakeProbe implements httpx.Probe with a canned TCP reply and error.
type fakeProbe struct {
	tcpResp []byte
	tcpErr  error
}

func (f fakeProbe) TCP(_ context.Context, _ model.Target, payload []byte, _ int) ([]byte, error) {
	if len(payload) != 0 {
		panic("OpenWire must never write a payload — it is server-speaks-first")
	}
	return f.tcpResp, f.tcpErr
}
func (f fakeProbe) Get(context.Context, model.Target, string) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (f fakeProbe) Fingerprint(context.Context, model.Target) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (f fakeProbe) Post(context.Context, model.Target, string, string, []byte) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}
func (f fakeProbe) Options(context.Context, model.Target, string) (httpx.Response, error) {
	return httpx.Response{Headers: map[string]string{}}, nil
}

func TestOpenWireLadder(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:61616")
	cases := []struct {
		name         string
		probe        fakeProbe
		wantIdentify bool
		wantVersion  string
		wantErr      bool
	}{
		{"real_5.17.5_frame", fakeProbe{tcpResp: synthWireFormatInfo("5.17.5")}, true, "5.17.5", false},
		{"real_5.16.6_frame", fakeProbe{tcpResp: synthWireFormatInfo("5.16.6")}, true, "5.16.6", false},
		{"fixed_5.17.6_frame", fakeProbe{tcpResp: synthWireFormatInfo("5.17.6")}, true, "5.17.6", false},
		{"dial_error", fakeProbe{tcpErr: errors.New("connection refused")}, false, "", true},
		{"policy_blocked", fakeProbe{tcpErr: errors.New("blocked by policy")}, false, "", true},
		{"empty_read_timeout", fakeProbe{tcpResp: nil}, false, "", true},
		{"short_read_partial_magic", fakeProbe{tcpResp: []byte{0, 0, 0, 0, 0x01, 'A', 'c', 't'}}, false, "", true},
		{"not_activemq_random_bytes", fakeProbe{tcpResp: []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")}, false, "", false},
		{"magic_present_no_version_property", fakeProbe{tcpResp: append([]byte{0, 0, 0, 0, 0x01}, append([]byte("ActiveMQ"), 0, 0, 0, 0x0c)...)}, true, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			identified, version, obs := OpenWire(context.Background(), tc.probe, target)
			if identified != tc.wantIdentify {
				t.Errorf("identified = %v, want %v (obs=%+v)", identified, tc.wantIdentify, obs)
			}
			if version != tc.wantVersion {
				t.Errorf("version = %q, want %q", version, tc.wantVersion)
			}
			if (obs.Error != "") != tc.wantErr {
				t.Errorf("obs.Error = %q, want present=%v", obs.Error, tc.wantErr)
			}
		})
	}
}

// TestOpenWireNeverWrites is a regression guard for the core safety property:
// the probe must send a nil/empty payload, never the crafted trigger. fakeProbe
// panics if a non-empty payload reaches TCP(), so this fails loudly if that
// invariant is ever broken.
func TestOpenWireNeverWrites(t *testing.T) {
	target, _ := model.ParseTarget("http://127.0.0.1:61616")
	OpenWire(context.Background(), fakeProbe{tcpResp: synthWireFormatInfo("5.17.5")}, target)
}
