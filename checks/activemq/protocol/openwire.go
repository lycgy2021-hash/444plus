// Package protocol implements the OpenWire wire-protocol probe for Apache
// ActiveMQ. It performs a real handshake read, never inferring the product from
// an open port alone. The probe is non-destructive: it reads the broker's own
// unsolicited banner; it never writes the crafted class-name payload that
// triggers CVE-2023-46604 — that write IS the exploit itself, not a probe.
package protocol

import (
	"bytes"
	"context"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// openWireMagic is the literal 8-byte ASCII sequence "ActiveMQ" that appears at
// a fixed offset in every OpenWire WireFormatInfo frame. Confirmed byte-for-byte
// identical on four real Apache ActiveMQ binaries (5.16.6, 5.17.5, 5.17.6,
// 5.18.2) — see docs/activemq-attack-surface.md.
var openWireMagic = []byte("ActiveMQ")

// openWireMagicOffset is where the magic starts: a 4-byte frame-length prefix
// plus a 1-byte WireFormatInfo data-type tag precede it.
const openWireMagicOffset = 5

// openWireReadLimit bounds the passive read. A default-property WireFormatInfo
// frame is ~340 bytes on every version tested; 2048 leaves generous headroom.
const openWireReadLimit = 2048

// providerVersionMarker is the property name carrying the broker's exact
// semver, confirmed present and correct on all four test binaries.
const providerVersionMarker = "ProviderVersion"

// OpenWire probes the OpenWire wire protocol. It writes NOTHING to the socket:
// OpenWire is server-speaks-first, so a real broker sends its WireFormatInfo
// frame unsolicited on connect, before any client data. `client.TCP` is called
// with a nil payload, so no bytes are ever written.
//
// obs.Error is set whenever the outcome is ambiguous (dial/read error, policy
// block, or too few bytes to check the magic) — the caller must treat that as
// "could not verify", not as "confirmed absent". identified=false with
// obs.Error=="" means real bytes were read and they are conclusively not
// OpenWire — a clean negative.
func OpenWire(ctx context.Context, client httpx.Probe, target model.Target) (identified bool, version string, obs model.Observation) {
	resp, err := client.TCP(ctx, target, nil, openWireReadLimit)
	obs = model.Observation{Kind: "openwire_handshake", URL: target.Origin(), Bytes: len(resp)}
	if err != nil {
		obs.Error = err.Error()
		return false, "", obs
	}
	if len(resp) < openWireMagicOffset+len(openWireMagic) {
		obs.Error = "short_read"
		return false, "", obs
	}
	if !bytes.Equal(resp[openWireMagicOffset:openWireMagicOffset+len(openWireMagic)], openWireMagic) {
		return false, "", obs // real bytes, conclusively not OpenWire — a clean negative
	}
	return true, providerVersion(resp), obs
}

// providerVersion locates the ProviderVersion property in a WireFormatInfo
// frame's marshaled property map and returns its value. OpenWire properties are
// UTF strings: a 2-byte big-endian length prefix followed by that many bytes.
// Returns "" if the marker is absent or the length looks implausible for a
// version string (empty, or longer than any real ActiveMQ release string).
func providerVersion(resp []byte) string {
	idx := bytes.Index(resp, []byte(providerVersionMarker))
	if idx == -1 {
		return ""
	}
	after := resp[idx+len(providerVersionMarker):]
	if len(after) < 2 {
		return ""
	}
	n := int(after[0])<<8 | int(after[1])
	if n <= 0 || n > 32 || len(after) < 2+n {
		return ""
	}
	return string(after[2 : 2+n])
}
