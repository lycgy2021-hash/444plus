package jbosswildfly

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"strings"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// remotingMagic is the fixed GUID JBoss Remoting's HTTP-upgrade handshake
// mixes into the key it echoes back, mirroring (with a different, unrelated
// constant) how RFC 6455 WebSocket computes Sec-WebSocket-Accept. Source:
// org.jboss.remoting3.remote.HttpUpgradeConnectionProvider (jboss-remoting).
const remotingMagic = "CF70DEB8-70F9-4FBA-8B4F-DFC3E723B4CD"

// RemotingExposed probes the target's own host:port for the JBoss Remoting
// "http-remoting" upgrade handshake — the transport WildFly/EAP use for
// remote EJB/JNDI invocation, normally multiplexed onto the app HTTP port. It
// performs one real protocol handshake and verifies the server's returned
// Sec-JbossRemoting-Accept against the key this probe sent, exactly as a real
// Remoting3 client would: an unrelated server that merely reflects an Upgrade
// header (or nothing at all) cannot pass this check. It only proves the
// transport is reachable; it never sends an invocation over it, so it cannot
// itself confirm or exploit an EJB deserialization CVE — that is left for a
// future advisory built on top of this signal.
func RemotingExposed(ctx context.Context, client httpx.Probe, target model.Target) (exposed bool, obs model.Observation) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return false, model.Observation{Kind: "remoting_handshake", Error: err.Error()}
	}
	secKey := base64.StdEncoding.EncodeToString(key)
	req := "GET / HTTP/1.1\r\n" +
		"Host: " + target.Host + "\r\n" +
		"Upgrade: jboss-remoting\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-JbossRemoting-Key: " + secKey + "\r\n" +
		"\r\n"

	raw, err := client.TCP(ctx, target, []byte(req), 4096)
	obs = model.Observation{Kind: "remoting_handshake", URL: target.Origin(), Bytes: len(raw)}
	if err != nil {
		obs.Error = err.Error()
		return false, obs
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		return false, obs
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), "jboss-remoting") {
		return false, obs
	}
	accept := resp.Header.Get("Sec-JbossRemoting-Accept")
	return accept != "" && accept == expectedRemotingAccept(secKey), obs
}

func expectedRemotingAccept(key string) string {
	sum := sha1.Sum([]byte(key + remotingMagic))
	return base64.StdEncoding.EncodeToString(sum[:])
}
