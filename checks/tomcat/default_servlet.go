package tomcat

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// writableDefaultServlet reports whether Tomcat's DefaultServlet is write-enabled
// (readonly=false), the first prerequisite for CVE-2025-24813. It uses OPTIONS on
// a random file path: a writable DefaultServlet advertises PUT/DELETE in Allow,
// a read-only one does not. OPTIONS is safe and writes nothing (validated on live
// Tomcat 9.0.97 with readonly true/false). Probing a file path, not "/", is
// required: a directory never advertises PUT even when writable.
func writableDefaultServlet(ctx context.Context, client httpx.Probe, target model.Target) (bool, model.Observation) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	path := "/gopoc-" + hex.EncodeToString(b[:]) + ".txt"
	r, err := client.Options(ctx, target, path)
	obs := r.Observation("default_servlet_options", err)
	if err != nil {
		return false, obs
	}
	return strings.Contains(strings.ToUpper(r.Get("Allow")), "PUT"), obs
}
