// Command labtarget is a loopback-only lab target that faithfully emulates the
// path-traversal behavior of vulnerable Apache HTTP Server 2.4.x for exercising
// gopoc end to end without Docker. It is NOT a general web server and must never
// be exposed off localhost.
//
// It speaks raw HTTP/1.1 over TCP so that invalid percent escapes in the request
// target (notably CVE-2021-42013's %%32%65) survive to the handler, exactly as
// real Apache saw them. Go's net/http server rejects those before any handler,
// which is why this uses a hand-rolled reader like internal/testutil.
//
// Version gating mirrors reality:
//
//	Apache/2.4.49  vulnerable to both CVE-2021-41773 (.%2e) and CVE-2021-42013 (%%32%65)
//	Apache/2.4.50  41773 patched; still vulnerable to 42013's double encoding
//	Apache/2.4.51+ both patched
//
// Usage:
//
//	go run ./cmd/labtarget -addr 127.0.0.1:8080 -banner Apache/2.4.49
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"path"
	"strings"
	"time"
)

type config struct {
	banner string
	alias  string
	file   string
	canary string
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address (loopback only)")
	banner := flag.String("banner", "Apache/2.4.49", "Server header, e.g. Apache/2.4.49, Apache/2.4.50, Apache/2.4.51")
	alias := flag.String("alias", "/canary-alias/", "Alias URL prefix that the traversal escapes from")
	file := flag.String("file", "/tmp/gopoc-canary.txt", "absolute server path the traversal resolves to")
	canary := flag.String("canary", "GOPOC-CANARY-7f732a64b98947ed", "exact canary file content served on a successful traversal")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("invalid -addr: %v", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		log.Fatalf("refusing to bind %q: labtarget is loopback-only (use 127.0.0.1 or ::1)", *addr)
	}

	cfg := config{banner: *banner, alias: *alias, file: *file, canary: *canary}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("labtarget listening on http://%s  banner=%q  alias=%s  file=%s", *addr, cfg.banner, cfg.alias, cfg.file)
	log.Printf("41773 vulnerable=%t  42013 vulnerable=%t", vulnerable(cfg.banner, false), vulnerable(cfg.banner, true))
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go serve(conn, cfg)
	}
}

func serve(conn net.Conn, cfg config) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) != 3 {
		writeResponse(conn, cfg.banner, 400, "")
		return
	}
	method, rawURI := parts[0], parts[1]
	// Drain headers up to the blank line; we only need the request target.
	for {
		h, err := reader.ReadString('\n')
		if err != nil || strings.TrimRight(h, "\r\n") == "" {
			break
		}
	}
	log.Printf("%s %s", method, rawURI)

	status, body := route(rawURI, cfg)
	writeResponse(conn, cfg.banner, status, body)
}

// route reproduces vulnerable-Apache behavior for the request target.
func route(rawURI string, cfg config) (int, string) {
	if rawURI == "/" || rawURI == "" {
		return 200, "" // fingerprint probe: banner only
	}

	// Which CVE family does the raw target use? %%32%65 is double-encoded (42013);
	// .%2e is single-encoded (41773). They are mutually exclusive by construction.
	is42013 := strings.Contains(rawURI, "%%")
	is41773 := !is42013 && strings.Contains(strings.ToLower(rawURI), ".%2e")

	decoded := decodeOnce(decodeOnce(rawURI))
	cleaned := path.Clean(decoded)
	traversed := strings.Contains(decoded, "..")

	// A successful exploit: the right CVE family for this version, real traversal,
	// and the escaped path resolves exactly to the protected file.
	if traversed && cleaned == cfg.file && (is42013 && vulnerable(cfg.banner, true) || is41773 && vulnerable(cfg.banner, false)) {
		return 200, cfg.canary + "\n"
	}
	// Everything else (direct file request, randomized missing-file control,
	// or a patched version) is not readable from the web root.
	return 404, "not found\n"
}

// vulnerable reports whether the advertised banner is exploitable by the given
// CVE family. double=true selects CVE-2021-42013 (%%32%65); false selects
// CVE-2021-41773 (.%2e).
func vulnerable(banner string, double bool) bool {
	switch {
	case strings.HasPrefix(banner, "Apache/2.4.49"):
		return true
	case strings.HasPrefix(banner, "Apache/2.4.50"):
		return double // 41773 patched, 42013's double encoding still bypasses
	default:
		return false // 2.4.51+ and everything else
	}
}

// decodeOnce percent-decodes %HH byte-wise and, like the vulnerable Apache
// unescape, leaves a lone % (as in %%) literal so a second pass can decode it.
func decodeOnce(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok := hexVal(s[i+1]); ok {
				if lo, ok := hexVal(s[i+2]); ok {
					b.WriteByte(byte(hi<<4 | lo))
					i += 2
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexVal(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

func writeResponse(conn net.Conn, banner string, status int, body string) {
	reason := map[int]string{200: "OK", 400: "Bad Request", 404: "Not Found"}[status]
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n", status, reason)
	if banner != "" {
		fmt.Fprintf(conn, "Server: %s\r\n", banner)
	}
	fmt.Fprintf(conn, "Content-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
	_, _ = conn.Write([]byte(body))
}
