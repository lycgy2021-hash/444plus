// Command labsharepoint is a loopback-only mock of a SharePoint web surface for
// exercising the ToolShell family checkers without a real SharePoint farm. It is
// a fixture, not SharePoint; markers are heuristic.
//
// Usage:
//
//	go run ./cmd/labsharepoint -addr 127.0.0.1:8095 -build 16.0.10417.20020 -toolpane=true
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8095", "listen address (loopback only)")
	build := flag.String("build", "16.0.10417.20020", "MicrosoftSharePointTeamServices build (empty to hide)")
	toolpane := flag.Bool("toolpane", true, "expose /_layouts/15/ToolPane.aspx (the ToolShell surface)")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("invalid -addr: %v", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		log.Fatalf("refusing to bind %q: labsharepoint is loopback-only", *addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_layouts/15/start.aspx", func(w http.ResponseWriter, r *http.Request) {
		if *build != "" {
			w.Header().Set("MicrosoftSharePointTeamServices", *build)
		}
		w.Header().Set("X-SharePointHealthScore", "0")
		w.Header().Set("Server", "Microsoft-IIS/10.0")
		_, _ = w.Write([]byte(`<html>_spPageContextInfo /_layouts/15/ Microsoft SharePoint</html>`))
	})
	mux.HandleFunc("/_layouts/15/ToolPane.aspx", func(w http.ResponseWriter, r *http.Request) {
		if !*toolpane {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(302) // present but gated behind sign-in
	})
	log.Printf("labsharepoint on http://%s  build=%q toolpane=%t", *addr, *build, *toolpane)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Fprintln(log.Writer(), "ready")
	log.Fatal(srv.ListenAndServe())
}
