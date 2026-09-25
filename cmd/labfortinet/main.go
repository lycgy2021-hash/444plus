// Command labfortinet is a loopback-only mock of a Fortinet appliance web
// surface, for exercising the fortinet detection checkers end to end without a
// real appliance. It is a fixture, not a Fortinet product, and its fingerprints
// are heuristic — matching what the checkers look for, not a validated appliance.
//
// Usage:
//
//	go run ./cmd/labfortinet -addr 127.0.0.1:8090 -product FortiGate -version 7.0.16 -expose=true
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8090", "listen address (loopback only)")
	product := flag.String("product", "FortiGate", "product marker in the login page, e.g. FortiGate, FortiMail, FortiVoice")
	version := flag.String("version", "7.0.16", "version string exposed in the page (empty to hide)")
	expose := flag.Bool("expose", true, "serve the management login surface at /remote/login,/login,/admin")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("invalid -addr: %v", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		log.Fatalf("refusing to bind %q: labfortinet is loopback-only", *addr)
	}

	verField := ""
	if *version != "" {
		verField = fmt.Sprintf(` "version":"%s"`, *version)
	}
	// FortiGate/FortiOS/FortiProxy surfaces carry fgt_lang / SSL-VPN markers;
	// other products are identified by their name only.
	behavioral := ""
	if p := strings.ToLower(*product); strings.Contains(p, "fortigate") || strings.Contains(p, "fortios") || strings.Contains(p, "fortiproxy") {
		behavioral = " fgt_lang /remote/login"
	}
	loginPage := fmt.Sprintf(`<html><head><title>%s</title></head><body>%s logindisclaimer%s%s</body></html>`, *product, *product, behavioral, verField)
	mgmtPage := fmt.Sprintf(`<html>%s login</html>`, *product)

	mgmt := map[string]bool{"/remote/login": true, "/login": true, "/admin": true}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(loginPage))
			return
		}
		if mgmt[r.URL.Path] {
			if !*expose {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(mgmtPage))
			return
		}
		w.WriteHeader(404)
	})
	log.Printf("labfortinet on http://%s  product=%s version=%q expose=%t", *addr, *product, *version, *expose)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
