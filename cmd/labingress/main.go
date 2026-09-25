// Command labingress is a loopback-only lab target that emulates the TLS
// admission webhook of a Kubernetes ingress-nginx controller, for exercising
// the IngressNightmare (CVE-2025-1974) exposure checker without a real cluster.
// It is NOT an ingress controller and must never be exposed off localhost.
//
// The real risk IngressNightmare depends on is the admission webhook being
// network-reachable and processing AdmissionReview requests from clients other
// than the API server. This mock reproduces exactly that surface: a self-signed
// HTTPS server that answers an AdmissionReview POST with an AdmissionReview
// response. With -expose=false it instead refuses unauthenticated callers (401),
// modelling a webhook that is not openly reachable.
//
// Usage:
//
//	go run ./cmd/labingress -addr 127.0.0.1:8443 -expose=true
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

// webhookPath is ingress-nginx's default admission webhook path.
const webhookPath = "/networking/v1/ingresses"

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address (loopback only)")
	expose := flag.Bool("expose", true, "true: answer AdmissionReview unauthenticated (vulnerable exposure); false: refuse with 401")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("invalid -addr: %v", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		log.Fatalf("refusing to bind %q: labingress is loopback-only", *addr)
	}

	cert := selfSignedCert(host)
	mux := http.NewServeMux()
	mux.HandleFunc(webhookPath, func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !*expose {
			// Model a webhook that only the API server (with its client cert) may call.
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		uid := extractUID(body)
		w.Header().Set("Content-Type", "application/json")
		// A genuine ingress-nginx admission response for a benign Ingress.
		resp := map[string]any{
			"apiVersion": "admission.k8s.io/v1",
			"kind":       "AdmissionReview",
			"response": map[string]any{
				"uid":     uid,
				"allowed": true,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	server := &http.Server{
		Addr:      *addr,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	log.Printf("labingress listening on https://%s%s  expose=%t", *addr, webhookPath, *expose)
	// ListenAndServeTLS with empty files uses TLSConfig.Certificates.
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}

// extractUID echoes the request's admission uid, as a real webhook must.
func extractUID(body []byte) string {
	var review struct {
		Request struct {
			UID string `json:"uid"`
		} `json:"request"`
	}
	if json.Unmarshal(body, &review) == nil && review.Request.UID != "" {
		return review.Request.UID
	}
	return "00000000-0000-0000-0000-000000000000"
}

func selfSignedCert(host string) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ingress-nginx-controller-admission"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP(host)},
		DNSNames:     []string{"ingress-nginx-controller-admission.ingress-nginx.svc"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}
