// Package testutil provides loopback-only fixtures for raw request-target tests.
package testutil

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type RawServer struct {
	URL      string
	listener net.Listener
	wg       sync.WaitGroup
	once     sync.Once
}

// NewRawServer preserves invalid percent escapes in RequestURI. Go's regular
// HTTP server rejects these before a handler, unlike the Apache versions tested.
// Responses close the connection, so no background handler survives Close.
func NewRawServer(t *testing.T, handler http.Handler) *RawServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &RawServer{URL: "http://" + listener.Addr().String(), listener: listener}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
				if len(parts) != 3 {
					t.Errorf("invalid request line %q", line)
					return
				}
				headers, err := textproto.NewReader(reader).ReadMIMEHeader()
				if err != nil {
					t.Error(err)
					return
				}
				parsed, err := url.Parse(strings.ReplaceAll(parts[1], "%%", "%25%"))
				if err != nil {
					t.Error(err)
					return
				}
				req := &http.Request{Method: parts[0], RequestURI: parts[1], URL: parsed, Header: http.Header(headers), Host: headers.Get("Host"), Body: http.NoBody, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, req)
				response := recorder.Result()
				response.Close = true
				_ = response.Write(conn)
				_ = response.Body.Close()
			}()
		}
	}()
	t.Cleanup(s.Close)
	return s
}

func (s *RawServer) Close() {
	s.once.Do(func() { _ = s.listener.Close(); s.wg.Wait() })
}
