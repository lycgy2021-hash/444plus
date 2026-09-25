package model

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type Target struct {
	Scheme  string   `json:"scheme"`
	Host    string   `json:"host"`
	Port    int      `json:"port"`
	BaseURL string   `json:"base_url"`
	Tags    []string `json:"tags,omitempty"`
}

func ParseTarget(raw string) (Target, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Target{}, fmt.Errorf("invalid target URL: %w", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Opaque != "" {
		return Target{}, fmt.Errorf("target must be an absolute http:// or https:// URL")
	}
	if u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery {
		return Target{}, fmt.Errorf("target must not contain credentials, a query, or a fragment")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" || strings.ContainsAny(host, "\\% \t\r\n") {
		return Target{}, fmt.Errorf("invalid target hostname")
	}
	if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
		host = addr.String()
	} else {
		if len(host) > 253 {
			return Target{}, fmt.Errorf("hostname too long")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return Target{}, fmt.Errorf("invalid DNS label")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return Target{}, fmt.Errorf("hostname must be an IP address or ASCII DNS name (use punycode for IDNs)")
				}
			}
		}
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return Target{}, fmt.Errorf("port must be between 1 and 65535")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return Target{}, fmt.Errorf("empty port")
	}
	u.Host = host
	if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	}
	if (u.Scheme == "http" && port != 80) || (u.Scheme == "https" && port != 443) {
		u.Host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return Target{Scheme: u.Scheme, Host: host, Port: port, BaseURL: u.String()}, nil
}

func (t Target) Origin() string {
	host := t.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if (t.Scheme == "http" && t.Port != 80) || (t.Scheme == "https" && t.Port != 443) {
		host = net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	}
	return t.Scheme + "://" + host
}
