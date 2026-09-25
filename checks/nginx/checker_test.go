package nginx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"gopoc/checks/detect"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
	"gopoc/internal/policy"
)

func TestCVE202642533AffectedRange(t *testing.T) {
	c := NewCVE202642533(nil)
	cases := []struct {
		v        detect.Version
		affected bool
	}{
		{detect.Version{1, 29, 0}, true},  // old mainline, below stable fix
		{detect.Version{1, 30, 3}, true},  // stable branch, before fix
		{detect.Version{1, 30, 4}, false}, // stable fix
		{detect.Version{1, 30, 9}, false}, // later stable, patched
		{detect.Version{1, 31, 0}, true},  // mainline window, vulnerable
		{detect.Version{1, 31, 2}, true},  // mainline window, vulnerable
		{detect.Version{1, 31, 3}, false}, // mainline fix
		{detect.Version{1, 32, 0}, false}, // beyond fix
	}
	for _, tc := range cases {
		if got := c.Affected(tc.v); got != tc.affected {
			t.Errorf("Affected(%v) = %v, want %v", tc.v, got, tc.affected)
		}
	}
}

func TestCVE202642533Verdicts(t *testing.T) {
	cases := []struct {
		banner string
		want   model.Verdict
	}{
		{"nginx/1.29.0", model.VerdictDetected},
		{"nginx/1.31.3", model.VerdictNotFound},
		{"nginx", model.VerdictUnknown},
		{"", model.VerdictUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.banner, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.banner != "" {
					w.Header().Set("Server", tc.banner)
				}
			}))
			defer s.Close()
			p, err := policy.New(model.ModePassive, nil)
			if err != nil {
				t.Fatal(err)
			}
			opts := httpx.Defaults()
			opts.Rate = 0
			client, err := httpx.New(opts, p)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			target, err := model.ParseTarget(s.URL)
			if err != nil {
				t.Fatal(err)
			}
			c := NewCVE202642533(client)
			c.Client = client
			f := c.Check(context.Background(), target)
			if f.Verdict != tc.want {
				t.Fatalf("got %s, want %s: %+v", f.Verdict, tc.want, f)
			}
		})
	}
}
