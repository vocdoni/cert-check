package revocation

import (
	"slices"
	"testing"
	"time"
)

func TestPolicyValidate(t *testing.T) {
	cases := []struct {
		name    string
		policy  Policy
		wantErr bool
	}{
		{
			name:   "valid",
			policy: Policy{OCSPHosts: []string{"ocsp.example.es"}, CRLHosts: []string{"crl.example.es"}, AllowCRL: true, OCSPNonce: true},
		},
		{
			name:   "valid ocsp only",
			policy: Policy{OCSPHosts: []string{"ocsp.example.es"}},
		},
		{
			name:   "valid crl only",
			policy: Policy{CRLHosts: []string{"crl.example.es"}, AllowCRL: true},
		},
		{
			name:    "uppercase host",
			policy:  Policy{OCSPHosts: []string{"OCSP.example.es"}},
			wantErr: true,
		},
		{
			name:    "uppercase crl host",
			policy:  Policy{OCSPHosts: []string{"ocsp.example.es"}, CRLHosts: []string{"Crl.example.es"}, AllowCRL: true},
			wantErr: true,
		},
		{
			name:    "ipv4 host",
			policy:  Policy{OCSPHosts: []string{"192.0.2.1"}},
			wantErr: true,
		},
		{
			name:    "ipv6 host with port",
			policy:  Policy{OCSPHosts: []string{"[2001:db8::1]:80"}},
			wantErr: true,
		},
		{
			name:    "wildcard",
			policy:  Policy{OCSPHosts: []string{"*.example.es"}},
			wantErr: true,
		},
		{
			name:    "url instead of host",
			policy:  Policy{OCSPHosts: []string{"http://ocsp.example.es/"}},
			wantErr: true,
		},
		{
			name:    "empty host",
			policy:  Policy{OCSPHosts: []string{""}},
			wantErr: true,
		},
		{
			name:   "host:port valid",
			policy: Policy{OCSPHosts: []string{"ocsp.example.es:8080"}},
		},
		{
			name:    "host:0",
			policy:  Policy{OCSPHosts: []string{"ocsp.example.es:0"}},
			wantErr: true,
		},
		{
			name:    "host:65536",
			policy:  Policy{OCSPHosts: []string{"ocsp.example.es:65536"}},
			wantErr: true,
		},
		{
			name:    "AllowCRL without hosts",
			policy:  Policy{OCSPHosts: []string{"ocsp.example.es"}, AllowCRL: true},
			wantErr: true,
		},
		{
			name:    "neither method",
			policy:  Policy{CRLHosts: []string{"crl.example.es"}},
			wantErr: true,
		},
		{
			name:    "zero policy",
			policy:  Policy{},
			wantErr: true,
		},
		{
			name:    "negative max age",
			policy:  Policy{OCSPHosts: []string{"ocsp.example.es"}, MaxAgeWithoutNextUpdate: -time.Second},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()
			if got := err != nil; got != tc.wantErr {
				t.Errorf("Validate(%+v) error = %v, want error %v", tc.policy, err, tc.wantErr)
			}
		})
	}
}

func TestStatusValid(t *testing.T) {
	cases := []struct {
		status Status
		want   bool
	}{
		{StatusGood, true},
		{StatusRevoked, true},
		{StatusUnknown, true},
		{StatusUnavailable, true},
		{StatusStale, true},
		{StatusInvalidEvidence, true},
		{StatusUnsupportedMethod, true},
		{"", false},
		{"GOOD", false},
		{"ok", false},
	}
	for _, tc := range cases {
		if got := tc.status.Valid(); got != tc.want {
			t.Errorf("Status(%q).Valid() = %v, want %v", tc.status, got, tc.want)
		}
	}
}

func TestPolicyMaxAge(t *testing.T) {
	cases := []struct {
		name   string
		maxAge time.Duration
		want   time.Duration
	}{
		{"zero uses default", 0, DefaultMaxAgeWithoutNextUpdate},
		{"explicit", 30 * time.Minute, 30 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{OCSPHosts: []string{"ocsp.example.es"}, MaxAgeWithoutNextUpdate: tc.maxAge}
			if got := p.MaxAge(); got != tc.want {
				t.Errorf("MaxAge() = %v, want %v", got, tc.want)
			}
		})
	}
	if DefaultMaxAgeWithoutNextUpdate != 15*time.Minute {
		t.Errorf("DefaultMaxAgeWithoutNextUpdate = %v, want 15m", DefaultMaxAgeWithoutNextUpdate)
	}
}

func TestAllHosts(t *testing.T) {
	cases := []struct {
		name   string
		policy Policy
		want   []string
	}{
		{"both", Policy{OCSPHosts: []string{"a.example.es"}, CRLHosts: []string{"b.example.es", "c.example.es:8080"}},
			[]string{"a.example.es", "b.example.es", "c.example.es:8080"}},
		{"ocsp only", Policy{OCSPHosts: []string{"a.example.es"}}, []string{"a.example.es"}},
		{"none", Policy{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.AllHosts(); !slices.Equal(got, tc.want) {
				t.Errorf("AllHosts() = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("result does not alias the policy", func(t *testing.T) {
		p := Policy{OCSPHosts: make([]string, 1, 4), CRLHosts: []string{"b.example.es"}}
		p.OCSPHosts[0] = "a.example.es"
		got := p.AllHosts()
		got[0] = "changed.example.es"
		if p.OCSPHosts[0] != "a.example.es" || len(p.OCSPHosts[:cap(p.OCSPHosts)][1]) != 0 {
			t.Errorf("AllHosts mutated the policy: OCSPHosts = %q", p.OCSPHosts[:cap(p.OCSPHosts)])
		}
	})
}
