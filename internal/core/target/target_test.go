package target

import "testing"

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    Target
		wantErr bool
	}{
		{
			name: "host only defaults to port 443",
			raw:  "example.com",
			want: Target{Host: "example.com", Port: 443},
		},
		{
			name: "host with explicit port",
			raw:  "example.com:8443",
			want: Target{Host: "example.com", Port: 8443},
		},
		{
			name: "ipv4 literal with port",
			raw:  "93.184.216.34:443",
			want: Target{Host: "93.184.216.34", Port: 443},
		},
		{
			name:    "empty input",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "non-numeric port",
			raw:     "example.com:abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTarget(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseTarget(%q) = %v, want error", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q) error: %v", tt.raw, err)
			}
			if got.Host != tt.want.Host || got.Port != tt.want.Port {
				t.Errorf("ParseTarget(%q) = %+v, want %+v", tt.raw, got, tt.want)
			}
			if addr := got.Addr(); addr != tt.want.Addr() {
				t.Errorf("ParseTarget(%q).Addr() = %q, want %q", tt.raw, addr, tt.want.Addr())
			}
		})
	}
}

func TestAddr(t *testing.T) {
	got := Target{Host: "example.com", Port: 8443}.Addr()
	if got != "example.com:8443" {
		t.Errorf("Addr() = %q, want %q", got, "example.com:8443")
	}
}

func TestParseSingleMatchesParseTarget(t *testing.T) {
	a, errA := ParseSingle("example.com:8443")
	b, errB := ParseTarget("example.com:8443")
	if (errA == nil) != (errB == nil) || (errA == nil && (a != b)) {
		t.Errorf("ParseSingle and ParseTarget disagree: %v/%v vs %v/%v", a, errA, b, errB)
	}
}

func TestSortTargets(t *testing.T) {
	in := []Target{
		{Host: "b.example.com", Port: 443},
		{Host: "a.example.com", Port: 8443},
		{Host: "a.example.com", Port: 80},
	}
	SortTargets(in)

	want := []Target{
		{Host: "a.example.com", Port: 80},
		{Host: "a.example.com", Port: 8443},
		{Host: "b.example.com", Port: 443},
	}
	for i := range want {
		if in[i] != want[i] {
			t.Errorf("SortTargets()[%d] = %+v, want %+v", i, in[i], want[i])
		}
	}
}
