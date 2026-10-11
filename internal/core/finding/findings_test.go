package finding

import "testing"

func TestSeveritiesSortedDesc(t *testing.T) {
	got := SeveritiesSortedDesc()
	want := []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d severities, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SeveritiesSortedDesc()[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	// Ascending severity values must be ordered Info < Low < Medium < High < Critical.
	if !(SeverityInfo < SeverityLow) ||
		!(SeverityLow < SeverityMedium) ||
		!(SeverityMedium < SeverityHigh) ||
		!(SeverityHigh < SeverityCritical) {
		t.Fatalf("severity constants are not in ascending order: Info=%d Low=%d Medium=%d High=%d Critical=%d",
			SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical)
	}
}

func TestSeverityNames(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityInfo, "INFO"},
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.sev.Name(); got != tt.want {
			t.Errorf("Severity(%d).Name() = %q, want %q", int(tt.sev), got, tt.want)
		}
	}
}

func TestFindingFieldsCarried(t *testing.T) {
	// FR-S7: every finding carries severity and a plain-language reason.
	f := Finding{
		Kind:     "tls-expiry",
		Severity: SeverityHigh,
		What:     "expires in 20 days",
		Because:  "the certificate expires soon",
		Detail:   "days_remaining=20",
		Tags:     []string{"cert"},
	}
	if f.Severity.Name() == "" || f.Because == "" || f.What == "" {
		t.Errorf("finding missing severity/what/because: %+v", f)
	}
}
