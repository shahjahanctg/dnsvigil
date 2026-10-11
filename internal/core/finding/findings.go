package finding

// Severity is ordered for sorting and reporting.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// Name returns a stable, human-readable severity name.
func (s Severity) Name() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Finding is the single results model consumed by UI and reporting.
type Finding struct {
	Kind     string
	Severity Severity
	What     string // stable, machine-readable assertion
	Because  string // plain-language explainer for a generalist
	Detail   string // fuller technical detail for a specialist
	Tags     []string
}

// Ordered severities from most to least severe.
func SeveritiesSortedDesc() []Severity {
	return []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
}
