package target

// ParseSingle parses a single host:port target. It is the stable parsing surface.
func ParseSingle(raw string) (Target, error) {
	return ParseTarget(raw)
}

// ValidateTarget validates and normalizes a target.
func ValidateTarget(t Target) error {
	return t.Validate()
}

// SortTargets is a stable sort for determinism across UIs.
func SortTargets(targets []Target) {
	Sort(targets)
}

// Sort is a stable sort on Host then Port.
func Sort(t []Target) {
	for i := 1; i < len(t); i++ {
		for j := i; j > 0; j-- {
			a, b := t[j-1], t[j]
			if a.Host > b.Host || (a.Host == b.Host && a.Port > b.Port) {
				t[j-1], t[j] = b, a
			} else {
				break
			}
		}
	}
}
