package target

import (
	"fmt"
	"net"
	"strconv"
)

// Target is one host:port a user explicitly named.
type Target struct {
	// Host is the DNS name or IP to check.
	Host string

	// Port is the TCP port.
	Port int
}

// Addr returns host:port ready for net.Dial or tls.Dial.
func (t Target) Addr() string {
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

// Validate checks basic invariants.
func (t Target) Validate() error {
	if t.Host == "" {
		return fmt.Errorf("target host is empty")
	}
	if _, err := net.LookupIP(t.Host); err != nil {
		// We do not reject here; resolution may still work via IP literal
		// or at connect time. Returning nil lets the engine attempt the call.
	}
	if t.Port < 1 || t.Port > 65535 {
		return fmt.Errorf("invalid port %d", t.Port)
	}
	return nil
}

// ParseTarget parses a single target from user input.
// Accepted forms:
//
//	example.com
//	example.com:443
//	93.184.216.34:443
func ParseTarget(raw string) (Target, error) {
	if raw == "" {
		return Target{}, fmt.Errorf("cannot parse target: empty input")
	}
	parts := splitHostPort(raw)
	if len(parts) == 1 {
		return Target{
			Host: parts[0],
			Port: 443,
		}, nil
	}
	if len(parts) != 2 {
		return Target{}, fmt.Errorf("cannot parse target: %q", raw)
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return Target{}, fmt.Errorf("bad port in %q: %w", raw, err)
	}
	if port < 1 || port > 65535 {
		return Target{}, fmt.Errorf("port %d out of range in %q", port, raw)
	}
	return Target{
		Host: parts[0],
		Port: port,
	}, nil
}

func splitHostPort(raw string) []string {
	if idx := lastIndexByte(raw, ':'); idx >= 0 {
		return []string{raw[:idx], raw[idx+1:]}
	}
	return []string{raw}
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}
