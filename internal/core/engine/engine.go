package engine

import (
	"time"

	"github.com/soc-tool/internal/core/dnscheck"
	"github.com/soc-tool/internal/core/finding"
	"github.com/soc-tool/internal/core/target"
	"github.com/soc-tool/internal/core/tlscheck"
)

// Context is the shared runtime context for both check paths.
type Context struct {
	TLSContext tlscheck.Context
	DNSContext dnscheck.Context
}

// Result is the end-to-end result for one target.
type Result struct {
	Target    target.Target
	Findings  []finding.Finding
	Error     error
	StartTime time.Time
}

// Run performs all checks for a target (DNS and TLS) and returns a combined
// result. TLS findings are appended after the DNS findings; errors from the
// TLS path take precedence when both paths fail.
func Run(ctx Context, t target.Target) Result {
	start := time.Now()

	r := dnscheck.Run(ctx.DNSContext, t)
	f := r.Findings

	tlsFindings, tlsErr := tlscheck.Run(ctx.TLSContext, t)
	f = append(f, tlsFindings...)

	err := r.Error
	if tlsErr != nil {
		err = tlsErr
	}

	return Result{
		Target:    t,
		Findings:  f,
		Error:     err,
		StartTime: start,
	}
}
