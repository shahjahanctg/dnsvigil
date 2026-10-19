package engine

import (
	"time"

	"github.com/dnsvigil/dnsvigil/internal/core/dnscheck"
	"github.com/dnsvigil/dnsvigil/internal/core/finding"
	"github.com/dnsvigil/dnsvigil/internal/core/target"
	"github.com/dnsvigil/dnsvigil/internal/core/tlscheck"
)

// DefaultBudget bounds one target's whole run (NFR-2/3). A batch is bounded
// per target; a negative Budget disables the bound.
const DefaultBudget = 60 * time.Second

// Context is the shared runtime context for both check paths.
type Context struct {
	TLSContext tlscheck.Context
	DNSContext dnscheck.Context
	// Budget bounds the whole run for one target. Zero means DefaultBudget; a
	// negative value runs without a budget.
	Budget time.Duration
}

// budget resolves the run bound and returns the deadline to apply (zero when
// the operator disabled the budget).
func (c Context) budget() time.Time {
	switch {
	case c.Budget < 0:
		return time.Time{}
	case c.Budget == 0:
		return time.Now().Add(DefaultBudget)
	default:
		return time.Now().Add(c.Budget)
	}
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

	// One deadline for both paths, so the target as a whole is bounded.
	deadline := ctx.budget()
	dnsCtx := ctx.DNSContext
	dnsCtx.Deadline = deadline
	tlsCtx := ctx.TLSContext
	tlsCtx.Deadline = deadline

	r := dnscheck.Run(dnsCtx, t)
	f := r.Findings

	tlsFindings, tlsErr := tlscheck.Run(tlsCtx, t)
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
