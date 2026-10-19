package main

import (
	"flag"

	"time"

	"github.com/dnsvigil/dnsvigil/internal/core/settings"
	"github.com/dnsvigil/dnsvigil/internal/webui"
)

// runWebUI starts the embedded local web interface (FR-S1/S3). It accepts the
// same --history-retention knob as headless so run history is pruned
// consistently in every interface; the shared settings file seeds the default.
func runWebUI(args []string) {
	st, _, _ := settings.Load("")
	fs := flag.NewFlagSet("dnsvigil gui", flag.ExitOnError)
	retention := fs.Duration("history-retention", time.Duration(st.HistoryRetention), "prune run history older than this; 0 disables (default 30 days)")
	_ = fs.Parse(args)
	webui.Run(*retention)
}
