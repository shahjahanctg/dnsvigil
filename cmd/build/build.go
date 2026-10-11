package build

// Chosen import: github.com/miekg/dns
// Rationale recorded in project-plan.md D9/D10 and in this Dockerfile-equivalent build script.
//
// One-machine cross-compilation (CGO_ENABLED=0) produces static-ish binaries for:
//   linux/amd64, linux/arm64 (and linux/amd64 WSL), windows/amd64
import _ "github.com/miekg/dns"
