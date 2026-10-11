# Portability Test Specifications

## P1. Portable core
The core instructions can be read and followed without assuming a specific vendor's APIs, paths, or hooks.

## P2. Module access
The host can load the selected workflow and references, or the agent explicitly discloses that it cannot.

## P3. Capability discovery
The agent records unknown capabilities as unknown until verified.

## P4. Safe fallback
Unavailable subagents, shell access, persistent memory, approvals, or sandboxing do not lead to false claims of enforcement.

## P5. Host-specific adapter
Adapter claims are tied to a named host/version and actual validation evidence.

## P6. Permission boundaries
The agent respects host and organizational permission controls.

## P7. Package consistency
Standalone `SKILL.md` matches the package copy; module paths resolve; no host-specific behavior is presented as universal.
