# Host Portability

## Portable core, host adapters
Keep intent routing, approval principles, workflow semantics, evidence labels, and safety expectations host-neutral. Put host-specific syntax, paths, hooks, commands, subagent support, and memory integrations in adapters.

## Capability profile
Establish whether the current host actually supports:
- loading reusable Skills/instructions and references;
- reading/writing authorized files;
- shell/command execution and network access;
- sandboxing, containerization, branches, or worktrees;
- independent agents or subagents;
- user approval gates and permission scopes;
- persistent memory and project isolation;
- automated tests, logging, and evidence export.

Use `adapters/capability-profile-template.md`. Do not infer capability from the product name alone; check the current host/version and actual session tools.

## Graceful fallback
If a capability is missing:
1. choose a safe supported alternative if it preserves task validity;
2. disclose material limitations;
3. ask the user if the alternative changes risk, scope, or expected result;
4. pause if proceeding would be unsafe or invalid.

Never describe instruction-only guidance as enforced isolation, permissions, sandboxing, or approval.
