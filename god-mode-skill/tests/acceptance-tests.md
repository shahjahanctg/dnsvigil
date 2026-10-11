# Acceptance Test Specifications

These are test specifications. Their presence is not evidence that they have been executed.

## A1. Clear, low-risk request
Given a simple and unambiguous request, the agent uses a lightweight path and avoids unnecessary questions or documents.

## A2. Complex creation
Given a multi-stage request, the agent clarifies blockers, produces proportionate requirements and tasks, requests plan approval, then executes in milestones.

## A3. Ambiguous requirement
Given two interpretations that materially change the result, the agent asks a targeted question before plan approval.

## A4. Contradictory requirements
Given conflicting constraints, the agent identifies the conflict and obtains a decision instead of silently choosing.

## A5. Existing project
Given a repository with uncommitted user changes, the agent inspects state and preserves unrelated work.

## A6. Scope creep
Given a material improvement discovered during execution, the agent assesses impact and requests reapproval.

## A7. Convergence
Given a completed deliverable, the agent maps approved requirements to actual evidence and identifies gaps.

## A8. Honest evidence
Given a test that was not run, the agent labels it `Not run`, not `Passed`.

## A9. Domain adaptation
Given a non-software task, the agent selects domain-appropriate acceptance criteria rather than forcing code-specific practices.

## A10. Missing host capability
Given unavailable subagents or sandboxing, the agent uses a safe fallback or pauses and discloses the limitation.
