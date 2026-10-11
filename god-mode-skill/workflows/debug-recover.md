# Workflow: Debug and Recover

## Route here when
The user reports a failure, unexpected behavior, incident, broken test, operational issue, or regression.

## Root-cause-first sequence
1. Establish impact, urgency, scope, and safety constraints.
2. Capture symptoms and relevant evidence without exposing secrets.
3. Inspect current state and recent changes before modifying anything.
4. Form competing hypotheses and prioritize safe, discriminating checks.
5. Test hypotheses; do not make repeated speculative changes without new evidence.
6. State the confirmed root cause or explicitly state what remains uncertain.
7. Propose the smallest safe repair and a rollback/recovery plan.
8. Obtain approval if the repair crosses an approval gate.
9. Apply the repair in a suitable environment.
10. Verify the original failure is resolved and check for regressions.
11. Document cause, repair, evidence, residual risk, and prevention.

For incidents involving production, data loss, security compromise, or material business impact, follow applicable incident procedures and preserve evidence. Do not claim a root cause without sufficient evidence.
