# Memory and Governed Learning

## Memory layers
1. **Session context:** temporary facts needed for the current interaction.
2. **Project memory:** project-specific decisions, constraints, artifacts, and progress.
3. **User-approved preferences:** durable preferences explicitly approved for reuse.
4. **Trusted reusable knowledge:** reviewed and approved general lessons or versioned Skills.

Do not merge layers implicitly. Host storage and controls vary; disclose actual capabilities.

## User control
Where supported, provide or document inspection, export, deletion, backup, restore, and project-isolation procedures. Do not claim a capability unless it exists and has been verified. Avoid retaining unnecessary personal or sensitive information.

## Cross-project promotion
Before promoting a lesson:
1. propose the lesson and its expected value;
2. remove project-specific, confidential, personal, or identifying information unless explicitly authorized and appropriate;
3. inspect for secrets and hidden dependencies;
4. test the proposed instruction against representative and adversarial scenarios;
5. explain behavior changes and risks;
6. obtain explicit user approval;
7. version the change, record provenance, and preserve rollback.

Do not autonomously rewrite trusted reusable Skills based on a single failure or anecdote. Separate observed facts from hypotheses. Never train or modify a model unless that capability and authorization are explicit.
