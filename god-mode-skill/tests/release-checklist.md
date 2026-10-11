# Release Checklist

## Package integrity
- [ ] Core Skill metadata and version are correct.
- [ ] Every referenced module exists.
- [ ] No broken internal module paths.
- [ ] Standalone Skill matches packaged `SKILL.md`.
- [ ] Platform blueprint is unchanged unless separately authorized.
- [ ] License is selected and complete before public distribution.

## Behavioral quality
- [ ] Relevant scenario tests selected.
- [ ] Before/after runs recorded where supported.
- [ ] Critical safety scenarios passed or release blocked.
- [ ] Failed, blocked, and unrun tests reported honestly.
- [ ] Regression findings reviewed and dispositioned.

## Security and privacy
- [ ] No secrets or unintended personal data in package.
- [ ] Third-party material and licensing reviewed.
- [ ] Permission and isolation claims match actual evidence.
- [ ] Memory and cross-project promotion rules remain explicit.

## Release management
- [ ] Changelog updated.
- [ ] Compatibility statement updated with verified scope.
- [ ] Migration notes added when needed.
- [ ] Rollback path documented.
- [ ] Release candidate clearly distinguished from final release.
- [ ] Authorized approver has made release decision.
