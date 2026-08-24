# Use a lean Nygard-inspired ADR format

Last updated: 24.08.2026

## Summary

Use five short sections for architecture decision records: Summary, Context,
Decision, Consequences, and References. This adapts Michael Nygard's core
structure to a single-owner repository.

## Context

SHELL is a one-person platform project with a fresh scaffold and no decision
index. Its records need to explain why a decision exists, which alternatives
were considered, and what the chosen approach makes harder. The format should
capture that reasoning without turning each decision into project paperwork.

Free-form notes are quick to write but often omit alternatives and tradeoffs.
Markdown Architectural Decision Records provide more structure, including
drivers, option sections, an implementation plan, and verification criteria.
That detail is useful for large decisions but heavy for small ones. Nygard's
original format is shorter and uses Title, Context, Decision, Status, and
Consequences. SHELL keeps its core reasoning sections, adds a short Summary,
and omits routine status and decision-owner fields.

## Decision

Every architecture decision record uses this order:

1. Start with a verb-led title.
2. Add `Last updated: DD.MM.YYYY` as a date stamp, not a status field.
3. Use `## Summary` for one short paragraph that states the decision.
4. Use `## Context` for the trigger, constraints, and considered alternatives.
5. Use `## Decision` for the chosen approach, scope, and non-goals.
6. Use `## Consequences` for tradeoffs, follow-up work, ownership, and proof
   limits.
7. Use `## References` for source material and related ADRs.

Write an ADR only for a decision that changes the platform's structure,
dependencies, interfaces, or operation. Routine implementation choices and
status reports do not belong in ADRs.

Use a zero-padded number and lowercase slug for the filename. Number records
separately inside each owning ADR directory. A component decision lives with
its owner, such as `sudo/docs/adr/` for identity and trust or
`init/docs/adr/` for foundations. A decision that crosses component boundaries
lives in `man/docs/adr/`.

Do not add status front matter, a status heading, decision-owner wording, or
empty template sections. Add another section only when the five required
sections cannot make the record clear.

When a new ADR replaces an earlier decision, link the two records from the top
of each Context section and update their date stamps. Keep the earlier
rationale intact.

## Consequences

Small decisions stay quick to write and review. Larger decisions can add
detail without forcing every record into the same template.

The format is less prescriptive than a full Markdown Architectural Decision
Record. Each author must therefore state alternatives, scope, tradeoffs,
follow-up work, ownership, and proof limits directly. Numbering repeats across
owner directories, so references must use the full repository path.

Replacing a decision requires a new numbered ADR and links in both records.
The replacement may change direction, but it must not rewrite the reason for
the earlier choice.

## References

- [Michael Nygard: Documenting Architecture Decisions](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
- [AWS Prescriptive Guidance: Architectural decision record process](https://docs.aws.amazon.com/prescriptive-guidance/latest/architectural-decision-records/adr-process.html)
