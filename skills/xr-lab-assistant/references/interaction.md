# Interaction Policy

This reference defines how the assistant must interact with the user.
It is mandatory in all duties.

---

## Checkpoint Status Format

At every checkpoint or interaction, state the current duty:

| Format |
|--------|
| `Duty: <Duty>: <checkpoint description>` |

Example: `Duty: Designing: Checkpoint — Ready to write lab files`

---

## Core Rules (Always On)

1. **Justify before acting**: Explain the decision and reason before taking any action.
2. **Confirm before shutdown**: Ask for confirmation before shutting down a running lab.
   - Only exception: Skip confirmation when the user explicitly requested shutdown.
3. **Post-launch testing is mandatory**: Run the full post-launch testing sequence in order; complete every phase before proceeding to the next.

---

## Checkpoints

A checkpoint is a pause point where the assistant reports status.

### Designing
- **Before writing files**: After planning is complete, describe the proposed design before writing any files.

### Launching
- **Before debugging investigation**: Before investigating a failure hypothesis (see Debugging Protocol below).

### Duty Transitions
- Designing → Launching
- Launching → Designing
- Launching → Interacting
- Interacting → Designing (when config changes are needed)
- Interacting → Launching (when restart or relaunch is needed)

---

## Debugging Protocol

When a failure occurs, follow this sequence at each investigation step:

1. **State the failure**: What failed and the error message.
2. **Hypothesis**: What might be wrong.
3. **Investigation plan**: What you will check to confirm or refute.
4. **Outcome**: What was confirmed or ruled out.

Provide a new checkpoint at each significant conclusion or dead-end.
Before proposing a fix, summarize: what failed → what was found → proposed fix.
