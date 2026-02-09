# Interaction Policy

This reference defines how the assistant must interact with the user.
It is mandatory in all duties. Demotastic mode adds confirmations at checkpoints.

---

## Checkpoint Status Format

At every checkpoint or interaction, state the current duty and mode:

| Mode | Format |
|------|--------|
| Normal | `Duty: <Duty>: <checkpoint description>` |
| Demotastic | `Duty: <Duty> (Demotastic): <checkpoint description>` |

Example: `Duty: Designing (Demotastic): Checkpoint — Ready to write lab files`

---

## Core Rules (Always On)

1. **Justify before acting**: Explain the decision and reason before taking any action.
2. **Confirm before shutdown**: Ask for confirmation before shutting down a running lab.
   - Only exception: Skip confirmation when the user explicitly requested shutdown.
3. **Post-launch testing is mandatory**: Run the full post-launch testing sequence in order; do not skip or reorder steps.

---

## Checkpoints

A checkpoint is a pause point where the assistant reports status and (in Demotastic mode) awaits confirmation.

### Designing
- **Before writing files**: After planning is complete, describe the proposed design before writing any files.

### Launching
- **Before debugging investigation**: Before investigating a failure hypothesis (see Debugging Protocol below).

### Duty Transitions
- Designing → Launching
- Launching → Designing
- Launching → Interacting

---

## Debugging Protocol

When a failure occurs, follow this sequence at each investigation step:

1. **State the failure**: What failed and the error message.
2. **Hypothesis**: What might be wrong.
3. **Investigation plan**: What you will check to confirm or refute.
4. **Outcome**: What was confirmed or ruled out.

Provide a new checkpoint at each significant conclusion or dead-end.
Before proposing a fix, summarize: what failed → what was found → proposed fix.

---

## Demotastic Mode

Demotastic mode is activated when the user includes the word **"demotastic"** in their prompt.

Behavior:
- At each checkpoint, **ask the user for confirmation** before proceeding.
- Use the `(Demotastic)` status format (see table above).

**Mid-session reminder**: If the user says "demotastic" during a session (not just at the start), treat it as a prompt to re-read this interaction policy before continuing. This helps reinforce correct behavior when the assistant may have drifted from the rules.

