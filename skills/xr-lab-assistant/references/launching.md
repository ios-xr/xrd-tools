# Launching Duty Reference

## Rules

- Follow the interaction requirements in [interaction.md](interaction.md) for confirmations and user-facing decisions.

## Post-Launch Testing

After *every* launch, test the lab in four phases. All phases are mandatory and must complete successfully in order before proceeding to the next.

### Phase 1: Boot Wait

Use the tooling-provided boot-wait command to wait for all routers to become ready.

### Phase 2: Configuration Validation

**Purpose:** Verify that configuration was accepted by the routers.

Run `show configuration failed startup` on all routers using the tooling-provided run-command mechanism. Any output (other than the timestamp) indicates a configuration error that must be fixed before proceeding.

**Analyzing Configuration Failures:**

When errors are present, analyze the COMPLETE output before proposing fixes:

1. Identify ALL distinct error categories (semantic errors, syntax errors, authorization errors)
2. Group related errors by feature/protocol
3. Only switch to Designing duty after understanding the full scope of failures

Fixing one issue and relaunching without analyzing others leads to unnecessary iteration cycles.

### Phase 3: Convergence Checks

**Purpose:** Verify that distributed protocols have finished exchanging information.

These checks assume configuration is correct (validated in Phase 2). We are detecting *when* the network has converged, not *if* the configuration is right. Only investigate failures after exhausting retries.

**Retry algorithm (MANDATORY — follow exactly):**

Allow up to **150 seconds** from when the lab was launched for convergence.

1. Note the timestamp when the lab finishes launching — this is T₀. Capture T₀ as part of the launch command (e.g., `launch ... && echo "T0: $(date +%s)"`), not as a separate command or with boot-wait. This avoids user approval delays affecting the timing.
2. Run all applicable convergence checks (see below)
3. If all checks pass, proceed to Phase 4
4. If ANY check fails:
   a. Calculate remaining time: `remaining = 150 - (now - T₀)`
   b. If `remaining ≤ 0`, convergence window exhausted — investigate
   c. Calculate wait time: `wait = min(20, remaining)`
   d. Wait exactly `wait` seconds, then re-run ONLY the failed checks
   e. Go back to step 3

**Example calculation:**
- T₀ = 1000, now = 1145 → elapsed = 145s, remaining = 5s
- wait = min(20, 5) = **5 seconds** (NOT 20!)
- If remaining ≤ 0, stop retrying and investigate

**Status reporting (MANDATORY):** When running or retrying convergence checks, explicitly report:
- Elapsed time since T₀
- Remaining time in the 150s window
- Which checks passed/failed
- Next action (wait duration, retry, or investigate)

⚠️ **Do NOT investigate failures early. Do NOT skip retries.** The network needs time to converge. BGP commonly shows 0 prefixes or `Active` state for 120+ seconds after launch—this is normal convergence delay, not a configuration error.

**What "converged" means for BGP:** The `St/PfxRcd` column must show a **non-zero number**. Values of `0`, `Idle`, or `Active` mean BGP has NOT converged—keep retrying.

**Which checks to run:** Consult the lab's README and router configs. Only check protocols actually configured.

**IS-IS (if configured):**
- `show isis neighbors` — all expected neighbors should be "Up"
- `show isis route` — routes should be present (database has converged)

**OSPF (if configured):**
- `show ospf neighbor` — all expected neighbors should be "FULL"
- `show ospf route` — routes should be present (database has converged)

**BGP (if configured):**
- `show bgp <address-family> summary` — the `St/PfxRcd` column should show prefix counts (not 0, `Idle`, or `Active`)
  - Check **every** address-family that the lab configures, including VRF-scoped sessions.

### Phase 4: Smoke Tests

Run all smoke tests defined in the lab's README.

## Phase Gate Verification

Before proceeding past each phase, explicitly verify:

**Before leaving Phase 2:**
- [ ] Did `show configuration failed startup` return ONLY a timestamp on ALL routers?
- [ ] If there was ANY other output, have I switched to Designing to fix it?

**Before leaving Phase 3:**
- [ ] Are ALL protocol neighbors in the expected state (Up/FULL)?
- [ ] Does BGP show **non-zero** prefix counts for ALL configured address-families?
- [ ] Did I follow the retry algorithm (150s window from launch)?

**Before leaving Phase 4:**
- [ ] Did ALL smoke tests defined in the README pass?
- [ ] If any smoke test failed, have I debugged and fixed it?

**Before switching to Interacting duty:**
- [ ] Did ALL FOUR phases complete successfully?

⚠️ **NEVER move to Interacting duty until all smoke tests pass.** There are no exceptions.

## Handling Failures

If tests fail after exhausting retries:

- Debug and resolve before moving to Interacting.
- Start with the most likely hypothesis based on the error message.
- Consult documentation whenever the cause is unclear, and always after two hypothesis cycles without progress. This is especially important for complex features.
- **To apply fixes, switch to Designing duty**—update config files and relaunch. Do not apply fixes via interactive CLI; this creates drift between config files and running state.
