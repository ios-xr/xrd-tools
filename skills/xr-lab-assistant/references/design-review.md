# End-of-Design Review

After writing all lab files, perform this review before completing Designing duty.

## README Alignment

Verify each router config reflects the lab's stated intent, topology, and addressing in `README.md`.

## Documentation Reconciliation

Reconcile non-trivial protocol and feature configuration against authoritative references.

### What to Reconcile

**Identifying features**: Use the README's Protocol/Feature Plan as a checklist — each protocol or feature listed there requires its own reconciliation. If no plan exists, enumerate the non-trivial protocols and services present in the configs.

**Role-specific scope**: The same protocol may require different configuration on routers with different roles - for example CE, PE or P routers.  When a feature's config differs materially by role, treat each role's variant as a separate reconciliation scope so that role-specific lines are compared against role-appropriate reference examples.

**All lines**: A feature for reconciliation is the **entire config block** under its protocol or service parent — not just the lines that feel novel. Include the full block; splitting into "standard base config" and "interesting parts" produces an incomplete reconciliation.

### Locating References

#### How many

Find **two references per feature** that corroborate each other — different features will
typically need different references. A single document may cover multiple features, which
is fine. Consistent configs across sources increase confidence;
differences may indicate platform/version variations or optional elements worth
understanding.

If only one complete example can be found, proceed but note the single-source limitation.

#### How to pick

**Use structurally different source types**: Same guide across platforms or software
versions shares nearly identical content and does not provide genuine corroboration.
Same-platform CCO guides also count as one source type unless they cover the feature
from genuinely different angles (e.g., an IS-IS config guide chapter vs. an SRv6
guide chapter that includes IS-IS for locator advertisement). Pick references from
different source types — for example, a CCO config guide chapter and an xrdocs.io
tutorial.

**Verify the operating system**: References must describe IOS-XR configuration. Cisco's
support-doc URL taxonomy can be misleading (e.g., paths containing `ios-nx-os-software`
may still host IOS-XR content, or vice versa).

**Software versions**: When search returns multiple versions of the same guide, prefer
recent releases (e.g., 25.x.y over 24.x.y over 7.x.y). Do not seek a newer version
if search already returned a usable chapter-level page — the content is nearly
identical across versions for stable features. (Note: XR version 25.x is more recent
than 7.x — the naming scheme changed.)

#### Documentation sources

Cisco CCO documentation (cisco.com) is the preferred primary source — use IOS XR
Configuration Guide and Command Reference chapters for authoritative syntax. Prefer
chapter-level pages; guide landing pages are tables of contents that contain no
configuration examples.

Two references per feature means at least one will typically come from outside CCO.
Other sources include xrdocs.io tutorials, workspace lab configs and sample topologies,
other context available to the agent, or references obtained from other agents. These
are examples, not an exhaustive list. Both references must contain IOS-XR
configuration examples — conceptual or multi-vendor material does not provide
syntactic corroboration.

#### How to fetch

Save complete documents to `<lab path>/references/` for reuse throughout the session.
Convert to markdown for searchability.

```bash
curl -sL --max-time 60 "https://r.jina.ai/<url>" -o references/<doc-name>.md
```

**Finding URLs**: Search the web for the feature name, platform, and software version
to locate documentation pages. Do not construct or guess URLs — Cisco's URL structure
changes across releases, so a constructed URL is unlikely to resolve to real content.
Target chapter-level pages rather than guide roots.

**Detecting failures**: After fetching, check the result with `wc -l`. A result with
very few lines (≤ 20) indicates the URL resolves to a not-found stub or access-denied
page served as HTTP 200. These failures are deterministic — retrying the same URL
produces the same result. Search for a different URL instead (e.g., a different
software version or platform).

If the result has more lines but reads as a table of contents (section headings and
links, no configuration blocks), the URL is a guide landing page. Extract the
chapter URLs from the links in the fetched document and fetch the relevant chapter
directly.

**Network errors**: Retry the same URL once only for genuine network errors (timeout,
empty response, or curl error code). If the retry also fails, move to a different URL.

### Performing the Reconciliation

For each feature, produce a comparison table, apply the reconciliation criteria, then resolve and iterate until the table is clean.

#### Reconciliation Table — what

Produce a table with one row per configuration line — every line under the feature's config context, without exception. Interface declarations, address-family statements, mode settings, and base protocol parameters all get rows, not just the lines that seem feature-specific. Lines from all three sources (proposal and both references) are merged into a single table. Empty cells mean the line is absent from that source. See **Reconciliation Criteria** below for the rules governing how each row is assessed.

| Column | Content |
|--------|---------|
| (status) | ✅ = matches/required, ❌ = needs action, ℹ️ = justified difference or optional |
| `Proposal` | The line as it appears in the proposed config |
| `Ref 1` | The corresponding line from the first reference |
| `Ref 2` | The corresponding line from the second reference |
| `Necessity` | `Req` = required for the lab to function, `Opt` = optional but justified, `Extra` = candidate for removal |
| `Verdict` | For ❌/ℹ️ rows: **bold keyword** (**Missing**, **Extra**, **Differs**, or **Optional**) followed by explanation. For ✅ rows: brief note or empty |

**Status selection rule**: The status column reflects both correctness and necessity:
- ✅ means the line matches a reference and is required (`Req`) — no difference to explain.
- ℹ️ means a justified difference OR an optional line (`Opt`) — the verdict must explain why the line is kept (e.g., best practice, deterministic behavior).
- ❌ means an action is needed — the line is missing, incorrect, or unnecessary (`Extra`). All `Extra` rows must be resolved: either remove the line, or reclassify as `Opt` with justification.

If the Verdict describes any difference (Missing, Extra, Differs, Optional), the status must be ℹ️ or ❌; use ✅ only when the line matches a reference and is required.

**Formatting**: Wrap every config-line cell in backticks. **Indentation is mandatory**: use dots to represent IOS-XR hierarchy depth (two dots per nesting level below the top-level parent). For example, a command nested 2 levels deep uses `....command`. This is necessary because markdown renderers strip leading whitespace from inline code spans. A table where all config lines appear flush-left (no dots) is a review failure — it makes hierarchy verification impossible.

**Example** (fictional config — illustrates format only):

Feature: ACME Tunneling (under `router acme 100`)

| | Proposal | Ref 1 | Ref 2 | Necessity | Verdict |
|---|----------|-------|-------|-----------|---------|
| ✅ | `router acme 100` | `router acme 1` | `router acme 100` | Req | instance number is user-chosen |
| ✅ | `..mode transport` | `..mode transport` | `..mode transport` | Req | |
| ✅ | `..address-family ipv4` | `..address-family ipv4` | `..address-family ipv4` | Req | |
| ✅ | `....tunnel-policy foo` | `....tunnel-policy bar` | `....tunnel-policy foo` | Req | name is user-chosen |
| ℹ️ | `......metric 50` | `......metric 100` | `......metric 50` | Opt | **Optional** — works without it (default 10), but explicit metric is best practice for deterministic path selection |
| ℹ️ | `......color blue` | | `......color blue` | Opt | **Optional** — cosmetic tag, confirmed by ref2; kept for operational clarity |
| ❌ | | `....encap gre` | | Req | **Missing** — in ref1 under address-family, investigate |
| ❌ | `....fast-reroute` | | | Extra | **Extra** — not in either ref, not required for lab intent; remove |
| ❌ | `....description Main` | `....description Main` | | Extra | **Extra** — matches ref1 but not required; cosmetic line adds no value |

#### Reconciliation Criteria — how

The following criteria govern whether each row in the table is correct. All criteria contribute ❌ or ℹ️ rows.

**Line-by-line comparison**: Walk through every line in the proposal and both references. For each line, determine whether it matches, differs, is missing from the proposal, or is extra in the proposal. Every line within the feature's scope must appear as a row — including lines that might seem "standard" or "basic". This produces the initial table.

**Hierarchy**: Verify each command appears under the **same config context** as in the references. Compare the full parent path, not just the command itself. Example: if a reference shows `router foo` → `child-a` → `feature-x`, but the proposal has `router foo` → `child-b` → `feature-x`, that's wrong even though `feature-x` syntax is correct.

**Parameter-dependent companions**: When the proposal uses a parameter value that differs from a reference, check what **other lines** accompany that value in the reference. Some parameters have companion requirements that only appear when that specific value is used.

**Best-practice alignment**: Where references reveal a cleaner, more current, or more idiomatic approach than the proposal — even if the proposal would technically work — consider adopting it. Earlier design choices were made with less context; revisiting them in light of authoritative examples is a feature of the review, not a failure.

**Minimal configuration**: Populate the Necessity column for every row. For each proposal line, ask: "Would the lab function without this line?" If yes and there is no strong best-practice reason to keep it, mark it `Extra` (status ❌). If yes but it is justified (best practice, deterministic behavior, operational clarity), mark it `Opt` (status ℹ️) with the justification in the verdict. If the line is required, mark it `Req`. Every row must have a Necessity value — a table with empty Necessity cells is incomplete. This is lower priority than best-practice alignment — if best practice says the line should be there, mark it `Req` or `Opt` rather than `Extra`.

#### Resolving the Table — iteration

After the initial table is complete and all criteria have been applied, resolve all ❌ rows: add missing lines, remove extras, correct differences. Then re-examine the resulting config against the same criteria — a fix may make an existing line redundant, or a removal may affect a dependency. Add any new findings to the table and resolve them. Repeat until the config is stable and the table has no unresolved ❌ rows.

The table presented in the reconciliation output should reflect the final state, not just the first pass.

### Reconciliation Output

Present the following for each feature:

- The reconciliation table (visible — verification claims without a table are insufficient)
- Key doc titles consulted (and sections if relevant) so the user can verify
- Key differences reconciled and their resolution
- Iteration notes: fixes applied, what was re-examined afterwards, and any rows whose status or necessity changed as a result (or an explicit statement that none changed and why)

Walk through each line of each reference.

## Review Completion Checklist

Verify all items before the review is considered passed:

- [ ] README alignment check performed
- [ ] Two corroborating references found per feature (or single-source limitation noted)
- [ ] Reconciliation table produced for each feature
- [ ] Line-by-line comparison performed
- [ ] Hierarchy verified
- [ ] Parameter-dependent companions checked
- [ ] Best-practice alignment considered
- [ ] Necessity column complete (every row marked Req, Opt, or Extra)
- [ ] Table resolved (no unresolved ❌ rows)
- [ ] Post-fix iteration performed and Iteration Notes written:  List rows whose status changed by re-running checks after initial fixes.
- [ ] Doc titles recorded in review notes

⚠️ **The review is NOT complete until this checklist passes.** Present it to the user before proceeding.
