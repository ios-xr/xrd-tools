# Designing Duty Reference

## Design

Create/update files in the lab directory:

- Use snake_case for lab directory names (e.g., `srv6_l3vpn`, `isis_basic`)
- Create new labs in new directories; reusing a directory overwrites the existing lab

### Topology Definition

Topology definitions are backend-specific. Consult the selected lab backend skill for format guidance (look for a compose-file or topology reference).

### Router Configs

One config file per router: `<router name>.cfg`

Always include this base configuration:

```cisco
hostname <hostname>
logging console debugging
username <user>
 group root-lr
 group cisco-support
 secret <password>
!
```

Resolve `<user>` and `<password>` from the lab backend skill's credential guidance. If the lab backend skill does not specify credentials, ask the user before writing configs.

Additional requirements:
- Each router must have at least one loopback interface
- Use a consistent, lab-wide addressing scheme

### README.md

Document the lab using these sections. The README should be detailed enough that someone can understand the intended behavior and validate the configs without opening them.

- **Introduction**: What this lab demonstrates and how it does it (protocols, technologies, topology)
- **Topology diagram**: ASCII diagram showing router connections and link types
- **Roles and intent**: Per-router role, key protocols/features, and what each node is responsible for
- **Addressing scheme**: Table or list of interface IPs (IPv4/IPv6), loopbacks, and any notable subnets
- **Protocol/feature plan**: Expected adjacencies, areas/levels, labels, VRFs, policies, or services (as applicable)
- **Key show commands**: Commands to inspect the lab state and confirm the intent above
- **Smoke tests**: A small number of tests verifying end-to-end behaviour (e.g. ping) rather than intermediate protocol state
- **Evolutions** (optional): Suggestions to evolve the lab for more advanced concepts

Include explanation and justification for key decisions; keep it concise and actionable.

## Review

After writing all lab files, perform the end-of-design review before completing Designing duty.

⚠️ **Step 1**: Re-read [design-review.md](design-review.md) immediately before starting the review. It was likely read at session start and is no longer in active context.  Then follow it step by step.

## Designing Duty Completion

**Every time** Designing duty completes — whether initial design or returning to fix issues — explicitly verify:

- [ ] All lab files written or updated:
  - [ ] Topology definition file
  - [ ] Router configs (one per router)
  - [ ] README.md
- [ ] Credentials resolved — `<user>`/`<password>` placeholders replaced with actual values from the lab backend skill or user input
- [ ] Re-read [design-review.md](design-review.md) immediately before starting the review
- [ ] End-of-design review passed — includes its own checklist in [design-review.md](design-review.md)

⚠️ **Designing duty is NOT complete until this checklist passes.** Run these checks each time, not just on initial design. Present the checklist to the user before proceeding.
