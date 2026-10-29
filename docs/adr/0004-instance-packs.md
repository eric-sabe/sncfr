# ADR-0004: Instance Packs for Brownfield ServiceNow Instances

- **Status**: Accepted
- **Date**: 2026-10-28
- **Spec**: [`docs/specs/brownfield-instance-support.md`](../specs/brownfield-instance-support.md) (§Requirements 2, §Pack schema)

## Context

`sncfr` 0.1.x assumes an out-of-the-box (OOTB) instance. Real enterprise instances differ in ways that break that assumption:

- choice values are renumbered or relabeled per table
- field-level ACLs hide `sys_choice`, `sys_dictionary`, or `sys_number` from non-admins
- ticket prefixes are custom, some of them hyphenated
- group names follow suffix conventions
- local workflow defects exist (terminal states that leave `active=true`)

The facts needed to handle these are specific to one organization. They must not be committed to this repository, and they must not require forking the code.

## Decision

1. **An Instance Pack is a declarative TOML file of instance facts.** It holds prefixes, choice sets, open/closed rules, group suffixes, default fields, recipes, catalog settings, audit marker, limits, and doctor probes. It is referenced from a profile (`pack = "<path>"`), `SNCFR_PACK`, or `--pack`. Packs carry `schema_version` (an unknown major is rejected), `pack_version`, `status` (`active` | `draft`), and `instances` (the hosts the pack describes).
2. **The binary ships exactly one pack, `ootb`.** It holds every built-in default that used to be a constant. With no user pack, behavior on a readable OOTB instance is unchanged.
3. **Layers are `ootb` ⊕ profile pack ⊕ override (`--pack`/`SNCFR_PACK`).**
   - Facts replace by key. A user choice set replaces the ootb set whole and is **complete by definition**: values not listed are rejected. Merging value by value would be dangerous once values are renumbered.
   - `[remove]` deletes keys after the merge.
4. **Safety keys are a strictest union across layers.**
   - `auth.allow_credentials_file`: `false` wins.
   - `audit.agent_write_marker`: once defined, it can't be removed.
   - `limits.max_requests_per_minute`: the minimum wins.
   - `instances`: the intersection.
   - A pack has no key that can clear `read_only`. User packs cannot set `core.known_free_text`, because marking a field free text would bypass the write gate. A profile may set `pack_locked = true` to forbid overrides.
5. **Packs are shared files, so they are only partly trusted.**
   - A mutation is refused when the merged `instances` does not include the profile's host.
   - Values that come from a `draft` pack are UNVERIFIABLE.
   - A pack choice that contradicts readable instance metadata is UNVERIFIABLE, unless the set is flagged `workaround = true`.
   - Pack strings are treated as untrusted text when rendered.
6. **Packs are validated strictly** (`deny_unknown_fields` at every depth, `sncfr pack validate`), and identified by a SHA-256 hash of the merged pack. The hash is shown in previews, `doctor`, `auth status`, and the generated skill.
7. **Load order.** The pack loads before the credential store is chosen on every command, so `allow_credentials_file = false` is enforced before any credential file is touched.

## Consequences

- Organizations adapt `sncfr` with a private pack and skill overlay. Nothing in this repository changes.
- A pack can make `sncfr` stricter but never looser. A wrong, stale, or foreign pack degrades to UNVERIFIABLE or refusal, never to a silent wrong write.
- Hardcoded defaults are deleted in favor of `ootb.pack.toml`, so each default has one source of truth.
- Pack authors bootstrap with `sncfr discover`, which writes a `draft` pack. Writes stay blocked until the author reviews it and sets `status = "active"`.
