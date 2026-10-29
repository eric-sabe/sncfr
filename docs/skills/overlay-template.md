# Example Corp: sncfr agent overlay

<!--
How to use this template (SKILL-4)

An overlay is your organization's own guidance for AI agents. `sncfr skill install` appends it,
verbatim, after the generated SKILL.md:

    sncfr skill install --overlay docs/skills/example-corp.overlay.md
    # or set it once per profile in config.toml:
    #   [profiles.prod]
    #   skill_overlay = "skills/example-corp.overlay.md"

sncfr adds a marker line and records the overlay's sha256 in the generated header. Do not write
that marker yourself: an overlay that contains it is refused. The generated SKILL.md already
lists the instance's facts (pack, prefixes, choice labels, open rules, recipes, saved views).
Use the overlay for what only your team knows: context, terminology, which recipe to use when,
and stricter guardrails. Example Corp is fictional; replace it with your own content and keep the
file in a private repository.

Delete this comment block in your copy.
-->

## Context

Example Corp runs its IT service desk on `example.service-now.com`. Tickets you will see most:

- `INC…`: incidents from the service desk and monitoring.
- `ABC-…`: badge and facilities requests (`u_abc_request`). Treat these like requested items:
  never close them yourself; the facilities team does.
- `RITM…` / `SCTASK…`: catalog requests and their fulfillment tasks.

## Terminology

- "L2" / "L3" are support tiers. Assignment groups are named `<Team> - L2` and `<Team> - L3`.
  `--group Network` already includes both tiers; say which tier when you report results.
- "Resolved" incidents stay `active=true` here until the caller confirms. Use `--open`, not
  `--active`, when the user asks for open work.
- "Customer code" means the `u_customer_code` field on incidents.

## Which recipe to use

| The user asks… | Run |
| :--- | :--- |
| "What is open on server web-01?" | `sncfr recipe run ci-open-incidents --param host=web-01` |
| "How busy is the Network queue?" | `sncfr recipe run queue-by-priority --param group="Network - L2"` |
| "What needs my attention?" | `sncfr triage` |

## Guardrails (in addition to the built-in ones)

- Never set `priority` to `0 - Emergency` or `1 - Critical`. Ask the user to page the on-call
  lead instead.
- Customer-visible `comment`s go out only with the user's exact wording. Draft internal
  `note`s yourself if you like, but show them before `--write`.
- Catalog orders over one item (`--quantity` > 1) need the user's explicit confirmation of the
  quantity.
- If an approval names a group you do not recognize, stop and ask; do not approve on a guess.
