# Contributing to `sncfr`

Thanks for helping. Please read [`AGENTS.md`](AGENTS.md) first. It covers the project's first principles and the rule that every change updates the living docs ([`docs/SPEC.md`](docs/SPEC.md), [`docs/PLAN.md`](docs/PLAN.md), [`docs/specs/`](docs/specs/), and [`docs/adr/`](docs/adr/)) in the same change set.

## Keep organization-specific values out of this repository

`sncfr` is public, and it is used against many private enterprise ServiceNow instances. Nothing that identifies a real organization or instance belongs in this repository, whether in code, tests, fixtures, docs, issues, or commit messages. That includes:

- real instance hostnames (`<something>.service-now.com`, `<something>.servicenowservices.com`)
- group names, user names, emails, customer or cost-center codes
- sys_ids copied from a real instance
- custom ticket prefixes, renumbered choice values, or `u_*` / `x_*` field names taken from a real instance

**Where those values go instead:**

- **Instance facts** (prefixes, choice sets, open rules, group suffixes, default fields, recipes) go in a private **Instance Pack** that you keep outside the repo and point a profile at (`pack = "<path>"` in `config.toml`). See [ADR-0004](docs/adr/0004-instance-packs.md) and the fictional example in `docs/packs/example.pack.toml`.
- **Organizational guidance for agents** (terminology, which recipes to use, local guardrails) goes in a private **skill overlay** passed to `sncfr skill install --overlay <file>`.

**Use only these hostnames** in docs, tests, and examples: `example.service-now.com` and `mycompany.service-now.com`. The fictional organization for fixtures is **Example Corp**.

## Leak scanning (CI and pre-commit)

CI runs two leak checks on every push and PR:

- `scripts/leakcheck.sh` flags any `*.service-now.com` / `*.servicenowservices.com` host other than the two allowed examples. It also flags any term from a private denylist, which CI loads from the `LEAKCHECK_DENYLIST` secret. It scans tracked files and the PR's commit messages.
- [gitleaks](https://github.com/gitleaks/gitleaks), pinned by version and checksum, with `--redact`.

Findings print only `file:line rule`, never the matched text.

To catch leaks before they are committed, install the hook locally. It reads your own gitignored `.leakcheck/denylist.txt`, with one term per line:

```bash
printf '#!/bin/sh\nexec scripts/leakcheck.sh --staged\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Reporting issues

Describe behavior against a **fictional instance**, for example: "on an instance where `sys_choice` is unreadable and priority 4 is labeled `4 - Minor`, `sncfr update … --priority low` does X". Redact hostnames, names, and sys_ids from logs before pasting them. `sncfr -v` output includes request URLs and queries.

## Development checks

Run these before pushing. CI enforces the same checks:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```
