# Host Characterization + targeted-scan P1 — port to Command? (4.7 review spec)

**Written 2026-07-29. Status: NOT STARTED — blocked pending ruling.**

## What this is

Host Characterization (Phase A, 07-05) and the targeted-scan P1 decision layer (07-06) were
built **Prodex-first** and registered as `intentional_divergence.prodex_only` in
`.migration-divergence.yaml` (4.7 Q6). `todo_port` is empty. Howie has now asked to port the
feature to Command.

Before writing any code, three things surfaced that make this more than a file copy.

## The surface

| kind | items |
|---|---|
| migrations | `20260705a_asset_kind_add_redirect_dead.sql` (35 lines), `20260705b_asset_kind_characterization_cols.sql` (98), `20260706a_targeted_scan_p1_schema.sql` (38), `20260706b_finding_source_commandsentry_exposure.sql` (69) |
| code | `scripts/normalize/derive_asset_kind.py` (333), `scripts/scanner/dispatch.py` (129), `scripts/scanner/matrix_loader.py` (200), `scripts/scanner/surface_read.py` (100) |
| config | `scripts/scanner/matrix/roles.yaml` (183) — repo-versioned SSOT, never hot-edited (4.7 ruling 5) |
| tests | 4 files, 647 lines total |
| wiring | `run_medium.py` — planner call, `ScanPlan`, `scan_profile` + `matrix_version_sha` stamped at close_out (2 sites), ExposureFinding mapping |

## Blocker 1 — the enum migration uses a `do $$` block the splitter cannot parse

`20260706b` is:

```sql
do $$
begin
  if not exists (select 1 from pg_enum where enumlabel = 'commandsentry_exposure' ...) then
    alter type public.finding_source_t add value 'commandsentry_exposure';
  end if;
end $$;
```

**We have hit this exact wall before, in the opposite direction.** The divergence registry
records it verbatim for the cloud columns:

> *"Type divergence: Command cloud_provider = cloud_provider_t enum, Prodex = text
> (idempotent enum needs a do-block the migration splitter can't parse)."*

So the established precedent for "idempotent enum guarded by a do-block" was **to diverge
rather than solve the splitter**. Porting this migration to Command re-opens that decision.

## Blocker 2 — `ALTER TYPE ... ADD VALUE` is a one-way door

Postgres cannot remove an enum value. Once `commandsentry_exposure` is added to
`finding_source_t` on Command's production DB, it is permanent short of recreating the type
(which means rewriting every dependent column). Note `findings.source` is this enum — that is
already recorded as a gotcha (`42883` on `LIKE`, must use `IN (...)`).

Every other migration here is additive columns and reversible. This one is not.

## Blocker 3 — `run_medium.py` has drifted 223 lines between instances

Command 4346 lines / Prodex 4515, **223 differing lines**. The wiring is not copyable; it has
to be re-applied by hand into a **live production scanner**, on the instance we deliberately
do not actively watch.

## Not a blocker — the upstream data exists

`derive_asset_kind.py` reads `asset_surface.surface_data.subdomains[]`. Command's
`import_asm_to_surface.py` writes `subdomains` at 4 call sites. **The input shape is present
on Command**, so the feature would have real data to act on.

## Context 4.7 should weigh

- **Command is courtesy-only.** Howie has left Command; there is no outbound reporting from it
  and its findings serve as a scanner-correctness signal. Stated goals are *"site keeps working
  + feature parity."* Parity is a real goal, but Command is not actively operated.
- **Prodex is primary** and already has the feature working.
- The classifier soak on both instances is mid-flight, **soak-end 08-07** — landing schema and
  live-scanner wiring on Command during a soak window may muddy that instrument.
- Command's CI now runs 580 tests + 9 mechanism suites on every push (shipped today), so a port
  would at least be test-covered on arrival.

## Questions for ruling

**Q1 — Port at all?** Given Command is courtesy-only and Prodex is primary, is feature parity
here worth schema change + live-scanner wiring on an unwatched instance? Or is the honest answer
to reword `.migration-divergence.yaml` from *"Prodex-first"* to *"Prodex-only"* and close it?

**Q2 — If yes, the enum.** Options: (a) fix the migration splitter to be `$$`-aware; (b) rewrite
`20260706b` splitter-safe without a do-block; (c) follow the cloud-column precedent and let
Command diverge (text instead of enum value); (d) apply the enum by hand out-of-band and record
it. Which, and does the irreversibility of `ADD VALUE` change the answer?

**Q3 — Phasing.** Ship it inert first (migrations + modules + `roles.yaml` + tests, with
`run_medium.py` wiring withheld) so Command gains the capability with zero behaviour change, then
wire in a second reviewed step? Or all-at-once?

**Q4 — Soak interaction.** Land before or after the 08-07 device-class soak-end? The features are
adjacent (both classify hosts) and both write `assets.*` columns.

**Q5 — Registry bookkeeping.** On approval, do the four entries move
`intentional_divergence.prodex_only` → `todo_port` first (surfacing as action items), then get
deleted when done? And should there be an equivalent registry for instance-first **code**? Today
only migrations are registered, which is precisely why the four Prodex-only modules read as
unexplained drift until their migrations explained them.

**Q6 — Rollback.** If the wiring destabilises Command's medium scans, what is the defined
back-out? Revert the commit and leave the (additive) columns? The enum value cannot be removed
either way.

## Recommendation from the floor

Weak preference for **Q1 = yes, Q3 = phased inert-first**, on the grounds that the modules are
pure and well-tested (647 lines of tests, 4 files) and landing them inert is nearly risk-free
while genuinely closing the parity gap. **But** the enum is the sharp edge — I would not add an
irreversible enum value to Command's production type without an explicit ruling, especially when
the standing precedent for this exact problem was to diverge instead.

---

# RULINGS RECEIVED + PR 1 IMPLEMENTED — 2026-07-29

4.7 ruled Q1–Q6: **port** (do not formalise as prodex_only), **splitter-safe enum rewrite**,
**two-step inert-first**, **PR 1 anytime / PR 2 after the 08-07 soak**, **delete registry entry
on completion + register code divergence**, **revert PR 2 only on rollback**.

Implemented PR 1 by number. **Four deviations, all evidence-driven — flagged, not silent.**

## Deviation 1 — BOTH enum migrations held for PR 2, not just one

4.7's Q1 scope said *"3 of 4 migrations (the reversible column-additions) — port"*, treating
`20260705a` as reversible. **It is not.** It contains 2 × `ALTER TYPE public.asset_kind_t ADD
VALUE IF NOT EXISTS` ('redirect', 'dead'). My own spec above said *"every other migration here
is additive columns and reversible"* — that was wrong, and 4.7 inherited the error from me.

So there are **two** irreversible enum migrations, and neither is needed while the feature is
inert:

- `20260706b` — verified: `commandsentry_exposure` appears ONLY in `run_medium.py`. **Zero**
  references across all four PR-1 modules.
- `20260705a` — `derive_asset_kind.py` emits 'redirect'/'dead', but it is not invoked in PR 1.

Holding both makes **PR 1 100% reversible and 100% auto-appliable**, and keeps the one-way door
shut until we are committed to wiring. Strictly safer than the ruled scope, and it protects Q6:
if PR 2 is reverted we will not have added permanent enum values for nothing.

**PR 1 migrations: `20260705b` + `20260706a` only.**

## Deviation 2 — the enum migrations CANNOT be safe_auto_apply (Q2 correction)

4.7 concluded *"If (b) works (splitter-safe), migrate.yml handles this automatically."* It does
not. `20260705a`'s own header states:

> *"ALTER TYPE ... ADD VALUE cannot run inside a DO block or an explicit transaction (Postgres).
> Top-level only — this file has NO BEGIN/COMMIT wrap; psql runs each statement in its own
> implicit txn under autocommit."*

`apply_pending_migrations.py` wraps statements **and** the ledger insert in ONE transaction. So
splitter-safety is necessary but not sufficient — these need **hand-apply via psql then a seeded
ledger row**, which is 4.7's own Q2 option (d). Recorded in `todo_port` reasons.

Also worth noting: **`20260705a` already uses `ADD VALUE IF NOT EXISTS`**, the exact syntax 4.7
prescribed. The pattern is established in this codebase; `20260706b`'s do-block wrapper is
redundant rather than necessary. Splitter verified: quote-aware on `'` only, splits on `;`, **no
`$$` awareness** — 4.7's diagnosis was right.

## Deviation 3 — original migration FILENAMES preserved (do not rename)

4.7's Q2 suggested `20260726a_finding_source_commandsentry_exposure.sql`. **That would defeat
Q5.** `compare_migrations.py` diffs migration sets by `os.path.basename` — renaming makes the
two sets permanently unequal, so the registry entry could never be deleted. Filenames kept as
`20260705a/b`, `20260706a/b`. (4.7's date was also wrong: it wrote 07-26; today is 07-29.)

## Deviation 4 — registry keeps its filename; `code_divergence` added in place

4.7 wanted consolidation to `.instance-divergence.yaml`. `compare_migrations.py` and
`migration-parity.yml` read the current name, so renaming would change the parity tooling's
contract inside a feature port. Added a `code_divergence:` section to the existing file (the Q5
substance) and deferred the rename + CI enforcement to follow-up, both recorded in the file.

## Also fixed on the way

- **None of the 4 Prodex migrations carry a `MIGRATION-META` block** — they predate the ledger
  (first META migration is `20260710a`). `validate_meta` requires one on new migrations, so both
  PR-1 migrations got hand-written META headers. Verified valid via `validate_meta()`.
- `derive_asset_kind.py` docstring told a Command operator to scan `preview.prodexlabs.com`.
  Replaced with `<hostname>`. (The `"PRODEX"` strings in `test_derive_asset_kind.py` are
  arbitrary page-title fixtures for `meaningful_title()` — left alone, changing them is noise.)
- 4.7's illustrative registry YAML used module names (`host_characterization.py`,
  `targeted_scan_p1.py`) that **do not exist in either repo**. Used the real names.

## The two wiring tests — a skip that cannot rot

`test_surface_read.py` has 2 tests importing `run_medium.exposure_to_finding`, which is PR 2
wiring. A `@pytest.mark.skip("until PR 2")` would need manual removal, and **a skip nobody
removes is a permanently disabled test** — the same failure mode as today's CI floors and the
soak's empty red-flag check.

Instead the skip is keyed on **the import succeeding**, so it self-enables the moment PR 2 lands.
Verified from a **byte-identical file**:

| instance | result |
|---|---|
| Command (wiring absent) | 16 passed, **2 skipped** |
| Prodex (wiring present) | **18 passed, 0 skipped** |

Parity held — the file is identical in both repos and the change is a no-op on Prodex.

## PR 1 verification

| | Command | Prodex |
|---|---|---|
| pytest | **651 passed** (was 580), 5 skipped | 656 passed, 3 skipped |
| script suites | 9 run, 0 fail | 9 run, 0 fail |
| preflight | 31 modules import clean | — |
| META validation | both new migrations VALID | — |

**+71 tests on Command.** Residual 5-test gap reconciles exactly: 2 wiring skips + 3 extra
`test_degradation.py` cases (pre-existing, out of scope). 651 + 2 + 3 = 656.

**Zero behaviour change on Command** — `run_medium.py` untouched, so the modules are inert and
`scan_profile` / `matrix_version_sha` stay NULL on every scan.

## PR 2 — blocked until after 2026-08-07 (Q4)

Not started. Requires: hand-apply `20260705a` + `20260706b` via psql + seed ledger; hand-port
the wiring across a 223-line drift; the Q3 byte-equivalence mechanism test at the
module-invocation boundary; Q6 rollback triggers defined **with instrumentation verified to
detect them** before landing.
