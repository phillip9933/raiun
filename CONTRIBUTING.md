# Contributing to Raiun

Raiun is an independent OpenCloud client maintained on a best-effort basis. Report reproducible bugs and discuss large feature or dependency changes before implementation. Report vulnerabilities through [Security](SECURITY.md).

## Choose an app

Android source, Gradle configuration, dependency locks, tests and scripts live in `apps/android`. Start with the [Android contribution guide](apps/android/CONTRIBUTING.md) and [testing guide](apps/android/docs/TESTING.md). Open that directory in Android Studio and run its wrapper there.

Desktop source, Cargo/npm locks, Linux/Windows packaging and app-specific docs live in `apps/desktop`. Run Rust and desktop commands from that directory; its Tauri UI has its own `desktop-shell` project. Start with the [desktop setup](apps/desktop/README.md). Linux and Windows x86_64 are the released Beta platforms; portable tests on other systems do not imply a released macOS app. The [monorepo guide](docs/MONOREPO.md) describes platform boundaries.

Shared branding and product design references live in `design/`. Use the [Raiun design reference](design/raiun/DESIGN-SYSTEM.md), [component catalog](design/raiun/reference.html) and evidence-based scorecard for UI reviews. Desktop consumes the canonical palette through generated CSS; run `python3 apps/desktop/scripts/design-tokens.py --check` after visual changes. Regenerate consumers with `--write` after deliberate token edits. Grade Linux, Windows and Android separately; unverified states do not count as passes. Keep native UI code, dependencies and platform behavior inside the app that uses them. Introduce shared source packages only when actual consumers need them.

## Change expectations

Prioritize data safety, security, correctness and privacy, then usability and maintainability. Preserve application identities, user data, account separation and compatibility. Changes to one app must not require installing another app's toolchain.

Run checks appropriate to the change. Review visual diffs deliberately, preserve translations and document checks that could not run. Platform workflows live in `.github/workflows` at the root; commands and artifact paths must point to the correct app. See [Releasing](docs/RELEASING.md).

Keep credentials, private signing material, local account data, build products and recovery records out of Git. Tests use synthetic files and accounts. See [Privacy](PRIVACY.md).

## Reports and AI usage

Identify the affected platform, app version, OS version, server version if known, reproduction steps, expected behavior and actual behavior. Remove credentials, tokens, private URLs, filenames and file contents from reports. Explain the concrete change, relevant validation and remaining limits in pull requests.

Disclose material AI assistance and distinguish observed validation from planned checks. Contributors remain responsible for understanding their changes. Keep discussion respectful; there is no guaranteed support schedule.

Contributions use [AGPL-3.0-only](LICENSE). Retain platform [third-party notices](THIRD-PARTY-NOTICES.md).

## Issues, work board and release roadmap

Use the public [Roadmap and work board](https://github.com/users/phillip9933/projects/3) for live planning. The roadmap contains release-tracking issues; the work board contains bugs, features, maintenance and documentation. Do not duplicate the live task list in a ROADMAP.md file. Dates are estimates, not promises.

### Labels and triage

Give every issue exactly one purpose label: `type:bug` (broken existing behavior), `type:feature` (new or changed user-facing capability), `type:maintenance` (refactoring, dependencies, CI, performance or technical debt), `type:docs` (documentation only), or `type:release` (release scope and gates). A bug needing refactoring is still a bug.

After triage, apply exactly one priority: `priority:urgent` (immediate serious impact), `priority:high` (next work, significant impact), `priority:normal` (default accepted work), or `priority:low` (worthwhile, not currently important). Priority sets work order, not a promised release date. Keep suspected vulnerabilities out of public issues and use [private security reporting](SECURITY.md).

Raiun is a multi-platform repository: use `platform:android`, `platform:desktop`, or `platform:shared`. Platform labels are not needed in an Android-only repository unless they distinguish real ownership.

### Work status and release targets

Use the GitHub Project **Status** field, not status labels:

- **Inbox:** needs assessment or clarification.
- **Ready:** accepted, sufficiently defined and available to work on.
- **In progress:** actively being worked on.
- **Blocked:** record the dependency and what unblocks it.
- **Done:** acceptance criteria met, with verification evidence.

Close duplicate or rejected issues with the appropriate reason; do not present them as delivered work. **Done means the issue's work is complete, not necessarily shipped.**

Use repository milestones only for intended stable release versions. Assign a milestone only when the work is intended for that release; unscheduled ideas have none. Beta and RC builds share the intended stable milestone. Do not invent version commitments or dates. A cross-repository release tracker links the relevant repository milestones.

### Release maturity and promotion gates

Each `type:release` issue has exactly one owner and a separate Project **Stage** field: **Planned → Alpha → Beta → RC → Stable**. Stage describes release maturity; it is independent of work Status.

- **Planned → Alpha:** scope, acceptance criteria and supported platforms recorded; an installable build exists.
- **Alpha → Beta:** intended release features implemented; core workflows pass; remaining limitations documented.
- **Beta → RC:** release-blocking bugs resolved; required regression, upgrade/migration and data-safety tests pass; scope frozen.
- **RC → Stable:** final candidate validated; release notes and known limitations ready; signed/checksummed artifacts verified where applicable; release actually published.

For Raiun and Kura, relevant data-safety evidence explicitly covers encryption, storage, backup/restore and sync. A gate passes on evidence, not a target date. GitHub fields and views display this policy; they do not automatically enforce the checklists. **Stable means published.** If a new feature enters after RC, move the release back to Beta and repeat affected checks.

### Issue content and public views

Every issue records its goal/problem, scope and explicit exclusions, a **Done when** acceptance checklist, dependencies (or none), and verification results/links before closure. A release tracker additionally records target version (explicitly unassigned when undecided), included work, promotion gates, remaining blockers, owner and build/release links.

The **Roadmap** view shows only release trackers on a timeline, with Stage and estimated start/target dates where known. The **Work board** groups bugs/features/maintenance/docs by Status. Never publish credentials, private account details, recovery files or sensitive vulnerability details in either view.
