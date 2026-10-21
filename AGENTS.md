# Working on Raiun

Read applicable project/shared guidance when available. This is a linked development worktree with extensive unpublished Android work; preserve the primary `repo/` checkout and other worktrees with their independent local changes. Historical release permissions are not current authorization.

## Monorepo layout

Android's complete Gradle project is `apps/android/`; read its `AGENTS.md` and run Android commands there. Repository policies, shared branding in `design/`, product docs in `docs/` and executable GitHub workflows stay at the root. Keep native code, locks, tests, scripts, notices and implementation docs with their app.

Desktop is developed separately and is not imported yet. Do not modify or copy its live checkout during Android migration. Follow `docs/MONOREPO.md` for a coordinated history-preserving import into `apps/desktop`. Do not add empty platform scaffolding or claim absent source is built.

Task deliverables belong in the Raiun project's `outputs/` outside Git. Preserve ignored translations, unpublished docs, source, recovery data and backups. Inspect status before edits, avoid incidental staging, run relevant checks and distinguish historical evidence from current results. Preserve Android identities, user data and update compatibility.

Signing material stays in the project's `private/signing/` outside every Git repository. Never read, print, copy into source, publish or activate credentials during restructuring. Signing and publication are separate actions requiring current authorization. Never initialize Git at a project-container or Projects root.

The owner requests efficient model selection and bounded work on cheaper agents; the parent owns integration and validation. The owner explicitly resumed this Android migration despite desktop's separate 500-credit threshold; that threshold is not a blocker here. Preserve Raiun's project credit rule: pause if observed account-wide usage exceeds 100 credits in 30 minutes, reporting measured usage without inventing per-agent charges.
