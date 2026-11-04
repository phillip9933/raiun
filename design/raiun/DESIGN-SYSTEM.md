# Raiun shared design reference

**Draft v1 · 28 October 2026**

This document defines a shared visual vocabulary for Raiun Desktop (Linux and Windows) and Raiun Android. It is a starting reference for implementation and review, not a claim that either app already conforms. Native controls, platform typography, interaction conventions, and accessibility behavior remain native; the shared contract covers semantic color, spacing, shape, and component intent.

## Shared tokens

[`tokens.json`](tokens.json) is the versioned source for the v1 color and spacing contract. Both platforms should resolve `light` and `dark` semantic colors from it and use system appearance by default. A consumer may map tokens into its native theme layer; it should not replace platform fonts or controls with a web imitation.

| Purpose | Shared rule |
| --- | --- |
| Canvas and panels | `canvas` behind content, `surface` for cards and dialogs, `inset` for nested fields and quiet wells. |
| Borders | `border` for panel separation; `controlBorder` for controls that need a visible boundary. |
| Text | `text` for primary content and `muted` for supporting content. Both are intended for normal-size text. |
| Status | `success`, `warning`, `danger`, and `info` color the status text, icon, chip, or a narrow indicator. Keep the surrounding panel on `surface` or `inset`. |
| Accent | Use the account accent across the full selected-account card and in its persistent header identity. Account-related text and symbols on that accent must meet 4.5:1. Keep all other content panels neutral; do not color status by account. |
| Focus | `focus` is a visible keyboard/accessibility focus indicator, not a decorative border. |

Informational, help, success, warning, error, and offline panels remain neutral `surface`/`inset` panels. Signal the state with a status-colored icon and label, or a narrow leading rule. Do not color a whole panel by feature or account. Do not rely on color alone to distinguish status.

## Component vocabulary

- **Account context:** keep the current service/account identifiable in the persistent app header or navigation context. Show the account accent across the full selected-account card and in the persistent header identity; remove narrow left-edge selection slivers. Keep other application panels neutral and ensure all text on the account accent has at least 4.5:1 contrast. Account switching must preserve clear labels and selected state.
- **Buttons:** use one prominent primary action, quiet neutral secondary actions, and text/icon actions for low emphasis. Destructive actions use `danger` text/icon and explicit wording; confirmation is required when impact is irreversible.
- **Fields:** pair native controls with persistent labels, helper text when needed, and error text next to the affected field. A placeholder is not a label. Focus and invalid states must remain visible in both themes.
- **Transfers:** represent direction, item, progress, and state in a stable row/card. Progress uses a neutral track and primary fill; failures use a concise status label/icon plus a recovery action where possible. Never imply completion before verification.
- **Rows:** keep file, setting, and account rows neutral with clear separators, alignment, and hit areas. Selection uses a full account-accent treatment for the selected-account card, plus text/icon/check state. Do not use a left-edge accent sliver as the selected state.
- **Loading, empty, and error:** give each a concise explanation and the next useful action. Loading should not flash; empty states should distinguish “nothing here” from a failed load; error states should preserve context and retry options.
- **Help and information:** use the neutral-panel rule above. Keep help dismissible or persistently available by user choice, and do not use success styling for general information.

## Platform translation

Desktop retains system fonts, native window conventions, keyboard operation, and OS controls where appropriate. Android retains system font scaling, touch target conventions, Compose/Material behavior, and Android navigation. The shared design reference does not mandate identical layout or pixel dimensions. Preserve the Raiun crest and wordmark SVG assets; do not redraw or recolor those source marks as part of token adoption.

Use the [review record template](REVIEW-TEMPLATE.md) for a repeatable assessment.

## Objective review scorecard

Score each criterion **0** (fails or absent), **1** (partial/inconsistent), or **2** (meets with evidence). Record evidence separately for Desktop Linux, Desktop Windows, and Android, and for light and dark appearance. Every score must cite evidence: screenshots or recordings, build/review artifact identifiers, viewport/device dimensions, and interaction steps. Mark unavailable platforms or states **unverified**, not passed; do not award a score based on assumptions. Interpret totals as **18–20: ready**, **14–17: needs work**, and **0–13: redesign**. A critical privacy, destructive-action, or accessibility failure—or an unverified critical state—prevents a ready result regardless of total.

| Criterion | 0 / 1 / 2 evidence guide |
| --- | --- |
| Semantic color and neutral panels | Status color floods non-status panels / partial application or weak status cues / status stays on text, icon, chip, or narrow rule while the selected account card and persistent header identity use the account accent. |
| Text contrast | Any normal text below 4.5:1 / incomplete sampled states / all sampled normal text at least 4.5:1. |
| Controls and boundaries | Essential controls lack 3:1 boundary contrast / inconsistent states / visible control boundary contrast at least 3:1 against adjacent surface. |
| Focus and keyboard | Focus missing or keyboard path blocked / partial or obscured focus / visible focus and complete keyboard path through interactive content. |
| Status is not color-only | State cannot be distinguished without color / inconsistent redundant cues / status has text or icon/shape cue in every reviewed state. |
| Account and privacy context | Wrong/ambiguous account context or cross-account disclosure / context intermittently visible / persistent, correctly scoped header identity and full selected-account card, with neutral data surfaces. |
| Destructive actions | Unclear or accidental destructive action / warning or recovery inconsistent / clear impact, deliberate action, and suitable confirmation/recovery. |
| Font scaling and reflow | Clipping/overlap blocks content / some constrained areas / readable and usable at platform large text settings without lost actions. |
| Screen-size adaptation | Core actions clipped or inaccessible / constrained but recoverable / reviewed compact, typical, and expanded sizes preserve hierarchy and actions. |
| Motion and loading | Motion ignores reduced-motion preference or blocks feedback / partial accommodation / reduced-motion behavior and non-flashing, understandable loading states. |

### Verification basis and known scope

The proposal was informed by the current desktop stylesheet structure (PostCSS inspection: 1,213 rules; existing teal primary, neutral surfaces, status notices, account context, transfer rows, focus/reduced-motion and dark/media-query patterns) and Android's `OpenCloudColor.kt` / `OpenCloudTheme.kt` in `worktrees/android-updater/apps/android/core/designsystem/theme`. The Android source already has a teal primary, native Sans Serif typography, 4–32 dp spacing, 12 dp content radius, and a native dark scheme. This inspection is context, not a platform conformance grade.

The standalone HTML embeds `tokens.json` in an `application/json` script element with id `raiun-reference-tokens`; its catalog reads colors and account accents from that data. A generator can replace the embedded JSON from the canonical file without maintaining a second hand-edited palette. The eight account accent values match the existing Desktop UI preference choices (ocean, teal, violet, rose, amber, indigo, forest, plum). Their white-text contrast is checked separately; validate rendered account states before adoption. The criteria above derive from WCAG 2.2 guidance: [Contrast Minimum](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html), [Use of Color](https://www.w3.org/WAI/WCAG22/Understanding/use-of-color.html), and [Non-text Contrast](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html). The catalog is a design proposal only; it does not establish runtime, keyboard, scaling, screen-reader, or platform acceptance.

## Adoption and review workflow

Desktop consumes `tokens.json` through generated `apps/desktop/desktop-shell/src/raiun-tokens.css`. Run `python3 apps/desktop/scripts/design-tokens.py --write` after deliberate token changes, then `--check` to verify generated CSS, the catalog embed, text contrast and essential control/focus contrast. Desktop CI runs the check. These checks cover token pairs, not every rendered combination or disabled state. Android maps the same semantic names into its native theme in a separately reviewed change; this Desktop work does not modify Android.

For a release review, record one row per criterion and platform/theme with the score, screenshot/recording, exact candidate, device/viewport, interaction and remaining issue. Leave a criterion unverified when its evidence is absent; a partial palette review is not an overall app grade. Use neutral panels even when a status or account accent changes.
