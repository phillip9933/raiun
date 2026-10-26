# Translation review checklist

Use this checklist to record linguistic and layout acceptance for Android resource translations. Structural validation and complete string-key coverage are useful checks, but they do not count as native-speaker review. Do not mark a locale accepted until a qualified reviewer has completed the relevant sections and findings are resolved or explicitly deferred.

## Review record

Create one record per locale and review pass.

| Field | Record |
| --- | --- |
| Locale | German (`de`), French (`fr`), Spanish (`es`), European Portuguese (`pt-rPT`), or Japanese (`ja`) |
| Reviewer | Name or agreed public attribution; confirm native or professional fluency |
| Review date | YYYY-MM-DD |
| Resource revision | Commit or source snapshot reviewed |
| Structural validator | Command/result and key count |
| Layout review | Device/emulator, Android version, width, font scale, light/dark |
| Findings | Resource key, issue, disposition, and follow-up owner |
| Acceptance | Draft / changes requested / accepted, with reviewer sign-off |

## Linguistic review

- [ ] Read the full app UI in context; check natural phrasing, spelling, punctuation, and locale conventions.
- [ ] Use consistent product, navigation, file, cloud, Space, and settings terminology across the app.
- [ ] Check formal/informal address and tone for consistency, including Japanese politeness and honorific choices.
- [ ] Check grammar and agreement for plurals, placeholders, word order, gender, and number. Confirm values and formatted strings remain natural when expanded.
- [ ] Review accessibility labels and short controls for clarity when read aloud or without surrounding context.
- [ ] Review security and data-loss warnings for direct, unambiguous meaning: encryption and password recovery, plaintext handoff, APK source/signature verification, permissions, conflicts, cancellation, and deletion behavior.
- [ ] Review backup, offline, upload/download, and scanner terminology; preserve distinctions between queued and completed work, pause and cancel, and scan/save/export actions.
- [ ] Review updater settings and prompts: stable/beta, automatic checks, metered/Wi-Fi behavior, **Later**, Download, Install, Android's separate install confirmation, and what Raiun can and cannot verify.
- [ ] Confirm no machine-translated or English fallback text remains in the reviewed flow unless explicitly accepted.

## Layout and interaction review

Check each locale on a narrow 320 dp wide screen at font scales **1.3** and **2.0**, in light and dark themes. Include the supported minimum Android API and a current API where the layout differs.

- [ ] Settings screen rows wrap without clipping or obscuring controls; switches, checkboxes, chips, and actions remain reachable.
- [ ] App update popup title, version line, release notes, Download/Install action, and **Later** remain visible or can be reached by scrolling. Test Download and Later separately.
- [ ] Long translated text does not overlap icons, status indicators, progress, dialog actions, or navigation controls.
- [ ] TalkBack labels and focus order remain useful; focus does not become trapped behind a dialog.
- [ ] Backup settings, exclusions, scanner destination, and permission/security dialogs preserve clear actions and cancellation paths.
- [ ] Record any truncation, awkward wrapping, excessive scrolling, or tap-target obstruction with screenshots and exact locale/device settings.

## Fallback and structural checks

- [ ] Run the locale resource validator and record the result. Use strict completeness validation for the locale being accepted.
- [ ] Confirm missing optional strings deliberately fall back to English, and that required security/data-loss warnings do not unexpectedly fall back.
- [ ] Compare resource keys against the default locale after the review; do not treat matching key counts as proof of translation quality.
- [ ] Re-run validation after edits and retain the reviewer record and layout evidence with the change.

## Current status

The five Android translations are drafts. Existing strict resource checks establish structure and key coverage; they do not establish linguistic acceptance. Reviewer and sign-off fields remain intentionally blank until reviews occur.
