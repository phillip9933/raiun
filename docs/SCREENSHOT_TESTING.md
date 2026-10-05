# Screenshot Golden Testing

Raiun uses [Roborazzi](https://github.com/takahirom/roborazzi) with Robolectric for host-side Compose visual regression tests. This is the required visual-parity gate for every screen and reusable design-system component.

## Golden ownership

- Active app golden images live in `app/src/test/snapshots/rendered`. The September 14 batch deliberately moved the app tests to Robolectric native graphics and reviewed 33 actual rendered images. Most older `images` and extensionless baselines are historical. Active recovery/text-editor baselines include `document_recovery.png`, `document_recovery_active_dark.png`, `text_editor.png` and `text_editor_queued_dark.png`. Image-document fixtures were removed with the feature. Do not treat the entire `images` directory as obsolete.

- Generated comparison reports and actual/diff images live under `build/` and are ignored by Git.
- Golden updates require a deliberate review of the image diff against the OpenCloud mobile-web reference; they must not be refreshed incidentally during unrelated changes.

October 1 feedback adds `file_browser_project_space.png` and `file_browser_add_menu.png` under `rendered`. Browser baselines were deliberately reviewed for the requested three-item bottom bar (Favorites, Personal, Spaces), drawer Recents/Offline entries and FAB availability. These host renders do not validate native camera controls or server uploads.

## Commands

From the repository root (PowerShell):

```powershell
# Create or deliberately update baselines.
.\gradlew.bat :app:recordRoborazziDebug

# Compare current output with committed baselines.
.\gradlew.bat :app:verifyRoborazziDebug

# Run the normal unit-test suite, including golden verification.
.\gradlew.bat testDebugUnitTest
```

`verifyRoborazziDebug` fails on missing or mismatched goldens and writes actual/diff images and reports under `app/build/outputs/roborazzi` and `app/build/reports/roborazzi`.

## Required test determinism

Each golden test must set all rendering inputs explicitly:

- fixed device dimensions/qualifiers;
- fixed locale, layout direction, font scale, and API level where relevant;
- no real network, clock, animation, random data, or system dynamic color;
- fixed state supplied through pure UI-state fixtures.

The initial baseline is `FoundationScreenGoldenTest`, rendered at 360×800 dp. New screens require at least compact-phone goldens before they may be considered visually complete. Add 412×915 and font-scale 1.3 variants when the screen contains responsive or dense content.

The app golden classes use `@GraphicsMode(GraphicsMode.Mode.NATIVE)`. The foundation fixture renders the sign-in screen directly, rather than racing asynchronous application startup and recording a loading spinner. Browser account navigation has a callback assertion; account-screen visuals are covered separately by `FeatureGoldenTest`.

The app-shell golden permits a 0.1% changed-pixel threshold solely for known Robolectric host anti-aliasing variance. New goldens should use zero tolerance unless the same host-renderer variance is demonstrated and documented in the test.

## German Settings coverage

`GermanSettingsGoldenTest` adds 360x800 light and 412x915 dark fixtures with font scale 1.3 (`settings_german.png`, `settings_german_large_dark.png`). Both use deterministic German qualifiers and verify the temporary-copy cleanup action remains reachable. The two new images were reviewed without clipped or overlapping content; existing baselines were not replaced. This covers representative translated Settings layout, not camera/system UI or native-device acceptance. `GermanLocaleResourceTest` checks German quantity selection and typed status/password formatting; `scripts/validate-locale-resources.ps1` checks extracted key/placeholder coverage.
Image-document screenshot fixtures were removed with the withdrawn feature on October 1. Historical validation remains in the implementation record.

October 5 test 5 adds reviewed `encrypted_browser`, `vault_biometric_offer`,
`encrypted_preferences`, `permissions_settings` and `temporary_files_settings`
rendered baselines. Settings/Security and active German Settings baselines were
intentionally updated for the requested Security/Data separation. Root rename
text entry is validated with `EncryptedRootRenameInstrumentedTest` because the
Robolectric API 35 dialog layout did not settle; Android 15 completes the same flow.

Test 6 adds reviewed compact `encrypted_space_management`,
`encrypted_folder_sharing` and `encrypted_folder_share_remove` baselines. Existing
unlock/browser/biometric and light/dark/German Settings images were deliberately
updated for the password eye control, root-management button and toggle-only App
lock. All fixtures are synthetic; these renders do not establish live Graph/OCS
write compatibility or physical biometric authentication.

## Test 8 intentional changes

The backup editor now shows source/destination, file type chips, setting switches
and Save/Cancel below the scrollable options. Added light/dark editor baselines
and updated the destination picker backdrop. No unrelated screenshots were
intentionally changed.

## Test 9 intentional changes

Encrypted browsing now follows the standard layout and FAB, with a pencil root
edit action and a folder chooser for copy/move. Reviewed offline browser,
destination chooser and disabled Space management baselines were added. The
biometric offer backdrop follows the updated browser toolbar; its phone-only
warning and recovery reminder remain. Full screenshot verification passed.

## Test 10 intentional changes

Reviewed Material contained primary/secondary actions in encrypted Space/folder
management, normal destination/name forms, members and encrypted preferences.
Three-dot menus retain text-and-icon menu rows. The encrypted image browser fixture
shows a synthetic in-memory thumbnail; copy/move confirms with a filled button.
Separate lifecycle confirmation behavior is tested. No phone/server data is used.

## Test 14 intentional changes

Reviewed the encrypted destination chooser's full-screen browser layout and the
new compact encrypted text reader/editor baselines (`encrypted_text_preview`,
`encrypted_text_editor`). The reader uses the ordinary FilePreviewScreen; the
editor adds its memory-only draft notice. The edit fixture explicitly advances
a rendered frame after UTF-8 text entry before capture. Only these three
baselines were recorded. Native text-entry assertions are also included; these
UI fixtures do not establish live-server save acceptance.

## Test 15 intentional changes

Encrypted browser rows, offline rows, thumbnails and destination selection use the ordinary browser spacing and metadata style, with a full-width encrypted-location banner. Destination selection stays in the browser and uses the shared placement footer. The extra top offline pin becomes a location overflow action. The biometric-offer snapshot includes the same updated background browser layout; the dialog behavior is unchanged.

The encrypted text reader adds Open with. Both text editors use SharedTextEditorScreen, with Save in the top bar and Discard draft at the bottom; encrypted drafts remain volatile. The encrypted editor and reader snapshots were visually reviewed. The reader waits for a completed render frame before capture to avoid recording a partially drawn top bar. Ordinary queued drafts preserve their Check save action and do not offer Discard.

Only these intentional snapshots were recorded. Full verification must pass before accepting the production-signed test APK. This is local UI/security validation, not a claim of phone or live-server acceptance.

Test16 refreshes only `encrypted_preferences`: padded Material card, separate status and contextual biometric-choice action. The screenshot was visually reviewed; other goldens were verified without re-recording.
