# Translations

English defaults live in each module’s `src/main/res/values` directory. Use matching Android string/plural resources rather than branching on language in Kotlin. Use each language’s plural categories (including `many` for French, Spanish and Portuguese; only `other` for Japanese). Preserve numbered format arguments, date-pattern tokens, product names such as Raiun, OpenCloud and Spaces, and Android XML escaping. Do not translate identifiers or resources marked `translatable="false"`.

The app supports these languages:

| Language | Android resources | Language preference | Style |
| --- | --- | --- | --- |
| German | `values-de` | `de` | Informal “du”; preserve existing translations |
| French | `values-fr` | `fr` | Polite “vous”, concise action labels |
| Spanish | `values-es` | `es` | Informal “tú”, broadly understandable vocabulary |
| Portuguese (Portugal) | `values-pt-rPT` | `pt-PT` | European Portuguese, not Brazilian Portuguese |
| Japanese | `values-ja` | `ja` | Natural compact labels and polite explanations |

Settings → Appearance → Language exposes these choices alongside System default and English in the app. AppCompat persists the choice on Android 12 and older; Android 13 and newer use the platform per-app language preference. The supported list is in `feature/settings/src/main/res/xml/locales_config.xml`. The in-app picker reads this same XML and generates native language names using Android’s locale data; there is no separate Kotlin language list. To add a language, add its translations and one locale entry, then include it in CI validation. Preserve the full regional tag when displaying or saving Portuguese.

Native-speaker sign-off is not a release requirement. Users can report wording or layout problems through [GitHub issues](https://github.com/phillip9933/raiun/issues/new). Automated validation and selected screenshots do not establish the accuracy of every phrase. Keep encryption warnings, biometric recovery limitations, external-app plaintext disclosures and backup-versus-sync wording precise; do not shorten away their meaning.

The scanner remains a versioned library. Scanner translations are resource overlays in each app locale directory’s `strings_scanner_sdk.xml`; no scanner implementation or English defaults are copied. The validator reads English definitions from the installed, pinned scanner AAR. When upgrading the SDK, review added or changed strings and the capture/review/save UI.

After installing the pinned scanner SDK, run `scripts/validate-locale-resources.ps1 -Locale <qualifier> -RequireComplete` for each qualifier in the table. CI checks XML and placeholder safety for all five. English fallback remains allowed in CI for future additions; strict completeness is checked when preparing translation updates. Preserve existing local translation work rather than overwriting it during generation.

Check text fit, enlarged fonts, language selection, switching back to System default, plural counts, scanner screens, and security confirmations on a phone. Structural validation alone is not a linguistic or physical-device review.

The local scanner pin is 0.8.0-beta.1. Its scanner UI AAR is byte-identical to 0.7.0, so the existing resource overlays remain applicable; run the validator against the newly pinned cache. OCR is a separate module and is not included in Raiun by this update.
