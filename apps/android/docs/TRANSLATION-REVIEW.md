# Translation feedback

German, French, Spanish, European Portuguese and Japanese use standard Android resources with English fallback. Native-speaker sign-off is not a release requirement. Automated XML, placeholder, plural and resource-completeness checks remain part of translation validation; they do not prove every phrase is correct.

## Reporting a problem

[Open a GitHub issue](https://github.com/phillip9933/raiun/issues/new) for unclear wording, a wrong translation or clipped text. Include:

- App version and selected language.
- The screen and wording affected; a screenshot is useful if it contains no private information.
- A suggested correction, if available.
- Android version and font/display size when reporting a layout issue.

Security warnings and data-loss wording deserve particular care. Reports are welcome without a full language review or reviewer sign-off.

## Maintaining translations

Follow [the translation guide](TRANSLATING.md), preserve placeholders and Android plural rules, and run resource validation after changes. Check affected screens for wrapping, reachable controls, accessibility and English fallback. Broader language and device checks are useful voluntary contributions, not release gates.
