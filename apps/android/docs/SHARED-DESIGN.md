# Shared design and Android mapping

Android's native theme maps the frozen Raiun shared design draft v1 reviewed for [issue #42](https://github.com/phillip9933/raiun/issues/42). The reference snapshots and their identities are recorded in the project container at `outputs/android-style-review-20261028/reference-identities.json`:

| Reference | SHA-256 |
| --- | --- |
| `DESIGN-SYSTEM.md` | `9ca0c0ce900b9e392e536cea2a341ee07781775d10149a953bf8ed7289ab52c3` |
| `tokens.json` | `45ec7942ce332805ae72b70e36773b9196b3532deac6eed192b06b9609fb3c5d` |
| `REVIEW-TEMPLATE.md` | `74e69d7ed4eedb8097ec25b545e2dd107908b5f477dad63b6b6e4a50e862ea7d` |

This is an explicit Android mapping of a draft, not an automatic dependency on live Desktop source. Changes to the shared guide require a separate native review. Android retains Material components, platform fonts and native behavior; brand marks, document paper and custom resource icon colors keep their existing identity.

`OpenCloudTheme` defines light and dark Material roles for canvas, surface, inset, text, primary and error colors, including explicit container and inverse roles. `LocalOpenCloudExtendedColors` supplies chrome, success, warning, info and a quiet decorative border where Material roles alone do not express the intended use. Both Material outline roles use stronger native control-border colors than the draft's quiet border, so outlined controls remain visible against neutral surfaces. The design-system divider wrappers use the quiet border instead; it is decorative and should not identify an interactive control.

Account identity uses the draft's eight color families. Automatic selection stays deterministic from the stable account ID; users may instead choose a named color in Account information → Account color. The choice is stored locally per account, without changing server profile information, account identity, credentials or photo. Removing the account clears its local choice.

Toolbars retain normal Material light/dark surfaces and platform insets. Account color appears as a slim avatar ring, a small account-settings swatch and a softly tinted selected account card. The ring has a lighter tone on dark surfaces, while labels retain the theme's normal foreground colors. The picker previews both themes before Save; Cancel discards the draft. These choices replace the earlier full-color toolbar/card experiment at the owner's request.

Accents can coincide between accounts, so names, server context and explicit selection controls remain authoritative. The existing account button exposes sanitized account/server context to accessibility services and opens account information; there is no extra identity row.

Contrast tests check specified theme foregrounds and control outlines against neutral surfaces. They are targeted checks, not an overall accessibility certification. Platform accessibility, focus, font scaling, representative layouts and privacy or destructive states still need appropriate native review.
