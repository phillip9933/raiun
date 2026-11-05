# Raiun Android 1.5.0

## Fixes

- Prevent delayed folder listings, search results and status messages from appearing in another account after switching accounts.
- Keep old copy/move results and conflict prompts from carrying over after leaving and returning to a folder.
- Fix backup destination browsing getting stuck when reopening the same folder, and clear the previous account's selection when switching accounts.
- Keep a newly unlocked encrypted folder or Space open when a resumed upload is cancelled.
- Prevent delayed unlock checks and failed “Remember on this phone” requests from interfering with a newer encrypted session or its unlock setup.

## Improvements

- Remove unnecessary diagnostic lookups when reopening encrypted folders and Spaces with a remembered key, while retaining the existing security checks.
- Reorganize file browsing and encrypted-location handling into smaller, focused components to make future maintenance easier.

Requires Android 8.0/API 26 or newer. Install over an existing Raiun app to keep its app data.
