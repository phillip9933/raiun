# Raiun Android 1.3.3

## Fixes

- Keep unrecognized transfers visible for attention without automatically retrying them.
- Require a successful download before opening cached content.
- Prevent background transfers from starting for unavailable or removing accounts.

## Improvements

- Add **Open in web app** for the server's configured document editors, alongside local **Open with**. Editing and collaboration depend on the server's supported providers.
- Strengthen saved sign-in protection while migrating readable existing records.
- On Android 15 and newer, verify the sending app's read access to each incoming shared file. Older Android versions retain their existing sharing behavior.

Install over your existing Raiun app to keep its data. New saved sign-in records cannot be read by older builds; downgrade is unsupported.
