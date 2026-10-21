# Raiun 0.8.0-beta.1

This update adds cloud folders for other apps, file viewers, version history and home screen folder shortcuts. It also brings shared folders closer to how Personal files and Spaces work.

## What's new

- Other apps can select Raiun in Android's file picker and use a folder in Personal files or a writable Space for backups. Creating folders, writing files and restoring backups were tested with Kura.
- View text files, PDFs and images inside Raiun. Text files open in the viewer first, with an Edit option there. File opening preferences have their own settings page. Open with still lets you choose another app.
- View and restore older file versions when the server supports it. Saved text drafts now warn when the server file has changed, including after a restore.
- Add folders to the home screen, including shared folders. Choose a folder color or import an image using the standard file picker. Pinch to zoom and drag to crop custom images.
- View server notifications in the app and mark them as read.
- View and manage Space members where your account has permission. Download a Space, pull down to refresh the list and create a Space from the overview's plus button.

## Fixes and cleanup

- Fixed Shared with me failing to load on some servers.
- Large shared files now use the normal download queue and progress display when opened. Shared folders also have download, shortcut and details actions.
- Made layout and refresh controls consistent across Shared with me, Shared by me and Public links.
- Check for a newer server copy before opening downloaded Personal or Space files in another app.
- Cleaned up the text editor and grouped settings under Personalization and Data and Security.
- Removed Open in web app and the separate Edit text menu item.
- Changed network checks so a reachable local server should work on Wi-Fi without internet. This still needs testing on a device in that setup.

## Things to know

- This is still a beta. Android 8 or newer is required. Install over the previous Raiun version to keep your account and settings.
- Backup apps need to support Android's folder picker. Incoming shared folders are read-only through that picker. An app may say its backup is finished before Raiun finishes uploading; check Transfers.
- Version history, notifications and Space management depend on server support and your permissions. Notifications refresh while the app is open; background push notifications are not included.
- End-to-end encrypted Spaces are not supported. Some actions available on the web are still missing in the app.
- Large transfers can still need a retry after switching networks. Shared files need a folder refresh to pick up changed versions.

The APK uses the same signing certificate as the previous release. Checksums, the public certificate, license and source are attached.
