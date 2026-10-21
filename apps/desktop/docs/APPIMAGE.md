# Linux AppImage

The AppImage is an additional Linux x86_64 package for Desktop 0.7.0-beta.1.
Download it from the [Linux beta release](https://github.com/phillip9933/raiun/releases/tag/desktop-v0.7.0-beta.1) and verify it against the attached `SHA256SUMS`.

Save the AppImage in a permanent location, such as `~/Applications`, then make it executable and run it:

```sh
chmod +x raiun-desktop-0.7.0-beta.1-linux-x86_64.AppImage
./raiun-desktop-0.7.0-beta.1-linux-x86_64.AppImage
```

This package targets Ubuntu 24.04-era Linux systems (glibc 2.39 or newer). It includes the Desktop interface, background agent, command-line tool and bundled runtime libraries. A working desktop session and Secret Service keyring are needed for persistent sign-in. Cloud-drive mounting still needs the system's FUSE 3 support and `fusermount3`; the AppImage does not install privileged system components.

If the AppImage runtime reports that FUSE is unavailable, try its extract-and-run mode:

```sh
./raiun-desktop-0.7.0-beta.1-linux-x86_64.AppImage --appimage-extract-and-run
```

Extract-and-run avoids the AppImage runtime mount; it does not replace FUSE 3 for Raiun's cloud drive.

Real OpenCloud accounts work normally. The AppImage uses the same account, settings, keyring and recovery locations as the tarball installation. Quit an existing Raiun instance normally before switching packages. Switching packages does not require logging out or uninstalling your existing configuration.

Browser sign-in uses a local loopback callback. Desktop-menu integration and `raiun://` encrypted-location links require registering the AppImage with your desktop; the AppImage itself is not a system-wide installer.

Start-at-login is opt-in. Keep the AppImage at the same path after enabling it; if you move it, disable and re-enable that setting from the new location. It starts the saved AppImage rather than a temporary mounted executable.

The existing tarball remains available. The companion AppImage has an additional packaging revision, including the AppImage startup-path handling. Its build-source and dependency inventory identify that revision; the original tarball and release tag are preserved.

See the app [README](../README.md) for beta limitations and installation alternatives.
