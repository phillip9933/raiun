# Raiun 0.9.0 beta

Raiun 0.9.0 beta adds end-to-end encrypted folders and Spaces.

- Unlock with your password or phone biometrics. Keep encrypted files offline; authentication is still required to open them.
- Find saved and previously seen locations in Files and Spaces, including offline. Locations without saved content are unavailable.
- Copy or move within the same encrypted location, with clearer Space management and file controls.
- Preview encrypted images, PDFs and text in memory; scan PDFs or JPEGs directly into an encrypted location. See [beta limits](../README.md#known-beta-limitations) for preview and editing bounds.

Optional “Open with” explains the plaintext handoff and asks first. Raiun grants the selected app read-only access to a temporary file, expires new access after ten minutes and attempts cleanup. The app may retain or copy the file.

Read the [encrypted security review](ENCRYPTED-SECURITY-REVIEW.md) for format limits. It is not an independent penetration test or certification.

Install over an existing release to keep app data. Verify the APK with SHA256SUMS. See [Known beta limitations](../README.md#known-beta-limitations) and the [changelog](../CHANGELOG.md).
