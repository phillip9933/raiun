# Raiun 0.9.1 beta

This beta improves scans, automatic backups, previews and download safety.

- The updated document scanner makes saved JPEGs and PDFs sharper, improves paper and shadow cleanup, and warns about poor capture quality. You can compare filters before saving; Original is available when you need to preserve faint marks.
- Choose backup destinations from Personal, Spaces, or writable folders shared with you. Existing backups keep their settings and local originals.
- Choose a date pattern for camera and folder backups, such as `[YYYY]/[MM]` or `[YYYY]/[MMM]/[DD]`. Photos and videos use their capture date when available. Other files use Android's provider-added date when available, then the file's modified date. If no usable date is available, Raiun puts the upload in an `Undated` folder. Backups upload copies and leave local originals in place.
- Video thumbnails can appear for ordinary and encrypted files when the server or local file provides a supported preview. Raiun falls back to the regular file icon when it cannot make a thumbnail.
- Large encrypted previews use temporary encrypted storage instead of a fixed file-size cutoff. Large text files can be viewed and edited in sections. Storage space, file format and device decoder limits still apply.
- An upload conflict remains available after reopening Raiun and can be resolved while browsing a different folder.
- Improved protection against oversized server responses and incoming shares using too much phone storage. Shared files start copying after you confirm Upload.
- Raiun checks supported server checksums before making ordinary or received-share downloads available, including resumed downloads. When a server does not provide a supported checksum, the existing size and version checks still apply.

Encrypted folders and Spaces use a Web-compatible format. As described in the [encrypted security review](ENCRYPTED-SECURITY-REVIEW.md), the format does not authenticate filenames or a complete file manifest. Read the [known beta limitations](../README.md#known-beta-limitations) before relying on the app for important data.

Install over an existing Raiun release to keep app data. Verify the downloaded APK against the attached `SHA256SUMS` file. See the [release procedure](RELEASING.md) and [changelog](../CHANGELOG.md).
