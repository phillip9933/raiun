# Raiun Android 1.3.2

## Fixes

- Fix folders getting stuck while loading, and improve recovery when a copy or move is interrupted.
- Keep accounts on different case-sensitive server paths separate without losing existing account data.
- Keep other file operations available while preparing a document for an external editor.
- Preserve connection settings when rotating the phone and correctly save replacement client certificates.
- Resume account cleanup after an interruption, with a visible pending status and a retry option. Other accounts and recovery files with an unknown owner are preserved.
- Show clearer errors when an action from search results fails.

## Improvements

- Strengthen saved credential handling and reduce sensitive information in diagnostic output.
- Improve protections around encrypted locations in Android's file picker, incoming file sharing and copied sharing links.
- Improve cancellation responsiveness, reduce unnecessary background UI work and update the architecture and testing documentation.

Install over your existing Raiun app to keep its data. This update upgrades the local database; older builds cannot open it afterward.
