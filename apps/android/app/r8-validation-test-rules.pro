# Test APK only: these missing Error Prone annotations are compile-time contracts in
# AndroidX Test, not executable runtime classes. Do not copy this into app rules.
-dontwarn com.google.errorprone.annotations.CanIgnoreReturnValue
-dontwarn com.google.errorprone.annotations.MustBeClosed
