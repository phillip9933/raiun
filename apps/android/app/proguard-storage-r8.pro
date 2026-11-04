# Opt-in R8 validation only: generated AppSettings Protobuf Lite schema ABI.
# protobuf-javalite/protoc 3.25.8 BUILD_MESSAGE_INFO names these exact 14 fields.
# MessageSchema.reflectField finds them by string, then uses Unsafe field offsets.
# Prevent field removal, renaming and type-changing optimization; keep no class, getter,
# builder, parser or probe entrypoint. Reaudit when app_settings.proto changes.
-keepclassmembers class eu.opencloud.android.next.core.datastore.proto.AppSettings {
    int browserLayout_;
    java.lang.String activeAccountId_;
    int cacheRetentionDays_;
    boolean localDiagnosticsEnabled_;
    int appearance_;
    int temporaryCopyRetentionHours_;
    boolean hideFileSize_;
    boolean hideModifiedDate_;
    boolean hideFileExtensions_;
    boolean showHiddenFiles_;
    boolean externalText_;
    boolean externalPdf_;
    boolean externalImages_;
    com.google.protobuf.Internal$ProtobufList pinnedNavigationItems_;
}
