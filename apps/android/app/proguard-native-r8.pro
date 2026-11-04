# JNI / reflection ABI for the opt-in R8 validation candidate only.
# These exact names and descriptors come from pinned native source + artifact bytecode.
# Keep Android's default native-method rules: they preserve surviving Java -> JNI
# symbol names, including JNA Native.register's surviving Lazysodium bindings.
# Do not replace this inventory with package keeps or blanket missing-class warnings.
# Reaudit when JNA 5.17.0, Lazysodium Android 5.2.0, OpenCV 4.12.0 or
# ONNX Runtime Android 1.24.1 changes. Runtime acceptance remains separate.
#
# JNA: https://github.com/java-native-access/jna/blob/5.17.0/native/dispatch.c
# Native.initIDs eagerly resolves these declarations, including unused conversions.
-keep,includedescriptorclasses,allowoptimization class com.sun.jna.Pointer {
    public <init>(long);
    long peer;
}
-keep,includedescriptorclasses,allowoptimization class com.sun.jna.Native {
    private static void dispose();
    static com.sun.jna.NativeMapped fromNative(java.lang.Class,java.lang.Object);
    static com.sun.jna.NativeMapped fromNative(java.lang.reflect.Method,java.lang.Object);
    static java.lang.Class nativeType(java.lang.Class);
    static java.lang.Object toNative(com.sun.jna.ToNativeConverter,java.lang.Object);
    static java.lang.Object fromNative(com.sun.jna.FromNativeConverter,java.lang.Object,java.lang.reflect.Method);
}
-keep,includedescriptorclasses,allowoptimization class com.sun.jna.Structure {
    com.sun.jna.Pointer getTypeInfo();
    static com.sun.jna.Structure newInstance(java.lang.Class,long);
    public void autoRead();
    public void autoWrite();
    com.sun.jna.Pointer memory;
    long typeInfo;
}
-keep,allowoptimization interface com.sun.jna.Structure$ByValue
-keep,allowoptimization interface com.sun.jna.Callback
-keep,includedescriptorclasses,allowoptimization class com.sun.jna.CallbackReference {
    static com.sun.jna.Callback getCallback(java.lang.Class,com.sun.jna.Pointer,boolean);
    static com.sun.jna.Pointer getFunctionPointer(com.sun.jna.Callback,boolean);
    static com.sun.jna.Pointer getNativeString(java.lang.Object,boolean);
    static java.lang.ThreadGroup initializeThread(com.sun.jna.Callback,com.sun.jna.CallbackReference$AttachOptions);
}
-keep,includedescriptorclasses,allowoptimization class com.sun.jna.CallbackReference$AttachOptions {
    public boolean daemon;
    public boolean detach;
    public java.lang.String name;
}
-keep,allowoptimization class com.sun.jna.WString {
    public <init>(java.lang.String);
}
-keep,allowoptimization interface com.sun.jna.NativeMapped {
    public java.lang.Object toNative();
}
-keep,allowoptimization class com.sun.jna.IntegerType {
    long value;
}
-keep,includedescriptorclasses,allowoptimization class com.sun.jna.PointerType {
    com.sun.jna.Pointer pointer;
}
-keep,allowoptimization class com.sun.jna.JNIEnv
-keep,allowoptimization interface com.sun.jna.Native$ffi_callback {
    public void invoke(long,long,long);
}
-keep,allowoptimization interface com.sun.jna.FromNativeConverter {
    public java.lang.Class nativeType();
}
-keep,includedescriptorclasses,allowoptimization class com.sun.jna.Structure$FFIType$FFITypes {
    static com.sun.jna.Pointer ffi_type_void;
    static com.sun.jna.Pointer ffi_type_float;
    static com.sun.jna.Pointer ffi_type_double;
    static com.sun.jna.Pointer ffi_type_longdouble;
    static com.sun.jna.Pointer ffi_type_uint8;
    static com.sun.jna.Pointer ffi_type_sint8;
    static com.sun.jna.Pointer ffi_type_uint16;
    static com.sun.jna.Pointer ffi_type_sint16;
    static com.sun.jna.Pointer ffi_type_uint32;
    static com.sun.jna.Pointer ffi_type_sint32;
    static com.sun.jna.Pointer ffi_type_uint64;
    static com.sun.jna.Pointer ffi_type_sint64;
    static com.sun.jna.Pointer ffi_type_pointer;
}
# Structure.java FFIType uses FieldOrder strings to discover its public layout;
# Structure.newInstance -> Klass.newInstance also reflects its default constructor.
# NativeMappedConverter reflects size_t's default constructor.
-keepattributes RuntimeVisibleAnnotations
-keep,allowoptimization @interface com.sun.jna.Structure$FieldOrder {
    public java.lang.String[] value();
}
# The field types are part of the reflective layout, so keep their class identities.
# Explicitly keep this annotated class: R8 full mode otherwise removes FieldOrder.
-keep,includedescriptorclasses,allowoptimization class com.sun.jna.Structure$FFIType {
    public <init>();
    public com.sun.jna.Structure$FFIType$size_t size;
    public short alignment;
    public short type;
    public com.sun.jna.Pointer elements;
}
# Klass.newInstance invokes a public constructor on package-private FFIType.
# Keep this exact caller in com.sun.jna and prevent inlining/relocation: moving
# the reflective call to another package changes Java's constructor access check.
-keep class com.sun.jna.Klass {
    public static java.lang.Object newInstance(java.lang.Class);
}
-keepclassmembers,allowoptimization class com.sun.jna.Structure$FFIType$size_t {
    public <init>();
}
# dispatch.c throwByName uses ELastError from dispatch.h on last-error paths.
-keep,allowoptimization class com.sun.jna.LastErrorException {
    public <init>(java.lang.String);
}
# OpenCV4.12.0 Mat.cpp throwJavaException invokes FindClass then ThrowNew.
-keep,allowoptimization class org.opencv.core.CvException {
    public <init>(java.lang.String);
}
# JNA5.17.0 native/callback.c handle_exception late-path string lookup.
-keepclassmembers,includedescriptorclasses,allowoptimization class com.sun.jna.Native {
    static com.sun.jna.Callback$UncaughtExceptionHandler callbackExceptionHandler;
}
-keep,includedescriptorclasses,allowoptimization interface com.sun.jna.Callback$UncaughtExceptionHandler {
    public void uncaughtException(com.sun.jna.Callback,java.lang.Throwable);
}

# CallbackReference.java reflects CallbackProxy.callback(Object[]) on initialization.
-keepclassmembers,allowoptimization interface com.sun.jna.CallbackProxy {
    public java.lang.Object callback(java.lang.Object[]);
}

# ONNX Runtime v1.24.1:
# java/src/main/native/OrtJniUtil.c creates metadata/value wrappers and exceptions.
# java/src/main/native/ai_onnxruntime_OrtSession.c creates NodeInfo and model metadata.
# Preserve only the exact native-created classes/constructors and descriptor types;
# Java-callable inference methods and their native methods use normal reachability
# plus the Android default native-name rule. No scanner or inference entrypoint keep.
-keep,includedescriptorclasses,allowoptimization class ai.onnxruntime.TensorInfo {
    <init>(long[],java.lang.String[],int);
}
-keep,includedescriptorclasses,allowoptimization class ai.onnxruntime.NodeInfo {
    public <init>(java.lang.String,ai.onnxruntime.ValueInfo);
}
-keep,includedescriptorclasses,allowoptimization class ai.onnxruntime.OnnxTensor {
    <init>(long,long,ai.onnxruntime.TensorInfo);
}
-keep,allowoptimization class ai.onnxruntime.OrtException {
    public <init>(int,java.lang.String);
}
# Other exact native return wrappers are retained for native's type-dispatch paths,
# including error paths. The bundled document model currently returns dense tensors.
-keep,allowoptimization class ai.onnxruntime.MapInfo {
    <init>(int,int,int);
}
-keep,includedescriptorclasses,allowoptimization class ai.onnxruntime.SequenceInfo {
    <init>(int,int);
    <init>(int,ai.onnxruntime.MapInfo);
}
-keep,includedescriptorclasses,allowoptimization class ai.onnxruntime.OnnxMap {
    <init>(long,long,ai.onnxruntime.MapInfo);
}
-keep,includedescriptorclasses,allowoptimization class ai.onnxruntime.OnnxSequence {
    <init>(long,long,ai.onnxruntime.SequenceInfo);
}
-keep,includedescriptorclasses,allowoptimization class ai.onnxruntime.OnnxSparseTensor {
    <init>(long,long,int,ai.onnxruntime.TensorInfo);
}
-keep,allowoptimization class ai.onnxruntime.OnnxModelMetadata {
    <init>(java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,long,java.lang.String[]);
}
