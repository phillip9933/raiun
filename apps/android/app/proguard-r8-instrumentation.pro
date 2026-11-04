# Opt-in instrumentation target only, NEVER part of standalone shrinking rules.
# AndroidX Test shares this dependency with the target APK; AGP omits its duplicate
# from the test APK, so the runner needs this public tracing API to remain available.
-keep,allowoptimization class androidx.tracing.Trace {
    public static void beginSection(java.lang.String);
    public static void endSection();
    public static boolean isEnabled();
    public static void beginAsyncSection(java.lang.String,int);
    public static void endAsyncSection(java.lang.String,int);
    public static void setCounter(java.lang.String,int);
    public static void forceEnableAppTracing();
}
# Existing archive-verifier tests reflect into this INTERNAL library type. Its
# retention proves only that test path, not standalone production reachability.
-keep,allowoptimization class io.github.phillip9933.appupdater.UpdateApkVerifier {
    <init>(android.content.Context,io.github.phillip9933.appupdater.UpdatePolicy);
    *** verify*(java.io.File,io.github.phillip9933.appupdater.AndroidUpdateRelease,java.lang.String);
}
# AndroidX TestDirCalculator invokes this shared Kotlin facade from the test APK.
# The normal app can inline/remove it; retain only the runner's exact ABI here.
-keep,allowoptimization class kotlin.LazyKt {
    public static kotlin.Lazy lazy(kotlin.jvm.functions.Function0);
}
# The separate test APK supplies coroutine subclasses. Static reference tracing
# cannot see target-to-test virtual callbacks; preserve this exact override ABI.
-keep class kotlin.coroutines.jvm.internal.BaseContinuationImpl {
    public kotlin.coroutines.Continuation create(kotlin.coroutines.Continuation);
    public kotlin.coroutines.Continuation create(java.lang.Object,kotlin.coroutines.Continuation);
    protected java.lang.Object invokeSuspend(java.lang.Object);
}
# Compose's separate coroutine test runtime calls this default-interface helper.
# Its original method name is part of that cross-APK callback contract.
-keep class kotlin.coroutines.ContinuationInterceptor$DefaultImpls {
    public static void releaseInterceptedContinuation(kotlin.coroutines.ContinuationInterceptor,kotlin.coroutines.Continuation);
}
