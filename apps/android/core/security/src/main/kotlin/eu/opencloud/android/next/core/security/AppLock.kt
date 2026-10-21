package eu.opencloud.android.next.core.security

import android.app.KeyguardManager
import android.content.Context
import android.os.SystemClock

/** Policy is durable; authentication grants are process-local and never restored after a restart. */
class AppLock(
    context: Context,
) {
    private val context = context.applicationContext
    val preferences = this.context.getSharedPreferences("app-lock", Context.MODE_PRIVATE)
    val biometricEnabled: Boolean get() = preferences.getBoolean("biometric", false)
    val biometricAvailable: Boolean get() =
        androidx.biometric.BiometricManager
            .from(context)
            .canAuthenticate(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS

    fun setBiometricEnabled(value: Boolean) {
        check(canOpenApp())
        check(!value || biometricAvailable)
        check(preferences.edit().putBoolean("biometric", value).commit())
    }

    val enabled: Boolean get() = preferences.getBoolean("enabled", false)
    val protectDocuments: Boolean get() = enabled && preferences.getBoolean("documents", true)
    val timeoutMinutes: Int get() = preferences.getInt("timeout", 0).takeIf { it in listOf(0, 1, 5, 30) } ?: 0
    val deviceSecure: Boolean get() = context.getSystemService(KeyguardManager::class.java).isDeviceSecure
    private val deviceLocked: Boolean get() = context.getSystemService(KeyguardManager::class.java).isDeviceLocked

    fun canOpenApp(): Boolean =
        !enabled || (!deviceLocked && session.appAllowed(SystemClock.elapsedRealtime(), timeoutMinutes))

    fun canOpenDocuments(): Boolean =
        !protectDocuments || (!deviceLocked && session.documentsAllowed(SystemClock.elapsedRealtime()))

    /** Explicit locking permanently revokes an in-app action, including after reauthentication. */
    fun beginAppAction(): () -> Boolean {
        check(canOpenApp()) { "Device authentication is required." }
        val revision = session.readRevision()
        return { session.readRevision() == revision && canOpenApp() }
    }

    /** A single already-authorized read can finish after the picker lease expires. Screen-off revokes it. */
    fun beginDocumentRead(): () -> Boolean {
        check(canOpenDocuments()) { "Device authentication is required." }
        val revision = session.readRevision()
        return { session.readRevision() == revision && (!protectDocuments || !deviceLocked) }
    }

    /** An editor may outlive the picker lease; an explicit lock permanently revokes this edit's grant. */
    fun beginDocumentEdit(): () -> Boolean {
        check(canOpenDocuments()) { "Device authentication is required." }
        val revision = session.readRevision()
        return { session.readRevision() == revision && (!protectDocuments || !deviceLocked) }
    }

    fun foreground() = session.foreground(SystemClock.elapsedRealtime(), timeoutMinutes)

    fun background() = session.background(SystemClock.elapsedRealtime())

    fun authenticated() = session.authenticate(SystemClock.elapsedRealtime())

    fun lock() = session.clear()

    /** An explicit Open/Open with action in the unlocked app authorizes the receiving viewer. */
    fun allowDocumentOpenFromApp() {
        if (!canOpenApp()) throw SecurityException("Unlock Raiun before opening a file.")
        if (protectDocuments) session.allowDocuments(SystemClock.elapsedRealtime())
    }

    fun setEnabled(value: Boolean) {
        check(
            deviceSecure && session.documentsAllowed(SystemClock.elapsedRealtime()),
        ) { "Device authentication is required." }
        check(preferences.edit().putBoolean("enabled", value).commit())
        notifyProvider()
    }

    fun setProtectDocuments(value: Boolean) {
        check(canOpenApp())
        check(preferences.edit().putBoolean("documents", value).commit())
        notifyProvider()
    }

    fun setTimeout(minutes: Int) {
        check(canOpenApp())
        require(minutes in listOf(0, 1, 5, 30))
        check(preferences.edit().putInt("timeout", minutes).commit())
    }

    fun notifyProvider() {
        context.contentResolver.notifyChange(
            android.provider.DocumentsContract.buildRootsUri("${context.packageName}.documents"),
            null,
        )
    }

    companion object {
        private val session = LockSession()
        const val AUTH_ACTIVITY = "eu.opencloud.android.next.DeviceUnlockActivity"
    }
}

internal class LockSession {
    private var authenticated = false
    private var foreground = false
    private var backgroundAt = 0L
    private var documentDeadline = 0L
    private var freshUntil = 0L
    private var revision = 0L

    @Synchronized fun readRevision(): Long = revision

    @Synchronized fun authenticate(now: Long) {
        authenticated = true
        documentDeadline = now + 60_000L
        freshUntil = documentDeadline
        backgroundAt = now
    }

    @Synchronized fun appAllowed(
        now: Long,
        timeoutMinutes: Int,
    ): Boolean = authenticated && (foreground || now - backgroundAt < timeoutMinutes * 60_000L || now < freshUntil)

    @Synchronized fun documentsAllowed(now: Long): Boolean = authenticated && now < documentDeadline

    @Synchronized fun allowDocuments(now: Long) {
        check(authenticated)
        documentDeadline = now + 60_000L
    }

    @Synchronized fun foreground(
        now: Long,
        timeoutMinutes: Int,
    ) {
        if (!appAllowed(now, timeoutMinutes)) authenticated = false
        foreground = true
        freshUntil = 0L
    }

    @Synchronized fun background(now: Long) {
        foreground = false
        freshUntil = 0L
        backgroundAt = now
    }

    @Synchronized fun clear() {
        revision++
        authenticated = false
        documentDeadline = 0L
    }
}
