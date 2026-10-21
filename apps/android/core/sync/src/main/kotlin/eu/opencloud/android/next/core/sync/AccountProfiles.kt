package eu.opencloud.android.next.core.sync

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.model.cacheIdentity
import eu.opencloud.android.next.core.network.AccountProfileClient
import eu.opencloud.android.next.core.network.OpenCloudApi
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import java.io.File
import java.util.concurrent.TimeUnit

data class ProfileAppearance(
    val name: String,
    val image: Bitmap? = null,
)

/** Only the account's own server supplies avatars. Cache v2 deliberately excludes old third-party images. */
object AccountProfiles {
    private val mutex = Mutex()
    private val changes = MutableStateFlow(0L)
    val revision = changes.asStateFlow()

    suspend fun refreshAppearance(
        context: Context,
        accountId: String,
    ) = withContext(Dispatchers.IO) {
        mutex.withLock {
            preferences(context).edit().remove(accountId).apply()
            changes.value++
        }
    }

    suspend fun clear(
        context: Context,
        accountId: String,
    ) = withContext(Dispatchers.IO) {
        mutex.withLock {
            file(context, accountId).delete()
            File(context.cacheDir, "avatar-${cacheIdentity(accountId)}").delete()
            preferences(context)
                .edit()
                .remove(accountId)
                .remove("name-$accountId")
                .apply()
            changes.value++
        }
    }

    suspend fun details(
        context: Context,
        accountId: String,
    ) = withContext(Dispatchers.IO) {
        val account = account(context, accountId)
        val http = TlsPolicy(context).applyTo(OkHttpClient(), account.serverUrl)
        val auth = WorkerAuthorizationProvider(context).authorization(account)
        val details = AccountProfileClient(http).details(account.serverUrl, auth)
        val personal =
            eu.opencloud.android.next.core.network
                .LibreGraphSpacesClient(http)
                .listSpaces(account.serverUrl, auth)
                .firstOrNull { it.type == "personal" && !it.disabled && !it.deleted }
        details.copy(usedBytes = personal?.quotaUsedBytes, totalBytes = personal?.quotaTotalBytes)
    }

    suspend fun changePhoto(
        context: Context,
        accountId: String,
        uri: Uri?,
    ) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val account = account(context, accountId)
            val client = client(context, account)
            val auth = WorkerAuthorizationProvider(context).authorization(account)
            if (uri == null) {
                client.removePhoto(account.serverUrl, auth)
            } else {
                val bytes =
                    context.contentResolver.openInputStream(uri)?.use { it.readBytesBounded() }
                        ?: error("The selected picture could not be read.")
                client.uploadPhoto(account.serverUrl, auth, profilePhotoJpeg(bytes), "image/jpeg")
            }
            // The server confirmed the mutation. Invalidate all UI avatars and fetch the authoritative result.
            file(context, accountId).delete()
            preferences(context).edit().remove(accountId).apply()
            changes.value++
        }
    }

    suspend fun load(
        context: Context,
        accountId: String,
        refresh: Boolean,
    ): ProfileAppearance =
        withContext(Dispatchers.IO) {
            mutex.withLock {
                val account =
                    FileBrowserDatabase
                        .create(context)
                        .accountDao()
                        .findById(accountId)
                        ?.takeIf { it.isActive } ?: return@withLock ProfileAppearance("")
                val preferences = preferences(context)
                val file = file(context, accountId)
                // Remove the obsolete cache on first use; never display or request a Gravatar.
                File(context.cacheDir, "avatar-${cacheIdentity(accountId)}").delete()
                var name = preferences.getString("name-$accountId", null) ?: account.displayName
                val now = System.currentTimeMillis()
                val age = now - preferences.getLong(accountId, 0)
                if (refresh && (age < 0 || age >= TimeUnit.MINUTES.toMillis(15))) {
                    name = refreshProfile(context, account, file, now) ?: name
                }
                ProfileAppearance(name, decode(file.takeIf(File::exists)?.readBytes()))
            }
        }

    private fun refreshProfile(
        context: Context,
        account: AccountEntity,
        file: File,
        now: Long,
    ): String? =
        try {
            val http = TlsPolicy(context).applyTo(OkHttpClient(), account.serverUrl)
            val auth = WorkerAuthorizationProvider(context).authorization(account)
            val profile = OpenCloudApi(http).profile(account.serverUrl, auth)
            val name = profile.displayName.takeIf(String::isNotBlank) ?: account.displayName
            val bytes = AccountProfileClient(http).photo(account.serverUrl, auth)
            if (bytes == null) {
                file.delete()
            } else {
                requireNotNull(decode(bytes))
                file.writeBytes(bytes)
            }
            preferences(context)
                .edit()
                .putLong(account.id, now)
                .putString("name-${account.id}", name)
                .apply()
            name
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            null // Offline and unsupported servers retain initials or their last server image.
        }

    private fun decode(bytes: ByteArray?): Bitmap? {
        val input = bytes ?: byteArrayOf()
        val options = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(input, 0, input.size, options)
        if (options.outWidth <= 0 || options.outHeight <= 0) return null
        options.inSampleSize = 1
        while (maxOf(options.outWidth, options.outHeight) / options.inSampleSize > 512) options.inSampleSize *= 2
        options.inJustDecodeBounds = false
        return BitmapFactory.decodeByteArray(input, 0, input.size, options)
    }

    private fun java.io.InputStream.readBytesBounded(): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val count = read(buffer)
            if (count < 0) break
            require(output.size() + count <= AccountProfileClient.MAX_PHOTO) { "Choose a picture up to 10 MB." }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private suspend fun account(
        context: Context,
        id: String,
    ): AccountEntity =
        requireNotNull(
            FileBrowserDatabase
                .create(context)
                .accountDao()
                .findById(id)
                ?.takeIf { it.isActive },
        )

    private fun client(
        context: Context,
        account: AccountEntity,
    ) = AccountProfileClient(TlsPolicy(context).applyTo(OkHttpClient(), account.serverUrl))

    private fun preferences(context: Context) =
        context.getSharedPreferences("server-profile-avatars-v2", Context.MODE_PRIVATE)

    private fun file(
        context: Context,
        id: String,
    ) = File(context.cacheDir, "server-avatar-${cacheIdentity(id)}")
}
