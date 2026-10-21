package eu.opencloud.android.next.feature.auth

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.datastore.SettingsRepository
import eu.opencloud.android.next.core.designsystem.localizedString
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.model.auth.AuthenticationType
import eu.opencloud.android.next.core.model.auth.NEXT_OIDC_REDIRECT_URI
import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import eu.opencloud.android.next.core.network.OpenCloudApi
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.KeystoreCredentialStore
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import java.security.cert.CertificateException
import javax.net.ssl.SSLHandshakeException
import kotlin.coroutines.cancellation.CancellationException

class AuthViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val tlsPolicy = TlsPolicy(application)
    private val fileStore = FileBrowserStore(FileBrowserDatabase.create(application))
    private val credentialStore = KeystoreCredentialStore(application)
    private val settings = SettingsRepository.create(application)
    private var repository = repositoryFor("")
    private var discovery: DiscoveryResult? = null

    private val mutableState = MutableStateFlow(AuthUiState(isRestoringSession = true))
    val state: StateFlow<AuthUiState> = mutableState.asStateFlow()

    init {
        viewModelScope.launch(Dispatchers.IO) {
            val accounts =
                fileStore.activeAccounts().filter { saved ->
                    hasUsablePersistedCredential(saved, credentialStore, System.currentTimeMillis() / 1000)
                }
            val preferred = settings.settings.first().activeAccountId
            val account = accounts.firstOrNull { it.id == preferred } ?: accounts.firstOrNull()
            settings.setActiveAccountId(account?.id)
            mutableState.value =
                mutableState.value.copy(
                    activeAccountId = account?.id,
                    isRestoringSession = false,
                )
        }
    }

    fun discover(
        serverInput: String,
        staticClientId: String? = null,
    ) = launchAuth {
        mutableState.value = mutableState.value.copy(isLoading = true, error = null)
        val result = repositoryFor(serverInput).discover(serverInput, staticClientId)
        discovery = result
        repository = repositoryFor(result.serverUrl)
        mutableState.value =
            mutableState.value.copy(
                isLoading = false,
                serverUrl = result.serverUrl,
                authenticationMode =
                    if (result.oidcConfiguration ==
                        null
                    ) {
                        AuthenticationMode.BASIC
                    } else {
                        AuthenticationMode.OIDC
                    },
                oidcConfiguration = result.oidcConfiguration,
            )
    }

    fun loginBasic(
        username: String,
        password: String,
    ) = launchAuth {
        val serverUrl = requireNotNull(discovery).serverUrl
        mutableState.value = mutableState.value.copy(isLoading = true, error = null)
        setSession(repository.loginBasic(serverUrl, username, password))
    }

    fun loginBasicDirect(
        serverUrl: String,
        username: String,
        password: String,
    ) = launchAuth {
        require(serverUrl.isNotBlank() && username.isNotBlank() && password.isNotBlank()) {
            getApplication<Application>().localizedString(R.string.auth_required_fields)
        }
        val normalized =
            eu.opencloud.android.next.core.network
                .EndpointPolicy()
                .endpoint(
                    if ("://" in
                        serverUrl
                    ) {
                        serverUrl.trim()
                    } else {
                        "https://${serverUrl.trim()}"
                    },
                    allowQuery = false,
                ).toString()
                .trimEnd('/')
        repository = repositoryFor(normalized)
        mutableState.value = mutableState.value.copy(serverUrl = normalized, isLoading = true, error = null)
        setSession(repository.loginBasic(normalized, username, password))
    }

    @Suppress("TooGenericExceptionCaught")
    fun beginOidc(): String? {
        val configuration = mutableState.value.oidcConfiguration ?: return null
        return try {
            val request = repository.beginPkce(configuration)
            credentialStore.savePendingLogin(
                eu.opencloud.android.next.core.security.PendingOidcLogin(
                    requireNotNull(mutableState.value.serverUrl),
                    configuration,
                    request,
                    System.currentTimeMillis(),
                ),
            )
            request.authorizationUrl
        } catch (exception: CancellationException) {
            throw exception
        } catch (exception: Exception) {
            mutableState.value =
                mutableState.value.copy(error = exception.toAuthError(getApplication(), certificateErrorMessage()))
            null
        }
    }

    fun completeOidcCallback(callback: String) =
        launchAuth {
            val callbackUri = android.net.Uri.parse(callback)
            require(
                callbackUri.scheme == NEXT_OIDC_REDIRECT_URI.substringBefore("://") &&
                    callbackUri.authority == "oauth",
            )
            require(callbackUri.path.isNullOrEmpty() && callbackUri.fragment == null)
            val states = callbackUri.getQueryParameters("state")
            require(states.size == 1 && states.single().isNotBlank())
            val pending = credentialStore.consumePendingLogin(states.single(), System.currentTimeMillis())
            if (pending == null) {
                mutableState.value =
                    mutableState.value.copy(
                        isLoading = false,
                        error =
                            getApplication<Application>().localizedString(R.string.auth_oidc_session_expired),
                    )
                return@launchAuth
            }
            val codes = callbackUri.getQueryParameters("code")
            if (callbackUri.getQueryParameter("error") != null || codes.size != 1 || codes.single().isBlank()) {
                mutableState.value =
                    mutableState.value.copy(
                        isLoading = false,
                        error =
                            getApplication<Application>().localizedString(R.string.auth_sign_in_cancelled),
                    )
                return@launchAuth
            }
            repository = repositoryFor(pending.serverUrl)
            mutableState.value = mutableState.value.copy(isLoading = true, error = null, serverUrl = pending.serverUrl)
            setSession(
                repository.completePkce(
                    pending.serverUrl,
                    pending.configuration,
                    codes.single(),
                    pending.request.codeVerifier,
                ),
            )
        }

    fun approveCertificatePin(pin: String) {
        val serverUrl = mutableState.value.serverUrl ?: return
        val host = java.net.URI(serverUrl).host ?: return
        tlsPolicy.approvePin(host, pin)
        mutableState.value = mutableState.value.copy(error = null)
    }

    fun switchAccount(accountId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            settings.setActiveAccountId(accountId)
            mutableState.value = mutableState.value.copy(activeAccountId = accountId, session = null)
        }
    }

    fun accountRemoved(nextAccountId: String?) {
        mutableState.value = mutableState.value.copy(activeAccountId = nextAccountId, session = null)
    }

    private fun repositoryFor(serverUrl: String): AuthRepository {
        val baseClient = OkHttpClient.Builder().followRedirects(false).build()
        return AuthRepository(
            OpenCloudApi(tlsPolicy.applyTo(baseClient, serverUrl)),
            credentialStore,
            eu.opencloud.android.next.core.security.AccountSessions
                .get(getApplication()),
        )
    }

    private suspend fun setSession(session: AuthenticatedSession) {
        fileStore.saveAccount(session.account, session.capabilities, session.oidcConfiguration)
        settings.setActiveAccountId(session.account.id)
        mutableState.value =
            mutableState.value.copy(
                session = session,
                activeAccountId = session.account.id,
                isLoading = false,
                isRestoringSession = false,
            )
    }

    @Suppress("TooGenericExceptionCaught")
    private fun launchAuth(block: suspend () -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                block()
            } catch (exception: CancellationException) {
                throw exception
            } catch (exception: Exception) {
                // Network, protocol, and TLS failures are intentionally mapped to one safe UI error boundary.
                mutableState.value =
                    mutableState.value.copy(
                        isLoading = false,
                        error = exception.toAuthError(getApplication(), certificateErrorMessage()),
                    )
            }
        }
    }

    private fun certificateErrorMessage() =
        getApplication<Application>().localizedString(R.string.auth_certificate_untrusted)
}

data class AuthUiState(
    val serverUrl: String? = null,
    val authenticationMode: AuthenticationMode? = null,
    val oidcConfiguration: OidcConfiguration? = null,
    val isLoading: Boolean = false,
    val error: String? = null,
    val session: AuthenticatedSession? = null,
    val activeAccountId: String? = null,
    val isRestoringSession: Boolean = false,
)

enum class AuthenticationMode {
    BASIC,
    OIDC,
}

internal fun Throwable.toAuthError(): String =
    toAuthError(
        "The server certificate could not be trusted. " +
            "Review the certificate fingerprint before approving an explicit pin.",
    )

internal fun Throwable.toAuthError(
    context: Context,
    certificateErrorMessage: String,
): String =
    when {
        this is SSLHandshakeException || cause is SSLHandshakeException || cause is CertificateException ->
            certificateErrorMessage
        this is eu.opencloud.android.next.core.network.OpenCloudException -> error.safeMessage(context)
        else -> toOpenCloudError().safeMessage(context)
    }

internal fun Throwable.toAuthError(certificateErrorMessage: String): String =
    when {
        this is SSLHandshakeException || cause is SSLHandshakeException || cause is CertificateException ->
            certificateErrorMessage
        this is eu.opencloud.android.next.core.network.OpenCloudException -> error.safeMessage()
        else -> toOpenCloudError().safeMessage()
    }

internal fun hasUsablePersistedCredential(
    account: AccountEntity,
    credentialStore: eu.opencloud.android.next.core.security.CredentialStore,
    nowEpochSeconds: Long,
): Boolean =
    when (account.authenticationType) {
        AuthenticationType.BASIC.name -> credentialStore.readBasicPassword(account.id) != null
        AuthenticationType.OIDC.name -> credentialStore.readTokens(account.id).isUsable(nowEpochSeconds)
        else -> false
    }

private fun AuthTokens?.isUsable(nowEpochSeconds: Long): Boolean =
    this != null && (expiresAtEpochSeconds > nowEpochSeconds || !refreshToken.isNullOrBlank())
