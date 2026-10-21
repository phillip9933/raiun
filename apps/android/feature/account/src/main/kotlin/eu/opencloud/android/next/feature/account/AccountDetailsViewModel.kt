package eu.opencloud.android.next.feature.account

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import eu.opencloud.android.next.core.designsystem.localizedString
import eu.opencloud.android.next.core.network.ServerAccountProfile
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.AccountProfiles
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class AccountDetailsState(
    val profile: ServerAccountProfile? = null,
    val loading: Boolean = false,
    val saving: Boolean = false,
    val error: String? = null,
)

// Presentation boundary: cancellation propagates; all other failures are converted to redacted messages.
@Suppress("TooGenericExceptionCaught", "SwallowedException")
class AccountDetailsViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val mutable = MutableStateFlow(AccountDetailsState())
    val state = mutable.asStateFlow()

    fun refresh(accountId: String) {
        if (mutable.value.loading) return
        viewModelScope.launch {
            mutable.value = mutable.value.copy(loading = true, error = null)
            try {
                AccountProfiles.refreshAppearance(getApplication(), accountId)
                val profile = AccountProfiles.details(getApplication(), accountId)
                mutable.value = mutable.value.copy(profile = profile)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                mutable.value =
                    mutable.value.copy(error = failure.toOpenCloudError().safeMessage(getApplication<Application>()))
            } finally {
                mutable.value = mutable.value.copy(loading = false)
            }
        }
    }

    fun changePhoto(
        accountId: String,
        uri: Uri?,
    ) {
        if (mutable.value.saving) return
        viewModelScope.launch {
            mutable.value = mutable.value.copy(saving = true, error = null)
            try {
                AccountProfiles.changePhoto(getApplication(), accountId, uri)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: IllegalArgumentException) {
                mutable.value =
                    mutable.value.copy(
                        error =
                            getApplication<Application>().localizedString(R.string.account_invalid_picture),
                    )
            } catch (failure: Exception) {
                mutable.value =
                    mutable.value.copy(error = failure.toOpenCloudError().safeMessage(getApplication<Application>()))
            } finally {
                mutable.value = mutable.value.copy(saving = false)
            }
        }
    }
}
