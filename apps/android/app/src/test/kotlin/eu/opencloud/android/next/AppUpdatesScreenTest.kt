package eu.opencloud.android.next

import android.app.Application
import android.content.Context
import androidx.activity.ComponentActivity
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.Density
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ApplicationProvider
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.settings.AppUpdateNotice
import eu.opencloud.android.next.feature.settings.AppUpdateNoticeDialog
import eu.opencloud.android.next.feature.settings.AppUpdatesScreen
import eu.opencloud.android.next.feature.settings.AppUpdatesViewModel
import eu.opencloud.android.next.feature.settings.RaiunUpdates
import eu.opencloud.android.next.feature.settings.SettingsScreen
import eu.opencloud.android.next.feature.settings.UpdateActions
import io.github.phillip9933.appupdater.AndroidUpdateChannel
import io.github.phillip9933.appupdater.AndroidUpdateRelease
import io.github.phillip9933.appupdater.UpdateConfig
import io.github.phillip9933.appupdater.UpdateError
import io.github.phillip9933.appupdater.UpdateManager
import io.github.phillip9933.appupdater.UpdateState
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import eu.opencloud.android.next.feature.settings.R as SettingsR

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w360dp-h800dp", application = Application::class)
class AppUpdatesScreenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Before fun clearUpdaterPreferences() {
        ApplicationProvider
            .getApplicationContext<Application>()
            .getSharedPreferences("android_updates", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }

    @Test fun stableAndBetaSelectionAndManualCheckAreExplicit() {
        var selected: AndroidUpdateChannel? = null
        var checks = 0
        compose.setContent {
            OpenCloudTheme {
                AppUpdatesScreen(
                    UpdateState(installedVersion = "1.0.0"),
                    {},
                    UpdateActions(onChannel = { selected = it }, onCheck = { checks++ }),
                )
            }
        }
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/app_updates_settings.png")
        compose.onNodeWithText("Stable and beta").performClick()
        assertEquals(AndroidUpdateChannel.BETA, selected)
        compose.onNodeWithText("Check now").performScrollTo().performClick()
        assertEquals(1, checks)
    }

    @Test fun busyDownloadCanBeCancelledAndCannotStartAnotherCheck() {
        var cancellations = 0
        compose.setContent {
            OpenCloudTheme {
                AppUpdatesScreen(
                    UpdateState(
                        installedVersion = "1.0.0",
                        available = release(),
                        downloading = true,
                        bytesDownloaded = 50,
                    ),
                    {},
                    UpdateActions(onCancel = { cancellations++ }),
                )
            }
        }
        compose.onNodeWithText("Check now").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("Downloading update… 50%").performScrollTo().assertExists()
        compose.onNodeWithText("Cancel download").performScrollTo().performClick()
        assertEquals(1, cancellations)
    }

    @Test fun readyReleaseShowsInstallAction() {
        var installs = 0
        compose.setContent {
            OpenCloudTheme(darkTheme = true) {
                AppUpdatesScreen(
                    UpdateState(installedVersion = "1.0.0", available = release(), ready = true),
                    {},
                    UpdateActions(),
                    installControl = { Button(onClick = { installs++ }) { Text("Install update") } },
                )
            }
        }
        compose.onNodeWithText("Install update").performScrollTo().performClick()
        assertEquals(1, installs)
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/app_update_release_dark.png")
    }

    @Test fun failedCheckNeverSaysUpToDate() {
        compose.setContent {
            OpenCloudTheme {
                AppUpdatesScreen(
                    UpdateState(
                        installedVersion = "1.0.0",
                        lastChecked = 1,
                        error = UpdateError.NETWORK,
                    ),
                    {
                    },
                    UpdateActions(),
                )
            }
        }
        compose
            .onNodeWithText(
                "Could not check for updates. Check your connection or try again later.",
            ).performScrollTo()
            .assertExists()
        compose.onNodeWithText("No newer compatible Android release was found.").assertDoesNotExist()
    }

    @Test fun mismatchedSigningKeyNeverOffersInstall() {
        compose.setContent {
            OpenCloudTheme {
                AppUpdatesScreen(
                    UpdateState(
                        installedVersion = "1.0.0",
                        available = release(),
                        error = UpdateError.SIGNATURE_MISMATCH,
                    ),
                    {},
                    UpdateActions(),
                )
            }
        }
        compose
            .onNodeWithText(
                "This update uses a different signing key and cannot update this installation. Keep the current app installed to preserve your data.",
            ).performScrollTo()
            .assertExists()
        compose.onNodeWithText("Install update").assertDoesNotExist()
    }

    @Test fun updateSettingsAreReachableAndBackReturnsToSettings() {
        compose.setContent { OpenCloudTheme { SettingsScreen(UserSettings(), {}, {}, {}) } }
        compose.onNodeWithText("App updates").performScrollTo().performClick()
        compose.onNodeWithText("Check now").performScrollTo().assertExists()
        compose.onNodeWithContentDescription("Back").performClick()
        compose.onNodeWithText("Settings").assertExists()
    }

    @Test fun installedReleaseAndProjectLinksUseFixedGitHubDestinations() {
        val opened = mutableListOf<String>()
        compose.setContent {
            OpenCloudTheme {
                AppUpdatesScreen(
                    UpdateState(installedVersion = "1.0.0-debug"),
                    {},
                    UpdateActions(onOpenLink = { opened += it }),
                )
            }
        }
        compose.onNodeWithText("GitHub project").performScrollTo().performClick()
        compose.onNodeWithText("Installed release").performScrollTo().performClick()
        assertEquals(
            listOf(
                "https://github.com/phillip9933/raiun",
                "https://github.com/phillip9933/raiun/releases/tag/android-v1.0.0",
            ),
            opened,
        )
        assertEquals(null, RaiunUpdates.installedReleaseUrl("1.0.0/path"))
        assertEquals(
            "https://github.com/phillip9933/raiun/releases/tag/v0.9.3",
            RaiunUpdates.installedReleaseUrl("0.9.3"),
        )
    }

    @Test fun directUpdatesEntryReturnsToSettingsOnBack() {
        compose.setContent {
            OpenCloudTheme {
                SettingsScreen(UserSettings(), {}, {}, {}, openUpdatesInitially = true)
            }
        }
        compose.onNodeWithText("Check now").performScrollTo().assertExists()
        compose.onNodeWithContentDescription("Back").performClick()
        compose.onNodeWithText("Settings").assertExists()
    }

    @Test fun updatePopupRequiresAnOfferAndAnAvailableRelease() {
        val state = mutableStateOf(UpdateState(available = release(), offer = false))
        compose.setContent {
            OpenCloudTheme { AppUpdateNoticeDialog(state.value, {}, {}, {}, {}) }
        }
        compose.onNodeWithText("New version available").assertDoesNotExist()
        compose.runOnIdle { state.value = UpdateState(offer = true) }
        compose.onNodeWithText("New version available").assertDoesNotExist()
    }

    @Test fun offeredReleasePopupShowsVersionNotesAndExplicitDownload() {
        var downloads = 0
        compose.setContent {
            OpenCloudTheme {
                AppUpdateNoticeDialog(
                    UpdateState(available = release(), offer = true),
                    {},
                    { downloads++ },
                    {},
                    {},
                )
            }
        }
        compose.onNodeWithText("New version available").assertExists()
        compose.onNodeWithText("Raiun 1.0.1 is available").assertExists()
        compose.onNodeWithText("A safer update experience.").assertExists()
        assertEquals(0, downloads)
        compose.onNodeWithText("Download update").performClick()
        assertEquals(1, downloads)
    }

    @Test fun laterDismissesTheOfferWithoutDownloading() {
        var dismissals = 0
        var downloads = 0
        compose.setContent {
            OpenCloudTheme {
                AppUpdateNoticeDialog(
                    UpdateState(available = release(), offer = true),
                    { dismissals++ },
                    { downloads++ },
                    {},
                    {},
                )
            }
        }
        compose.onNodeWithText("Later").performClick()
        assertEquals(1, dismissals)
        assertEquals(0, downloads)
    }

    @Test fun readyPopupInstallsOnlyWhenRequested() {
        var installs = 0
        compose.setContent {
            OpenCloudTheme {
                AppUpdateNoticeDialog(
                    UpdateState(available = release(), offer = true, ready = true),
                    {},
                    {},
                    {},
                    { Button(onClick = { installs++ }) { Text("Install update") } },
                )
            }
        }
        compose.onNodeWithText("Download update").assertDoesNotExist()
        assertEquals(0, installs)
        compose.onNodeWithText("Install update").performClick()
        assertEquals(1, installs)
    }

    @Test
    @Config(sdk = [26, 35], application = Application::class)
    fun noticeChecksOnResumeAndThrottlesRepeatedResumesUntilDue() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        val calls = AtomicInteger()
        val firstFetch = CountDownLatch(1)
        val secondFetch = CountDownLatch(1)
        val manager =
            manager(application) {
                when (calls.incrementAndGet()) {
                    1 -> firstFetch.countDown()
                    2 -> secondFetch.countDown()
                }
                release("android-v1.2.0")
            }
        val model = AppUpdatesViewModel(application, manager)

        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.setContent { OpenCloudTheme { AppUpdateNotice(model) } }
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)

        assertTrue("foreground lifecycle should check the configured feed", firstFetch.await(5, TimeUnit.SECONDS))
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        assertFalse(
            "a second foreground return inside 24 hours must be throttled",
            secondFetch.await(250, TimeUnit.MILLISECONDS),
        )

        application
            .getSharedPreferences("android_updates", Context.MODE_PRIVATE)
            .edit()
            .putLong("attempted", System.currentTimeMillis() - DAILY_CHECK_INTERVAL_MS - 1)
            .commit()
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        assertTrue(
            "a foreground return after the throttle expires should check again",
            secondFetch.await(5, TimeUnit.SECONDS),
        )
        assertEquals(2, calls.get())
    }

    @Test
    @Config(sdk = [26, 35], application = Application::class)
    fun noticeDoesNotCheckOnResumeWhenAutomaticChecksAreDisabled() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        application
            .getSharedPreferences("android_updates", Context.MODE_PRIVATE)
            .edit()
            .putBoolean("automatic", false)
            .commit()
        val calls = AtomicInteger()
        val model =
            AppUpdatesViewModel(
                application,
                manager(application) {
                    calls.incrementAndGet()
                    release("android-v1.2.0")
                },
            )

        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.setContent { OpenCloudTheme { AppUpdateNotice(model) } }
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitForIdle()

        assertFalse(model.manager.state.value.automaticChecks)
        assertEquals(0, calls.get())
        assertEquals(
            0L,
            application.getSharedPreferences("android_updates", Context.MODE_PRIVATE).getLong("attempted", 0L),
        )
    }

    @Test
    @Config(sdk = [26, 35], application = Application::class)
    fun dismissedReleaseAndCheckAttemptSurviveManagerRecreation() =
        runBlocking {
            val application = ApplicationProvider.getApplicationContext<Application>()
            val firstCalls = AtomicInteger()
            val firstRelease = release("android-v1.2.0")
            val firstManager =
                manager(application) {
                    firstCalls.incrementAndGet()
                    firstRelease
                }

            assertTrue(firstManager.checkNow(force = false))
            assertTrue(firstManager.state.value.offer)
            assertEquals(1, firstCalls.get())
            firstManager.dismissOffer()
            assertFalse(firstManager.state.value.offer)

            val restoredCalls = AtomicInteger()
            val restored =
                manager(application) {
                    restoredCalls.incrementAndGet()
                    firstRelease
                }
            assertEquals(
                firstRelease.tag,
                restored.state.value.available
                    ?.tag,
            )
            assertFalse(
                "dismissed release should remain dismissed after process recreation",
                restored.state.value.offer,
            )
            assertFalse(
                "the persisted daily attempt should throttle a recreated manager",
                restored.checkNow(force = false),
            )
            assertEquals(0, restoredCalls.get())

            val newer = manager(application) { release("android-v1.2.1") }
            assertTrue(newer.checkNow(force = true))
            assertTrue("a different release tag should be offered", newer.state.value.offer)
        }

    @Test
    @Config(sdk = [35], qualifiers = "de-rDE-w320dp-h640dp", application = Application::class)
    fun germanPopupRemainsReadableAndDismissibleAtLargeFontScale() = assertLocalizedPopup()

    @Test
    @Config(sdk = [35], qualifiers = "fr-rFR-w320dp-h640dp", application = Application::class)
    fun frenchPopupRemainsReadableAndDismissibleAtLargeFontScale() = assertLocalizedPopup()

    @Test
    @Config(sdk = [35], qualifiers = "es-rES-w320dp-h640dp", application = Application::class)
    fun spanishPopupRemainsReadableAndDismissibleAtLargeFontScale() = assertLocalizedPopup()

    @Test
    @Config(sdk = [35], qualifiers = "pt-rPT-w320dp-h640dp", application = Application::class)
    fun portuguesePopupRemainsReadableAndDismissibleAtLargeFontScale() = assertLocalizedPopup()

    @Test
    @Config(sdk = [35], qualifiers = "ja-w320dp-h640dp", application = Application::class)
    fun japanesePopupRemainsReadableAndDismissibleAtLargeFontScale() = assertLocalizedPopup()

    private fun assertLocalizedPopup() {
        var dismissals = 0
        var downloads = 0
        compose.setContent {
            val largeFontScale = Density(LocalDensity.current.density, fontScale = 1.3f)
            CompositionLocalProvider(LocalDensity provides largeFontScale) {
                OpenCloudTheme {
                    AppUpdateNoticeDialog(
                        UpdateState(available = release("android-v1.2.0"), offer = true),
                        { dismissals++ },
                        { downloads++ },
                        {},
                        {},
                    )
                }
            }
        }
        val context = compose.activity
        compose.onNodeWithText(context.getString(SettingsR.string.updates_new_version_title)).assertIsDisplayed()
        compose
            .onNodeWithText(context.getString(SettingsR.string.updates_available, "1.2.0"))
            .performScrollTo()
            .assertIsDisplayed()
        compose.onNodeWithText(context.getString(SettingsR.string.updates_download)).assertIsDisplayed().performClick()
        assertEquals(1, downloads)
        compose.onNodeWithText(context.getString(SettingsR.string.updates_later)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(SettingsR.string.updates_later)).performClick()
        assertEquals(1, dismissals)
    }

    private fun release(tag: String = "android-v1.0.1") =
        AndroidUpdateRelease(
            tag,
            "A safer update experience.",
            "raiun-android-${tag.removePrefix("android-v")}.apk",
            "https://github.com/phillip9933/raiun/releases/download/$tag/raiun-android-${tag.removePrefix(
                "android-v",
            )}.apk",
            100,
            null,
            null,
        )

    private fun manager(
        application: Application,
        feed: () -> AndroidUpdateRelease?,
    ): UpdateManager {
        val config =
            UpdateConfig(
                owner = "phillip9933",
                repository = "raiun",
                tagPrefix = "android-v",
                assetPrefix = "raiun-android-",
                stateName = "android_updates",
            )
        val constructor =
            UpdateManager::class.java.declaredConstructors.single {
                it.parameterTypes.size == 5 && it.parameterTypes[0] == Context::class.java
            }
        constructor.isAccessible = true
        val latestRelease: (AndroidUpdateChannel) -> AndroidUpdateRelease? = { feed() }
        val installedVersion: () -> String = { "1.1.0" }
        return constructor.newInstance(application, config, latestRelease, installedVersion, true) as UpdateManager
    }

    private companion object {
        const val DAILY_CHECK_INTERVAL_MS = 24L * 60 * 60 * 1000
    }
}
