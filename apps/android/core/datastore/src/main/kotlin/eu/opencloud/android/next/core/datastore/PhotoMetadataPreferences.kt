package eu.opencloud.android.next.core.datastore

import android.content.Context

/** Stores the user's choice about asking for access to photo location metadata. */
class PhotoMetadataPreferences(
    context: Context,
) {
    private val preferences = context.applicationContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    var askForLocationPermission: Boolean
        get() = preferences.getBoolean(ASK_FOR_LOCATION_PERMISSION, true)
        set(value) {
            preferences.edit().putBoolean(ASK_FOR_LOCATION_PERMISSION, value).apply()
        }

    private companion object {
        const val PREFERENCES_NAME = "photo_metadata_preferences"
        const val ASK_FOR_LOCATION_PERMISSION = "ask_for_location_permission"
    }
}
