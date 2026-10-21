package eu.opencloud.android.next.core.datastore

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.callbackFlow
import org.json.JSONArray

data class RecentFileRef(
    val spaceId: String,
    val resourceId: String,
)

/** Bounded, local history of files opened in the app, separated by account. */
class RecentFiles(
    context: Context,
) {
    private val preferences = context.applicationContext.getSharedPreferences("recent_files", Context.MODE_PRIVATE)

    fun observe(accountId: String) =
        callbackFlow {
            val listener =
                SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
                    if (key == accountId) trySend(read(accountId))
                }
            preferences.registerOnSharedPreferenceChangeListener(listener)
            trySend(read(accountId))
            awaitClose { preferences.unregisterOnSharedPreferenceChangeListener(listener) }
        }

    fun record(
        accountId: String,
        spaceId: String,
        resourceId: String,
    ) {
        val entry = RecentFileRef(spaceId, resourceId)
        val values = (listOf(entry) + read(accountId).filterNot { it == entry }).take(100)
        val json = JSONArray()
        values.forEach { json.put(JSONArray().put(it.spaceId).put(it.resourceId)) }
        preferences.edit().putString(accountId, json.toString()).apply()
    }

    private fun read(accountId: String): List<RecentFileRef> =
        try {
            val json = JSONArray(preferences.getString(accountId, "[]"))
            (0 until minOf(json.length(), 100)).map { index ->
                val value = json.getJSONArray(index)
                RecentFileRef(value.getString(0), value.getString(1))
            }
        } catch (_: org.json.JSONException) {
            emptyList()
        }
}
