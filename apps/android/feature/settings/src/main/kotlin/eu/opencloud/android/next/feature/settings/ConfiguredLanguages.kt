package eu.opencloud.android.next.feature.settings

import android.content.res.Resources
import org.xmlpull.v1.XmlPullParser
import java.util.Locale

/** Uses the same packaged locale configuration as Android's per-app language settings. */
internal fun configuredLanguages(resources: Resources): List<Pair<String, String>> =
    resources.getXml(R.xml.locales_config).use { parser ->
        buildList {
            while (parser.next() != XmlPullParser.END_DOCUMENT) {
                if (parser.eventType == XmlPullParser.START_TAG && parser.name == "locale") {
                    val tag =
                        requireNotNull(parser.getAttributeValue("http://schemas.android.com/apk/res/android", "name"))
                    val locale = Locale.forLanguageTag(tag)
                    val label = locale.getDisplayName(locale).replaceFirstChar { it.titlecase(locale) }
                    add(tag to label)
                }
            }
        }
    }
