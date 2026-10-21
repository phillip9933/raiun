package eu.opencloud.android.next.core.network

import org.w3c.dom.Document
import org.xml.sax.InputSource
import org.xml.sax.SAXException
import org.xml.sax.SAXParseException
import org.xml.sax.helpers.DefaultHandler
import java.io.StringReader
import javax.xml.parsers.DocumentBuilderFactory

/** Android does not implement the Apache-specific JAXP feature switches used on desktop JVMs. */
@Suppress("ThrowsCount") // Entity resolution and both SAX callbacks must fail closed.
internal fun parseSafeXml(xml: String): Document {
    if (xml.contains("<!DOCTYPE", true) || xml.contains("<!ENTITY", true) || '\u0000' in xml) {
        throw OpenCloudException(OpenCloudError.InvalidResponse)
    }
    val parser =
        DocumentBuilderFactory
            .newInstance()
            .apply {
                isNamespaceAware = true
                isExpandEntityReferences = false
            }.newDocumentBuilder()
    parser.setEntityResolver { _, _ -> throw SAXException("External entities are forbidden") }
    parser.setErrorHandler(
        object : DefaultHandler() {
            override fun error(exception: SAXParseException): Unit = throw exception

            override fun fatalError(exception: SAXParseException): Unit = throw exception
        },
    )
    return try {
        parser.parse(InputSource(StringReader(xml)))
    } catch (_: SAXException) {
        throw OpenCloudException(OpenCloudError.InvalidResponse)
    }
}
