package eu.opencloud.android.next.core.network

import org.w3c.dom.Element
import org.xml.sax.Attributes
import org.xml.sax.InputSource
import org.xml.sax.SAXException
import org.xml.sax.ext.DefaultHandler2
import java.io.FilterInputStream
import java.io.InputStream
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.SAXParserFactory

/** Keep only one response DOM alive; no complete response string or document is retained. */
internal fun readDavResponses(
    input: InputStream,
    maxBytes: Long,
    consume: (Element) -> Unit,
) {
    val handler = DavResponseHandler(consume)
    val reader =
        SAXParserFactory
            .newInstance()
            .apply { isNamespaceAware = true }
            .newSAXParser()
            .xmlReader
    reader.contentHandler = handler
    reader.entityResolver = handler
    reader.errorHandler = handler
    // Required rather than best-effort: DTDs must be rejected before entity expansion.
    reader.setProperty("http://xml.org/sax/properties/lexical-handler", handler)
    reader.parse(InputSource(ListingInputStream(input, maxBytes)))
}

private class ListingInputStream(
    input: InputStream,
    private val limit: Long,
) : FilterInputStream(input) {
    private var consumed = 0L

    override fun read(): Int = super.read().also { if (it >= 0) count(1) }

    override fun read(
        buffer: ByteArray,
        offset: Int,
        length: Int,
    ): Int =
        `in`.read(buffer, offset, minOf(length.toLong(), limit - consumed + 1).toInt()).also {
            if (it > 0) count(it)
        }

    private fun count(size: Int) {
        consumed += size
        if (consumed > limit) throw OpenCloudException(OpenCloudError.DirectoryListingTooLarge)
    }
}

private class DavResponseHandler(
    private val consume: (Element) -> Unit,
) : DefaultHandler2() {
    private val builder = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }.newDocumentBuilder()
    private var depth = 0
    private var current: Element? = null
    private var responseChars = 0
    private var responseNodes = 0
    private var ignoringExtension = false
    private val text = StringBuilder()

    override fun startDTD(
        name: String?,
        publicId: String?,
        systemId: String?,
    ): Unit = invalid()

    override fun resolveEntity(
        publicId: String?,
        systemId: String?,
    ): InputSource = invalid()

    override fun startElement(
        uri: String,
        localName: String,
        qName: String,
        attributes: Attributes,
    ) {
        flushText()
        depth++
        if (depth > 64) invalid()
        if (depth == 1) {
            if (uri != "DAV:" || localName != "multistatus") invalid()
            return
        }
        if (depth == 2) {
            // RFC 4918 permits a multistatus description and foreign extension elements.
            // They cannot contribute resources, even if they contain nested DAV responses.
            ignoringExtension = uri != "DAV:" || localName == "responsedescription"
            if (ignoringExtension) return
            if (localName != "response") invalid()
            responseChars = 0
            responseNodes = 1
            val document = builder.newDocument()
            current = document.createElementNS(uri, qName).also(document::appendChild)
        } else if (!ignoringExtension) {
            countNode()
            if (uri == "DAV:" && localName == "response") invalid()
            val parent = current ?: invalid()
            current = parent.ownerDocument.createElementNS(uri.ifEmpty { null }, qName).also(parent::appendChild)
        }
    }

    override fun characters(
        ch: CharArray,
        start: Int,
        length: Int,
    ) {
        if (current == null) return
        responseChars += length
        if (responseChars > 1024 * 1024) throw OpenCloudException(OpenCloudError.DirectoryListingTooLarge)
        text.append(ch, start, length)
    }

    override fun endElement(
        uri: String,
        localName: String,
        qName: String,
    ) {
        flushText()
        if (depth == 2) {
            if (!ignoringExtension) consume(current ?: invalid())
            current = null
            ignoringExtension = false
        } else if (depth > 2) {
            if (!ignoringExtension) current = current?.parentNode as? Element ?: invalid()
        }
        depth--
    }

    /** SAX can split a single value into arbitrarily many callbacks, including CDATA boundaries. */
    private fun flushText() {
        if (text.isEmpty()) return
        val element = current ?: invalid()
        countNode()
        element.appendChild(element.ownerDocument.createTextNode(text.toString()))
        text.setLength(0)
    }

    private fun countNode() {
        if (++responseNodes > 4096) throw OpenCloudException(OpenCloudError.DirectoryListingTooLarge)
    }

    private fun invalid(): Nothing = throw SAXException("Invalid directory XML")
}
