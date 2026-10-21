package eu.opencloud.android.next.core.documentsprovider

import android.database.AbstractCursor

/** One Room page in memory regardless of directory size. Reloading also rechecks account access. */
internal class PagedDocumentCursor(
    private val columns: Array<String>,
    private val total: Int,
    private val load: (Int) -> List<Array<Any?>>,
) : AbstractCursor() {
    private var pageStart = -1
    private var rows = emptyList<Array<Any?>>()

    override fun getCount(): Int = total

    override fun getColumnNames(): Array<String> = columns

    override fun onMove(
        oldPosition: Int,
        newPosition: Int,
    ): Boolean {
        val start = newPosition / 128 * 128
        if (start != pageStart) {
            rows = load(start)
            pageStart = start
        }
        return newPosition - start < rows.size
    }

    private fun value(column: Int): Any? {
        checkPosition()
        return rows[position - pageStart][column]
    }

    override fun getString(column: Int): String? = value(column)?.toString()

    override fun getLong(column: Int): Long = (value(column) as? Number)?.toLong() ?: 0L

    override fun getInt(column: Int): Int = getLong(column).toInt()

    override fun getShort(column: Int): Short = getLong(column).toShort()

    override fun getFloat(column: Int): Float = getDouble(column).toFloat()

    override fun getDouble(column: Int): Double = (value(column) as? Number)?.toDouble() ?: 0.0

    override fun isNull(column: Int): Boolean = value(column) == null

    override fun getType(column: Int): Int =
        when (value(column)) {
            null -> FIELD_TYPE_NULL
            is Number -> FIELD_TYPE_INTEGER
            else -> FIELD_TYPE_STRING
        }

    override fun close() {
        rows = emptyList()
        super.close()
    }
}
