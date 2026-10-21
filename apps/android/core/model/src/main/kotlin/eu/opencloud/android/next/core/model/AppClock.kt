package eu.opencloud.android.next.core.model

fun interface AppClock {
    fun epochMillis(): Long
}

object SystemAppClock : AppClock {
    override fun epochMillis(): Long = System.currentTimeMillis()
}
