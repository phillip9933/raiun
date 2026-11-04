package eu.opencloud.android.next.core.database

/** Parse at the persistence boundary without changing Room's schema or silently repairing ambiguous work. */
val TransferEntity.typedState: TransferState get() = TransferState.fromPersisted(state)
