package eu.opencloud.android.next.feature.auth

/** Local admission failure; never includes account identity, credentials or server details. */
internal class AccountRemovalPendingException : IllegalStateException("Account cleanup pending.")
