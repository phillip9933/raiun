package eu.opencloud.android.next.core.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LockSessionTest {
    @Test fun restartAndCancelledAuthenticationDoNotGrantAccess() {
        val session = LockSession()
        session.foreground(100, 30)
        assertFalse(session.appAllowed(100, 30))
        assertFalse(session.documentsAllowed(100))
    }

    @Test fun immediateLockClosesAppOnBackground() {
        val session = LockSession()
        session.authenticate(100)
        session.foreground(101, 0)
        assertTrue(session.appAllowed(1_000_000, 0))
        session.background(1_000_001)
        assertFalse(session.appAllowed(1_000_001, 0))
        session.foreground(1_000_002, 0)
        assertFalse(session.appAllowed(1_000_002, 0))
    }

    @Test fun delayedLockExpiresAndDoesNotRenewOnAnUnauthenticatedForeground() {
        val session = LockSession()
        session.authenticate(100)
        session.foreground(101, 1)
        session.background(200)
        assertTrue(session.appAllowed(60_199, 1))
        assertFalse(session.appAllowed(60_200, 1))
        session.foreground(60_201, 1)
        assertFalse(session.appAllowed(60_201, 1))
    }

    @Test fun explicitOpenExtendsViewerAccessWithoutDelayingAppLock() {
        val session = LockSession()
        session.authenticate(100)
        session.foreground(101, 0)
        session.allowDocuments(1_000_000)
        session.background(1_000_001)
        assertTrue(session.documentsAllowed(1_000_002))
        assertFalse(session.appAllowed(1_000_002, 0))
    }

    @Test fun documentGrantExpiresEvenWhileAppIsForegroundAndScreenLockRevokesIt() {
        val session = LockSession()
        session.authenticate(100)
        session.foreground(101, 0)
        assertTrue(session.documentsAllowed(60_099))
        assertFalse(session.documentsAllowed(60_100))
        session.authenticate(70_000)
        session.clear()
        assertFalse(session.documentsAllowed(70_001))
        assertFalse(session.appAllowed(70_001, 30))
    }
}
