#!/usr/bin/env python3

import unittest

from check_play_bundle import verify_manifest

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
      package="app.raiun.cloud" android:versionName="1.7.0" android:versionCode="65">
    <uses-sdk android:minSdkVersion="31" android:targetSdkVersion="36" />
    <uses-permission android:name="android.permission.INTERNET" />
    <application><provider android:authorities="app.raiun.cloud.documents" /></application>
</manifest>"""


class PlayManifestTests(unittest.TestCase):
    def test_accepts_expected_play_manifest(self):
        verify_manifest(MANIFEST, "1.7.0", "65")

    def test_rejects_install_permission_in_sdk_specific_element(self):
        manifest = MANIFEST.replace(
            "<application>", '<uses-permission-sdk-23 android:name="android.permission.REQUEST_INSTALL_PACKAGES" /><application>'
        )
        with self.assertRaisesRegex(ValueError, "APK installation"):
            verify_manifest(manifest, "1.7.0", "65")

    def test_rejects_updater_provider_authority(self):
        manifest = MANIFEST.replace("app.raiun.cloud.documents", "app.raiun.cloud.documents;app.raiun.cloud.android-updates")
        with self.assertRaisesRegex(ValueError, "updater component"):
            verify_manifest(manifest, "1.7.0", "65")

    def test_rejects_wrong_version(self):
        with self.assertRaisesRegex(ValueError, "version code"):
            verify_manifest(MANIFEST, "1.7.0", "66")


if __name__ == "__main__":
    unittest.main()
