#!/usr/bin/env python3
"""Build a fixed, synthetic external URI provider APK using only the standard debug key."""

import argparse
import os
from pathlib import Path
import tempfile
import zipfile

from generate_updater_test_apks import newest, run, sdk_directory

PACKAGE = "app.raiun.test.shareprovenance"
SOURCE = r'''
package app.raiun.test.shareprovenance;

import android.app.Activity;
import android.content.ClipData;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Intent;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public final class GrantActivity extends Activity {
    public static final Uri URI = Uri.parse("content://app.raiun.test.shareprovenance.documents/synthetic.dbf");
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        Intent share = new Intent(Intent.ACTION_SEND)
            .setComponent(new android.content.ComponentName("app.raiun.cloud", "eu.opencloud.android.next.IncomingShareActivity"))
            .setType("application/octet-stream")
            .putExtra(Intent.EXTRA_STREAM, URI)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        share.setClipData(ClipData.newRawUri("synthetic", URI));
        startActivity(share);
        finish();
    }
    public static final class Provider extends ContentProvider {
        @Override public boolean onCreate() { return true; }
        @Override public Cursor query(Uri uri, String[] projection, String selection, String[] args, String order) {
            MatrixCursor cursor = new MatrixCursor(new String[] { OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE });
            cursor.addRow(new Object[] { "synthetic.dbf", 25L });
            return cursor;
        }
        @Override public String getType(Uri uri) { return "application/octet-stream"; }
        @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
            if (!URI.equals(uri) || !"r".equals(mode)) throw new FileNotFoundException("synthetic read only");
            File file = new File(getContext().getFilesDir(), "synthetic.dbf");
            try (FileOutputStream output = new FileOutputStream(file)) {
                output.write("synthetic share provenance".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            } catch (IOException failure) { throw new FileNotFoundException("synthetic source unavailable"); }
            return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
        }
        @Override public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException(); }
        @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { throw new UnsupportedOperationException(); }
        @Override public int delete(Uri uri, String selection, String[] args) { throw new UnsupportedOperationException(); }
    }
}
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--keystore", required=True, type=Path)
    parser.add_argument("--key-alias", required=True)
    parser.add_argument("--compile-sdk", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if os.environ.get("FIXTURE_STORE_PASSWORD") != "android":
        raise SystemExit("Only the standard Android debug-key password is supported")
    if not args.keystore.is_file():
        raise SystemExit("The existing standard Android debug keystore is missing")
    sdk = sdk_directory(args.project)
    tools = newest(sdk / "build-tools", ("aapt", "zipalign", "lib/apksigner.jar", "lib/d8.jar"))
    platform = sdk / "platforms" / f"android-{args.compile_sdk}" / "android.jar"
    if not platform.is_file():
        raise SystemExit("Compile SDK platform is missing")
    java = args.java_home / "bin" / "java"
    javac = args.java_home / "bin" / "javac"
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="raiun-share-provenance-") as directory:
        work = Path(directory)
        source = work / "GrantActivity.java"
        source.write_text(SOURCE, encoding="utf-8")
        classes = work / "classes"
        classes.mkdir()
        run(str(javac), "-source", "8", "-target", "8", "-bootclasspath", str(platform), "-d", str(classes), str(source))
        dex = work / "dex"
        dex.mkdir()
        run(str(java), "-cp", str(tools / "lib/d8.jar"), "com.android.tools.r8.D8", "--min-api", "26", "--lib", str(platform), "--output", str(dex), *map(str, sorted(classes.rglob("*.class"))))
        manifest = work / "AndroidManifest.xml"
        manifest.write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            f'package="{PACKAGE}" android:versionCode="1" android:versionName="1">'
            '<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35"/>'
            '<application android:label="Synthetic share provenance fixture" android:debuggable="true" android:allowBackup="false">'
            f'<activity android:name="{PACKAGE}.GrantActivity" android:exported="true"/>'
            f'<provider android:name="{PACKAGE}.GrantActivity$Provider" android:authorities="{PACKAGE}.documents" '
            'android:exported="false" android:grantUriPermissions="true"/>'
            '</application></manifest>', encoding="utf-8",
        )
        unsigned = work / "unsigned.apk"
        run(str(tools / "aapt"), "package", "-f", "-M", str(manifest), "-I", str(platform), "-F", str(unsigned))
        with zipfile.ZipFile(unsigned, "a") as apk:
            apk.write(dex / "classes.dex", "classes.dex")
        aligned = work / "aligned.apk"
        run(str(tools / "zipalign"), "-f", "4", str(unsigned), str(aligned))
        result = args.output / "share-provenance-fixture.apk"
        run(str(java), "-jar", str(tools / "lib/apksigner.jar"), "sign", "--ks", str(args.keystore), "--ks-key-alias", args.key_alias,
            "--ks-pass", "env:FIXTURE_STORE_PASSWORD", "--key-pass", "env:FIXTURE_STORE_PASSWORD", "--out", str(result), str(aligned))
        run(str(java), "-jar", str(tools / "lib/apksigner.jar"), "verify", str(result))


if __name__ == "__main__":
    main()
