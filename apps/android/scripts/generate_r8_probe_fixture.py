#!/usr/bin/env python3
"""Build a framework-only instrumentation probe for an independently minimized test APK.

Only the standard debug key is supported. This helper does not build, change,
install or run the target app, and introduces no R8 retention roots into it.
"""

import argparse
import os
from pathlib import Path
import tempfile
import zipfile

from generate_updater_test_apks import newest, run, sdk_directory

PACKAGE = "app.raiun.test.r8probe"
TARGET_PACKAGE = "app.raiun.cloud"
SOURCE = r'''
package app.raiun.test.r8probe;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;

/** Uses only framework classes; target types are deliberately absent from this APK. */
public final class R8ProbeInstrumentation extends Instrumentation {
    private String probe;

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        probe = arguments == null ? "jna" : arguments.getString("probe", "jna");
        start();
    }

    @Override public void onStart() {
        Bundle results = new Bundle();
        if (!"jna".equals(probe) && !"opencv-exception".equals(probe)) {
            results.putString("status", "invalid-argument");
            results.putString("probe", "invalid");
            finish(Activity.RESULT_CANCELED, results);
            return;
        }
        results.putString("probe", probe);
        try {
            if (!"app.raiun.cloud".equals(getTargetContext().getPackageName())) {
                results.putString("status", "wrong-target");
                finish(Activity.RESULT_CANCELED, results);
                return;
            }
            ClassLoader loader = getTargetContext().getClassLoader();
            if ("jna".equals(probe)) {
                // Initialization, not just class presence: invokes the packaged JNI initIDs path.
                Class.forName("com.sun.jna.Native", true, loader);
            } else {
                // Exact string looked up by OpenCV JNI; no mapped-method or renamed-class guess.
                Class<?> exception = Class.forName("org.opencv.core.CvException", true, loader);
                exception.getConstructor(String.class);
            }
            results.putString("status", "pass");
            finish(Activity.RESULT_OK, results);
        } catch (Throwable failure) {
            // Never emit messages, stack traces, intent data, target files or arbitrary arguments.
            results.putString("status", "fail");
            results.putString("exception_type", boundedType(failure));
            Throwable cause = failure.getCause();
            if (cause != null) results.putString("cause_type", boundedType(cause));
            finish(Activity.RESULT_CANCELED, results);
        }
    }

    private static String boundedType(Throwable failure) {
        String type = failure.getClass().getName();
        return type.length() <= 160 ? type : type.substring(0, 160);
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
    with tempfile.TemporaryDirectory(prefix="raiun-r8-probe-") as directory:
        work = Path(directory)
        source = work / "R8ProbeInstrumentation.java"
        source.write_text(SOURCE, encoding="utf-8")
        classes = work / "classes"
        classes.mkdir()
        run(
            str(javac), "-source", "8", "-target", "8", "-bootclasspath", str(platform),
            "-d", str(classes), str(source),
        )
        dex = work / "dex"
        dex.mkdir()
        run(
            str(java), "-cp", str(tools / "lib/d8.jar"), "com.android.tools.r8.D8",
            "--min-api", "26", "--lib", str(platform), "--output", str(dex),
            *map(str, sorted(classes.rglob("*.class"))),
        )
        manifest = work / "AndroidManifest.xml"
        manifest.write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            f'package="{PACKAGE}" android:versionCode="1" android:versionName="1">'
            '<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35"/>'
            '<application android:label="Synthetic framework R8 probe" '
            'android:debuggable="true" android:allowBackup="false"/>'
            f'<instrumentation android:name="{PACKAGE}.R8ProbeInstrumentation" '
            f'android:targetPackage="{TARGET_PACKAGE}" android:functionalTest="true"/>'
            '</manifest>', encoding="utf-8",
        )
        unsigned = work / "unsigned.apk"
        run(
            str(tools / "aapt"), "package", "-f", "-M", str(manifest),
            "-I", str(platform), "-F", str(unsigned),
        )
        with zipfile.ZipFile(unsigned, "a") as apk:
            apk.write(dex / "classes.dex", "classes.dex")
        aligned = work / "aligned.apk"
        run(str(tools / "zipalign"), "-f", "4", str(unsigned), str(aligned))
        result = args.output / "r8-probe-fixture.apk"
        run(
            str(java), "-jar", str(tools / "lib/apksigner.jar"), "sign", "--ks", str(args.keystore),
            "--ks-key-alias", args.key_alias, "--ks-pass", "env:FIXTURE_STORE_PASSWORD",
            "--key-pass", "env:FIXTURE_STORE_PASSWORD", "--out", str(result), str(aligned),
        )
        run(str(java), "-jar", str(tools / "lib/apksigner.jar"), "verify", str(result))


if __name__ == "__main__":
    main()
