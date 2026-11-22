# Rebuild the Android scanner's OpenCV library

The recipe builds the OpenCV 4.12.0 `libopencv_java4.so` for
`arm64-v8a` and `x86_64`. It replays the recorded November 6, 2026
configure and build commands with local paths substituted. It also repeats
the original build's generated-header path normalization before compilation.

Use a Linux x86-64 host with Python 3.14.8, GNU patch, and an Android SDK
installation containing these packages:

- `ndk;28.2.13676358` (r28c, Android Clang 19.0.1)
- `cmake;3.22.1` (Android package, CMake 3.22.1-g37088a8 and Ninja 1.10.2)

Run the following from the native security bundle directory. Set
`ANDROID_HOME` to the SDK directory. Use paths without spaces and a fresh
work directory on a filesystem with several gigabytes free. Download the ZIP
from the URL recorded in [the build provenance](../opencv-build.json).

```sh
sha256sum -c SHA256SUMS
python3 provenance/opencv-rebuild/rebuild.py \
  --archive /path/to/opencv-4.12.0.zip \
  --sdk "$ANDROID_HOME" \
  --work /path/to/new-opencv-build
```

The script verifies the archive, bundled patch, and patched source SHA-256
values. It disables OpenCV dependency downloads, verifies the configured
module set, and builds the API 26 Release libraries serially with two Ninja
workers. Only core, imgproc and the Java bindings are built. The recorded
Android compile SDK setting is 35, but Gradle projects are disabled and
CMake does not use the SDK platform JAR.

Compare `results.json` in the work directory to the SHA-256 values under
`build.abis` in [the build provenance](../opencv-build.json). The script exits
with a nonzero status if either size or digest differs. Each output is the
direct `opencv_java` target under `build-<abi>/jni/<abi>/libopencv_java4.so`.
The build keeps logs and files in the work directory. The shipped scanner AAR
and all of its other payloads are outside this recipe's build scope.

The exact tool versions and path substitutions allow an independent rebuild
and comparison. The recipe does not pin the full Linux host image, Python
binary or environment, so compare the resulting digests before asserting
byte identity on another host.
