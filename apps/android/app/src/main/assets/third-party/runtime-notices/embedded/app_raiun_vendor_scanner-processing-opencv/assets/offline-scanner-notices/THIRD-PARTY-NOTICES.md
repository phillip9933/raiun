# Third-party attribution

Original scanner code is Apache-2.0 (LICENSE). Preserve this file, NOTICE, and the complete third-party directory when redistributing source. Native notices also travel in processing AAR/APK assets under offline-scanner-notices.

| Component | Version / provenance | License evidence |
| --- | --- | --- |
| OpenCV Java wrappers | Official 4.12.0 Android classes.jar, exact SHA256 in native inventory | Apache-2.0; full OpenCV LICENSE retained |
| OpenCV core/imgproc/JNI | Immutable 4.12.0 source archive, optional binary engines disabled | Apache-2.0 and embedded source notices, including SoftFloat BSD and fdlibm terms; native-source-notices inventory |
| LLVM libc++ | Android NDK 28.2.13676358, both ABIs | Exact NDK NOTICE and NOTICE.toolchain retained |
| CameraX | 1.4.2 | Apache-2.0; camera-core POM also declares BSD libyuv; full libyuv-LICENSE.txt retained |
| AndroidX / Compose / Kotlin / coroutines / ONNX Runtime | Exact 81 external runtime coordinates in runtime-inventory.json | POM declarations and 28 preserved embedded license/notice resources in runtime-notices |
| DocQuadNet-256 exported inference model | MakeACopy revision 01bebd394b9dd6f3a692f28aea7c0638085eb4da; unmodified ORT artifact | Apache-2.0 inference grant; full pinned LICENSE and NOTICE in processing assets. Scope and training-data caveat: docs/LEARNED-DETECTOR-RC8.md |
| ONNX Runtime Android | 1.24.1 official Maven artifact; CPU inference | MIT; full LICENSE and upstream ThirdPartyNotices in processing assets |
| Gradle wrapper | 8.13 official wrapper with distribution checksum | Apache-2.0 |

Build/test dependencies are separate: Android SDK tools have their distributed licenses; AndroidX Test is Apache-2.0, JUnit4 EPL-1.0 and Hamcrest BSD. These test frameworks are not SDK runtime dependencies.

The stock OpenCV native AAR is excluded from runtime resolution. Its earlier inventory and opencv-source-notices directory are historical investigation evidence; optional components in those records do not ship in this candidate. Final native-build manifest, native inventory and release audit identify actual packaged libraries.

The libyuv notice is retained from the official Android upstream [LICENSE](https://android.googlesource.com/platform/external/libyuv/+/refs/heads/main/LICENSE). CameraX's POM does not expose the exact embedded libyuv revision. That limitation is recorded rather than inventing a revision; the retained BSD copyright/license text is included in SDK assets.

No reuse-candidate application UI source was copied. DocQuad preprocessing and heatmap decoding conventions informed a new Kotlin adapter. OpenCV Java classes for excluded modules remain in the upstream wrapper JAR, but those native methods are unsupported; the public scanner API exposes no OpenCV types. Benchmark images are synthetic and contain no personal documents.

This technical attribution inventory is not a legal certification. Preserve all upstream notices and review dependency changes against the actual final packaged graph.
