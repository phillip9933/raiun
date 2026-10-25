import java.security.MessageDigest

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

// The updater is a versioned artifact bundle, never a dependency on a sibling checkout.
val updaterBundle = rootDir.resolve("third_party/android-updater")
val updaterPins = updaterBundle.resolve("SHA256SUMS")
check(updaterPins.isFile) { "Missing pinned Android updater bundle; see third_party/android-updater/README.md" }
val pinnedFiles = updaterPins.readLines().filter { it.isNotBlank() }.map { line ->
    val parts = line.split("  ", limit = 2)
    check(parts.size == 2 && parts[0].matches(Regex("[0-9a-f]{64}"))) { "Invalid updater checksum entry" }
    val artifact = updaterBundle.resolve(parts[1]).canonicalFile
    check(artifact.toPath().startsWith(updaterBundle.canonicalFile.toPath()) && artifact.isFile) {
        "Missing or unsafe pinned updater artifact: ${parts[1]}"
    }
    val actual = MessageDigest.getInstance("SHA-256").digest(artifact.readBytes()).joinToString("") { "%02x".format(it) }
    check(actual == parts[0]) { "Pinned Android updater checksum mismatch: ${parts[1]}" }
    parts[1]
}
check(pinnedFiles.distinct().size == pinnedFiles.size && pinnedFiles.any { it.endsWith(".aar") } &&
    pinnedFiles.any { it.endsWith(".pom") } && pinnedFiles.any { it.endsWith(".module") }) {
    "Incomplete pinned Android updater artifact index"
}

val bundledMavenFiles = updaterBundle.resolve("maven").walkTopDown().filter { it.isFile }.map {
    it.relativeTo(updaterBundle).invariantSeparatorsPath
}.toSet()
check(bundledMavenFiles == pinnedFiles.filter { it.startsWith("maven/") }.toSet()) {
    "Pinned Android updater Maven repository contains missing or unpinned files"
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        exclusiveContent {
            forRepository {
                maven {
                    name = "PinnedAndroidUpdater"
                    url = uri(rootDir.resolve("third_party/android-updater/maven"))
                }
            }
            filter { includeModule("io.github.phillip9933", "android-updater") }
        }
        maven {
            name = "OfflineScannerRelease"
            url = uri(rootDir.resolve(".gradle/open-android-doc-scanner-0.7.0/maven"))
            content {
                includeGroup("dev.offlinescan")
            }
        }
    }
}

rootProject.name = "raiun"

include(":app")
include(":core:model")
include(":core:crypto")
include(":core:designsystem")
include(":core:ui")
include(":core:network")
include(":core:security")
include(":core:database")
include(":core:sync")
include(":core:documentsprovider")
include(":core:datastore")
include(":feature:auth")
include(":feature:files")
include(":feature:search")
include(":feature:transfers")
include(":feature:settings")
include(":feature:account")
include(":feature:shares")
include(":feature:spaces")
