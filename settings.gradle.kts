pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven {
            name = "OfflineScannerRelease"
            url = uri(rootDir.resolve(".gradle/open-android-doc-scanner-0.1.0-rc11/maven"))
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
