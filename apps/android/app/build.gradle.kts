import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.security.MessageDigest
import java.util.Properties

val localProperties =
    Properties().apply {
        val propertiesFile = rootProject.file("local.properties")
        if (propertiesFile.exists()) propertiesFile.inputStream().use(::load)
    }

fun localPropertyBuildConfigValue(name: String): String =
    localProperties
        .getProperty(name, "")
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .let { "\"$it\"" }

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.roborazzi)
}

val appVersionCode = 62
// Deliberately absent from ordinary builds: this candidate is for disposable native validation.
val r8ValidationEnabled = providers.gradleProperty("raiun.r8Validation").map { it.toBooleanStrict() }.getOrElse(false)
val r8InstrumentationEnabled =
    providers
        .gradleProperty("raiun.r8Instrumentation")
        .map {
            it.toBooleanStrict()
        }.getOrElse(false)
check(!r8InstrumentationEnabled || r8ValidationEnabled) { "R8 instrumentation requires raiun.r8Validation=true" }
val r8TestAbiRules = providers.gradleProperty("raiun.r8TestAbiRules").orNull
check(r8TestAbiRules == null || r8InstrumentationEnabled) {
    "R8 test ABI rules require raiun.r8Instrumentation=true"
}
val r8UpgradeVersionCode = providers.gradleProperty("raiun.r8UpgradeVersionCode").orNull?.toInt()
check(r8UpgradeVersionCode == null || (r8ValidationEnabled && !r8InstrumentationEnabled)) {
    "Upgrade version overrides require standalone R8 validation"
}
check(r8UpgradeVersionCode == null || r8UpgradeVersionCode > appVersionCode) {
    "The synthetic upgrade version must exceed the published version code"
}

android {
    namespace = "eu.opencloud.android.next"
    compileSdk =
        libs.versions.compileSdk
            .get()
            .toInt()

    defaultConfig {
        applicationId = "app.raiun.cloud"
        minSdk =
            libs.versions.minSdk
                .get()
                .toInt()
        targetSdk =
            libs.versions.targetSdk
                .get()
                .toInt()
        // The scanner SDK ships native processing for 64-bit Android only.
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        versionCode = r8UpgradeVersionCode ?: appVersionCode
        versionName = "1.6.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("String", "DEV_SERVER_URL", "\"\"")
        buildConfigField("String", "DEV_SERVER_USERNAME", "\"\"")
        buildConfigField("String", "DEV_SERVER_PASSWORD", "\"\"")
    }

    buildTypes {
        debug {
            versionNameSuffix = "-debug"
            buildConfigField("String", "DEV_SERVER_URL", localPropertyBuildConfigValue("dev.server.url"))
            buildConfigField("String", "DEV_SERVER_USERNAME", localPropertyBuildConfigValue("dev.server.username"))
            buildConfigField("String", "DEV_SERVER_PASSWORD", localPropertyBuildConfigValue("dev.server.password"))
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
                "proguard-native-r8.pro",
                "proguard-storage-r8.pro",
            )
        }
        if (r8ValidationEnabled) {
            create("r8Validation") {
                initWith(getByName("release"))
                matchingFallbacks += "release"
                signingConfig = signingConfigs.getByName("debug")
                isDebuggable = false
                isMinifyEnabled = true
                isShrinkResources = true
                // The independent standalone probe build omits these test-only access roots.
                if (r8InstrumentationEnabled) {
                    proguardFiles("proguard-r8-instrumentation.pro")
                    r8TestAbiRules?.let { path ->
                        val rules = file(path)
                        check(rules.isFile) { "The explicit R8 test ABI rule file is missing" }
                        proguardFiles(rules)
                    }
                }
                versionNameSuffix = "-r8-validation"
                testProguardFiles("r8-validation-test-rules.pro")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    buildFeatures {
        buildConfig = true
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
    if (r8ValidationEnabled) testBuildType = "r8Validation"
    if (r8InstrumentationEnabled) {
        // Compose's debug-only test host must not enter the standalone/release manifest.
        sourceSets.getByName("r8Validation").manifest.srcFile("src/r8Instrumentation/AndroidManifest.xml")
    }

    sourceSets.getByName("androidTest").assets.srcDir(layout.buildDirectory.dir("generated/updater-test-assets"))
    sourceSets
        .getByName(
            "androidTest",
        ).assets
        .srcDir(layout.buildDirectory.dir("generated/share-provenance-test-assets"))
}

// Match synthetic verifier fixtures to this build's disposable default debug key.
// In particular, a checked-in APK would not match another developer's debug signer.
val generateUpdaterTestApks =
    tasks.register<Exec>("generateUpdaterTestApks") {
        group = "verification"
        description = "Generates signed, manifest-only updater APKs for Android instrumentation tests."
        dependsOn("validateSigningDebug")
        val signing = android.signingConfigs.getByName("debug")
        val debugKey = requireNotNull(signing.storeFile) { "Default debug keystore is unavailable" }
        doFirst {
            check(signing.storePassword == "android" && signing.keyPassword == "android") {
                "Updater fixtures require the standard Android debug signing configuration"
            }
        }
        val script = rootProject.file("scripts/generate_updater_test_apks.py")
        val output = layout.buildDirectory.dir("generated/updater-test-assets/updater")
        inputs.file(script)
        inputs.file(debugKey)
        inputs.property("applicationId", android.defaultConfig.applicationId)
        inputs.property("versionCode", android.defaultConfig.versionCode)
        inputs.property("minSdk", android.defaultConfig.minSdk)
        inputs.property("compileSdk", android.compileSdk)
        outputs.dir(output)
        val javaHome = System.getProperty("java.home")
        val defaultPython = if (System.getProperty("os.name").startsWith("Windows")) "python" else "python3"
        val python = providers.gradleProperty("pythonExecutable").orElse(defaultPython).get()
        inputs.property("javaHome", javaHome)
        environment("FIXTURE_STORE_PASSWORD", "android")
        commandLine(
            python,
            script.absolutePath,
            "--java-home",
            javaHome,
            "--project",
            rootProject.projectDir.absolutePath,
            "--keystore",
            debugKey.absolutePath,
            "--key-alias",
            requireNotNull(signing.keyAlias),
            "--application-id",
            requireNotNull(android.defaultConfig.applicationId),
            "--installed-code",
            requireNotNull(android.defaultConfig.versionCode).toString(),
            "--min-sdk",
            requireNotNull(android.defaultConfig.minSdk).toString(),
            "--compile-sdk",
            requireNotNull(android.compileSdk).toString(),
            "--output",
            output.get().asFile.absolutePath,
        )
    }
// Separate external sender/provider APK; never included in the shipped application.
val generateShareProvenanceFixtureApk =
    tasks.register<Exec>("generateShareProvenanceFixtureApk") {
        group = "verification"
        description = "Generates an isolated external sender/provider fixture for URI provenance tests."
        dependsOn("validateSigningDebug")
        val signing = android.signingConfigs.getByName("debug")
        val debugKey = requireNotNull(signing.storeFile) { "Default debug keystore is unavailable" }
        doFirst {
            check(signing.storePassword == "android" && signing.keyPassword == "android") {
                "Share fixtures require the standard Android debug signing configuration"
            }
        }
        val script = rootProject.file("scripts/generate_share_provenance_fixture.py")
        val output = layout.buildDirectory.dir("generated/share-provenance-test-assets")
        val javaHome = System.getProperty("java.home")
        val defaultPython = if (System.getProperty("os.name").startsWith("Windows")) "python" else "python3"
        val python = providers.gradleProperty("pythonExecutable").orElse(defaultPython).get()
        inputs.file(script)
        inputs.file(debugKey)
        inputs.property("javaHome", javaHome)
        inputs.property("compileSdk", android.compileSdk)
        outputs.dir(output)
        environment("FIXTURE_STORE_PASSWORD", "android")
        commandLine(
            python,
            script.absolutePath,
            "--java-home",
            javaHome,
            "--project",
            rootProject.projectDir.absolutePath,
            "--keystore",
            debugKey.absolutePath,
            "--key-alias",
            requireNotNull(signing.keyAlias),
            "--compile-sdk",
            requireNotNull(android.compileSdk).toString(),
            "--output",
            output.get().asFile.absolutePath,
        )
    }
tasks.matching { it.name in setOf("mergeDebugAndroidTestAssets", "mergeR8ValidationAndroidTestAssets") }.configureEach {
    dependsOn(generateUpdaterTestApks, generateShareProvenanceFixtureApk)
}

tasks.withType<Test>().configureEach {
    maxHeapSize = "1g"
}

dependencies {
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment)
    implementation(project(":core:designsystem"))
    implementation(project(":core:model"))
    implementation(project(":core:ui"))
    implementation(project(":core:network"))
    implementation(project(":core:security"))
    implementation(project(":core:database"))
    implementation(project(":core:sync"))
    implementation(project(":core:documentsprovider"))
    implementation(project(":core:datastore"))
    implementation(project(":feature:auth"))
    implementation(project(":feature:files"))
    implementation(project(":feature:search"))
    implementation(project(":feature:transfers"))
    implementation(project(":feature:settings"))
    implementation(project(":feature:account"))
    implementation(project(":feature:shares"))
    implementation(project(":feature:spaces"))

    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.browser)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.offline.scanner.compose)

    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(project(":core:crypto"))
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.okhttp)
    androidTestImplementation(libs.offline.scanner.processing)
    androidTestImplementation(libs.offline.scanner.export)
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.androidx.room.runtime)
    testImplementation(libs.androidx.work.testing)
    testImplementation(libs.androidx.activity.compose)
    testImplementation(libs.androidx.compose.ui.test.junit4)
    testImplementation(libs.robolectric)
    testImplementation(libs.roborazzi)
    testImplementation(libs.roborazzi.compose)
}

// Runtime pins were cross-checked against publisher artifacts/metadata before being enabled.
val releaseRuntimeArtifacts =
    providers.provider {
        val configuration = configurations.getByName("releaseRuntimeClasspath")
        configuration.incoming.artifactView { componentFilter { it is ModuleComponentIdentifier } }.artifacts
    }
val verifyReleaseRuntimeArtifacts =
    tasks.register("verifyReleaseRuntimeArtifacts") {
        group = "verification"
        description = "Rejects unpinned or modified third-party binaries entering the release APK."
        val pinsFile = rootProject.file("gradle/runtime-artifact-pins.sha256")
        inputs.file(pinsFile)
        inputs.files(releaseRuntimeArtifacts.map { it.artifactFiles })
        doLast {
            val pins =
                pinsFile.readLines().filter { it.isNotBlank() }.associate { line ->
                    val fields = line.split("  ", limit = 2)
                    check(
                        fields.size == 2 && fields[0].matches(Regex("[0-9a-f]{64}")),
                    ) { "Invalid runtime artifact pin" }
                    fields[1] to fields[0]
                }
            val artifacts = releaseRuntimeArtifacts.get().artifacts
            check(artifacts.isNotEmpty()) { "No release runtime artifacts were resolved for verification" }
            artifacts.forEach { artifact ->
                val component = artifact.id.componentIdentifier as ModuleComponentIdentifier
                val coordinate = "${component.group}:${component.module}:${component.version}"
                val expected = pins[coordinate] ?: error("Unpinned release runtime dependency: $coordinate")
                val digest = MessageDigest.getInstance("SHA-256")
                artifact.file.inputStream().use { input ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        digest.update(buffer, 0, count)
                    }
                }
                val actual = digest.digest().joinToString("") { "%02x".format(it) }
                check(actual == expected) { "Release runtime artifact failed checksum verification: $coordinate" }
            }
            logger.lifecycle("Verified ${artifacts.size} release runtime artifact checksums")
        }
    }
tasks.named("preBuild") { dependsOn(verifyReleaseRuntimeArtifacts) }

if (r8ValidationEnabled) {
    val validationRuntimeArtifacts =
        providers.provider {
            configurations
                .getByName("r8ValidationRuntimeClasspath")
                .incoming
                .artifactView { componentFilter { it is ModuleComponentIdentifier } }
                .artifacts
        }
    val verifyR8ValidationRuntimeArtifacts =
        tasks.register("verifyR8ValidationRuntimeArtifacts") {
            group = "verification"
            description = "Requires R8 candidate binaries to match the checksum-verified release."
            dependsOn(verifyReleaseRuntimeArtifacts)
            inputs.files(validationRuntimeArtifacts.map { it.artifactFiles })
            inputs.files(releaseRuntimeArtifacts.map { it.artifactFiles })
            doLast {
                fun identities(artifacts: org.gradle.api.artifacts.ArtifactCollection): List<String> =
                    artifacts.artifacts
                        .map { artifact ->
                            val component = artifact.id.componentIdentifier as ModuleComponentIdentifier
                            val digest = MessageDigest.getInstance("SHA-256")
                            artifact.file.inputStream().use { input ->
                                val buffer = ByteArray(64 * 1024)
                                while (true) {
                                    val count = input.read(buffer)
                                    if (count < 0) break
                                    digest.update(buffer, 0, count)
                                }
                            }
                            val checksum = digest.digest().joinToString("") { "%02x".format(it) }
                            "${component.group}:${component.module}:${component.version}:$checksum"
                        }.sorted()
                val expected = identities(releaseRuntimeArtifacts.get())
                val actual = identities(validationRuntimeArtifacts.get())
                check(actual.isNotEmpty() && actual == expected) {
                    "R8 validation dependencies must exactly match the pinned release runtime coordinates and checksums"
                }
                logger.lifecycle("Verified ${actual.size} R8 validation runtime artifacts match the pinned release")
            }
        }
    tasks.matching { it.name == "preR8ValidationBuild" }.configureEach {
        dependsOn(verifyR8ValidationRuntimeArtifacts)
    }
}
