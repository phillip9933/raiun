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
        versionCode = 51
        versionName = "1.3.1"

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
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
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

    sourceSets.getByName("androidTest").assets.srcDir(layout.buildDirectory.dir("generated/updater-test-assets"))
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
tasks.matching { it.name == "mergeDebugAndroidTestAssets" }.configureEach {
    dependsOn(generateUpdaterTestApks)
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
