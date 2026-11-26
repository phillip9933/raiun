import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

val playBuild = providers.gradleProperty("raiun.playBuild").map { it.toBooleanStrict() }.getOrElse(false)

android {
    namespace = "eu.opencloud.android.next.feature.settings"
    compileSdk =
        libs.versions.compileSdk
            .get()
            .toInt()
    defaultConfig {
        minSdk =
            libs.versions.minSdk
                .get()
                .toInt()
    }
    val channel = if (playBuild) "play" else "direct"
    sourceSets.getByName("main").kotlin.srcDir("src/$channel/kotlin")
    if (playBuild) {
        sourceSets.getByName("main").res.srcDir("src/play/res")
    } else {
        sourceSets.getByName("main").manifest.srcFile("src/direct/AndroidManifest.xml")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }
}

dependencies {
    if (!playBuild) api(libs.android.app.updater)
    implementation(libs.androidx.core)
    implementation(libs.androidx.appcompat)
    implementation(project(":core:security"))
    implementation(project(":core:network"))
    implementation(project(":core:sync"))
    implementation(project(":core:datastore"))
    implementation(project(":core:designsystem"))
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.okhttp)
    testImplementation(libs.junit)
}
