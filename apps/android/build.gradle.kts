import io.gitlab.arturbosch.detekt.extensions.DetektExtension
import org.jlleitschuh.gradle.ktlint.KtlintExtension

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.ksp) apply false
    alias(libs.plugins.detekt) apply false
    alias(libs.plugins.ktlint) apply false
    alias(libs.plugins.roborazzi) apply false
    alias(libs.plugins.protobuf) apply false
}

val checkComposeDesignTokens =
    tasks.register("checkComposeDesignTokens") {
        group = "verification"
        description = "Rejects hardcoded Compose colors and dimensions outside the centralized theme."

        val composeSources =
            fileTree(rootDir) {
                include("**/src/main/**/*.kt")
                exclude("core/designsystem/src/main/**/theme/**")
            }
        doLast {
            val forbidden =
                listOf(
                    "hardcoded color" to Regex("\\bColor\\s*\\(|\\bColor\\."),
                    "hardcoded dimension" to Regex("\\b\\d+(?:\\.\\d+)?\\.(?:dp|sp)\\b"),
                )
            val violations =
                composeSources.files.flatMap { source ->
                    source.readLines().mapIndexedNotNull { index, line ->
                        forbidden.firstOrNull { (_, pattern) -> pattern.containsMatchIn(line) }
                            ?.let { (kind, _) -> "${source.relativeTo(rootDir)}:${index + 1}: $kind: ${line.trim()}" }
                    }
                }
            check(violations.isEmpty()) {
                "Compose design-token violations found. Use OpenCloudColor/OpenCloudDimensions:\n" +
                    violations.joinToString("\n")
            }
        }
    }

subprojects {
    apply(plugin = "io.gitlab.arturbosch.detekt")
    apply(plugin = "org.jlleitschuh.gradle.ktlint")

    extensions.configure<DetektExtension> {
        buildUponDefaultConfig = true
        allRules = false
        config.setFrom(rootProject.files("config/detekt/detekt.yml"))
    }

    extensions.configure<KtlintExtension> {
        android.set(true)
        outputToConsole.set(true)
        ignoreFailures.set(false)
    }

    dependencies {
        add("detektPlugins", "io.gitlab.arturbosch.detekt:detekt-formatting:1.23.8")
        add("detektPlugins", rootProject.libs.compose.rules.detekt)
    }

    tasks.matching { it.name.startsWith("detekt") }.configureEach {
        dependsOn(checkComposeDesignTokens)
    }
}
