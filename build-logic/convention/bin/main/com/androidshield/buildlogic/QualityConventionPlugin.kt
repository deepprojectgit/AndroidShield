package com.androidshield.buildlogic

import io.gitlab.arturbosch.detekt.extensions.DetektExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.dependencies
import org.jlleitschuh.gradle.ktlint.KtlintExtension
import java.io.File

/**
 * Detekt + Ktlint quality baseline for all Kotlin modules.
 */
class QualityConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply("io.gitlab.arturbosch.detekt")
            pluginManager.apply("org.jlleitschuh.gradle.ktlint")

            extensions.configure<DetektExtension> {
                buildUponDefaultConfig = true
                allRules = false
                config.setFrom(rootProject.file("config/detekt/detekt.yml"))
                parallel = true
            }

            extensions.configure<KtlintExtension> {
                android.set(true)
                ignoreFailures.set(false)
                filter {
                    exclude { element ->
                        element.file.path.contains("${File.separator}generated${File.separator}")
                    }
                }
            }

            dependencies {
                "detektPlugins"(
                    "io.gitlab.arturbosch.detekt:detekt-formatting:${libs.findVersion("detekt").get().requiredVersion}",
                )
            }
        }
    }
}
