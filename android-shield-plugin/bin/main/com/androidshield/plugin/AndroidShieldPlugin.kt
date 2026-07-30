package com.androidshield.plugin

import com.androidshield.plugin.extension.AndroidShieldExtension
import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * AndroidShield Gradle plugin entry point.
 *
 * Provides:
 * - `androidShield { }` DSL
 * - ASM bytecode instrumentation (string encryption, metadata strip, obfuscation noise)
 * - Integrity metadata + build fingerprint
 * - Resource encryption task
 * - R8 rule generation
 * - Native config generation
 * - Security report + release validation
 * - Mapping protection
 */
class AndroidShieldPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        val extension = target.extensions.create(
            "androidShield",
            AndroidShieldExtension::class.java,
        )

        val configure = {
            AndroidShieldConfigurator.configure(target, extension)
        }

        var configured = false
        fun configureOnce() {
            if (configured) return
            configured = true
            configure()
        }

        target.pluginManager.withPlugin("com.android.application") { configureOnce() }
        target.pluginManager.withPlugin("com.android.library") { configureOnce() }

        target.tasks.register("androidShieldValidate") {
            group = "androidshield"
            description = "Validates AndroidShield configuration"
            doLast {
                logger.lifecycle(
                    "AndroidShield plugin applied (enabled={}, stringEncryption={})",
                    extension.enabled.get(),
                    extension.stringEncryption.get(),
                )
            }
        }
    }
}
