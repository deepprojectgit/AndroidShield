package com.androidshield.plugin.validation

import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.plugin.extension.AndroidShieldExtension

/**
 * Validates release configuration for AndroidShield.
 */
object ReleaseValidator {
    fun validate(
        extension: AndroidShieldExtension,
        isMinifyEnabled: Boolean,
        isDebuggable: Boolean,
    ): List<Threat> {
        val threats = mutableListOf<Threat>()
        if (!extension.enabled.get()) {
            threats += Threat(
                id = "build.shield.disabled",
                title = "AndroidShield disabled",
                severity = Severity.HIGH,
                description = "androidShield.enabled is false",
                recommendation = "Enable AndroidShield for release builds",
            )
            return threats
        }
        if (isDebuggable) {
            threats += Threat(
                id = "build.debuggable",
                title = "Debuggable build",
                severity = Severity.CRITICAL,
                description = "android:debuggable (or debug variant) is enabled",
                recommendation = "Ship only non-debuggable release variants",
            )
        }
        if (!isMinifyEnabled && extension.releaseValidation.get()) {
            threats += Threat(
                id = "build.minify.disabled",
                title = "R8/ProGuard minify disabled",
                severity = Severity.HIGH,
                description = "Release minify is off while releaseValidation is enabled",
                recommendation = "Enable isMinifyEnabled for release",
            )
        }
        if (!extension.stringEncryption.get()) {
            threats += Threat(
                id = "build.stringEncryption.disabled",
                title = "String encryption disabled",
                severity = Severity.MEDIUM,
                description = "Sensitive string literals will remain in plaintext DEX",
                recommendation = "Enable stringEncryption",
            )
        }
        if (!extension.antiTamper.get()) {
            threats += Threat(
                id = "build.antiTamper.disabled",
                title = "Anti-tamper disabled",
                severity = Severity.MEDIUM,
                description = "Integrity metadata may not be enforced at runtime",
                recommendation = "Enable antiTamper",
            )
        }
        return threats
    }
}
