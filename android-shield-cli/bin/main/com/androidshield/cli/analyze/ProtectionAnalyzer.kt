package com.androidshield.cli.analyze

import com.androidshield.cli.apk.PackageAnalysis
import com.androidshield.cli.apk.PackageKind
import com.androidshield.core.model.SecurityReport
import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.core.report.ScoringPolicy
import com.androidshield.core.report.SecurityReportBuilder

/**
 * Offline protection posture analysis for CI / release gating.
 */
object ProtectionAnalyzer {
    fun analyze(
        analysis: PackageAnalysis,
        policy: ScoringPolicy = ScoringPolicy.DEFAULT,
        requireIntegrityMetadata: Boolean = false,
        requireNativeLib: Boolean = false,
        requireEncryptedAssets: Boolean = false
    ): SecurityReport {
        val threats = mutableListOf<Threat>()
        threats += packageStructureThreats(analysis)
        threats += integrityThreats(analysis, requireIntegrityMetadata, requireEncryptedAssets)
        threats += runtimeThreats(analysis)
        threats += nativeThreats(analysis, requireNativeLib)
        threats += encryptedAssetThreats(analysis, requireEncryptedAssets)
        threats += transformMarkerThreats(analysis)
        return SecurityReportBuilder.fromThreats(threats, policy)
    }

    private fun packageStructureThreats(analysis: PackageAnalysis): List<Threat> {
        val threats = mutableListOf<Threat>()
        if (analysis.kind == PackageKind.UNKNOWN) {
            threats += threat(
                "cli.package.unknown_type",
                "Unknown package type",
                Severity.MEDIUM,
                "File extension is not apk/aar/aab/zip",
                "Pass an Android package artifact"
            )
        }
        if (analysis.kind == PackageKind.APK || analysis.kind == PackageKind.AAB) {
            if (analysis.dexFiles.isEmpty()) {
                threats += threat(
                    "cli.package.no_dex",
                    "No DEX entries",
                    Severity.CRITICAL,
                    "Package contains no classes*.dex",
                    "Rebuild the Android app/bundle"
                )
            }
            if (!analysis.hasAndroidManifest) {
                threats += threat(
                    "cli.package.no_manifest",
                    "Missing AndroidManifest.xml",
                    Severity.HIGH,
                    "Manifest entry not found in archive",
                    "Ensure a valid Android package was provided"
                )
            }
        }
        if (analysis.kind == PackageKind.APK && analysis.v1SigningEntries.isEmpty()) {
            threats += threat(
                "cli.signing.v1_absent",
                "No V1 META-INF signatures",
                Severity.LOW,
                "No META-INF/*.RSA|*.SF entries (may still be V2/V3 signed)",
                "Prefer verifying with apksigner for production signing validation"
            )
        }
        return threats
    }

    private fun integrityThreats(
        analysis: PackageAnalysis,
        requireIntegrityMetadata: Boolean,
        requireEncryptedAssets: Boolean
    ): List<Threat> {
        if (!analysis.hasIntegrityMetadata) {
            val severity = if (requireIntegrityMetadata) Severity.HIGH else Severity.MEDIUM
            return listOf(
                threat(
                    "cli.shield.integrity_missing",
                    "Integrity metadata missing",
                    severity,
                    "assets/androidshield/integrity.json not found",
                    "Apply io.github.deepprojectgit.androidshield and ship " +
                        "generateShieldArtifacts output"
                )
            )
        }
        val meta = analysis.integrityMetadata ?: return emptyList()
        val threats = mutableListOf<Threat>()
        if (!meta.stringEncryptionEnabled) {
            threats += threat(
                "cli.shield.string_encryption_off",
                "String encryption disabled in metadata",
                Severity.MEDIUM,
                "integrity.json reports stringEncryptionEnabled=false",
                "Enable stringEncryption in androidShield DSL"
            )
        }
        if (!meta.resourceEncryptionEnabled && requireEncryptedAssets) {
            threats += threat(
                "cli.shield.resource_encryption_off",
                "Resource encryption disabled in metadata",
                Severity.MEDIUM,
                "integrity.json reports resourceEncryptionEnabled=false",
                "Enable resourceEncryption in androidShield DSL"
            )
        }
        return threats
    }

    private fun runtimeThreats(analysis: PackageAnalysis): List<Threat> {
        if (analysis.kind != PackageKind.APK) return emptyList()
        val hasRuntime = analysis.shieldMarkerHits.any {
            it.startsWith("dex:runtime") || it == "dex:android_shield"
        }
        if (hasRuntime) return emptyList()
        return listOf(
            threat(
                "cli.shield.runtime_missing",
                "AndroidShield runtime not detected in DEX",
                Severity.HIGH,
                "No com.androidshield.runtime markers found in classes.dex",
                "Add implementation dependency on android-shield-runtime"
            )
        )
    }

    private fun nativeThreats(analysis: PackageAnalysis, requireNativeLib: Boolean): List<Threat> {
        val hasNative = analysis.nativeLibraries.any { it.contains("libandroidshield") } ||
            analysis.shieldMarkerHits.contains("native:libandroidshield")
        return when {
            requireNativeLib && !hasNative -> listOf(
                threat(
                    "cli.shield.native_missing",
                    "Native libandroidshield missing",
                    Severity.HIGH,
                    "No libandroidshield.so under lib/",
                    "Depend on android-shield-native / enable nativeProtection"
                )
            )
            !hasNative && analysis.kind == PackageKind.APK -> listOf(
                threat(
                    "cli.shield.native_not_found",
                    "Native library not found",
                    Severity.LOW,
                    "libandroidshield.so not packaged (optional unless required)",
                    "Include android-shield-native for stronger native checks"
                )
            )
            else -> emptyList()
        }
    }

    private fun encryptedAssetThreats(
        analysis: PackageAnalysis,
        requireEncryptedAssets: Boolean
    ): List<Threat> {
        if (!requireEncryptedAssets || analysis.encryptedAssetPaths.isNotEmpty()) {
            return emptyList()
        }
        return listOf(
            threat(
                "cli.shield.encrypted_assets_missing",
                "No AS1 encrypted assets",
                Severity.MEDIUM,
                "No assets with AndroidShield AS1 magic",
                "Enable resourceEncryption and encryptAssetPatterns"
            )
        )
    }

    private fun transformMarkerThreats(analysis: PackageAnalysis): List<Threat> {
        if (analysis.kind != PackageKind.APK) return emptyList()
        val hasRuntime = analysis.shieldMarkerHits.any {
            it.startsWith("dex:runtime") || it == "dex:android_shield"
        }
        if (!hasRuntime) return emptyList()
        val hasTransformMarkers = analysis.shieldMarkerHits.any { hit ->
            hit.contains("string_decryptor") || hit.contains("build_secrets")
        }
        if (hasTransformMarkers) return emptyList()
        return listOf(
            threat(
                "cli.shield.transform_markers_weak",
                "String decrypt / secrets markers weak",
                Severity.LOW,
                "Runtime present but BuildShieldSecrets/ShieldStringDecryptor strings not obvious",
                "Confirm the Gradle plugin ran on this variant"
            )
        )
    }

    private fun threat(
        id: String,
        title: String,
        severity: Severity,
        description: String,
        recommendation: String
    ) = Threat(id, title, severity, description, recommendation)
}
