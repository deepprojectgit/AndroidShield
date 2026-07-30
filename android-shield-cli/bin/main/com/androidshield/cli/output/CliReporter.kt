package com.androidshield.cli.output

import com.androidshield.cli.apk.PackageAnalysis
import com.androidshield.core.model.SecurityReport
import com.androidshield.core.report.SecurityReportBuilder
import com.github.ajalt.mordant.rendering.TextColors
import com.github.ajalt.mordant.terminal.Terminal
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Human + JSON output helpers for the CLI.
 */
object CliReporter {
    private val json = Json {
        prettyPrint = true
        encodeDefaults = true
    }

    private val terminal = Terminal()

    fun printInspection(analysis: PackageAnalysis, verbose: Boolean) {
        terminal.println(TextColors.brightCyan("AndroidShield inspect"))
        terminal.println("path        : ${analysis.path}")
        terminal.println("kind        : ${analysis.kind}")
        terminal.println("sha256      : ${analysis.fileSha256}")
        terminal.println("size        : ${analysis.sizeBytes} bytes")
        terminal.println("entries     : ${analysis.entryCount}")
        terminal.println("dex         : ${analysis.dexFiles.joinToString().ifEmpty { "(none)" }}")
        terminal.println("native libs : ${analysis.nativeLibraries.size}")
        terminal.println("manifest    : ${analysis.hasAndroidManifest}")
        terminal.println("integrity   : ${analysis.hasIntegrityMetadata}")
        terminal.println("as1 assets  : ${analysis.encryptedAssetPaths.size}")
        terminal.println("markers     : ${analysis.shieldMarkerHits.joinToString().ifEmpty { "(none)" }}")
        if (verbose) {
            if (analysis.nativeLibraries.isNotEmpty()) {
                terminal.println("natives:")
                analysis.nativeLibraries.forEach { terminal.println("  - $it") }
            }
            if (analysis.encryptedAssetPaths.isNotEmpty()) {
                terminal.println("encrypted assets:")
                analysis.encryptedAssetPaths.forEach { terminal.println("  - $it") }
            }
            analysis.integrityMetadata?.let {
                terminal.println("fingerprint : ${it.buildFingerprint}")
                terminal.println("package     : ${it.packageName}")
                terminal.println("variant     : ${it.variantName}")
            }
        }
    }

    fun printReport(report: SecurityReport, asJson: Boolean) {
        if (asJson) {
            terminal.println(SecurityReportBuilder.toJson(report))
            return
        }
        val statusColor = if (report.secure) TextColors.green else TextColors.red
        terminal.println(statusColor("secure=${report.secure} score=${report.score} threats=${report.threats.size}"))
        report.threats.forEach { threat ->
            val color = when (threat.severity.name) {
                "CRITICAL", "HIGH" -> TextColors.red
                "MEDIUM" -> TextColors.yellow
                else -> TextColors.gray
            }
            terminal.println(color("[${threat.severity}] ${threat.id} — ${threat.title}"))
            terminal.println("  ${threat.description}")
            terminal.println("  → ${threat.recommendation}")
        }
    }

    fun inspectJson(analysis: PackageAnalysis): String =
        json.encodeToString(InspectDto.from(analysis))

    @Serializable
    data class InspectDto(
        val path: String,
        val kind: String,
        val fileSha256: String,
        val sizeBytes: Long,
        val entryCount: Int,
        val dexFiles: List<String>,
        val nativeLibraries: List<String>,
        val hasAndroidManifest: Boolean,
        val hasIntegrityMetadata: Boolean,
        val encryptedAssetPaths: List<String>,
        val shieldMarkerHits: List<String>,
        val buildFingerprint: String? = null,
    ) {
        companion object {
            fun from(a: PackageAnalysis) = InspectDto(
                path = a.path,
                kind = a.kind.name,
                fileSha256 = a.fileSha256,
                sizeBytes = a.sizeBytes,
                entryCount = a.entryCount,
                dexFiles = a.dexFiles,
                nativeLibraries = a.nativeLibraries,
                hasAndroidManifest = a.hasAndroidManifest,
                hasIntegrityMetadata = a.hasIntegrityMetadata,
                encryptedAssetPaths = a.encryptedAssetPaths,
                shieldMarkerHits = a.shieldMarkerHits,
                buildFingerprint = a.integrityMetadata?.buildFingerprint,
            )
        }
    }
}
