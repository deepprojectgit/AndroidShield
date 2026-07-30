package com.androidshield.cli

import com.androidshield.cli.analyze.ProtectionAnalyzer
import com.androidshield.cli.apk.ApkInspector
import com.androidshield.cli.output.CliReporter
import com.androidshield.core.AndroidShieldCore
import com.androidshield.core.report.ScoringPolicy
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.choice
import com.github.ajalt.clikt.parameters.types.file
import java.io.File
import java.io.IOException
import kotlin.system.exitProcess

/**
 * AndroidShield CLI — offline APK/AAR inspection, verify, and security reports for CI.
 *
 * Exit codes for `verify` / `report --fail-on-threats`:
 * - 0: secure
 * - 1: insecure (policy failed)
 * - 2: invalid input / I/O error
 */
fun main(args: Array<String>) {
    AndroidShieldCli()
        .subcommands(
            VersionCommand(),
            InspectCommand(),
            VerifyCommand(),
            ReportCommand()
        )
        .main(args)
}

internal class AndroidShieldCli : CliktCommand(name = "android-shield") {
    override fun help(context: Context): String =
        "AndroidShield offline protection tooling (inspect / verify / report)"

    override fun run(): Unit = Unit
}

internal class VersionCommand : CliktCommand(name = "version") {
    override fun help(context: Context): String = "Print CLI and core API version"

    override fun run() {
        echo(
            "android-shield-cli ${AndroidShieldCore.VERSION_NAME} " +
                "(core API level ${AndroidShieldCore.API_LEVEL})"
        )
    }
}

internal class InspectCommand : CliktCommand(name = "inspect") {
    override fun help(context: Context): String =
        "Inspect an APK/AAR/AAB for structure and AndroidShield markers"

    private val input by argument(help = "Path to APK, AAR, AAB, or ZIP")
        .file(mustExist = true, canBeDir = false, mustBeReadable = true)

    private val json by option("--json", help = "Emit machine-readable JSON").flag()
    private val verbose by option("-v", "--verbose", help = "Verbose listing").flag()

    override fun run() {
        try {
            val analysis = ApkInspector.inspect(input)
            if (json) {
                echo(CliReporter.inspectJson(analysis))
            } else {
                CliReporter.printInspection(analysis, verbose)
            }
        } catch (error: IOException) {
            echo("inspect failed: ${error.message}", err = true)
            exitProcess(2)
        } catch (error: IllegalArgumentException) {
            echo("inspect failed: ${error.message}", err = true)
            exitProcess(2)
        }
    }
}

internal class VerifyCommand : CliktCommand(name = "verify") {
    override fun help(context: Context): String =
        "Verify protection posture and exit non-zero when insecure (CI gate)"

    private val input by argument(help = "Path to APK/AAR/AAB")
        .file(mustExist = true, canBeDir = false, mustBeReadable = true)

    private val policyName by option("--policy", help = "Scoring policy")
        .choice("default", "strict")
        .default("default")

    private val requireIntegrity by option(
        "--require-integrity",
        help = "Fail when integrity.json is missing"
    ).flag()

    private val requireNative by option(
        "--require-native",
        help = "Fail when libandroidshield.so is missing"
    ).flag()

    private val requireEncryptedAssets by option(
        "--require-encrypted-assets",
        help = "Fail when no AS1 encrypted assets are present"
    ).flag()

    private val json by option("--json", help = "Print SecurityReport JSON").flag()

    override fun run() {
        try {
            val analysis = ApkInspector.inspect(input)
            val policy = if (policyName == "strict") ScoringPolicy.STRICT else ScoringPolicy.DEFAULT
            val report = ProtectionAnalyzer.analyze(
                analysis = analysis,
                policy = policy,
                requireIntegrityMetadata = requireIntegrity,
                requireNativeLib = requireNative,
                requireEncryptedAssets = requireEncryptedAssets
            )
            CliReporter.printReport(report, asJson = json)
            if (!report.secure) {
                exitProcess(1)
            }
        } catch (error: IOException) {
            echo("verify failed: ${error.message}", err = true)
            exitProcess(2)
        } catch (error: IllegalArgumentException) {
            echo("verify failed: ${error.message}", err = true)
            exitProcess(2)
        }
    }
}

internal class ReportCommand : CliktCommand(name = "report") {
    override fun help(context: Context): String =
        "Generate a SecurityReport JSON for an APK/AAR/AAB"

    private val input by argument(help = "Path to APK/AAR/AAB")
        .file(mustExist = true, canBeDir = false, mustBeReadable = true)

    private val output by option("-o", "--output", help = "Write report to file instead of stdout")
        .file(canBeDir = false)

    private val policyName by option("--policy", help = "Scoring policy")
        .choice("default", "strict")
        .default("default")

    private val requireIntegrity by option("--require-integrity").flag()
    private val requireNative by option("--require-native").flag()
    private val requireEncryptedAssets by option("--require-encrypted-assets").flag()
    private val failOnThreats by option(
        "--fail-on-threats",
        help = "Exit 1 when report is insecure"
    ).flag()

    override fun run() {
        try {
            val analysis = ApkInspector.inspect(input)
            val policy = if (policyName == "strict") ScoringPolicy.STRICT else ScoringPolicy.DEFAULT
            val report = ProtectionAnalyzer.analyze(
                analysis = analysis,
                policy = policy,
                requireIntegrityMetadata = requireIntegrity,
                requireNativeLib = requireNative,
                requireEncryptedAssets = requireEncryptedAssets
            )
            val text = com.androidshield.core.report.SecurityReportBuilder.toJson(report)
            val outFile: File? = output
            if (outFile != null) {
                outFile.parentFile?.mkdirs()
                outFile.writeText(text)
                echo("Wrote ${outFile.absolutePath}")
            } else {
                echo(text)
            }
            if (failOnThreats && !report.secure) {
                exitProcess(1)
            }
        } catch (error: IOException) {
            echo("report failed: ${error.message}", err = true)
            exitProcess(2)
        } catch (error: IllegalArgumentException) {
            echo("report failed: ${error.message}", err = true)
            exitProcess(2)
        }
    }
}
