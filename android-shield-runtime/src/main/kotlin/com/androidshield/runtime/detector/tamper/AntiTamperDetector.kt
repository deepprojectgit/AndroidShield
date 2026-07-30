package com.androidshield.runtime.detector.tamper

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.androidshield.core.config.ShieldConfig
import com.androidshield.core.integrity.DigestUtils
import com.androidshield.core.integrity.IntegrityMetadataCodec
import com.androidshield.core.integrity.IntegrityVerifier
import com.androidshield.core.integrity.ObservedIntegrity
import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.runtime.detector.ThreatDetector
import com.androidshield.runtime.detector.threat
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * APK signature / certificate / integrity metadata tamper checks.
 */
class AntiTamperDetector : ThreatDetector {
    override val id: String = "tamper"

    override fun isEnabled(config: ShieldConfig): Boolean = config.antiTamper

    override fun detect(context: Context): List<Threat> {
        val threats = mutableListOf<Threat>()

        val signatures = readSignatures(context)
        if (signatures.isEmpty()) {
            threats += threat(
                id = "tamper.signature_missing",
                title = "APK signatures unavailable",
                severity = Severity.HIGH,
                description = "Could not read package signing certificates",
                recommendation = "Investigate package manager / spoofed environment",
            )
        }

        loadEmbeddedMetadata(context)?.let { metadata ->
            val observed = ObservedIntegrity(
                buildFingerprint = metadata.buildFingerprint,
            )
            val result = IntegrityVerifier.verify(metadata, observed)
            if (!result.matches) {
                threats += result.threats
            }
        }

        if (installerSuspicious(context)) {
            threats += threat(
                id = "tamper.sideloaded",
                title = "Non-store installer",
                severity = Severity.MEDIUM,
                description = "Package installer is null or not a known store",
                recommendation = "Warn users or require Play distribution for production",
            )
        }

        return threats
    }

    private fun readSignatures(context: Context): List<ByteArray> {
        return runCatching {
            val pm = context.packageManager
            val packageName = context.packageName
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val signingInfo = info.signingInfo ?: return emptyList()
                val signers = if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners
                } else {
                    signingInfo.signingCertificateHistory
                }
                signers?.map { it.toByteArray() }.orEmpty()
            } else {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                info.signatures?.map { it.toByteArray() }.orEmpty()
            }
        }.getOrDefault(emptyList())
    }

    private fun loadEmbeddedMetadata(context: Context) =
        runCatching {
            context.assets.open("androidshield/integrity.json").use { input ->
                IntegrityMetadataCodec.decode(input.readBytes())
            }
        }.getOrNull()

    private fun installerSuspicious(context: Context): Boolean {
        val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getInstallerPackageName(context.packageName)
        }
        if (installer.isNullOrBlank()) return true
        val trusted = setOf(
            "com.android.vending",
            "com.google.android.feedback",
            "com.amazon.venezia",
        )
        return installer !in trusted
    }

    companion object {
        /**
         * Computes SHA-256 of the first X.509 certificate in a signing block (utility for hosts).
         */
        fun certificateSha256(certBytes: ByteArray): String {
            val factory = CertificateFactory.getInstance("X.509")
            val cert = factory.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
            return DigestUtils.sha256Hex(cert.encoded)
        }
    }
}
