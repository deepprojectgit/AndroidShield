package com.androidshield.runtime.play

import android.content.Context
import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.runtime.detector.threat
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import java.util.UUID

/**
 * Thin Play Integrity API wrapper returning token + basic interpretation hooks.
 *
 * Full verdict decoding requires a backend with Google Play Integrity decryption.
 * Client-side this module surfaces token acquisition and availability threats.
 */
class PlayIntegrityClient(
    context: Context,
    private val cloudProjectNumber: Long? = null,
) {
    private val appContext = context.applicationContext
    private val manager = IntegrityManagerFactory.create(appContext)

    /**
     * Requests an integrity token for [nonce] (UTF-8, max 500 chars recommended by Google).
     */
    suspend fun requestToken(nonce: String = UUID.randomUUID().toString()): String {
        val requestBuilder = IntegrityTokenRequest.builder().setNonce(nonce)
        cloudProjectNumber?.let { requestBuilder.setCloudProjectNumber(it) }
        return suspendCancellableCoroutine { cont ->
            manager.requestIntegrityToken(requestBuilder.build())
                .addOnSuccessListener { response ->
                    cont.resume(response.token())
                }
                .addOnFailureListener { error ->
                    cont.resumeWithException(error)
                }
        }
    }

    /**
     * Produces threats when Play Integrity is unavailable / misconfigured locally.
     */
    fun availabilityThreats(enabledInConfig: Boolean): List<Threat> {
        if (!enabledInConfig) return emptyList()
        return listOf(
            threat(
                id = "play.integrity.client_ready",
                title = "Play Integrity client ready",
                severity = Severity.LOW,
                description = "IntegrityManager created — decrypt/verdict on backend required for strong/device/basic",
                recommendation = "Call requestToken() and verify on your server for Basic/Device/Strong verdicts",
            ),
        )
    }

    companion object {
        /**
         * Interprets a server-side decoded verdict JSON fragment into threats (host supplied).
         *
         * Expected keys: `deviceIntegrity` list containing MEETS_BASIC/DEVICE/STRONG.
         */
        @JvmStatic
        fun threatsFromVerdict(deviceIntegrity: List<String>): List<Threat> {
            val threats = mutableListOf<Threat>()
            if (deviceIntegrity.none { it.contains("MEETS_BASIC", ignoreCase = true) }) {
                threats += threat(
                    id = "play.integrity.basic_failed",
                    title = "Basic integrity failed",
                    severity = Severity.HIGH,
                    description = "deviceIntegrity=$deviceIntegrity",
                    recommendation = "Device/app integrity does not meet BASIC",
                )
            }
            if (deviceIntegrity.none { it.contains("MEETS_DEVICE", ignoreCase = true) }) {
                threats += threat(
                    id = "play.integrity.device_failed",
                    title = "Device integrity failed",
                    severity = Severity.MEDIUM,
                    description = "deviceIntegrity=$deviceIntegrity",
                    recommendation = "Device may be rooted/unlocked — apply policy",
                )
            }
            if (deviceIntegrity.none { it.contains("MEETS_STRONG", ignoreCase = true) }) {
                threats += threat(
                    id = "play.integrity.strong_failed",
                    title = "Strong integrity not met",
                    severity = Severity.LOW,
                    description = "deviceIntegrity=$deviceIntegrity",
                    recommendation = "Hardware-backed strong integrity unavailable",
                )
            }
            return threats
        }
    }
}
