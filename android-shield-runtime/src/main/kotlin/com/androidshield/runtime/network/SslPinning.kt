package com.androidshield.runtime.network

import android.util.Base64
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManagerFactory

/**
 * Certificate / public-key pinning helpers with rotation support.
 *
 * Pins use OkHttp-compatible format: `sha256/<base64(SPKI)>`.
 */
data class SslPinningConfig(
    val hostname: String,
    val pins: List<String>,
) {
    init {
        require(hostname.isNotBlank()) { "hostname required" }
        require(pins.isNotEmpty()) { "at least one pin required" }
    }
}

object SslPinning {
    /**
     * Computes `sha256/<base64>` pin for a certificate's public key.
     */
    fun publicKeyPin(certificate: X509Certificate): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(certificate.publicKey.encoded)
        return "sha256/" + Base64.encodeToString(digest, Base64.NO_WRAP)
    }

    /**
     * Verifies that peer certificates match at least one pin for [hostname].
     */
    fun verifySession(hostname: String, session: SSLSession, pins: List<String>): Boolean {
        val certs = try {
            session.peerCertificates
        } catch (_: SSLPeerUnverifiedException) {
            return false
        }
        return certs.any { cert ->
            cert is X509Certificate && pins.contains(publicKeyPin(cert))
        }
    }

    /**
     * Hostname verifier that enforces SPKI pins in addition to default hostname checks.
     * Multiple pins enable rotation (any match succeeds).
     */
    fun pinningHostnameVerifier(
        configs: Map<String, List<String>>,
        delegate: HostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier(),
    ): HostnameVerifier =
        HostnameVerifier { hostname, session ->
            if (!delegate.verify(hostname, session)) return@HostnameVerifier false
            val pins = configs[hostname] ?: return@HostnameVerifier true
            verifySession(hostname, session, pins)
        }

    /**
     * Creates an [SSLContext] using the system trust store.
     */
    fun systemSslContext(): SSLContext {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        val context = SSLContext.getInstance("TLS")
        context.init(null, tmf.trustManagers, null)
        return context
    }

    /**
     * Converts [SslPinningConfig] list into hostname → pins map for [pinningHostnameVerifier].
     */
    fun toHostnameMap(configs: List<SslPinningConfig>): Map<String, List<String>> =
        configs.associate { it.hostname to it.pins }
}
