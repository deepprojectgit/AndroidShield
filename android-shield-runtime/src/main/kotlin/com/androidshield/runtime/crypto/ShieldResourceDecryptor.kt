package com.androidshield.runtime.crypto

import com.androidshield.core.crypto.ResourcePayloadCodec
import com.androidshield.core.crypto.ShieldAlgorithm

/**
 * Opens AS1 encrypted resources produced by the AndroidShield Gradle plugin.
 */
object ShieldResourceDecryptor {
    /**
     * Decrypts an AS1 container using the current [BuildSecrets] key.
     */
    @JvmStatic
    @JvmOverloads
    fun open(
        sealed: ByteArray,
        algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM,
    ): ByteArray {
        val key = BuildSecrets.resolveKey()
        return ResourcePayloadCodec.open(sealed, key, algorithm)
    }

    /**
     * Decrypts an AS1 container to a UTF-8 string.
     */
    @JvmStatic
    @JvmOverloads
    fun openUtf8(
        sealed: ByteArray,
        algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM,
    ): String = open(sealed, algorithm).toString(Charsets.UTF_8)
}
