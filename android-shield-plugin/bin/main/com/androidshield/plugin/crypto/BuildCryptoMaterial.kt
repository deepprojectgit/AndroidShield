package com.androidshield.plugin.crypto

import com.androidshield.core.crypto.AesGcmCipher
import com.androidshield.core.crypto.KeyScrambler
import java.security.SecureRandom
import java.util.Base64

/**
 * Per-build encryption material used by string/resource protection.
 */
data class BuildCryptoMaterial(
    val key: ByteArray,
    val seed: ByteArray,
    val scrambledKey: ByteArray,
) {
    fun encryptString(value: String): EncryptedString {
        val iv = AesGcmCipher.generateIv()
        val cipherText = AesGcmCipher.encryptUtf8(value, key, iv)
        return EncryptedString(cipherText = cipherText, iv = iv)
    }

    fun encryptBytes(value: ByteArray): EncryptedPayload {
        val iv = AesGcmCipher.generateIv()
        val cipherText = AesGcmCipher.encrypt(value, key, iv)
        return EncryptedPayload(cipherText = cipherText, iv = iv)
    }

    companion object {
        fun generate(random: SecureRandom = SecureRandom()): BuildCryptoMaterial {
            val key = AesGcmCipher.generateKey(random)
            val seed = KeyScrambler.randomSeed(random)
            val scrambled = KeyScrambler.scramble(key, seed)
            return BuildCryptoMaterial(key = key, seed = seed, scrambledKey = scrambled)
        }
    }
}

data class EncryptedString(
    val cipherText: ByteArray,
    val iv: ByteArray,
) {
    fun cipherTextBase64(): String = Base64.getEncoder().encodeToString(cipherText)
    fun ivBase64(): String = Base64.getEncoder().encodeToString(iv)
}

data class EncryptedPayload(
    val cipherText: ByteArray,
    val iv: ByteArray,
)
