package com.androidshield.core.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ChaCha20-Poly1305 AEAD helpers (Java 11+).
 *
 * Key: 32 bytes · Nonce: 12 bytes · Auth tag: appended by the JCE cipher.
 */
object ChaCha20Cipher {
    const val KEY_SIZE_BYTES: Int = 32
    const val NONCE_SIZE_BYTES: Int = 12

    private const val TRANSFORMATION: String = "ChaCha20-Poly1305"

    fun generateKey(random: SecureRandom = SecureRandom()): ByteArray {
        val key = ByteArray(KEY_SIZE_BYTES)
        random.nextBytes(key)
        return key
    }

    fun generateNonce(random: SecureRandom = SecureRandom()): ByteArray {
        val nonce = ByteArray(NONCE_SIZE_BYTES)
        random.nextBytes(nonce)
        return nonce
    }

    fun encrypt(plain: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray {
        require(key.size == KEY_SIZE_BYTES) { "ChaCha20 256-bit key required" }
        require(nonce.size == NONCE_SIZE_BYTES) { "12-byte nonce required" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, toKey(key), IvParameterSpec(nonce))
        return cipher.doFinal(plain)
    }

    fun decrypt(cipherText: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray {
        require(key.size == KEY_SIZE_BYTES) { "ChaCha20 256-bit key required" }
        require(nonce.size == NONCE_SIZE_BYTES) { "12-byte nonce required" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, toKey(key), IvParameterSpec(nonce))
        return cipher.doFinal(cipherText)
    }

    fun encryptUtf8(plain: String, key: ByteArray, nonce: ByteArray): ByteArray =
        encrypt(plain.toByteArray(Charsets.UTF_8), key, nonce)

    fun decryptUtf8(cipherText: ByteArray, key: ByteArray, nonce: ByteArray): String =
        decrypt(cipherText, key, nonce).toString(Charsets.UTF_8)

    private fun toKey(key: ByteArray): SecretKey = SecretKeySpec(key, "ChaCha20")
}
