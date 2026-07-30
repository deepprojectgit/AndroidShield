package com.androidshield.core.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-GCM helpers shared by the Gradle plugin (encrypt) and runtime (decrypt).
 */
object AesGcmCipher {
    const val KEY_SIZE_BYTES: Int = 32
    const val IV_SIZE_BYTES: Int = 12
    const val TAG_BITS: Int = 128

    private const val TRANSFORMATION: String = "AES/GCM/NoPadding"

    fun generateKey(random: SecureRandom = SecureRandom()): ByteArray {
        val key = ByteArray(KEY_SIZE_BYTES)
        random.nextBytes(key)
        return key
    }

    fun generateIv(random: SecureRandom = SecureRandom()): ByteArray {
        val iv = ByteArray(IV_SIZE_BYTES)
        random.nextBytes(iv)
        return iv
    }

    @JvmStatic
    fun encrypt(plain: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        require(key.size == KEY_SIZE_BYTES) { "AES-256 key required" }
        require(iv.size == IV_SIZE_BYTES) { "12-byte IV required" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, toKey(key), GCMParameterSpec(TAG_BITS, iv))
        return cipher.doFinal(plain)
    }

    @JvmStatic
    fun decrypt(cipherText: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        require(key.size == KEY_SIZE_BYTES) { "AES-256 key required" }
        require(iv.size == IV_SIZE_BYTES) { "12-byte IV required" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, toKey(key), GCMParameterSpec(TAG_BITS, iv))
        return cipher.doFinal(cipherText)
    }

    @JvmStatic
    fun encryptUtf8(plain: String, key: ByteArray, iv: ByteArray): ByteArray =
        encrypt(plain.toByteArray(Charsets.UTF_8), key, iv)

    @JvmStatic
    fun decryptUtf8(cipherText: ByteArray, key: ByteArray, iv: ByteArray): String =
        decrypt(cipherText, key, iv).toString(Charsets.UTF_8)

    private fun toKey(key: ByteArray): SecretKey = SecretKeySpec(key, "AES")
}
