package com.androidshield.core.crypto

/**
 * Immutable ciphertext + nonce/IV pair produced by [ShieldCipher].
 */
data class EncryptedPayload(
    val algorithm: ShieldAlgorithm,
    val cipherText: ByteArray,
    val ivOrNonce: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EncryptedPayload) return false
        return algorithm == other.algorithm &&
            cipherText.contentEquals(other.cipherText) &&
            ivOrNonce.contentEquals(other.ivOrNonce)
    }

    override fun hashCode(): Int {
        var result = algorithm.hashCode()
        result = 31 * result + cipherText.contentHashCode()
        result = 31 * result + ivOrNonce.contentHashCode()
        return result
    }
}

/**
 * Unified encrypt/decrypt façade over AES-GCM and ChaCha20-Poly1305.
 */
object ShieldCipher {
    fun generateKey(
        algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM,
        random: java.security.SecureRandom = java.security.SecureRandom()
    ): ByteArray = when (algorithm) {
        ShieldAlgorithm.AES_GCM -> AesGcmCipher.generateKey(random)
        ShieldAlgorithm.CHACHA20_POLY1305 -> ChaCha20Cipher.generateKey(random)
    }

    fun generateIvOrNonce(
        algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM,
        random: java.security.SecureRandom = java.security.SecureRandom()
    ): ByteArray = when (algorithm) {
        ShieldAlgorithm.AES_GCM -> AesGcmCipher.generateIv(random)
        ShieldAlgorithm.CHACHA20_POLY1305 -> ChaCha20Cipher.generateNonce(random)
    }

    fun encrypt(
        plain: ByteArray,
        key: ByteArray,
        algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM,
        ivOrNonce: ByteArray = generateIvOrNonce(algorithm)
    ): EncryptedPayload {
        val cipherText = when (algorithm) {
            ShieldAlgorithm.AES_GCM -> AesGcmCipher.encrypt(plain, key, ivOrNonce)
            ShieldAlgorithm.CHACHA20_POLY1305 -> ChaCha20Cipher.encrypt(plain, key, ivOrNonce)
        }
        return EncryptedPayload(algorithm, cipherText, ivOrNonce)
    }

    fun decrypt(payload: EncryptedPayload, key: ByteArray): ByteArray = when (payload.algorithm) {
        ShieldAlgorithm.AES_GCM ->
            AesGcmCipher.decrypt(payload.cipherText, key, payload.ivOrNonce)
        ShieldAlgorithm.CHACHA20_POLY1305 ->
            ChaCha20Cipher.decrypt(payload.cipherText, key, payload.ivOrNonce)
    }

    fun encryptUtf8(
        plain: String,
        key: ByteArray,
        algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM
    ): EncryptedPayload = encrypt(plain.toByteArray(Charsets.UTF_8), key, algorithm)

    fun decryptUtf8(payload: EncryptedPayload, key: ByteArray): String =
        decrypt(payload, key).toString(Charsets.UTF_8)
}
