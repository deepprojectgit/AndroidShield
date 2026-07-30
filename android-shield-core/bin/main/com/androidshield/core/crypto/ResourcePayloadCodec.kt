package com.androidshield.core.crypto

/**
 * AndroidShield encrypted resource container (version 1).
 *
 * Wire format:
 * ```
 * magic[3] = 'A','S','1'
 * ivLen[1]
 * iv[ivLen]
 * cipherText[remaining]
 * algorithm is implied by policy (default AES-GCM); AS2 may embed algorithm byte.
 * ```
 */
object ResourcePayloadCodec {
    private const val MAGIC_0: Byte = 'A'.code.toByte()
    private const val MAGIC_1: Byte = 'S'.code.toByte()
    private const val MAGIC_2: Byte = '1'.code.toByte()

    /**
     * Packs an [EncryptedPayload] into the AS1 binary container.
     */
    fun encode(payload: EncryptedPayload): ByteArray {
        require(payload.ivOrNonce.size in 1..255) { "IV/nonce length out of range" }
        val out = ByteArray(4 + payload.ivOrNonce.size + payload.cipherText.size)
        out[0] = MAGIC_0
        out[1] = MAGIC_1
        out[2] = MAGIC_2
        out[3] = payload.ivOrNonce.size.toByte()
        System.arraycopy(payload.ivOrNonce, 0, out, 4, payload.ivOrNonce.size)
        System.arraycopy(
            payload.cipherText,
            0,
            out,
            4 + payload.ivOrNonce.size,
            payload.cipherText.size
        )
        return out
    }

    /**
     * Parses an AS1 container into ciphertext + IV (algorithm defaults to [defaultAlgorithm]).
     */
    fun decode(
        bytes: ByteArray,
        defaultAlgorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM
    ): EncryptedPayload {
        require(bytes.size >= 5) { "AS1 payload too short" }
        require(bytes[0] == MAGIC_0 && bytes[1] == MAGIC_1 && bytes[2] == MAGIC_2) {
            "Invalid AS1 magic"
        }
        val ivLen = bytes[3].toInt() and 0xFF
        require(bytes.size >= 4 + ivLen) { "AS1 truncated IV" }
        val iv = bytes.copyOfRange(4, 4 + ivLen)
        val cipherText = bytes.copyOfRange(4 + ivLen, bytes.size)
        return EncryptedPayload(defaultAlgorithm, cipherText, iv)
    }

    fun isShieldPayload(bytes: ByteArray): Boolean = bytes.size >= 4 &&
        bytes[0] == MAGIC_0 &&
        bytes[1] == MAGIC_1 &&
        bytes[2] == MAGIC_2

    /**
     * Encrypts plaintext bytes and returns AS1 container bytes.
     */
    fun seal(
        plain: ByteArray,
        key: ByteArray,
        algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM
    ): ByteArray = encode(ShieldCipher.encrypt(plain, key, algorithm))

    /**
     * Opens an AS1 container and returns plaintext.
     */
    fun open(
        sealed: ByteArray,
        key: ByteArray,
        algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM
    ): ByteArray = ShieldCipher.decrypt(decode(sealed, algorithm), key)
}
