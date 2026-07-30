package com.androidshield.core.crypto

import java.nio.ByteBuffer

/**
 * Encrypts primitive constants so they are not stored as plaintext in DEX.
 *
 * Encoding (plaintext before AEAD):
 * - type tag (1 byte) + big-endian payload
 *
 * Type tags: 1=Int, 2=Long, 3=Float, 4=Double, 5=Boolean, 6=String(UTF-8)
 */
object ConstantEncryption {
    private const val TAG_INT: Byte = 1
    private const val TAG_LONG: Byte = 2
    private const val TAG_FLOAT: Byte = 3
    private const val TAG_DOUBLE: Byte = 4
    private const val TAG_BOOLEAN: Byte = 5
    internal const val TAG_STRING: Byte = 6

    fun encryptInt(
        value: Int,
        key: ByteArray,
        algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM
    ): EncryptedPayload {
        val plain = ByteBuffer.allocate(5).put(TAG_INT).putInt(value).array()
        return ShieldCipher.encrypt(plain, key, algorithm)
    }

    fun decryptInt(payload: EncryptedPayload, key: ByteArray): Int {
        val plain = ByteBuffer.wrap(ShieldCipher.decrypt(payload, key))
        require(plain.get() == TAG_INT) { "Not an encrypted Int constant" }
        return plain.int
    }

    fun encryptLong(
        value: Long,
        key: ByteArray,
        algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM
    ): EncryptedPayload {
        val plain = ByteBuffer.allocate(9).put(TAG_LONG).putLong(value).array()
        return ShieldCipher.encrypt(plain, key, algorithm)
    }

    fun decryptLong(payload: EncryptedPayload, key: ByteArray): Long {
        val plain = ByteBuffer.wrap(ShieldCipher.decrypt(payload, key))
        require(plain.get() == TAG_LONG) { "Not an encrypted Long constant" }
        return plain.long
    }

    fun encryptFloat(
        value: Float,
        key: ByteArray,
        algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM
    ): EncryptedPayload {
        val plain = ByteBuffer.allocate(5).put(TAG_FLOAT).putFloat(value).array()
        return ShieldCipher.encrypt(plain, key, algorithm)
    }

    fun decryptFloat(payload: EncryptedPayload, key: ByteArray): Float {
        val plain = ByteBuffer.wrap(ShieldCipher.decrypt(payload, key))
        require(plain.get() == TAG_FLOAT) { "Not an encrypted Float constant" }
        return plain.float
    }

    fun encryptDouble(
        value: Double,
        key: ByteArray,
        algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM
    ): EncryptedPayload {
        val plain = ByteBuffer.allocate(9).put(TAG_DOUBLE).putDouble(value).array()
        return ShieldCipher.encrypt(plain, key, algorithm)
    }

    fun decryptDouble(payload: EncryptedPayload, key: ByteArray): Double {
        val plain = ByteBuffer.wrap(ShieldCipher.decrypt(payload, key))
        require(plain.get() == TAG_DOUBLE) { "Not an encrypted Double constant" }
        return plain.double
    }

    fun encryptBoolean(
        value: Boolean,
        key: ByteArray,
        algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM
    ): EncryptedPayload {
        val plain = byteArrayOf(TAG_BOOLEAN, if (value) 1 else 0)
        return ShieldCipher.encrypt(plain, key, algorithm)
    }

    fun decryptBoolean(payload: EncryptedPayload, key: ByteArray): Boolean {
        val plain = ShieldCipher.decrypt(payload, key)
        require(plain.size == 2 && plain[0] == TAG_BOOLEAN) { "Not an encrypted Boolean constant" }
        return plain[1] != 0.toByte()
    }
}

/**
 * String constant AEAD helpers kept outside [ConstantEncryption] for complexity limits.
 */
fun ConstantEncryption.encryptString(
    value: String,
    key: ByteArray,
    algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM
): EncryptedPayload {
    val utf8 = value.toByteArray(Charsets.UTF_8)
    val plain = ByteArray(1 + utf8.size)
    plain[0] = ConstantEncryption.TAG_STRING
    System.arraycopy(utf8, 0, plain, 1, utf8.size)
    return ShieldCipher.encrypt(plain, key, algorithm)
}

fun ConstantEncryption.decryptString(payload: EncryptedPayload, key: ByteArray): String {
    val plain = ShieldCipher.decrypt(payload, key)
    require(plain.isNotEmpty() && plain[0] == ConstantEncryption.TAG_STRING) {
        "Not an encrypted String constant"
    }
    return plain.copyOfRange(1, plain.size).toString(Charsets.UTF_8)
}
