package com.androidshield.core.integrity

import java.io.InputStream
import java.security.MessageDigest

/**
 * Digest helpers shared by the plugin (emit) and runtime (verify).
 */
object DigestUtils {
    fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    fun sha512(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-512").digest(bytes)

    fun sha256Hex(bytes: ByteArray): String = toHex(sha256(bytes))

    fun sha512Hex(bytes: ByteArray): String = toHex(sha512(bytes))

    fun sha256Hex(stream: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val read = stream.read(buffer)
            if (read <= 0) break
            digest.update(buffer, 0, read)
        }
        return toHex(digest.digest())
    }

    fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].code xor b[i].code)
        }
        return result == 0
    }

    fun toHex(bytes: ByteArray): String =
        bytes.joinToString("") { each -> "%02x".format(each) }

    fun fromHex(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex length must be even" }
        return ByteArray(hex.length / 2) { index ->
            hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
