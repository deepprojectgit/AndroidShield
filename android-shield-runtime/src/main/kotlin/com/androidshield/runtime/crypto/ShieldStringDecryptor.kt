package com.androidshield.runtime.crypto

import com.androidshield.core.crypto.AesGcmCipher
import com.androidshield.core.crypto.KeyScrambler

/**
 * Runtime string decryptor invoked by bytecode rewritten by the AndroidShield plugin.
 *
 * Prefers native key unscramble when [com.androidshield.nativebridge.NativeShield] is available.
 */
object ShieldStringDecryptor {
    /**
     * Decrypts a UTF-8 string encrypted with AES-GCM.
     *
     * @param cipherText ciphertext including GCM tag
     * @param iv 12-byte IV
     */
    @JvmStatic
    fun decrypt(cipherText: ByteArray, iv: ByteArray): String {
        val key = BuildSecrets.resolveKey()
        if (com.androidshield.nativebridge.NativeShield.isAvailable()) {
            val plain = com.androidshield.nativebridge.NativeShield.nativeDecryptAesGcm(
                cipherText,
                iv,
                key,
            )
            if (plain != null) {
                return plain.toString(Charsets.UTF_8)
            }
        }
        return AesGcmCipher.decryptUtf8(cipherText, key, iv)
    }
}

/**
 * Placeholder build secrets replaced/augmented by the plugin-generated asset.
 * Default empty key causes decrypt to fail closed until the plugin embeds real material.
 */
object BuildSecrets {
    @Volatile
    private var cachedKey: ByteArray? = null

    @JvmStatic
    fun resolveKey(): ByteArray {
        cachedKey?.let { return it }
        val scrambled = SCRAMBLED_KEY
        val seed = SEED
        check(scrambled.isNotEmpty() && seed.isNotEmpty()) {
            "AndroidShield BuildSecrets not populated — apply com.androidshield.gradle"
        }
        val key =
            if (com.androidshield.nativebridge.NativeShield.isAvailable()) {
                com.androidshield.nativebridge.NativeShield.nativeUnscrambleKey(scrambled, seed)
                    ?: KeyScrambler.unscramble(scrambled, seed)
            } else {
                KeyScrambler.unscramble(scrambled, seed)
            }
        cachedKey = key
        return key
    }

    /** Overwritten by generated sources in consuming apps when the plugin runs. */
    @JvmField
    var SCRAMBLED_KEY: ByteArray = ByteArray(0)

    @JvmField
    var SEED: ByteArray = ByteArray(0)

    /**
     * Called by generated initializer code to install per-build key material.
     */
    @JvmStatic
    fun install(scrambledKey: ByteArray, seed: ByteArray) {
        SCRAMBLED_KEY = scrambledKey.copyOf()
        SEED = seed.copyOf()
        cachedKey = null
    }
}
