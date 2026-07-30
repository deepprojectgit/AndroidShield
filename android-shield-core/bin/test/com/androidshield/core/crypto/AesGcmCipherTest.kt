package com.androidshield.core.crypto

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class AesGcmCipherTest {
    @Test
    fun roundTrip_encryptDecrypt() {
        val key = AesGcmCipher.generateKey()
        val iv = AesGcmCipher.generateIv()
        val plain = "https://api.androidshield.example/v1/token"
        val cipher = AesGcmCipher.encryptUtf8(plain, key, iv)
        val restored = AesGcmCipher.decryptUtf8(cipher, key, iv)
        assertThat(restored).isEqualTo(plain)
    }

    @Test
    fun scrambler_roundTrip() {
        val key = AesGcmCipher.generateKey()
        val seed = KeyScrambler.randomSeed()
        val scrambled = KeyScrambler.scramble(key, seed)
        assertThat(KeyScrambler.unscramble(scrambled, seed)).isEqualTo(key)
    }
}
