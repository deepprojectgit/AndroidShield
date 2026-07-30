package com.androidshield.core.crypto

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class ChaCha20CipherTest {
    @Test
    fun roundTrip_utf8() {
        val key = ChaCha20Cipher.generateKey()
        val nonce = ChaCha20Cipher.generateNonce()
        val plain = "https://api.example.com/v1/secret"
        val cipher = ChaCha20Cipher.encryptUtf8(plain, key, nonce)
        assertThat(ChaCha20Cipher.decryptUtf8(cipher, key, nonce)).isEqualTo(plain)
    }
}

class ShieldCipherTest {
    @Test
    fun aesAndChaCha_roundTrip() {
        listOf(ShieldAlgorithm.AES_GCM, ShieldAlgorithm.CHACHA20_POLY1305).forEach { algorithm ->
            val key = ShieldCipher.generateKey(algorithm)
            val payload = ShieldCipher.encryptUtf8("token=abc123xyz", key, algorithm)
            assertThat(ShieldCipher.decryptUtf8(payload, key)).isEqualTo("token=abc123xyz")
            assertThat(payload.algorithm).isEqualTo(algorithm)
        }
    }
}

class StringEncryptionPolicyTest {
    @Test
    fun encryptsUrlsAndSecrets() {
        val policy = StringEncryptionPolicy.DEFAULT
        assertThat(policy.shouldEncrypt("https://secure.example/api")).isTrue()
        assertThat(policy.shouldEncrypt("my_api_token_value")).isTrue()
        assertThat(policy.shouldEncrypt("select * from users")).isTrue()
        assertThat(policy.shouldEncrypt("ab")).isFalse()
    }
}

class ConstantEncryptionTest {
    @Test
    fun roundTrip_primitives() {
        val key = AesGcmCipher.generateKey()
        assertThat(ConstantEncryption.decryptInt(ConstantEncryption.encryptInt(42, key), key))
            .isEqualTo(42)
        assertThat(ConstantEncryption.decryptLong(ConstantEncryption.encryptLong(99L, key), key))
            .isEqualTo(99L)
        assertThat(
            ConstantEncryption.decryptBoolean(ConstantEncryption.encryptBoolean(true, key), key)
        )
            .isTrue()
        assertThat(
            ConstantEncryption.decryptString(ConstantEncryption.encryptString("hello", key), key)
        ).isEqualTo("hello")
        assertThat(
            ConstantEncryption.decryptFloat(ConstantEncryption.encryptFloat(1.5f, key), key)
        ).isWithin(0.0001f).of(1.5f)
        assertThat(
            ConstantEncryption.decryptDouble(ConstantEncryption.encryptDouble(2.25, key), key)
        ).isWithin(0.0001).of(2.25)
    }
}

class ResourcePayloadCodecTest {
    @Test
    fun sealAndOpen_as1() {
        val key = AesGcmCipher.generateKey()
        val plain = "asset-secret".toByteArray()
        val sealed = ResourcePayloadCodec.seal(plain, key)
        assertThat(ResourcePayloadCodec.isShieldPayload(sealed)).isTrue()
        assertThat(ResourcePayloadCodec.open(sealed, key)).isEqualTo(plain)
    }
}
