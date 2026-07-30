package com.androidshield.core.integrity

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class DigestUtilsTest {
    @Test
    fun sha256Hex_isStable() {
        val hex = DigestUtils.sha256Hex("androidshield".toByteArray())
        assertThat(hex).hasLength(64)
        assertThat(DigestUtils.sha256Hex("androidshield".toByteArray())).isEqualTo(hex)
    }

    @Test
    fun constantTimeEquals() {
        assertThat(DigestUtils.constantTimeEquals("abc", "abc")).isTrue()
        assertThat(DigestUtils.constantTimeEquals("abc", "abd")).isFalse()
        assertThat(DigestUtils.constantTimeEquals("abc", "ab")).isFalse()
    }

    @Test
    fun hexRoundTrip() {
        val bytes = byteArrayOf(0x0A, 0xFF.toByte(), 0x10)
        assertThat(DigestUtils.fromHex(DigestUtils.toHex(bytes))).isEqualTo(bytes)
    }
}

class IntegrityVerifierTest {
    @Test
    fun matchingDigests_areOk() {
        val expected = IntegrityMetadata(
            buildFingerprint = "fp1",
            generatedAtEpochMs = 1L,
            dexDigestSha256 = "deadbeef",
        )
        val observed = ObservedIntegrity(
            buildFingerprint = "fp1",
            dexDigestSha256 = "DEADBEEF",
        )
        val result = IntegrityVerifier.verify(expected, observed)
        assertThat(result.matches).isTrue()
        assertThat(result.threats).isEmpty()
    }

    @Test
    fun mismatch_producesCriticalThreat() {
        val expected = IntegrityMetadata(
            buildFingerprint = "fp1",
            generatedAtEpochMs = 1L,
            dexDigestSha256 = "aaa",
        )
        val observed = ObservedIntegrity(
            buildFingerprint = "fp1",
            dexDigestSha256 = "bbb",
        )
        val result = IntegrityVerifier.verify(expected, observed)
        assertThat(result.matches).isFalse()
        assertThat(result.mismatchedFields).contains("dexDigestSha256")
        assertThat(result.threats).isNotEmpty()
    }

    @Test
    fun codec_roundTrip() {
        val meta = IntegrityMetadata(
            buildFingerprint = "abc",
            generatedAtEpochMs = 123,
            packageName = "com.example",
            stringEncryptionEnabled = true,
        )
        val decoded = IntegrityMetadataCodec.decode(IntegrityMetadataCodec.encode(meta))
        assertThat(decoded).isEqualTo(meta)
    }
}
