package com.androidshield.runtime.network

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class SslPinningTest {
    @Test
    fun toHostnameMap_preservesPins() {
        val map = SslPinning.toHostnameMap(
            listOf(
                SslPinningConfig("api.example.com", listOf("sha256/abc", "sha256/def")),
            ),
        )
        assertThat(map["api.example.com"]).containsExactly("sha256/abc", "sha256/def")
    }
}
