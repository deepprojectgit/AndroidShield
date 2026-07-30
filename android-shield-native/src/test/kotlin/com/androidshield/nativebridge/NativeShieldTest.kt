package com.androidshield.nativebridge

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class NativeShieldTest {
    @Test
    fun evaluate_whenUnloaded_returnsSentinel() {
        // On JVM unit tests the .so is typically not loadable.
        if (!NativeShield.isAvailable()) {
            val findings = NativeShield.evaluate()
            assertThat(findings.debuggerFlags).isEqualTo(-1)
            assertThat(findings.isClean).isFalse()
        }
    }

    @Test
    fun packedBitLayout_documented() {
        // Debug low 8, hook mid 8, memory high 8.
        val packed = 0x00010203
        assertThat(packed and 0xff).isEqualTo(0x03)
        assertThat((packed shr 8) and 0xff).isEqualTo(0x02)
        assertThat((packed shr 16) and 0xff).isEqualTo(0x01)
    }
}
