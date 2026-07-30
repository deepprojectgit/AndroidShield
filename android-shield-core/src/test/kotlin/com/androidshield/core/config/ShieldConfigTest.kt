package com.androidshield.core.config

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class ShieldConfigTest {
    @Test
    fun builder_andCodec() {
        val config = ShieldConfig.builder()
            .playIntegrity(true)
            .obfuscationIntensity(2)
            .protectPackages(listOf("com.example"))
            .build()
        assertThat(config.playIntegrity).isTrue()
        assertThat(config.obfuscationIntensity).isEqualTo(2)
        assertThat(config.featureFlags()["stringEncryption"]).isTrue()

        val decoded = ShieldConfigCodec.decode(ShieldConfigCodec.encode(config))
        assertThat(decoded).isEqualTo(config)
    }

    @Test
    fun releaseDefaults_enablePlayIntegrity() {
        assertThat(ShieldConfig.releaseDefaults().playIntegrity).isTrue()
        assertThat(ShieldConfig.debugDefaults().playIntegrity).isFalse()
    }
}
