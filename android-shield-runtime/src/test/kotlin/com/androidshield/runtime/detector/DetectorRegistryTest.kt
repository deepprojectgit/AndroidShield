package com.androidshield.runtime.detector

import com.androidshield.core.config.ShieldConfig
import com.google.common.truth.Truth.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class DetectorRegistryTest {
    @Test
    fun registry_respectsDisabledFlags() {
        val config = ShieldConfig(
            antiDebug = false,
            antiTamper = false,
            antiHook = false,
            rootDetection = false,
            emulatorDetection = false,
            runtimeProtection = false,
            nativeProtection = false,
        )
        val detectors = DetectorRegistry.create(config)
        assertThat(detectors).isEmpty()
    }

    @Test
    fun registry_enablesDefaults() {
        val detectors = DetectorRegistry.create(ShieldConfig())
        assertThat(detectors.map { it.id }).containsAtLeast(
            "debug", "tamper", "hook", "root", "emulator", "device", "rasp", "native",
        )
    }

    @Test
    fun evaluate_runsWithoutCrash() {
        val context = RuntimeEnvironment.getApplication()
        val engine = com.androidshield.runtime.engine.ThreatEngine(context, ShieldConfig())
        val threats = engine.evaluate()
        assertThat(threats).isNotNull()
    }
}
