package com.androidshield.runtime.detector

import android.content.Context
import com.androidshield.core.config.ShieldConfig
import com.androidshield.core.model.Threat

/**
 * Contract for a single security signal detector.
 */
interface ThreatDetector {
    /** Stable id prefix used in threat ids (e.g. `root`, `debug`). */
    val id: String

    fun isEnabled(config: ShieldConfig): Boolean

    fun detect(context: Context): List<Threat>
}

/**
 * Builds the ordered detector set for the given [config].
 */
internal object DetectorRegistry {
    fun create(config: ShieldConfig): List<ThreatDetector> {
        val all = listOf(
            com.androidshield.runtime.detector.debug.AntiDebugDetector(),
            com.androidshield.runtime.detector.tamper.AntiTamperDetector(),
            com.androidshield.runtime.detector.hook.AntiHookDetector(),
            com.androidshield.runtime.detector.root.RootDetector(),
            com.androidshield.runtime.detector.emulator.EmulatorDetector(),
            com.androidshield.runtime.detector.device.DeviceSecurityDetector(),
            com.androidshield.runtime.rasp.RaspDetector(),
            com.androidshield.runtime.detector.nativeprot.NativeProtectionDetector(),
        )
        return all.filter { it.isEnabled(config) }
    }
}
