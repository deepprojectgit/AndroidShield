package com.androidshield.runtime.detector.emulator

import android.content.Context
import android.os.Build
import com.androidshield.core.config.ShieldConfig
import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.runtime.detector.ThreatDetector
import com.androidshield.runtime.detector.threat
import com.androidshield.runtime.internal.ShieldFs

/**
 * Heuristic emulator / cloud-device detector.
 */
class EmulatorDetector : ThreatDetector {
    override val id: String = "emulator"

    override fun isEnabled(config: ShieldConfig): Boolean = config.emulatorDetection

    override fun detect(context: Context): List<Threat> {
        val signals = mutableListOf<String>()

        fun add(condition: Boolean, signal: String) {
            if (condition) signals += signal
        }

        val fingerprint = Build.FINGERPRINT.lowercase()
        val model = Build.MODEL.lowercase()
        val manufacturer = Build.MANUFACTURER.lowercase()
        val brand = Build.BRAND.lowercase()
        val device = Build.DEVICE.lowercase()
        val product = Build.PRODUCT.lowercase()
        val hardware = Build.HARDWARE.lowercase()

        add(fingerprint.contains("generic") || fingerprint.contains("emulator"), "fingerprint")
        add(model.contains("emulator") || model.contains("android sdk"), "model")
        add(manufacturer.contains("genymotion"), "genymotion")
        add(brand.startsWith("generic") && device.startsWith("generic"), "generic_brand_device")
        add(product.contains("sdk") || product.contains("emulator") || product.contains("vbox"), "product")
        add(
            hardware.contains("goldfish") || hardware.contains("ranchu") || hardware.contains("vbox"),
            "hardware",
        )
        add(Build.BOARD.lowercase().contains("unknown") && signals.isNotEmpty(), "board_unknown")

        EMULATOR_FILES.firstOrNull { ShieldFs.anyExists(arrayOf(it)) != null }?.let {
            signals += "file:$it"
        }

        EMULATOR_PACKAGES.filter { ShieldFs.packageInstalled(context, it) }.forEach {
            signals += "pkg:$it"
        }

        if (signals.isEmpty()) return emptyList()

        val severity = if (signals.size >= 2) Severity.HIGH else Severity.MEDIUM
        return listOf(
            threat(
                id = "emulator.environment",
                title = "Emulator / virtual environment",
                severity = severity,
                description = "Signals: ${signals.joinToString()}",
                recommendation = "Block high-risk actions on emulators if policy requires physical devices",
            ),
        )
    }

    companion object {
        private val EMULATOR_FILES = arrayOf(
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props",
            "/dev/vboxguest",
            "/dev/vboxuser",
        )
        private val EMULATOR_PACKAGES = arrayOf(
            "com.bluestacks",
            "com.bignox.app",
            "com.vphone.launcher",
            "com.microvirt.guide",
            "com.mumu.launcher",
        )
    }
}
