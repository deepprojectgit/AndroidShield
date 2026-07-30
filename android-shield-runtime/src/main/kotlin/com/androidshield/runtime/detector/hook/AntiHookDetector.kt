package com.androidshield.runtime.detector.hook

import android.content.Context
import com.androidshield.core.config.ShieldConfig
import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.runtime.detector.ThreatDetector
import com.androidshield.runtime.detector.threat
import com.androidshield.runtime.internal.ShieldFs

/**
 * Detects common hooking frameworks (Frida, Xposed family, Magisk Zygisk hints).
 */
class AntiHookDetector : ThreatDetector {
    override val id: String = "hook"

    override fun isEnabled(config: ShieldConfig): Boolean = config.antiHook

    override fun detect(context: Context): List<Threat> {
        val threats = mutableListOf<Threat>()

        HOOK_PACKAGES.filter { ShieldFs.packageInstalled(context, it) }.forEach { pkg ->
            threats += threat(
                id = "hook.package.$pkg",
                title = "Hooking framework package",
                severity = Severity.CRITICAL,
                description = "Installed package $pkg is associated with runtime hooking",
                recommendation = "Abort sensitive operations when hook frameworks are present",
            )
        }

        ShieldFs.anyExists(FRIDA_PATHS)?.let { path ->
            threats += threat(
                id = "hook.frida_artifact",
                title = "Frida artifact on disk",
                severity = Severity.CRITICAL,
                description = "Found Frida-related path $path",
                recommendation = "Treat as active instrumentation risk",
            )
        }

        val maps = ShieldFs.readText("/proc/self/maps")
        if (maps != null) {
            val hit = SUSPICIOUS_MAP_MARKERS.firstOrNull { maps.contains(it, ignoreCase = true) }
            if (hit != null) {
                threats += threat(
                    id = "hook.maps.$hit",
                    title = "Suspicious library in memory maps",
                    severity = Severity.CRITICAL,
                    description = "*/proc/self/maps* contains marker `$hit`",
                    recommendation = "Likely Frida/Xposed/inline hook — terminate privileged flows",
                )
            }
        }

        val stack = collectStackHint()
        if (stack != null) {
            threats += threat(
                id = "hook.stack_trace",
                title = "Hook framework in stack",
                severity = Severity.HIGH,
                description = "Stack contained `$stack`",
                recommendation = "Xposed-style hooks often appear in exception stacks",
            )
        }

        return threats
    }

    private fun collectStackHint(): String? {
        val trace = Throwable().stackTraceToString()
        return STACK_MARKERS.firstOrNull { trace.contains(it, ignoreCase = true) }
    }

    companion object {
        private val HOOK_PACKAGES = arrayOf(
            "de.robv.android.xposed.installer",
            "org.lsposed.manager",
            "org.meowcat.edxposed.manager",
            "com.saurik.substrate",
            "com.topjohnwu.magisk",
        )
        private val FRIDA_PATHS = arrayOf(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida",
        )
        private val SUSPICIOUS_MAP_MARKERS = arrayOf(
            "frida", "gadget", "xposed", "lsposed", "edxposed",
            "substrate", "libsandhook", "libyahfa", "riru", "zygisk",
        )
        private val STACK_MARKERS = arrayOf(
            "de.robv.android.xposed",
            "LSPosed",
            "XposedBridge",
            "Epic",
            "SandHook",
        )
    }
}
