package com.androidshield.runtime.detector.nativeprot

import android.content.Context
import com.androidshield.core.config.ShieldConfig
import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.nativebridge.NativeShield
import com.androidshield.runtime.detector.ThreatDetector
import com.androidshield.runtime.detector.threat

/**
 * Surfaces findings from the native (JNI) protection layer.
 */
class NativeProtectionDetector : ThreatDetector {
    override val id: String = "native"

    override fun isEnabled(config: ShieldConfig): Boolean = config.nativeProtection

    override fun detect(context: Context): List<Threat> {
        if (!NativeShield.isAvailable()) {
            return listOf(
                threat(
                    id = "native.unavailable",
                    title = "Native library unavailable",
                    severity = Severity.MEDIUM,
                    description = "libandroidshield failed to load",
                    recommendation = "Ensure android-shield-native AAR is packaged for this ABI",
                ),
            )
        }

        val findings = NativeShield.evaluate()
        if (findings.debuggerFlags < 0 || findings.hookFlags < 0 || findings.memoryFlags < 0) {
            return listOf(
                threat(
                    id = "native.error",
                    title = "Native self-check failed",
                    severity = Severity.LOW,
                    description = "JNI nativeSelfCheck threw or returned error",
                    recommendation = "Check native crashes / SELinux denials",
                ),
            )
        }

        val threats = mutableListOf<Threat>()
        threats += mapDebugger(findings.debuggerFlags)
        threats += mapHooks(findings.hookFlags)
        threats += mapMemory(findings.memoryFlags)
        return threats
    }

    private fun mapDebugger(flags: Int): List<Threat> {
        if (flags == 0) return emptyList()
        val parts = mutableListOf<String>()
        if (flags and 0x1 != 0) parts += "TracerPid"
        if (flags and 0x2 != 0) parts += "ptrace"
        if (flags and 0x4 != 0) parts += "debugger_port"
        if (flags and 0x8 != 0) parts += "timing"
        return listOf(
            threat(
                id = "native.debug.flags_$flags",
                title = "Native anti-debug triggered",
                severity = Severity.CRITICAL,
                description = "flags=$flags signals=${parts.joinToString()}",
                recommendation = "Treat as debugger attachment — abort privileged flows",
            ),
        )
    }

    private fun mapHooks(flags: Int): List<Threat> {
        if (flags == 0) return emptyList()
        val parts = mutableListOf<String>()
        if (flags and 0x1 != 0) parts += "frida_maps"
        if (flags and 0x2 != 0) parts += "xposed_maps"
        if (flags and 0x4 != 0) parts += "frida_thread"
        if (flags and 0x8 != 0) parts += "frida_file"
        if (flags and 0x10 != 0) parts += "inline_hint"
        return listOf(
            threat(
                id = "native.hook.flags_$flags",
                title = "Native anti-hook triggered",
                severity = Severity.CRITICAL,
                description = "flags=$flags signals=${parts.joinToString()}",
                recommendation = "Hooking framework likely present — terminate sensitive sessions",
            ),
        )
    }

    private fun mapMemory(flags: Int): List<Threat> {
        if (flags == 0) return emptyList()
        val parts = mutableListOf<String>()
        if (flags and 0x1 != 0) parts += "rwx_mapping"
        if (flags and 0x2 != 0) parts += "suspicious_name"
        return listOf(
            threat(
                id = "native.memory.flags_$flags",
                title = "Native memory validation failed",
                severity = Severity.HIGH,
                description = "flags=$flags signals=${parts.joinToString()}",
                recommendation = "Inspect /proc/self/maps for injected executable pages",
            ),
        )
    }
}
