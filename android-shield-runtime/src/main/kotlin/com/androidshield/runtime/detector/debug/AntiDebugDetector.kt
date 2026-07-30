package com.androidshield.runtime.detector.debug

import android.content.Context
import android.os.Debug
import com.androidshield.core.config.ShieldConfig
import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.runtime.detector.ThreatDetector
import com.androidshield.runtime.detector.threat
import com.androidshield.runtime.internal.ShieldFs

/**
 * Detects Java/native debugger attachment signals.
 */
class AntiDebugDetector : ThreatDetector {
    override val id: String = "debug"

    override fun isEnabled(config: ShieldConfig): Boolean = config.antiDebug

    override fun detect(context: Context): List<Threat> {
        val threats = mutableListOf<Threat>()

        if (Debug.isDebuggerConnected()) {
            threats += threat(
                id = "debug.jdwp_connected",
                title = "Debugger connected",
                severity = Severity.CRITICAL,
                description = "Debug.isDebuggerConnected() returned true",
                recommendation = "Terminate sensitive flows while a debugger is attached",
            )
        }

        if (Debug.waitingForDebugger()) {
            threats += threat(
                id = "debug.waiting_for_debugger",
                title = "Waiting for debugger",
                severity = Severity.HIGH,
                description = "Process is waiting for a debugger to attach",
                recommendation = "Avoid shipping builds that wait for debugger attachment",
            )
        }

        if (ShieldFs.isDebuggable(context)) {
            threats += threat(
                id = "debug.app_debuggable",
                title = "Application debuggable",
                severity = Severity.HIGH,
                description = "ApplicationInfo.FLAG_DEBUGGABLE is set",
                recommendation = "Disable debuggable for release builds",
            )
        }

        val tracer = parseTracerPid()
        if (tracer != null && tracer > 0) {
            threats += threat(
                id = "debug.tracer_pid",
                title = "Native tracer attached",
                severity = Severity.CRITICAL,
                description = "TracerPid=$tracer in /proc/self/status (ptrace/GDB/LLDB)",
                recommendation = "Treat as compromise — abort privileged operations",
            )
        }

        if (timingAnomaly()) {
            threats += threat(
                id = "debug.timing_anomaly",
                title = "Debugger timing anomaly",
                severity = Severity.MEDIUM,
                description = "Simple timing check suggests single-stepping or instrumentation delay",
                recommendation = "Increase monitoring frequency while anomaly persists",
            )
        }

        return threats
    }

    private fun parseTracerPid(): Int? {
        val status = ShieldFs.readText("/proc/self/status") ?: return null
        val line = status.lineSequence().firstOrNull { it.startsWith("TracerPid:") } ?: return null
        return line.substringAfter(":").trim().toIntOrNull()
    }

    private fun timingAnomaly(): Boolean {
        val start = System.nanoTime()
        var x = 0
        repeat(10_000) { x = x xor it }
        val elapsedMs = (System.nanoTime() - start) / 1_000_000.0
        // Extremely loose bound — flags heavy instrumentation, not normal devices
        return x >= 0 && elapsedMs > 50.0
    }
}
