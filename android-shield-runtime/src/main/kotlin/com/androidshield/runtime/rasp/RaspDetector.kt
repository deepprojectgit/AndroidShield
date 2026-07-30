package com.androidshield.runtime.rasp

import android.content.Context
import com.androidshield.core.config.ShieldConfig
import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.runtime.detector.ThreatDetector
import com.androidshield.runtime.detector.threat
import com.androidshield.runtime.internal.ShieldFs
import java.io.File

/**
 * Runtime Application Self-Protection checks: maps, injected threads, dynamic loaders.
 */
class RaspDetector : ThreatDetector {
    override val id: String = "rasp"

    override fun isEnabled(config: ShieldConfig): Boolean = config.runtimeProtection

    override fun detect(context: Context): List<Threat> {
        val threats = mutableListOf<Threat>()
        threats += scanMemoryMaps()
        threats += scanSuspiciousThreads()
        threats += scanTmpInjection()
        return threats
    }

    private fun scanMemoryMaps(): List<Threat> {
        val maps = ShieldFs.readText("/proc/self/maps") ?: return emptyList()
        val hits = DYNAMIC_MARKERS.filter { maps.contains(it, ignoreCase = true) }
        if (hits.isEmpty()) return emptyList()
        return listOf(
            threat(
                id = "rasp.maps.dynamic",
                title = "Suspicious dynamic code mapping",
                severity = Severity.HIGH,
                description = "Memory maps include: ${hits.joinToString()}",
                recommendation = "Investigate injected DEX/SO — possible Frida gadget or in-memory DEX",
            ),
        )
    }

    private fun scanSuspiciousThreads(): List<Threat> {
        val root = File("/proc/self/task")
        if (!root.isDirectory) return emptyList()
        val names = root.listFiles()?.mapNotNull { task ->
            ShieldFs.readText("${task.absolutePath}/comm")?.trim()
        }.orEmpty()
        val hit = names.firstOrNull { name ->
            THREAD_MARKERS.any { marker -> name.contains(marker, ignoreCase = true) }
        } ?: return emptyList()
        return listOf(
            threat(
                id = "rasp.thread.$hit",
                title = "Suspicious thread name",
                severity = Severity.HIGH,
                description = "Found thread `$hit`",
                recommendation = "Debugger/Frida threads often use recognizable names",
            ),
        )
    }

    private fun scanTmpInjection(): List<Threat> {
        val maps = ShieldFs.readText("/proc/self/maps") ?: return emptyList()
        val hit = TMP_MARKERS.firstOrNull {
            maps.contains("/data/local/tmp/") && maps.contains(it, ignoreCase = true)
        } ?: return emptyList()
        return listOf(
            threat(
                id = "rasp.loader.tmp_$hit",
                title = "Temporary injected module",
                severity = Severity.CRITICAL,
                description = "Maps reference /data/local/tmp with `$hit`",
                recommendation = "Classic Frida server gadget injection path",
            ),
        )
    }

    companion object {
        private val DYNAMIC_MARKERS = listOf("frida", "gadget", ".frida.", "linjector", "libsubstrate")
        private val THREAD_MARKERS = listOf("frida", "gum-js-loop", "gmain", "pool-frida", "JDWP")
        private val TMP_MARKERS = listOf("frida", "gadget", "hook")
    }
}
