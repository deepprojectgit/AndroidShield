package com.androidshield.runtime.detector.root

import android.content.Context
import android.os.Build
import com.androidshield.core.config.ShieldConfig
import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.runtime.detector.ThreatDetector
import com.androidshield.runtime.detector.threat
import com.androidshield.runtime.internal.ShieldFs

/**
 * Multi-signal root / Magisk environment detector.
 */
class RootDetector : ThreatDetector {
    override val id: String = "root"

    override fun isEnabled(config: ShieldConfig): Boolean = config.rootDetection

    override fun detect(context: Context): List<Threat> {
        val threats = mutableListOf<Threat>()

        ShieldFs.anyExists(SU_PATHS)?.let { path ->
            threats += threat(
                id = "root.su_binary",
                title = "su binary present",
                severity = Severity.CRITICAL,
                description = "Found su at $path",
                recommendation = "Refuse high-value operations on rooted devices",
            )
        }

        ShieldFs.anyExists(BUSYBOX_PATHS)?.let { path ->
            threats += threat(
                id = "root.busybox",
                title = "BusyBox present",
                severity = Severity.MEDIUM,
                description = "Found BusyBox at $path",
                recommendation = "Corroborate with additional root signals before hard-failing",
            )
        }

        ShieldFs.anyExists(MAGISK_PATHS)?.let { path ->
            threats += threat(
                id = "root.magisk",
                title = "Magisk artifacts",
                severity = Severity.CRITICAL,
                description = "Found Magisk-related path $path",
                recommendation = "Treat as rooted — Magisk can hide classical su checks",
            )
        }

        ROOT_PACKAGES.filter { ShieldFs.packageInstalled(context, it) }.forEach { pkg ->
            threats += threat(
                id = "root.package.$pkg",
                title = "Root management package",
                severity = Severity.HIGH,
                description = "Installed package $pkg is associated with rooting",
                recommendation = "Block or degrade features when root apps are installed",
            )
        }

        if (dangerousProps()) {
            threats += threat(
                id = "root.dangerous_props",
                title = "Dangerous system properties",
                severity = Severity.HIGH,
                description = "ro.debuggable/ro.secure/service.adb.root indicate an unlocked build",
                recommendation = "Combine with Play Integrity for stronger device attestation",
            )
        }

        if (testKeysBuild()) {
            threats += threat(
                id = "root.test_keys",
                title = "Build signed with test-keys",
                severity = Severity.HIGH,
                description = "Build.TAGS contains test-keys",
                recommendation = "Typical of custom/eng builds — elevate risk",
            )
        }

        if (writableSystem()) {
            threats += threat(
                id = "root.writable_system",
                title = "System partition appears writable",
                severity = Severity.MEDIUM,
                description = "/system is mounted rw or write probe succeeded",
                recommendation = "Corroborate before user-facing hard fail",
            )
        }

        return threats
    }

    private fun dangerousProps(): Boolean {
        val debuggable = getProp("ro.debuggable")
        val secure = getProp("ro.secure")
        val adbRoot = getProp("service.adb.root")
        return debuggable == "1" || secure == "0" || adbRoot == "1"
    }

    private fun testKeysBuild(): Boolean =
        Build.TAGS?.contains("test-keys") == true

    private fun writableSystem(): Boolean {
        val mounts = ShieldFs.readText("/proc/mounts") ?: return false
        return mounts.lineSequence().any { line ->
            line.contains(" /system ") && line.contains(" rw")
        }
    }

    private fun getProp(key: String): String? =
        runCatching {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
            process.inputStream.bufferedReader().use { it.readLine() }?.trim()
        }.getOrNull()

    companion object {
        private val SU_PATHS = arrayOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
            "/su/bin/su",
        )
        private val BUSYBOX_PATHS = arrayOf(
            "/system/xbin/busybox", "/system/bin/busybox", "/data/local/busybox",
        )
        private val MAGISK_PATHS = arrayOf(
            "/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules",
            "/cache/magisk.log", "/data/adb/magisk.db",
        )
        private val ROOT_PACKAGES = arrayOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
        )
    }
}
