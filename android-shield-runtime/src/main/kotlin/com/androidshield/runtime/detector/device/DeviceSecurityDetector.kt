package com.androidshield.runtime.detector.device

import android.content.Context
import android.net.ConnectivityManager
import android.net.Proxy
import android.os.Build
import android.provider.Settings
import com.androidshield.core.config.ShieldConfig
import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.runtime.detector.ThreatDetector
import com.androidshield.runtime.detector.threat

/**
 * Developer options, USB debugging, proxy/VPN, and OEM unlock signals.
 */
class DeviceSecurityDetector : ThreatDetector {
    override val id: String = "device"

    override fun isEnabled(config: ShieldConfig): Boolean =
        config.runtimeProtection || config.antiDebug

    override fun detect(context: Context): List<Threat> {
        val threats = mutableListOf<Threat>()
        val resolver = context.contentResolver

        val adb = Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0) == 1
        if (adb) {
            threats += threat(
                id = "device.adb_enabled",
                title = "USB debugging enabled",
                severity = Severity.MEDIUM,
                description = "Settings.Global.ADB_ENABLED is on",
                recommendation = "Warn users before performing privileged actions",
            )
        }

        val devOpts = Settings.Global.getInt(resolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        if (devOpts) {
            threats += threat(
                id = "device.developer_options",
                title = "Developer options enabled",
                severity = Severity.LOW,
                description = "Development settings are enabled on this device",
                recommendation = "Optional policy gate for enterprise apps",
            )
        }

        if (isOemUnlocked()) {
            threats += threat(
                id = "device.oem_unlock",
                title = "OEM unlock allowed",
                severity = Severity.MEDIUM,
                description = "sys.oem_unlock_allowed / related props indicate unlockable bootloader",
                recommendation = "Combine with Play Integrity strong for boot state",
            )
        }

        if (hasHttpProxy(context)) {
            threats += threat(
                id = "device.http_proxy",
                title = "HTTP proxy configured",
                severity = Severity.MEDIUM,
                description = "A global HTTP proxy is set — possible MITM setup",
                recommendation = "Enforce certificate pinning for sensitive APIs",
            )
        }

        if (isVpnActive(context)) {
            threats += threat(
                id = "device.vpn_active",
                title = "VPN network active",
                severity = Severity.LOW,
                description = "An active VPN transport/network was detected",
                recommendation = "Allow or restrict VPN based on product policy",
            )
        }

        return threats
    }

    private fun isOemUnlocked(): Boolean {
        val allowed = getProp("sys.oem_unlock_allowed")
        val unlocked = getProp("ro.boot.flash.locked")
        return allowed == "1" || unlocked == "0"
    }

    private fun hasHttpProxy(context: Context): Boolean {
        @Suppress("DEPRECATION")
        val host = Proxy.getHost(context)
        if (!host.isNullOrBlank()) return true
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
            val network = cm.activeNetwork ?: return false
            val proxy = cm.getLinkProperties(network)?.httpProxy
            return proxy != null && !proxy.host.isNullOrBlank()
        }
        return false
    }

    private fun isVpnActive(context: Context): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val networks = cm.allNetworks
            return networks.any { network ->
                val caps = cm.getNetworkCapabilities(network) ?: return@any false
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)
            }
        }
        @Suppress("DEPRECATION")
        return cm.allNetworks.any {
            @Suppress("DEPRECATION")
            cm.getNetworkInfo(it)?.type == ConnectivityManager.TYPE_VPN
        }
    }

    private fun getProp(key: String): String? =
        runCatching {
            Runtime.getRuntime().exec(arrayOf("getprop", key))
                .inputStream.bufferedReader().use { it.readLine() }?.trim()
        }.getOrNull()
}
