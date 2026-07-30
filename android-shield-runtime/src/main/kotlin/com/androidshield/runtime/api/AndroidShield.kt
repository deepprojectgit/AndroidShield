package com.androidshield.runtime.api

import android.app.Activity
import android.content.Context
import com.androidshield.core.config.ShieldConfig
import com.androidshield.core.model.SecurityReport
import com.androidshield.core.model.Threat
import com.androidshield.core.report.SecurityReportBuilder
import com.androidshield.runtime.clipboard.ClipboardProtection
import com.androidshield.runtime.di.ShieldRuntimeGraph
import com.androidshield.runtime.network.SslPinning
import com.androidshield.runtime.network.SslPinningConfig
import com.androidshield.runtime.play.PlayIntegrityClient
import com.androidshield.runtime.screen.ScreenProtection
import com.androidshield.runtime.storage.SecureStorage
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HostnameVerifier

/**
 * Public entry point for AndroidShield runtime protection and RASP.
 */
object AndroidShield {
    private val initialized = AtomicBoolean(false)
    private val monitoring = AtomicBoolean(false)
    private val graph = AtomicReference<ShieldRuntimeGraph?>(null)
    private val lastThreats = AtomicReference<List<Threat>>(emptyList())

    /**
     * Initializes the shield for the given [context].
     *
     * Safe to call once; subsequent calls are no-ops if already initialized.
     */
    @JvmStatic
    @JvmOverloads
    fun initialize(context: Context, config: ShieldConfig = ShieldConfig()) {
        if (initialized.compareAndSet(false, true)) {
            val appContext = context.applicationContext
            graph.set(ShieldRuntimeGraph.create(appContext, config, lastThreats))
        }
    }

    /**
     * Runs an on-demand verification pass and returns the aggregated report.
     */
    @JvmStatic
    fun verify(): SecurityReport {
        ensureInitialized()
        val threats = graph.get()!!.threatEngine.evaluate()
        lastThreats.set(threats)
        return SecurityReportBuilder.fromThreats(threats)
    }

    /**
     * Starts continuous RASP monitoring on a background scheduler.
     */
    @JvmStatic
    fun startMonitoring() {
        ensureInitialized()
        if (monitoring.compareAndSet(false, true)) {
            val g = graph.get()!!
            g.clipboardProtection.start()
            g.monitorScheduler.start()
        }
    }

    /**
     * Stops continuous monitoring.
     */
    @JvmStatic
    fun stopMonitoring() {
        if (monitoring.compareAndSet(true, false)) {
            graph.get()?.clipboardProtection?.stop()
            graph.get()?.monitorScheduler?.stop()
        }
    }

    /** Most recent threat set from [verify] or monitoring. */
    @JvmStatic
    fun getThreats(): List<Threat> = lastThreats.get()

    /** Builds a [SecurityReport] from current threats. */
    @JvmStatic
    fun generateReport(): SecurityReport =
        SecurityReportBuilder.fromThreats(getThreats())

    /** `true` when the last report is not secure (HIGH/CRITICAL by default policy). */
    @JvmStatic
    fun isCompromised(): Boolean = !generateReport().secure

    @JvmStatic
    fun isInitialized(): Boolean = initialized.get()

    @JvmStatic
    fun isMonitoring(): Boolean = monitoring.get()

    /** Keystore-backed secure storage. */
    @JvmStatic
    fun secureStorage(): SecureStorage {
        ensureInitialized()
        return graph.get()!!.secureStorage
    }

    /** Clipboard auto-clear helper. */
    @JvmStatic
    fun clipboard(): ClipboardProtection {
        ensureInitialized()
        return graph.get()!!.clipboardProtection
    }

    /** Applies FLAG_SECURE + tapjacking guards on an activity. */
    @JvmStatic
    fun protectScreen(activity: Activity) {
        ScreenProtection.enableFlagSecure(activity)
        ScreenProtection.enableTapjackingGuards(activity)
    }

    /** Builds a pinning [HostnameVerifier] from configs. */
    @JvmStatic
    fun sslHostnameVerifier(configs: List<SslPinningConfig>): HostnameVerifier =
        SslPinning.pinningHostnameVerifier(SslPinning.toHostnameMap(configs))

    /** Creates a Play Integrity client (requires Play services). */
    @JvmStatic
    @JvmOverloads
    fun playIntegrity(context: Context, cloudProjectNumber: Long? = null): PlayIntegrityClient =
        PlayIntegrityClient(context, cloudProjectNumber)

    /** Current runtime config snapshot. */
    @JvmStatic
    fun config(): ShieldConfig {
        ensureInitialized()
        return graph.get()!!.config
    }

    private fun ensureInitialized() {
        check(initialized.get()) {
            "AndroidShield.initialize(context) must be called before use"
        }
    }
}
