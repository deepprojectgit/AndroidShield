package com.androidshield.runtime.di

import android.content.Context
import com.androidshield.core.config.ShieldConfig
import com.androidshield.core.model.Threat
import com.androidshield.runtime.clipboard.ClipboardProtection
import com.androidshield.runtime.engine.MonitorScheduler
import com.androidshield.runtime.engine.ThreatEngine
import com.androidshield.runtime.storage.SecureStorage
import java.util.concurrent.atomic.AtomicReference

/**
 * Lightweight manual dependency graph — no reflection-based DI framework.
 */
internal class ShieldRuntimeGraph private constructor(
    val config: ShieldConfig,
    val threatEngine: ThreatEngine,
    val monitorScheduler: MonitorScheduler,
    val secureStorage: SecureStorage,
    val clipboardProtection: ClipboardProtection,
    val lastThreats: AtomicReference<List<Threat>>,
) {
    companion object {
        fun create(
            context: Context,
            config: ShieldConfig,
            lastThreats: AtomicReference<List<Threat>>,
        ): ShieldRuntimeGraph {
            val engine = ThreatEngine(context, config)
            val monitor = MonitorScheduler(engine) { threats ->
                lastThreats.set(threats)
            }
            val storage = SecureStorage.create(context)
            val clipboard = ClipboardProtection(context)
            return ShieldRuntimeGraph(
                config = config,
                threatEngine = engine,
                monitorScheduler = monitor,
                secureStorage = storage,
                clipboardProtection = clipboard,
                lastThreats = lastThreats,
            )
        }
    }
}
