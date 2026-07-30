package com.androidshield.runtime.engine

import com.androidshield.core.model.Threat
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Schedules periodic threat evaluation for RASP monitoring.
 */
internal class MonitorScheduler(
    private val threatEngine: ThreatEngine,
    private val intervalMs: Long = DEFAULT_INTERVAL_MS,
    private val onThreats: (List<Threat>) -> Unit,
) {
    private val executor: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "android-shield-monitor").apply { isDaemon = true }
        }

    private val future = AtomicReference<ScheduledFuture<*>?>(null)

    fun start() {
        if (future.get() != null) return
        val scheduled = executor.scheduleWithFixedDelay(
            {
                runCatching {
                    onThreats(threatEngine.evaluate())
                }
            },
            0L,
            intervalMs,
            TimeUnit.MILLISECONDS,
        )
        future.compareAndSet(null, scheduled)
    }

    fun stop() {
        future.getAndSet(null)?.cancel(false)
    }

    companion object {
        private const val DEFAULT_INTERVAL_MS: Long = 5_000L
    }
}
