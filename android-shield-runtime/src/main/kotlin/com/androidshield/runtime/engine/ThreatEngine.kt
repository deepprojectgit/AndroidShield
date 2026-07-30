package com.androidshield.runtime.engine

import android.content.Context
import com.androidshield.core.config.ShieldConfig
import com.androidshield.core.model.Threat
import com.androidshield.runtime.detector.DetectorRegistry
import com.androidshield.runtime.detector.ThreatDetector
import com.androidshield.runtime.play.PlayIntegrityClient
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Evaluates enabled detectors and aggregates [Threat] results.
 */
internal class ThreatEngine(
    private val context: Context,
    private val config: ShieldConfig,
    private val detectors: List<ThreatDetector> = DetectorRegistry.create(config),
) {
    private val listeners = CopyOnWriteArrayList<(List<Threat>) -> Unit>()
    private val playIntegrity = if (config.playIntegrity) {
        runCatching { PlayIntegrityClient(context) }.getOrNull()
    } else {
        null
    }

    fun addListener(listener: (List<Threat>) -> Unit) {
        listeners.add(listener)
    }

    fun removeListener(listener: (List<Threat>) -> Unit) {
        listeners.remove(listener)
    }

    fun evaluate(): List<Threat> {
        val threats = mutableListOf<Threat>()
        detectors.forEach { detector ->
            runCatching { detector.detect(context) }
                .onSuccess { threats += it }
                .onFailure { error ->
                    threats += com.androidshield.runtime.detector.threat(
                        id = "engine.detector_error.${detector.id}",
                        title = "Detector failure: ${detector.id}",
                        severity = com.androidshield.core.model.Severity.LOW,
                        description = error.message ?: error.toString(),
                        recommendation = "Check device permissions / SELinux for detector ${detector.id}",
                    )
                }
        }
        playIntegrity?.let { client ->
            threats += client.availabilityThreats(enabledInConfig = true)
        }
        val ordered = threats.sortedByDescending { it.severity.ordinal }
        listeners.forEach { listener -> listener(ordered) }
        return ordered
    }
}
