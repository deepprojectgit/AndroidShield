package com.androidshield.testing

import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat

/**
 * Shared fixtures for unit and instrumentation tests.
 */
object ThreatFixtures {
    fun sampleLow(): Threat = Threat(
        id = "test.sample.low",
        title = "Sample Low Threat",
        severity = Severity.LOW,
        description = "Fixture threat for unit tests",
        recommendation = "Ignore in production"
    )

    fun sampleCritical(): Threat = Threat(
        id = "test.sample.critical",
        title = "Sample Critical Threat",
        severity = Severity.CRITICAL,
        description = "Fixture critical threat for unit tests",
        recommendation = "Treat as compromising"
    )
}
