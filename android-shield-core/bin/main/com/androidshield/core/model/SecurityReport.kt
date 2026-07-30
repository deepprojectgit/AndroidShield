package com.androidshield.core.model

import kotlinx.serialization.Serializable

/**
 * Aggregated security posture report returned by [com.androidshield.runtime.api.AndroidShield]
 * and build-time tooling.
 *
 * @property secure `true` when no HIGH/CRITICAL threats are present (policy may refine this).
 * @property score Integer score in `0..100` derived from threat severities.
 * @property threats Ordered list of findings (highest severity first by convention).
 */
@Serializable
data class SecurityReport(
    val secure: Boolean,
    val score: Int,
    val threats: List<Threat> = emptyList()
) {
    init {
        require(score in 0..100) { "score must be in 0..100, was $score" }
    }
}
