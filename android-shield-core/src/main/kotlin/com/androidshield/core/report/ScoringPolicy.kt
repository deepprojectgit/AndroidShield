package com.androidshield.core.report

import com.androidshield.core.model.Severity
import kotlinx.serialization.Serializable

/**
 * Configurable scoring rules for [SecurityReportBuilder].
 *
 * @property penalties Points subtracted per threat of each severity.
 * @property insecureSeverities Severities that force `secure=false`.
 * @property maxScore Upper bound (typically 100).
 * @property minScore Lower bound (typically 0).
 */
@Serializable
data class ScoringPolicy(
    val penalties: Map<Severity, Int> = DEFAULT_PENALTIES,
    val insecureSeverities: Set<Severity> = setOf(Severity.HIGH, Severity.CRITICAL),
    val maxScore: Int = 100,
    val minScore: Int = 0
) {
    init {
        require(maxScore >= minScore) { "maxScore must be >= minScore" }
    }

    fun penaltyFor(severity: Severity): Int = penalties[severity] ?: 0

    fun isInsecure(severity: Severity): Boolean = severity in insecureSeverities

    companion object {
        val DEFAULT_PENALTIES: Map<Severity, Int> = mapOf(
            Severity.LOW to 2,
            Severity.MEDIUM to 8,
            Severity.HIGH to 20,
            Severity.CRITICAL to 40
        )

        val DEFAULT: ScoringPolicy = ScoringPolicy()

        /** Stricter enterprise policy: medium findings also mark insecure. */
        val STRICT: ScoringPolicy = ScoringPolicy(
            penalties = mapOf(
                Severity.LOW to 5,
                Severity.MEDIUM to 15,
                Severity.HIGH to 30,
                Severity.CRITICAL to 50
            ),
            insecureSeverities = setOf(Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        )
    }
}
