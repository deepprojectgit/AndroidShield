package com.androidshield.core.report

import com.androidshield.core.model.SecurityReport
import com.androidshield.core.model.Threat
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Builds and serializes [SecurityReport] instances from a set of [Threat]s.
 */
object SecurityReportBuilder {
    private val json =
        Json {
            prettyPrint = true
            encodeDefaults = true
            ignoreUnknownKeys = true
        }

    /**
     * Computes a report from the given threats using [policy].
     */
    @JvmOverloads
    fun fromThreats(
        threats: List<Threat>,
        policy: ScoringPolicy = ScoringPolicy.DEFAULT,
    ): SecurityReport {
        val ordered = threats.sortedByDescending { it.severity.ordinal }
        val penalty = ordered.sumOf { policy.penaltyFor(it.severity) }
        val score = (policy.maxScore - penalty).coerceIn(policy.minScore, policy.maxScore)
        val secure = ordered.none { policy.isInsecure(it.severity) }
        return SecurityReport(secure = secure, score = score, threats = ordered)
    }

    /**
     * Serializes a report to canonical JSON.
     */
    fun toJson(report: SecurityReport): String = json.encodeToString(report)

    /**
     * Parses a report from JSON.
     */
    fun fromJson(raw: String): SecurityReport = json.decodeFromString(raw)
}
