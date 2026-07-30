package com.androidshield.plugin.report

import com.androidshield.core.model.SecurityReport
import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.core.report.SecurityReportBuilder
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Build-time security report describing enabled protections and validation findings.
 */
object BuildSecurityReporter {
    private val json = Json { prettyPrint = true; encodeDefaults = true }

    fun create(
        enabledFeatures: Map<String, Boolean>,
        validationThreats: List<Threat>,
    ): SecurityReport {
        val featureThreats = enabledFeatures
            .filterValues { !it }
            .map { (name, _) ->
                Threat(
                    id = "build.feature.disabled.$name",
                    title = "Protection disabled: $name",
                    severity = Severity.LOW,
                    description = "Feature `$name` is disabled in androidShield DSL",
                    recommendation = "Enable `$name` for stronger release hardening",
                )
            }
        return SecurityReportBuilder.fromThreats(featureThreats + validationThreats)
    }

    fun toJson(report: SecurityReport): String = json.encodeToString(report)
}
