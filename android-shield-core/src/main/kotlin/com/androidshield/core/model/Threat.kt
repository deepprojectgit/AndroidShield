package com.androidshield.core.model

import kotlinx.serialization.Serializable

/**
 * A single security finding produced by a detector or the ThreatEngine.
 *
 * @property id Stable machine-readable identifier (e.g. `root.su_binary`).
 * @property title Short human-readable title.
 * @property severity Risk level.
 * @property description Detailed explanation of the finding.
 * @property recommendation Suggested remediation or response.
 */
@Serializable
data class Threat(
    val id: String,
    val title: String,
    val severity: Severity,
    val description: String,
    val recommendation: String
)
