package com.androidshield.runtime.detector

import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat

internal fun threat(
    id: String,
    title: String,
    severity: Severity,
    description: String,
    recommendation: String,
): Threat = Threat(
    id = id,
    title = title,
    severity = severity,
    description = description,
    recommendation = recommendation,
)
